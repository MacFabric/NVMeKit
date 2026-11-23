import Foundation

/// Who we are and what we are attaching to.
public struct NVMeControllerConfig: Sendable {
    public var host: NVMeHostIdentity
    public var subsystemNQN: String
    /// Offer header and data digests in ICReq; the controller picks.
    public var requestDigests = true
    /// Optional function-level diagnostics. The sink may be called concurrently.
    public var debugLog: (@Sendable (String) -> Void)?
    /// I/O queue depth to ask for, clamped to CAP.MQES.
    public var ioQueueEntries: UInt16 = 128
    /// I/O queues to ask for, each a TCP connection of its own with its own
    /// receive loop. The controller grants what it will (Set Features,
    /// Number of Queues) and the fewer of the two is opened. One, the
    /// default, is what this initiator always had; more spread commands over
    /// several connections, which is where small-block throughput is bounded
    /// by one connection's receive loop and not by the link.
    public var ioQueueCount = 1
    public var adminQueueEntries: UInt16 = 32
    /// KATO for the admin Connect, in ms. nil derives twice the keepalive
    /// interval from the session policy (0, i.e. no timer, when the policy
    /// runs no keepalive).
    public var keepAliveMS: UInt32?

    public init(host: NVMeHostIdentity, subsystemNQN: String) {
        self.host = host
        self.subsystemNQN = subsystemNQN
    }
}

/// One NVMe-oF controller: an admin queue and one I/O queue, each its own
/// TCP connection, brought up together and torn down together. Owns
/// keepalive and recovery the way `ISCSISession` does: any loss of either
/// queue destroys the pair, and the next command rebuilds a fresh one.
public actor NVMeController {
    public typealias TransportFactory = @Sendable () async throws -> any ConnectionTransport

    private enum QueueKind { case admin, io }

    /// The largest inbound I/O PDU: nvmet answers a read with a single
    /// C2HData for the whole transfer, so this bounds the transfer size.
    static let ioPDULimit = (1 << 20) + 4096
    static let adminPDULimit = 64 << 10
    /// The largest single Read a block device may issue: what fits in one
    /// inbound PDU with room for the header and digests.
    public static let maxIOTransferBytes = ioPDULimit - 4096

    private let makeTransport: TransportFactory
    private let config: NVMeControllerConfig
    private let policy: SessionPolicy
    nonisolated let debugLog: (@Sendable (String) -> Void)?

    private var admin: NVMeQueue?
    /// The I/O queues, QID 1 upward. Empty while there is no controller.
    private var ioQueues: [NVMeQueue] = []
    /// Which of them takes the next command: each in turn.
    private var nextIOQueue = 0
    private var controllerID: UInt16 = 0
    private var capabilities: ControllerCapabilities?
    public private(set) var identity: IdentifyController?
    public private(set) var digests = NVMeTCPDigests()
    private var keepaliveTask: Task<Void, Never>?
    private var recoveryTask: Task<Void, any Error>?
    private var loggedOut = false
    /// Latched when recovery gives up: the controller is dead until an
    /// explicit `activate()`. Without it every later command re-ran the whole
    /// recovery budget (5 attempts × the connect timeout), so a caller behind
    /// a dead target waited a full cycle only to fail — and the daemon's
    /// periodic flush tick re-triggered it forever. The iSCSI `ISCSISession`
    /// twin carries the same latch.
    private var recoveryFailed: SessionError?
    /// Diagnostics for tests and status reporting.
    public private(set) var recoveryCount = 0
    /// The last `logout()` saw CSTS.SHST report the shutdown complete.
    public private(set) var shutdownAcknowledged = false
    private var onEvent: (@Sendable (SessionEvent) -> Void)?

    public init(config: NVMeControllerConfig, policy: SessionPolicy = SessionPolicy(),
                transportFactory: @escaping TransportFactory) {
        self.config = config
        self.policy = policy
        self.debugLog = config.debugLog
        self.makeTransport = transportFactory
    }

    public func setEventHandler(_ handler: @escaping @Sendable (SessionEvent) -> Void) {
        onEvent = handler
    }

    public var subsystemNQN: String { config.subsystemNQN }

    /// VWC from Identify Controller: whether FUA and Flush mean anything.
    public var volatileWriteCachePresent: Bool? { identity?.volatileWriteCachePresent }

    /// SQ entries the live I/O queue was connected with; nil when down.
    public var ioQueueEntries: UInt16? { ioQueues.first?.entries }

    /// I/O queues open right now: the fewer of what the configuration asked
    /// for and what the controller granted.
    public var ioQueueCount: Int { ioQueues.count }

    /// MDTS in bytes; nil when the controller sets no limit.
    public var maxTransferBytes: Int? {
        guard let identity, let capabilities else { return nil }
        return identity.maxTransferBytes(pageBytes: capabilities.minPageBytes)
    }

    var keepAliveMS: UInt32 {
        if let explicit = config.keepAliveMS { return explicit }
        guard let interval = policy.nopInterval else { return 0 }
        return UInt32(clamping: Self.milliseconds(interval) * 2)
    }

    static func milliseconds(_ duration: Duration) -> Int {
        let parts = duration.components
        return Int(parts.seconds) * 1000 + Int(parts.attoseconds / 1_000_000_000_000_000)
    }

    // MARK: - Lifecycle

    public func activate() async throws {
        loggedOut = false
        recoveryFailed = nil
        guard ioQueues.isEmpty else { return }
        try await establish()
    }

    /// Ends the controller, including a recovery in progress: without
    /// stopping it, a recovery that was backing off when the user detached
    /// brought a fresh pair up afterwards — two connections and a keepalive
    /// nothing would ever stop.
    public func logout() async throws {
        loggedOut = true
        keepaliveTask?.cancel()
        keepaliveTask = nil
        if let recovery = recoveryTask {
            recovery.cancel()
            _ = try? await recovery.value
        }
        // Best effort: a normal shutdown notification (CC.SHN = 01b), then
        // wait for CSTS.SHST to report it complete, so a controller with a
        // volatile cache gets its chance to flush. nvmet frees the
        // controller when the admin connection closes anyway.
        shutdownAcknowledged = false
        if let admin {
            shutdownAcknowledged = (try? await withDeadline(.seconds(2)) {
                _ = try await admin.submitChecked(NVMeCommands.propertySet(
                    commandID: 0, offset: NVMeProperty.cc,
                    value: NVMeCommands.controllerConfigurationEnable | NVMeCommands.shutdownNormal))
                while true {
                    let raw = try await admin.submitChecked(
                        NVMeCommands.propertyGet(commandID: 0, offset: NVMeProperty.csts, wide: false)).cqe.dw0
                    if ControllerStatus(raw: raw).shutdownComplete { return true }
                    try await Task.sleep(for: .milliseconds(20))
                }
            }) ?? false
        }
        await dropQueues()
    }

    // MARK: - Command execution

    /// Run an I/O command to a successful completion, transparently
    /// rebuilding the controller and retrying on connection loss, and
    /// retrying in place on a Transient Transport Error — a data digest
    /// failure, which costs the command and not the connection. Both bounded
    /// by policy. Block I/O is idempotent, so the retry is safe.
    ///
    /// `readInto`: where the data is to be received; see `NVMeQueue.submit`.
    public func execute(_ sqe: SQE, data: Data = Data(), expectedRead: Int = 0,
                        readInto: ReadBuffer.Region? = nil) async throws -> NVMeCompletion {
        try await execute(on: .io, sqe, data: data, expectedRead: expectedRead, readInto: readInto)
    }

    /// The same for admin commands.
    public func executeAdmin(_ sqe: SQE, expectedRead: Int = 0) async throws -> NVMeCompletion {
        try await execute(on: .admin, sqe, data: Data(), expectedRead: expectedRead)
    }

    private func execute(on kind: QueueKind, _ sqe: SQE, data: Data, expectedRead: Int,
                         readInto: ReadBuffer.Region? = nil) async throws -> NVMeCompletion {
        debugLog?("NVMeController.\(#function) queue=\(kind) \(sqe.logCommandFields)"
                  + " dataBytes=\(data.count) expectedRead=\(expectedRead)")
        var attempt = 0
        while true {
            let queue = try await ensureActive(kind)
            do {
                let completion = try await withDeadline(policy.taskTimeout) {
                    try await queue.submitChecked(sqe, data: data, expectedRead: expectedRead, readInto: readInto)
                }
                debugLog?("NVMeController.\(#function) finished queue=\(kind) attempt=\(attempt + 1)"
                          + " connection=\(completion.connectionID?.uuidString ?? "-") cid=\(completion.cqe.commandID)"
                          + " receivedBytes=\(completion.receivedBytes)")
                return completion
            } catch let error as NVMeConnectionError {
                try Task.checkCancellation()
                let willRetry = !loggedOut && attempt < policy.taskRetries
                debugLog?("NVMeController.\(#function) \(willRetry ? "retrying" : "failed") queue=\(kind) attempt=\(attempt + 1)"
                          + " \(sqe.logCommandFields) error=\(error)")
                guard willRetry else { throw error }
                attempt += 1
                try await recover(after: error, on: queue)
            } catch BlockDeviceError.nvmeStatus(let sct, let sc, let opcode)
                where NVMeStatus(sct: sct, sc: sc) == NVMeQueue.transientTransportError {
                // Matched on SCT/SC alone: a controller-sent 22h with DNR set
                // is retried too, which is harmless for idempotent block I/O.
                try Task.checkCancellation()
                let error = BlockDeviceError.nvmeStatus(sct: sct, sc: sc, opcode: opcode)
                let willRetry = !loggedOut && attempt < policy.taskRetries
                debugLog?("NVMeController.\(#function) \(willRetry ? "retrying" : "failed") queue=\(kind) attempt=\(attempt + 1)"
                          + " \(sqe.logCommandFields) error=\(error)")
                guard willRetry else { throw error }
                attempt += 1
            } catch is DeadlineError {
                try Task.checkCancellation()
                // The command is still outstanding on that queue, which may
                // yet receive data for it. Closed first, and waited for: a
                // retry reads into the same buffer, and nothing may still be
                // writing there. Recovery would close it anyway.
                await queue.close()
                // No usable Abort on NVMe-oF: drop the pair rather than let a
                // wedge be inherited, and rebuild on the next attempt.
                let willRetry = !loggedOut && attempt < policy.taskRetries
                debugLog?("NVMeController.\(#function) \(willRetry ? "retrying" : "failed") queue=\(kind) attempt=\(attempt + 1)"
                          + " \(sqe.logCommandFields) error=\(SessionError.taskTimedOut)")
                guard willRetry else {
                    await dropQueues()
                    throw SessionError.taskTimedOut
                }
                attempt += 1
                try await recover(after: nil, on: queue)
            } catch {
                debugLog?("NVMeController.\(#function) failed queue=\(kind) attempt=\(attempt + 1)"
                          + " \(sqe.logCommandFields) error=\(error)")
                throw error
            }
        }
    }

    /// Identify Active Namespace ID list.
    public func activeNamespaces() async throws -> [UInt32] {
        let completion = try await executeAdmin(
            NVMeCommands.identify(commandID: 0, cns: IdentifyCNS.activeNamespaces, nsid: 0),
            expectedRead: IdentifyNamespace.size)
        return ActiveNamespaceList.parse(completion.data)
    }

    /// Identify Namespace, reduced to the geometry a block device needs.
    public func identifyNamespace(_ nsid: UInt32) async throws -> (blockSize: Int, blockCount: UInt64) {
        let completion = try await executeAdmin(
            NVMeCommands.identify(commandID: 0, cns: IdentifyCNS.namespace, nsid: nsid),
            expectedRead: IdentifyNamespace.size)
        return try IdentifyNamespace.geometry(from: completion.data)
    }

    /// Label/value pairs for the Sessions pane, the `OperationalParameters.
    /// displayPairs` twin.
    public var displayPairs: [String: String] {
        var out: [String: String] = [
            "HeaderDigest": digests.header ? "CRC32C" : "None",
            "DataDigest": digests.data ? "CRC32C" : "None",
            "KATO": "\(keepAliveMS) ms",
            "CNTLID": String(controllerID),
        ]
        if let identity {
            out["Model"] = identity.model
            out["Serial"] = identity.serial
            out["Firmware"] = identity.firmware
            out["VWC"] = identity.volatileWriteCachePresent ? "present" : "absent"
            out["MDTS"] = maxTransferBytes.map { "\($0) bytes" } ?? "unlimited"
            out["IOCCSZ"] = "\(identity.inCapsuleDataBytes) bytes in-capsule"
            out["MAXCMD"] = String(identity.maxOutstandingCommands)
        }
        if let capabilities {
            out["MQES"] = String(capabilities.maxQueueEntries)
        }
        if let first = ioQueues.first {
            out["IOQueueEntries"] = String(first.entries)
            out["IOQueues"] = String(ioQueues.count)
        }
        return out
    }

    // MARK: - Bring-up

    private func ensureActive(_ kind: QueueKind) async throws -> NVMeQueue {
        debugLog?("NVMeController.\(#function) queue=\(kind)")
        if loggedOut { throw SessionError.loggedOut }
        if let recoveryFailed { throw recoveryFailed }
        if let queue = queue(kind) { return queue }
        try await recover(after: nil, on: nil)
        guard let queue = queue(kind) else { throw SessionError.notActive }
        return queue
    }

    /// The queue a command of this kind goes to now. I/O commands take the
    /// I/O queues in turn: nothing orders one command against another, and
    /// the commands a large request is split into are issued together, so
    /// they land one per queue.
    private func queue(_ kind: QueueKind) -> NVMeQueue? {
        if kind == .admin { return admin }
        guard !ioQueues.isEmpty else { return nil }
        nextIOQueue = (nextIOQueue + 1) % ioQueues.count
        return ioQueues[nextIOQueue]
    }

    /// Admin queue up and the controller enabled — shared with discovery,
    /// which stops here.
    ///
    /// Nothing on a queue has an answer timeout of its own, so bring-up runs
    /// in bounded steps: the IC exchange through CC.EN within `timeout`
    /// (`SessionPolicy.loginTimeout`), then the CSTS.RDY wait within CAP.TO,
    /// which the controller states and can legitimately exceed the login
    /// timeout. A step that runs out closes the queue — the only thing that
    /// ends its parked read — and throws `DeadlineError.timedOut`.
    static func bringUpAdminQueue(
        _ queue: NVMeQueue, host: NVMeHostIdentity, subsystemNQN: String, keepAliveMS: UInt32,
        timeout: Duration? = SessionPolicy().loginTimeout
    ) async throws -> (controllerID: UInt16, capabilities: ControllerCapabilities) {
        let (controllerID, cap) = try await withDeadline(timeout, onTimeout: { await queue.close() }) {
            let (controllerID, authRequired) = try await queue.connect(
                host: host, subsystemNQN: subsystemNQN, controllerID: 0xFFFF, keepAliveMS: keepAliveMS)
            if authRequired {
                // Surfaced as the status the spec assigns it, so the error text
                // can say what to switch off on the NAS.
                throw BlockDeviceError.nvmeStatus(sct: 1, sc: 0x91, opcode: NVMeOpcode.Admin.fabrics)
            }
            let cap = ControllerCapabilities(raw: try await queue.submitChecked(
                NVMeCommands.propertyGet(commandID: 0, offset: NVMeProperty.cap, wide: true)).cqe.result64)
            guard cap.supportsNVMCommandSet else {
                throw NVMeConnectionError.protocolError("controller does not support the NVM command set")
            }
            _ = try await queue.submitChecked(NVMeCommands.propertySet(
                commandID: 0, offset: NVMeProperty.cc, value: NVMeCommands.controllerConfigurationEnable))
            return (controllerID, cap)
        }
        // CSTS.RDY follows CC.EN within CAP.TO; CFS means it never will.
        try await withDeadline(.milliseconds(max(cap.readyTimeoutMS, 500))) {
            while true {
                let raw = try await queue.submitChecked(
                    NVMeCommands.propertyGet(commandID: 0, offset: NVMeProperty.csts, wide: false)).cqe.dw0
                let csts = ControllerStatus(raw: raw)
                if csts.fatal { throw BlockDeviceError.notReady }
                if csts.ready { return }
                try await Task.sleep(for: .milliseconds(20))
            }
        }
        return (controllerID, cap)
    }

    private func establish() async throws {
        let adminQueue = NVMeQueue(
            transport: try await makeTransport(), queueID: 0, entries: config.adminQueueEntries,
            requestDigests: config.requestDigests, maxPDUBytes: Self.adminPDULimit, debugLog: debugLog)
        do {
            let (cntlid, cap) = try await Self.bringUpAdminQueue(
                adminQueue, host: config.host, subsystemNQN: config.subsystemNQN, keepAliveMS: keepAliveMS,
                timeout: policy.loginTimeout)
            controllerID = cntlid
            capabilities = cap
            digests = await adminQueue.digests

            let wanted = max(1, min(config.ioQueueCount, Self.maxIOQueues))
            let (id, granted) = try await withDeadline(policy.loginTimeout, onTimeout: { await adminQueue.close() }) {
                let id = try IdentifyController(data: try await adminQueue.submitChecked(
                    NVMeCommands.identify(commandID: 0, cns: IdentifyCNS.controller),
                    expectedRead: IdentifyController.size).data)
                // Submission and completion queues wanted, 0's based, in the
                // low and high halves; the answer is what was allocated, in
                // the same form, and may be more or fewer than asked.
                let allocated = try await adminQueue.submitChecked(NVMeCommands.setFeatures(
                    commandID: 0, featureID: NVMeFeature.numberOfQueues,
                    dword11: UInt32(wanted - 1) | UInt32(wanted - 1) << 16)).cqe.dw0
                return (id, Int(min(allocated & 0xFFFF, allocated >> 16)) + 1)
            }
            identity = id

            // Never deeper than CAP.MQES allows, nor than MAXCMD says the
            // controller will process per queue (0 = unstated).
            var entries = UInt16(clamping: min(Int(config.ioQueueEntries), cap.maxQueueEntries))
            if id.maxOutstandingCommands > 0 {
                entries = min(entries, UInt16(clamping: id.maxOutstandingCommands))
            }
            var opened: [NVMeQueue] = []
            do {
                for qid in 1 ... min(wanted, granted) {
                    let ioQueue = NVMeQueue(
                        transport: try await makeTransport(), queueID: UInt16(qid), entries: max(entries, 2),
                        requestDigests: config.requestDigests, maxPDUBytes: Self.ioPDULimit, debugLog: debugLog)
                    opened.append(ioQueue)
                    let host = config.host, subsystemNQN = config.subsystemNQN
                    _ = try await withDeadline(policy.loginTimeout, onTimeout: { await ioQueue.close() }) {
                        try await ioQueue.connect(host: host, subsystemNQN: subsystemNQN,
                                                  controllerID: cntlid, keepAliveMS: 0)
                    }
                    // In-capsule data is addressed from ICDOFF, which this
                    // initiator only supports at 0 (nvmet's value); anything
                    // else means every write is solicited instead.
                    await ioQueue.setInCapsuleLimit(id.inCapsuleDataOffsetBytes == 0 ? id.inCapsuleDataBytes : 0)
                }
                // Logged out while this bring-up was under way: queues
                // installed now would have nobody to take them down.
                guard !loggedOut else { throw SessionError.loggedOut }
            } catch {
                for queue in opened { await queue.close() }
                throw error
            }
            admin = adminQueue
            ioQueues = opened
            nextIOQueue = 0
            startKeepalive(on: adminQueue)
            watchForClose(of: adminQueue)
            for queue in opened { watchForClose(of: queue) }
        } catch {
            await adminQueue.close()
            throw error
        }
    }

    /// The most I/O queues this initiator opens, whatever is asked for: a
    /// connection and a receive loop each, and nothing here gains from more
    /// of them than there are cores to run the loops.
    public static let maxIOQueues = 16

    /// Tear every queue down without rebuilding. The next `ensureActive`
    /// starts fresh, so a wedge is not inherited by whoever comes next.
    private func dropQueues() async {
        keepaliveTask?.cancel()
        keepaliveTask = nil
        let oldAdmin = admin
        let oldIO = ioQueues
        admin = nil
        ioQueues = []
        for queue in oldIO { await queue.close() }
        await oldAdmin?.close()
    }

    private func isCurrent(_ queue: NVMeQueue) -> Bool {
        queue === admin || ioQueues.contains { $0 === queue }
    }

    /// Recovery: tear the pair down, back off, bring a fresh pair up.
    /// Coalesces concurrent callers onto a single recovery task.
    ///
    /// `failed` is the queue the caller's attempt ran on, nil when there was
    /// none. If neither queue is it any more, someone else's recovery already
    /// replaced the pair, and the caller just retries: tearing down the
    /// current pair would reset a healthy controller for a late failure.
    private func recover(after error: NVMeConnectionError?, on failed: NVMeQueue?) async throws {
        if let recoveryFailed { throw recoveryFailed }
        if loggedOut { throw SessionError.loggedOut }
        if let existing = recoveryTask {
            try await existing.value
            return
        }
        if let failed, !isCurrent(failed), admin != nil || !ioQueues.isEmpty { return }
        // `recoveryTask` MUST be assigned before the first suspension point.
        // Actor isolation does not span an `await`: with the teardown out here,
        // a second caller reaching the guard while this one was inside
        // `dropQueues()` also saw nil, and both rebuilt the controller —
        // double-counting the recovery and tearing down a pair the other was
        // bringing up. Everything that suspends therefore lives inside the
        // task, which is published synchronously below.
        // Observed in production 2026-09-02; see docs/resilience.md.
        let task = Task { [policy, onEvent] in
            onEvent?(.connectionLost(reason: error.map { "\($0)" } ?? "no active controller"))
            await self.dropQueues()

            var lastError = error.map { "\($0)" } ?? "initial"
            for attempt in 0 ..< policy.maxRecoveryAttempts {
                onEvent?(.recoveryAttempt(number: attempt + 1, of: policy.maxRecoveryAttempts))
                if attempt > 0 || error != nil {
                    try await Task.sleep(for: Self.recoveryDelay(attempt: attempt, policy: policy))
                }
                try Task.checkCancellation()
                do {
                    try await self.establishForRecovery()
                    onEvent?(.recovered(totalRecoveries: self.recoveryCount))
                    return
                } catch SessionError.loggedOut {
                    throw SessionError.loggedOut
                } catch {
                    lastError = "\(error)"
                }
            }
            onEvent?(.recoveryExhausted(lastError: lastError))
            throw SessionError.recoveryExhausted(lastError: lastError)
        }
        recoveryTask = task
        defer { recoveryTask = nil }
        do {
            try await task.value
        } catch let failure as SessionError {
            if case .recoveryExhausted = failure { recoveryFailed = failure }
            throw failure
        } catch {
            // Cancelled by `logout`: say so, not "cancelled".
            if loggedOut { throw SessionError.loggedOut }
            throw error
        }
    }

    /// Plain exponential backoff; NVMe-oF has no DefaultTime2Wait to honour.
    static func recoveryDelay(attempt: Int, policy: SessionPolicy) -> Duration {
        let factor = 1 << min(attempt, 8)
        return min(policy.recoveryBackoffBase * factor, policy.recoveryBackoffCap)
    }

    private func establishForRecovery() async throws {
        try await establish()
        recoveryCount += 1
    }

    private func startKeepalive(on queue: NVMeQueue) {
        keepaliveTask?.cancel()
        guard let interval = policy.nopInterval else { return }
        keepaliveTask = Task { [policy] in
            while !Task.isCancelled {
                try? await Task.sleep(for: interval)
                if Task.isCancelled { return }
                do {
                    try await withDeadline(policy.nopTimeout) {
                        _ = try await queue.submitChecked(NVMeCommands.keepAlive(commandID: 0))
                    }
                } catch {
                    // Dead peer: kill the queue; execute() paths recover.
                    await queue.close()
                    return
                }
            }
        }
    }

    private func watchForClose(of queue: NVMeQueue) {
        Task { [weak self] in
            _ = await queue.waitClosed()
            await self?.noteClosed(queue)
        }
    }

    /// Either queue closing ends the controller: nvmet frees it when the
    /// admin connection goes, and an I/O queue cannot outlive its admin
    /// queue's identity in any way this initiator wants to reason about.
    private func noteClosed(_ closed: NVMeQueue) async {
        guard isCurrent(closed) else { return }
        await dropQueues()
    }
}
