import Foundation

/// A command's completion: the CQE and, for reads, the bytes the C2HData
/// PDUs delivered.
public struct NVMeCompletion: Sendable {
    public let cqe: CQE
    public let data: Data
    let receivedBytes: Int
    let connectionID: UUID?
}

/// One NVMe/TCP connection, which is one queue pair: ICReq/ICResp, then a
/// Fabrics Connect, then command capsules with their data transfers. Free
/// of retry and recovery policy — that lives in `NVMeController`, exactly
/// as `ISCSIConnection` leaves it to `ISCSISession`.
public actor NVMeQueue {
    private enum State: Equatable {
        case idle
        case connected
        case closed
    }

    /// Completion holder: the responder side may complete before the
    /// requester suspends, so results are buffered. @unchecked Sendable is
    /// sound because every access happens on this actor.
    private final class Awaitable<Value: Sendable>: @unchecked Sendable {
        var buffered: Result<Value, any Error>?
        var continuation: CheckedContinuation<Value, any Error>?

        func complete(_ result: Result<Value, any Error>) {
            if let c = continuation {
                continuation = nil
                c.resume(with: result)
            } else if buffered == nil {
                buffered = result
            }
        }
    }

    private final class PendingCommand {
        let opcode: UInt8
        /// Write data, kept so R2Ts can be answered from it.
        let writeData: Data
        /// Bytes every R2T so far has asked for; the next one must start
        /// exactly here (NVMe/TCP 1.1 §3.3.2.2).
        var solicitedBytes = 0
        /// Where C2HData is received: the caller's region, or one made here.
        /// Not zeroed in advance; `complete` clears whatever was never
        /// delivered before the bytes can be seen. nil for a command that
        /// reads nothing.
        let destination: ReadBuffer.Region?
        /// The caller supplied `destination`, so the completion carries no data.
        let callerOwnsDestination: Bool
        /// Bytes the command asked for.
        let expectedRead: Int
        /// C2HData bytes accepted so far; a successful completion must
        /// account for every byte or the read has silent zero-filled holes.
        /// Every PDU must start exactly here (NVMe/TCP 1.1 §3.3.2.1), so a
        /// repeated or skipped range cannot make the count come out right.
        var receivedBytes = 0
        /// LAST_PDU seen: any further C2HData for this command is a
        /// sequence error.
        var dataComplete = false
        /// A C2HData PDU failed its data digest. The transfer continues and
        /// the command fails at completion (NVMe/TCP 1.1 §3.5).
        var dataDigestFailed = false
        /// Cancelled locally; the entry stays so the controller's completion
        /// for this CID is absorbed rather than mistaken for a stray.
        var terminated = false
        let completion = Awaitable<NVMeCompletion>()

        init(opcode: UInt8, writeData: Data, expectedRead: Int, readInto: ReadBuffer.Region?) {
            self.opcode = opcode
            self.writeData = writeData
            self.expectedRead = expectedRead
            callerOwnsDestination = readInto != nil
            destination = expectedRead > 0 ? (readInto ?? ReadBuffer(count: expectedRead).whole) : nil
        }
    }

    /// A C2HData PDU whose header has been taken and whose data is still
    /// arriving, and where that data is going.
    private struct Inbound {
        let head: NVMeTCPDeframer.Head
        /// The command's own buffer, when the checks `handleC2HData` will
        /// make have already been made; nil for every other PDU, whose data
        /// is taken whole.
        let placement: UnsafeMutableRawBufferPointer?
        /// Keeps `placement`'s memory alive while it is being filled.
        let owner: ReadBuffer?
        var filled = 0
    }

    private var inbound: Inbound?

    /// A fatal transport error detected here (NVMe/TCP 1.1 §3.5): what the
    /// H2CTermReq says, and what the connection then closes with.
    private struct FatalTransportError: Error {
        let fes: NVMeTCPFatalErrorStatus
        /// Byte offset of the offending field, for the FES values that
        /// carry one; 0 otherwise.
        let fei: UInt32
        let reason: String
    }

    private func fatal(_ fes: NVMeTCPFatalErrorStatus, fei: UInt32 = 0, _ reason: String) -> FatalTransportError {
        FatalTransportError(fes: fes, fei: fei, reason: reason)
    }

    /// Offsets, from the start of a PDU, of the fields a FEI can name.
    private enum FieldOffset {
        static let type: UInt32 = 0
        static let flags: UInt32 = 1
        static let cccid: UInt32 = 8
        static let cqeCID: UInt32 = 8 + 12
    }

    private let transport: any ConnectionTransport
    private let connectionID: UUID?
    private let debugLog: (@Sendable (String) -> Void)?
    public let queueID: UInt16
    /// SQ entries as sent in Connect. The controller is told SQSIZE−1 and
    /// may have at most that many commands outstanding, so that is the
    /// in-flight bound here too.
    public let entries: UInt16
    private let requestDigests: Bool
    private let maxPDUBytes: Int

    private var serializer = NVMeTCPSerializer()
    private var deframer: NVMeTCPDeframer
    public private(set) var digests = NVMeTCPDigests()
    /// From ICResp: the largest H2CData PDU the controller accepts.
    public private(set) var maxH2CData: UInt32 = 0
    /// Bytes of write data allowed in a command capsule. 8 KiB on the admin
    /// queue (the Linux host's `NVME_TCP_ADMIN_CCSZ`); the controller sets
    /// it from IOCCSZ on the I/O queue once Identify Controller is in.
    public private(set) var inCapsuleLimit: Int

    private var state: State = .idle
    private var closeReason: NVMeConnectionError?
    private var pending: [UInt16: PendingCommand] = [:]
    private var nextCID: UInt16 = 1
    private var slotWaiters: [Awaitable<Void>] = []
    private var closeWaiters: [CheckedContinuation<NVMeConnectionError, Never>] = []
    private var readLoop: Task<Void, Never>?

    public init(transport: any ConnectionTransport, queueID: UInt16, entries: UInt16,
                requestDigests: Bool, maxPDUBytes: Int, inCapsuleLimit: Int = 8192,
                debugLog: (@Sendable (String) -> Void)? = nil) {
        precondition(entries >= 2, "a queue needs room for at least one command")
        self.transport = transport
        if let debugLog {
            let connectionID = (transport as? NVMeTracingTransport)?.connectionID
            self.connectionID = connectionID
            let prefix = "connection=\(connectionID?.uuidString ?? "-") "
            self.debugLog = { message in debugLog(prefix + message) }
        } else {
            self.connectionID = nil
            self.debugLog = nil
        }
        self.queueID = queueID
        self.entries = entries
        self.requestDigests = requestDigests
        self.maxPDUBytes = maxPDUBytes
        self.inCapsuleLimit = inCapsuleLimit
        self.deframer = NVMeTCPDeframer(maxPDUBytes: maxPDUBytes)
    }

    public func setInCapsuleLimit(_ bytes: Int) {
        inCapsuleLimit = max(0, bytes)
    }

    // MARK: - Connection initialization

    /// ICReq/ICResp, then the Fabrics Connect for this queue. Returns the
    /// controller ID the Connect answered with and whether the controller
    /// demands in-band authentication (AUTHREQ), which this initiator does
    /// not implement.
    public func connect(host: NVMeHostIdentity, subsystemNQN: String, controllerID: UInt16,
                        keepAliveMS: UInt32) async throws -> (controllerID: UInt16, authRequired: Bool) {
        guard state == .idle else { throw NVMeConnectionError.protocolError("connect on a used queue") }

        var icreq = ICReqPDU()
        icreq.digests = requestDigests ? NVMeTCPDigests(header: true, data: true) : NVMeTCPDigests()
        icreq.maxR2T = 0
        try await sendRaw(serializer.serializeParts(icreq.encode()))
        let icresp = try await receiveICResp()
        guard icresp.pfv == 0 else {
            throw await fail(.protocolError("controller wants PDU format version \(icresp.pfv), only 0 is supported"))
        }
        // We asked for HPDA 0 (dword alignment, which every fixed header
        // length already satisfies, so the controller never pads). A CPDA
        // above 0 would have us pad our own data PDUs; that is conformant
        // but unsupported here, and the Linux host refuses it too.
        guard icresp.cpda == 0 else {
            throw await fail(.protocolError("controller requires CPDA \(icresp.cpda); only unaligned data is supported"))
        }
        if !requestDigests, icresp.digests != NVMeTCPDigests() {
            throw await fail(.protocolError("controller enabled digests that were not offered"))
        }
        // The NVMe/TCP spec makes MAXH2CDATA a multiple of four bytes; the
        // Linux host rejects it otherwise, so we do too.
        guard icresp.maxH2CData >= 4096, icresp.maxH2CData % 4 == 0 else {
            throw await fail(.protocolError("MAXH2CDATA \(icresp.maxH2CData) is below the 4096-byte minimum or not a multiple of four"))
        }
        digests = icresp.digests
        maxH2CData = icresp.maxH2CData
        // Digests apply from the first PDU after the IC exchange.
        serializer = NVMeTCPSerializer(digests: digests)
        // Reconfigured, not replaced: anything the controller sent in the
        // same segment as the ICResp (a C2HTermReq, say) is already buffered.
        deframer.digests = digests
        deframer.maxPDUBytes = maxPDUBytes
        state = .connected
        startReadLoop()

        let (sqe, data) = NVMeCommands.connect(
            commandID: 0, queueID: queueID, queueEntries: entries, keepAliveMS: keepAliveMS,
            hostID: host.hostID, controllerID: controllerID,
            subsystemNQN: subsystemNQN, hostNQN: host.nqn)
        let completion = try await submit(sqe, data: data, expectedRead: 0, forceInCapsule: true)
        let status = completion.cqe.status
        guard status.isSuccess else {
            throw BlockDeviceError.nvmeStatus(sct: status.sct, sc: status.sc, opcode: NVMeOpcode.Admin.fabrics)
        }
        return (UInt16(completion.cqe.dw0 & 0xFFFF), completion.cqe.dw0 >> 16 != 0)
    }

    /// Synchronous-style PDU pull used only before the read loop starts.
    private func receiveICResp() async throws -> ICRespPDU {
        while true {
            do {
                if let raw = try deframer.next() {
                    guard case .icResp(let resp) = try AnyNVMeTCPPDU.decode(raw) else {
                        throw NVMeConnectionError.protocolError("expected ICResp, got PDU type \(raw.type)")
                    }
                    return resp
                }
            } catch let error as NVMeTCPError {
                throw await fail(.protocolError("\(error)"))
            }
            guard let chunk = try await transport.receive() else {
                throw await fail(.connectionLost("EOF before ICResp"))
            }
            deframer.append(chunk)
        }
    }

    // MARK: - Commands

    /// Submit a command capsule and await its completion. `data` is write
    /// data — in the capsule when it fits `inCapsuleLimit`, otherwise sent
    /// as H2CData when the controller's R2T asks; `expectedRead` bytes are
    /// collected from C2HData PDUs. The queue assigns the CID and the SGL.
    ///
    /// `readInto`: a region at least `expectedRead` long to receive the data
    /// in, typically one command's part of a buffer a large read shares
    /// between its commands. The completion then carries no `data`. Without
    /// one the queue allocates, and the completion's `data` is that memory,
    /// not a copy of it.
    public func submit(_ sqe: SQE, data: Data = Data(), expectedRead: Int = 0,
                       readInto: ReadBuffer.Region? = nil) async throws -> NVMeCompletion {
        try await submit(sqe, data: data, expectedRead: expectedRead, readInto: readInto, forceInCapsule: false)
    }

    /// `submit`, requiring a successful status.
    public func submitChecked(_ sqe: SQE, data: Data = Data(), expectedRead: Int = 0,
                              readInto: ReadBuffer.Region? = nil) async throws -> NVMeCompletion {
        let completion = try await submit(sqe, data: data, expectedRead: expectedRead, readInto: readInto)
        let status = completion.cqe.status
        debugLog?("NVMeQueue.\(#function) queueID=\(queueID) cid=\(completion.cqe.commandID)"
                  + " sct=\(status.sct) sc=\(status.sc) receivedBytes=\(completion.receivedBytes)")
        guard status.isSuccess else {
            throw BlockDeviceError.nvmeStatus(sct: status.sct, sc: status.sc, opcode: sqe.opcode)
        }
        return completion
    }

    private func submit(_ sqe: SQE, data: Data, expectedRead: Int, readInto: ReadBuffer.Region? = nil,
                        forceInCapsule: Bool) async throws -> NVMeCompletion {
        try ensureOpen()
        if let readInto, readInto.count < expectedRead {
            throw NVMeConnectionError.protocolError(
                "read of \(expectedRead) bytes given a destination of \(readInto.count)")
        }
        try await waitForSlot()
        // Cancelled while waiting for a slot (or before): give the slot back
        // and stop, rather than reach `NetworkTransport.send`, whose
        // cancellation tears the whole connection down.
        do {
            try Task.checkCancellation()
        } catch {
            releaseSlot()
            throw error
        }

        let cid = allocateCID()
        var sqe = sqe
        sqe.commandID = cid
        let inCapsule = !data.isEmpty && (forceInCapsule || data.count <= inCapsuleLimit)
        if !data.isEmpty {
            sqe.sgl = inCapsule ? .inCapsule(length: UInt32(data.count)) : .transport(length: UInt32(data.count))
        } else if expectedRead > 0 {
            sqe.sgl = .transport(length: UInt32(expectedRead))
        }
        let command = PendingCommand(opcode: sqe.opcode, writeData: data, expectedRead: expectedRead,
                                     readInto: readInto)
        pending[cid] = command

        if let debugLog {
            let lba = queueID != 0 && sqe.opcode == NVMeOpcode.NVM.read
                ? " lba=\(UInt64(sqe.cdw11) << 32 | UInt64(sqe.cdw10))" : ""
            debugLog("NVMeQueue.\(#function) queueID=\(queueID) cid=\(cid) \(sqe.logCommandFields)\(lba)"
                     + " dataBytes=\(data.count) expectedRead=\(expectedRead) forceInCapsule=\(forceInCapsule)")
        }
        let capsule = CapsuleCmdPDU(sqe: sqe.bytes, inCapsuleData: inCapsule ? data : Data())
        do {
            try await sendRaw(serializer.serializeParts(capsule.encode()))

            let completion = try await withTaskCancellationHandler {
                try await suspend(command.completion)
            } onCancel: {
                Task { await self.tombstone(cid: cid) }
            }
            debugLog?("NVMeQueue.\(#function) resumed queueID=\(queueID) cid=\(cid)"
                      + " receivedBytes=\(completion.receivedBytes)")
            return completion
        } catch {
            debugLog?("NVMeQueue.\(#function) \(error is CancellationError ? "cancelled" : "failed")"
                      + " queueID=\(queueID) cid=\(cid) error=\(error)")
            throw error
        }
    }

    /// Await connection teardown (the controller's recovery trigger).
    public func waitClosed() async -> NVMeConnectionError {
        if state == .closed { return closeReason ?? .closed }
        return await withCheckedContinuation { c in
            closeWaiters.append(c)
        }
    }

    public func close() async {
        await close(reason: .closed)
    }

    // MARK: - Internals

    private func suspend<V: Sendable>(_ box: Awaitable<V>) async throws -> V {
        if let buffered = box.buffered {
            box.buffered = nil
            return try buffered.get()
        }
        return try await withCheckedThrowingContinuation { box.continuation = $0 }
    }

    private func ensureOpen() throws {
        guard state == .connected else {
            throw closeReason ?? NVMeConnectionError.closed
        }
    }

    /// Close with `reason` and hand it back, so a failed step can `throw`
    /// the very error the connection now carries.
    private func fail(_ reason: NVMeConnectionError) async -> NVMeConnectionError {
        await close(reason: reason)
        return reason
    }

    private func allocateCID() -> UInt16 {
        var cid = nextCID
        while cid == 0xFFFF || pending[cid] != nil {
            cid &+= 1
            if cid == 0 { cid = 1 }
        }
        nextCID = cid &+ 1
        if nextCID == 0 { nextCID = 1 }
        return cid
    }

    /// Block until the queue can take another command: never more than
    /// SQSIZE−1 outstanding, or the controller tears the connection down.
    private func waitForSlot() async throws {
        while state == .connected && pending.count >= Int(entries) - 1 {
            let waiter = Awaitable<Void>()
            slotWaiters.append(waiter)
            try await withTaskCancellationHandler {
                try await suspend(waiter)
            } onCancel: {
                Task { await self.cancelSlotWaiter(waiter) }
            }
        }
        try ensureOpen()
    }

    private func cancelSlotWaiter(_ waiter: Awaitable<Void>) {
        slotWaiters.removeAll { $0 === waiter }
        waiter.complete(.failure(CancellationError()))
    }

    private func releaseSlot() {
        guard !slotWaiters.isEmpty else { return }
        let waiter = slotWaiters.removeFirst()
        waiter.complete(.success(()))
    }

    private func tombstone(cid: UInt16) {
        guard state == .connected, let command = pending[cid], !command.terminated else { return }
        // Unblock the caller now; there is no cheap Abort on NVMe-oF, and the
        // entry stays so the eventual completion is absorbed, not mistaken.
        command.terminated = true
        command.completion.complete(.failure(CancellationError()))
    }

    /// The R2T answer most recently queued. Each waits for the one before,
    /// so H2CData leaves in the order the controller asked for it; command
    /// capsules do not queue here, since the transport keeps each send whole
    /// and nothing orders one command against another.
    private var lastDataSend: Task<Void, Never>?

    /// Queue `parts` and return without waiting for the transport to take
    /// them. For H2CData answering an R2T, which the read loop sends:
    /// waiting there stopped the loop receiving for as long as the send
    /// took, and against a full send buffer that is as long as the network
    /// takes to drain it — no C2HData and no completion for any other
    /// command meanwhile.
    ///
    /// Nothing is lost by not waiting. The bytes are slices of a buffer the
    /// command already holds, so no memory is added; a send that fails closes
    /// the connection exactly as an awaited one does; and one that never
    /// completes is ended, as before, by whoever closes the connection.
    private func sendWithoutWaiting(_ parts: [Data]) {
        let previous = lastDataSend
        let transport = self.transport
        lastDataSend = Task { [weak self] in
            await previous?.value
            do {
                try await transport.send(contentsOf: parts)
            } catch {
                await self?.close(reason: .connectionLost("send failed: \(error)"))
            }
        }
    }

    private func sendRaw(_ parts: [Data]) async throws {
        do {
            try await transport.send(contentsOf: parts)
        } catch {
            await close(reason: .connectionLost("send failed: \(error)"))
            throw closeReason ?? NVMeConnectionError.closed
        }
    }

    private func startReadLoop() {
        readLoop = Task { [weak self] in
            await self?.runReadLoop()
        }
    }

    private func runReadLoop() async {
        do {
            while state == .connected {
                // Drain first: the IC exchange may have left a PDU buffered.
                try await drain()
                guard state == .connected else { return }
                guard let chunk = try await transport.receive() else {
                    await close(reason: .connectionLost("EOF"))
                    return
                }
                deframer.append(chunk)
            }
        } catch let error as FatalTransportError {
            await terminate(fes: error.fes, fei: error.fei, reason: error.reason)
        } catch let error as NVMeTCPError {
            // The deframer or decoder refused the bytes: a header digest
            // error is its own FES; everything else is an invalid header.
            let fes: NVMeTCPFatalErrorStatus = error == .headerDigestMismatch ? .headerDigestError : .invalidPDUHeader
            await terminate(fes: fes, fei: 0, reason: "\(error)")
        } catch let error as NVMeConnectionError {
            await close(reason: error)
        } catch {
            await close(reason: .connectionLost("\(error)"))
        }
    }

    /// §3.5: on a fatal transport error the host stops processing PDUs,
    /// sends an H2CTermReq carrying the offending header, and terminates.
    /// Best effort with a short deadline: a peer that cannot take it gets
    /// the reset the spec prescribes instead. The close that follows may
    /// itself turn into a RST if the peer left inbound bytes unread, in
    /// which case the request is lost with it; diagnostic only.
    private func terminate(fes: NVMeTCPFatalErrorStatus, fei: UInt32, reason: String) async {
        guard state == .connected else { return }
        let pdu = H2CTermReqPDU(fes: fes, fei: fei, offendingHeader: deframer.lastHeader)
        let bytes = serializer.serialize(pdu.encode())
        _ = try? await withDeadline(.seconds(1)) { try await self.transport.send(bytes) }
        await close(reason: .protocolError(reason))
    }

    /// Handle everything the buffered bytes allow: whole PDUs, and as much
    /// of a C2HData's data as has arrived, moved straight into the buffer of
    /// the read it answers. Returns when more bytes are needed.
    ///
    /// The state check each time round matters: once a queue is closing,
    /// nothing more is written into a read's buffer, which is what lets a
    /// caller that gave up on this queue retry elsewhere into the same
    /// memory.
    private func drain() async throws {
        while state == .connected {
            if inbound == nil {
                guard let head = try deframer.nextHead() else { return }
                guard head.dataLength > 0 else {
                    try await handle(RawNVMeTCPPDU(rawType: head.type, flags: head.flags, psh: head.psh))
                    continue
                }
                let target = placement(for: head)
                inbound = Inbound(head: head, placement: target?.bytes, owner: target?.owner)
            }
            guard var current = inbound else { continue }
            let head = current.head
            guard let room = current.placement else {
                guard let (data, digestFailed) = deframer.takeData() else { return }
                inbound = nil
                var raw = RawNVMeTCPPDU(rawType: head.type, flags: head.flags, psh: head.psh, data: data)
                raw.dataDigestFailed = digestFailed
                try await handle(raw)
                continue
            }
            current.filled += deframer.readData(
                into: UnsafeMutableRawBufferPointer(rebasing: room[current.filled...]))
            inbound = current
            guard deframer.dataRemaining == 0 else { return }
            let end = deframer.finishData()
            guard end != .needMore else { return }
            inbound = nil
            // `placement` only accepts a well-formed C2HData, so the fields
            // can be read without the decoder, which would want the data.
            try handleC2HData(
                cccid: head.psh.leU16(0), dataOffset: head.psh.leU32(4), length: head.dataLength, data: nil,
                last: head.flags.contains(.lastPDU), success: head.flags.contains(.success),
                dataDigestFailed: end == .digestFailed)
        }
    }

    /// Where the data of the C2HData PDU with this header belongs, if it is
    /// one `handleC2HData` will accept as it stands: well formed, for a
    /// command we are waiting on, next in its sequence, and inside its
    /// buffer. Changes nothing. Anything else gets nil, is taken whole, and
    /// is refused (or absorbed, for an abandoned command) with the reason.
    private func placement(for head: NVMeTCPDeframer.Head)
        -> (bytes: UnsafeMutableRawBufferPointer, owner: ReadBuffer)? {
        guard head.type == NVMeTCPPDUType.c2hData.rawValue, head.psh.count == C2HDataPDU.pshSize,
              Int(head.psh.leU32(8)) == head.dataLength,
              let command = pending[head.psh.leU16(0)], !command.terminated, !command.dataComplete,
              let destination = command.destination,
              !head.flags.contains(.success) || head.flags.contains(.lastPDU)
        else { return nil }
        let offset = Int(head.psh.leU32(4))
        guard offset == command.receivedBytes, head.dataLength <= command.expectedRead - offset else { return nil }
        return (destination.bytes(offset ..< offset + head.dataLength), destination.buffer)
    }

    private func handle(_ raw: RawNVMeTCPPDU) async throws {
        debugLog?("NVMeQueue.\(#function) queueID=\(queueID) type=\(raw.type)")
        switch try AnyNVMeTCPPDU.decode(raw) {
        case .capsuleResp(let resp):
            try complete(try CQE(bytes: resp.cqe))
        case .c2hData(let pdu):
            try handleC2HData(cccid: pdu.cccid, dataOffset: pdu.dataOffset, length: pdu.data.count,
                              data: pdu.data, last: pdu.last, success: pdu.success,
                              dataDigestFailed: raw.dataDigestFailed)
        case .r2t(let r2t):
            try handleR2T(r2t)
        case .c2hTermReq(let term):
            // The controller already declared the error; answer with the
            // termination it asked for, not a termination request of our own.
            throw NVMeConnectionError.protocolError(
                "controller terminated the connection: FES 0x\(String(term.fes.rawValue, radix: 16)) FEI \(term.fei)")
        case .icResp:
            throw fatal(.pduSequenceError, "ICResp after the connection was initialized")
        case .icReq, .h2cTermReq, .capsuleCmd, .h2cData:
            throw fatal(.invalidPDUHeader, fei: FieldOffset.type,
                        "host-to-controller PDU type \(raw.type) received from the controller")
        }
    }

    /// Generic Command Status 22h: the status a command whose data failed
    /// its digest completes with (NVMe Base 2.0 Figure 94; NVMe/TCP 1.1
    /// §3.5 calls it a non-fatal transport error). Retryable by definition.
    public static let transientTransportError = NVMeStatus(sct: 0, sc: 0x22)

    private func complete(_ cqe: CQE) throws {
        guard let command = pending.removeValue(forKey: cqe.commandID) else {
            throw fatal(.invalidPDUHeader, fei: FieldOffset.cqeCID, "completion for unknown CID \(cqe.commandID)")
        }
        releaseSlot()
        if command.terminated { return }
        var cqe = cqe
        if cqe.status.isSuccess, command.dataDigestFailed {
            // The controller's success is overruled: what arrived is not
            // what it sent. The command fails; the connection is fine.
            cqe.statusField = Self.transientTransportError.field
        }
        // Success promises the data phase delivered everything; anything
        // less is a hole the pre-zeroed buffer would silently paper over.
        if cqe.status.isSuccess, command.receivedBytes != command.expectedRead {
            let reason = "read completed successfully with \(command.receivedBytes) of \(command.expectedRead) bytes delivered"
            // The caller gets the error every other pending command gets when
            // the connection closes, so the controller recovers and retries
            // it; the private fatal error is for the read loop alone.
            command.completion.complete(.failure(NVMeConnectionError.protocolError(reason)))
            throw fatal(.pduSequenceError, reason)
        }
        // What was not delivered is zeroed here, at the end, which is what
        // the buffer being zeroed at the start used to provide.
        var data = Data()
        if let destination = command.destination {
            destination.zero(min(command.receivedBytes, command.expectedRead) ..< command.expectedRead)
            if !command.callerOwnsDestination { data = destination.data(prefix: command.expectedRead) }
        }
        debugLog?("NVMeQueue.\(#function) queueID=\(queueID) cid=\(cqe.commandID)"
                  + " sct=\(cqe.status.sct) sc=\(cqe.status.sc)"
                  + " receivedBytes=\(command.receivedBytes) expectedRead=\(command.expectedRead)")
        let completion = NVMeCompletion(cqe: cqe, data: data,
                                        receivedBytes: command.receivedBytes, connectionID: connectionID)
        command.completion.complete(.success(completion))
    }

    /// One C2HData PDU. `data` is nil when `drain` has already put its
    /// `length` bytes in the command's buffer.
    private func handleC2HData(cccid: UInt16, dataOffset: UInt32, length: Int, data: Data?,
                               last: Bool, success: Bool, dataDigestFailed: Bool) throws {
        debugLog?("NVMeQueue.\(#function) queueID=\(queueID) cid=\(cccid) offset=\(dataOffset)"
                  + " bytes=\(length) last=\(last) success=\(success)"
                  + " dataDigestFailed=\(dataDigestFailed)")
        guard let command = pending[cccid] else {
            throw fatal(.invalidPDUHeader, fei: FieldOffset.cccid, "C2HData for unknown CID \(cccid)")
        }
        if dataDigestFailed { command.dataDigestFailed = true }
        guard !command.dataComplete else {
            throw fatal(.pduSequenceError, "C2HData for CID \(cccid) after its LAST_PDU")
        }
        guard !success || last else {
            throw fatal(.invalidPDUHeader, fei: FieldOffset.flags,
                        "C2HData for CID \(cccid) has SUCCESS set without LAST_PDU")
        }
        let offset = Int(dataOffset)
        guard offset == command.receivedBytes else {
            throw fatal(.pduSequenceError,
                "non-contiguous C2HData for CID \(cccid): offset \(offset), expected \(command.receivedBytes)")
        }
        guard length <= command.expectedRead - offset else {
            throw fatal(.dataTransferOutOfRange,
                "C2HData outside the read buffer (offset \(offset), \(length) bytes of \(command.expectedRead))")
        }
        if let data, !command.terminated {
            command.destination?.write(data, at: offset)
        }
        command.receivedBytes += length
        command.dataComplete = last
        if success {
            // No CapsuleResp follows: this PDU is the completion.
            try complete(CQE(sqID: queueID, commandID: cccid, status: .success))
        }
    }

    /// Answer an R2T with H2CData PDUs, each at most MAXH2CDATA, LAST_PDU on
    /// the final one for this R2T. A cancelled command still answers: the
    /// controller must collect the solicited data before it can complete.
    private func handleR2T(_ r2t: NVMeR2TPDU) throws {
        guard let command = pending[r2t.cccid] else {
            throw fatal(.invalidPDUHeader, fei: FieldOffset.cccid, "R2T for unknown CID \(r2t.cccid)")
        }
        let start = Int(r2t.offset)
        let length = Int(r2t.length)
        guard start == command.solicitedBytes else {
            throw fatal(.pduSequenceError,
                "non-contiguous R2T for CID \(r2t.cccid): offset \(start), expected \(command.solicitedBytes)")
        }
        guard length > 0, start + length <= command.writeData.count else {
            throw fatal(.dataTransferOutOfRange,
                "R2T requests bytes beyond the write buffer (offset \(start), \(length) of \(command.writeData.count))")
        }
        command.solicitedBytes = start + length
        // Built whole, as slices of the command's buffer, and queued as one
        // send that is not waited for; see `sendWithoutWaiting`.
        let chunk = max(1, Int(maxH2CData))
        var wire: [Data] = []
        var offset = start
        let end = start + length
        while offset < end {
            let next = min(offset + chunk, end)
            let pdu = H2CDataPDU(cccid: r2t.cccid, ttag: r2t.ttag, dataOffset: UInt32(offset),
                                 data: command.writeData.sub(offset, next - offset),
                                 last: next == end)
            wire += serializer.serializeParts(pdu.encode())
            offset = next
        }
        sendWithoutWaiting(wire)
    }

    private func close(reason: NVMeConnectionError) async {
        guard state != .closed else { return }
        state = .closed
        closeReason = reason
        // Whatever C2HData was part-way in stays where it got to: `drain`
        // stops at the state it has just been given.
        inbound = nil
        readLoop?.cancel()
        await transport.close()

        for (_, command) in pending {
            command.completion.complete(.failure(reason))
        }
        pending = [:]
        for w in slotWaiters { w.complete(.failure(reason)) }
        slotWaiters = []
        for w in closeWaiters { w.resume(returning: reason) }
        closeWaiters = []
    }
}
