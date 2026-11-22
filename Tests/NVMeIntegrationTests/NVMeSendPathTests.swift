import Foundation
import Testing
@testable import NVMeMockTarget
@testable import NVMeKit

/// A transport the test steers: it can hold what the queue has received
/// before handing it over, and hold a send that starts with an H2CData PDU,
/// which is what a full socket buffer does to an R2T answer.
final class SteeredNVMeTransport: ConnectionTransport, @unchecked Sendable {
    /// Lets waiters through while open; holds them while closed.
    final class Gate: @unchecked Sendable {
        private let lock = NSLock()
        private var open = true
        private var waiters: [CheckedContinuation<Void, Never>] = []
        private var held = 0

        func close() { lock.lock(); open = false; lock.unlock() }
        func release() {
            lock.lock()
            open = true
            let resume = waiters
            waiters = []
            lock.unlock()
            for c in resume { c.resume() }
        }
        /// Waiters held so far, whether or not they have been released.
        var everHeld: Int { lock.lock(); defer { lock.unlock() }; return held }

        func pass() async {
            await withCheckedContinuation { (c: CheckedContinuation<Void, Never>) in
                lock.lock()
                if open {
                    lock.unlock()
                    c.resume()
                } else {
                    held += 1
                    waiters.append(c)
                    lock.unlock()
                }
            }
        }
    }

    private let inner: any ConnectionTransport
    let inbound = Gate()
    let dataOut = Gate()
    private let lock = NSLock()
    private var sent = 0
    /// Sends handed to the transport so far, held ones included.
    var sendCount: Int { lock.lock(); defer { lock.unlock() }; return sent }

    init(wrapping inner: any ConnectionTransport) { self.inner = inner }

    private func noteSend() { lock.lock(); sent += 1; lock.unlock() }

    func send(_ data: Data) async throws {
        noteSend()
        if data.first == NVMeTCPPDUType.h2cData.rawValue { await dataOut.pass() }
        try await inner.send(data)
    }

    func receive() async throws -> Data? {
        let chunk = try await inner.receive()
        await inbound.pass()
        return chunk
    }

    func close() async {
        inbound.release()
        dataOut.release()
        await inner.close()
    }
}

/// The transports a controller was given, in the order it asked: the admin
/// queue's, then the I/O queue's.
private final class TransportLog: @unchecked Sendable {
    private let lock = NSLock()
    private var made: [SteeredNVMeTransport] = []
    func add(_ t: SteeredNVMeTransport) { lock.lock(); made.append(t); lock.unlock() }
    var all: [SteeredNVMeTransport] { lock.lock(); defer { lock.unlock() }; return made }
}

@Suite("Integration: the NVMe/TCP send path", .timeLimit(.minutes(1)))
struct NVMeSendPathTests {

    private static func pattern(_ count: Int, seed: Int = 1) -> Data {
        Data((0 ..< count).map { UInt8(truncatingIfNeeded: ($0 &* 31 &+ seed) ^ ($0 >> 8)) })
    }

    private func eventually(_ what: String, within: Duration = .seconds(5),
                            _ condition: () async -> Bool) async {
        let deadline = ContinuousClock.now.advanced(by: within)
        while ContinuousClock.now < deadline {
            if await condition() { return }
            try? await Task.sleep(for: .milliseconds(2))
        }
        Issue.record("never happened: \(what)")
    }

    /// The regression test for the read loop waiting on its own send. With an
    /// R2T's H2CData stuck in the transport, PDUs that arrive after the R2T
    /// must still be handled: here a read's C2HData and completion.
    @Test func aStuckR2TAnswerDoesNotStopTheQueueReceiving() async throws {
        let fleet = NVMeFleet()
        let stored = Self.pattern(4096, seed: 9)
        #expect(await fleet.disk.write(lba: 100, data: stored))
        let log = TransportLog()
        let controller = NVMeController(config: testControllerConfig(), policy: testPolicy()) {
            let transport = SteeredNVMeTransport(wrapping: await fleet.makeTransport())
            log.add(transport)
            return transport
        }
        try await controller.activate()
        let device = NVMeBlockDevice(controller: controller, nsid: 1)
        _ = try await device.readCapacity()
        let io = try #require(log.all.last)
        #expect(log.all.count == 2)

        // Larger than the in-capsule limit, so the controller answers with an R2T.
        let payload = Self.pattern(64 << 10)
        io.inbound.close()
        let sendsBefore = io.sendCount
        let write = Task { try await device.write(offset: 0, data: payload) }
        await eventually("the write capsule was sent") { io.sendCount == sendsBefore + 1 }
        let read = Task { try await device.read(offset: 100 * 4096, length: 4096) }
        await eventually("the read capsule was sent") { io.sendCount == sendsBefore + 2 }

        io.dataOut.close()
        io.inbound.release()

        // The read finishes although the write's H2CData has not left.
        #expect(try await withDeadline(.seconds(5)) { try await read.value } == stored)
        #expect(io.dataOut.everHeld == 1, "the R2T answer should be the send in the gate")

        io.dataOut.release()
        try await withDeadline(.seconds(5)) { try await write.value }
        #expect(await fleet.disk.read(lba: 0, blocks: 16) == payload)
        try await controller.logout()
        await fleet.shutdown()
    }

    /// Write data stays a slice of the caller's buffer down to the transport.
    /// A slice does not start at index zero, so the in-capsule data, each
    /// R2T's range and each H2CData PDU have to be taken relative to it.
    @Test(arguments: [
        // (in-capsule bytes, MAXH2CDATA, bytes per R2T, digests)
        (16384, 65536, 0, false),
        (16384, 65536, 0, true),
        (0, 4096, 0, true),
        (0, 8192, 20480, false),
        (1 << 20, 65536, 0, true),
        (4096, 65536, 12288, true),
    ])
    func aWriteHandedOverAsASliceLandsByteExact(
        inCapsule: Int, maxH2CData: Int, r2tChunk: Int, digests: Bool
    ) async throws {
        var config = MockNVMeConfig()
        config.inCapsuleDataBytes = inCapsule
        config.maxH2CData = UInt32(maxH2CData)
        config.r2tChunkBytes = r2tChunk
        let fleet = NVMeFleet(config: config)
        let controller = try await activatedController(fleet: fleet) { $0.requestDigests = digests }
        #expect(await controller.digests.data == digests)

        // 600 KiB in 256 KiB commands, plus one small enough to ride in a
        // capsule where the controller allows it.
        let device = NVMeBlockDevice(controller: controller, nsid: 1, maxTransferBytes: 256 << 10)
        let length = 600 << 10
        let buffer = Self.pattern(length + 12_345 + 777, seed: maxH2CData)
        let slice = buffer[12_345 ..< 12_345 + length]
        #expect(slice.startIndex != 0)
        try await device.write(offset: 4096 * 16, data: slice)
        let small = buffer[5 ..< 5 + 8192]
        try await device.write(offset: 4096 * 4, data: small)

        #expect(await fleet.disk.read(lba: 16, blocks: UInt32(length / 4096)) == Data(slice))
        #expect(try await device.read(offset: 4096 * 16, length: length) == Data(slice))
        #expect(await fleet.disk.read(lba: 4, blocks: 2) == Data(small))
        // The blocks either side were not touched.
        #expect(await fleet.disk.read(lba: 15, blocks: 1) == Data(count: 4096))
        #expect(await fleet.disk.read(lba: 16 + UInt64(length / 4096), blocks: 1) == Data(count: 4096))
        try await controller.logout()
        await fleet.shutdown()
    }
}
