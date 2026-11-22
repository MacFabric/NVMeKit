import Foundation
import Testing
@testable import NVMeMockTarget
@testable import NVMeKit

/// Hands on what it receives cut into pieces of awkward sizes, so a PDU's
/// header, data and digest each arrive split across chunks.
final class FragmentingNVMeTransport: ConnectionTransport, @unchecked Sendable {
    private let inner: any ConnectionTransport
    private let sizes: [Int]
    private var leftover = Data()
    private var turn = 0

    init(wrapping inner: any ConnectionTransport, sizes: [Int]) {
        self.inner = inner
        self.sizes = sizes
    }

    func send(_ data: Data) async throws { try await inner.send(data) }

    // One reader at a time, as every transport's contract has it.
    func receive() async throws -> Data? {
        if leftover.isEmpty {
            guard let chunk = try await inner.receive() else { return nil }
            leftover = chunk
        }
        let size = min(sizes[turn % sizes.count], leftover.count)
        turn += 1
        let piece = leftover.prefix(size)
        leftover = leftover.dropFirst(size)
        return piece
    }

    func close() async { await inner.close() }
}

@Suite("Integration: the NVMe/TCP read path", .timeLimit(.minutes(1)))
struct NVMeReadPathTests {

    private static func pattern(_ count: Int, seed: Int = 1) -> Data {
        Data((0 ..< count).map { UInt8(truncatingIfNeeded: ($0 &* 31 &+ seed) ^ ($0 >> 8)) })
    }

    /// C2HData is received straight into the read's buffer, a piece at a
    /// time as chunks arrive. Whatever the PDU size, the digests, how the
    /// read is completed, whether the controller interleaves commands' data
    /// and how the stream is cut up, reads come back byte-exact.
    @Test(arguments: [
        // (C2HData size, digests, SUCCESS flag, reads interleaved, receive fragment sizes)
        (65536, false, false, 0, [1 << 20]),
        (65536, true, false, 0, [1 << 20]),
        (512, true, true, 0, [1, 23, 24, 25, 3, 700]),
        (4096, false, true, 4, [5000, 13, 28]),
        (4096, true, false, 4, [28, 65536, 1, 4, 99_999]),
        (1 << 20, true, true, 0, [4096]),
    ])
    func readsComeBackByteExact(
        c2hSize: Int, digests: Bool, successFlag: Bool, interleave: Int, fragments: [Int]
    ) async throws {
        var config = MockNVMeConfig()
        config.c2hChunkBytes = c2hSize
        config.emitSuccessFlag = successFlag
        config.interleaveReads = interleave
        let disk = RAMDisk(blockSize: 4096, capacityBlocks: 4096)
        let stored = Self.pattern(700 << 10, seed: c2hSize)
        #expect(await disk.write(lba: 8, data: stored))
        let fleet = NVMeFleet(config: config, disk: disk)
        let controller = NVMeController(
            config: testControllerConfig { $0.requestDigests = digests }, policy: testPolicy()
        ) {
            FragmentingNVMeTransport(wrapping: await fleet.makeTransport(), sizes: fragments)
        }
        try await controller.activate()
        #expect(await controller.digests.data == digests)
        let device = NVMeBlockDevice(controller: controller, nsid: 1, maxTransferBytes: 256 << 10)

        // Three commands, the last one short.
        let large = try await device.read(offset: 4096 * 8, length: 600 << 10)
        #expect(large == stored.prefix(600 << 10))
        // One command.
        let small = try await device.read(offset: 4096 * 9, length: 8192)
        #expect(small == stored.subdata(in: 4096 ..< 4096 + 8192))
        // Several reads at once on one queue.
        try await withThrowingTaskGroup(of: Void.self) { group in
            for index in 0 ..< 6 {
                group.addTask {
                    let offset = index * (100 << 10)
                    let data = try await device.read(offset: UInt64(4096 * 8 + offset), length: 100 << 10)
                    #expect(data == stored.subdata(in: offset ..< offset + (100 << 10)), "read \(index)")
                }
            }
            try await group.waitForAll()
        }
        try await controller.logout()
        await fleet.shutdown()
    }

    /// A read retried after its queue died receives into the same buffer
    /// again, from the start.
    @Test func aReadRetriedAfterADropMidDataIsStillByteExact() async throws {
        var config = MockNVMeConfig()
        config.c2hChunkBytes = 4096
        var dropping = MockTargetFaults()
        dropping.dropAfterSentPDUs = 5
        let disk = RAMDisk(blockSize: 4096, capacityBlocks: 4096)
        let stored = Self.pattern(600 << 10, seed: 7)
        #expect(await disk.write(lba: 0, data: stored))
        // The first controller's I/O queue drops a few C2HData PDUs into the
        // read; its admin queue, and the pair built by recovery, do not.
        let fleet = NVMeFleet(config: config, disk: disk,
                              faultScripts: [MockTargetFaults(), dropping, MockTargetFaults()])
        let controller = try await activatedController(fleet: fleet)
        let device = NVMeBlockDevice(controller: controller, nsid: 1, maxTransferBytes: 256 << 10)
        let data = try await device.read(offset: 0, length: 600 << 10)
        #expect(data == stored)
        #expect(await controller.recoveryCount >= 1, "the drop should have forced a recovery")
        try await controller.logout()
        await fleet.shutdown(expectingViolations: true)
    }

    /// The two ways a command can be told where its data goes.
    @Test func aCommandReadsIntoTheCallersRegionOrItsOwnBuffer() async throws {
        let disk = RAMDisk(blockSize: 4096, capacityBlocks: 4096)
        let stored = Self.pattern(8192, seed: 3)
        #expect(await disk.write(lba: 8, data: stored))
        let fleet = NVMeFleet(disk: disk)
        let controller = try await activatedController(fleet: fleet)
        let read = NVMeCommands.read(commandID: 0, nsid: 1, slba: 8, blocks: 2, blockSize: 4096)

        let own = try await controller.execute(read, expectedRead: 8192)
        #expect(own.data == stored)

        let buffer = ReadBuffer(count: 3 * 8192)
        buffer.bytes(0 ..< 3 * 8192).initializeMemory(as: UInt8.self, repeating: 0xEE)
        let placed = try await controller.execute(
            read, expectedRead: 8192, readInto: ReadBuffer.Region(buffer: buffer, offset: 8192, count: 8192))
        #expect(placed.data.isEmpty)
        #expect(buffer.data() == Data(repeating: 0xEE, count: 8192) + stored + Data(repeating: 0xEE, count: 8192))
        try await controller.logout()
        await fleet.shutdown()
    }
}
