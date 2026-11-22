import Foundation
import Testing
@testable import NVMeMockTarget
@testable import NVMeKit

/// Several I/O queues: a TCP connection and a receive loop each, with
/// commands taking them in turn.
@Suite("Integration: NVMe/TCP I/O queues", .timeLimit(.minutes(1)))
struct NVMeIOQueuesTests {

    private static func pattern(_ count: Int, seed: Int = 1) -> Data {
        Data((0 ..< count).map { UInt8(truncatingIfNeeded: ($0 &* 31 &+ seed) ^ ($0 >> 8)) })
    }

    @Test func oneQueueUnlessMoreAreAskedFor() async throws {
        let fleet = NVMeFleet()
        let controller = try await activatedController(fleet: fleet)
        #expect(await controller.ioQueueCount == 1)
        #expect(await fleet.connectionsServed == 2)
        let device = NVMeBlockDevice(controller: controller, nsid: 1)
        _ = try await device.read(offset: 0, length: 4096)
        #expect(Set(await fleet.subsystem.commandsSeen.keys).subtracting([0]) == [1])
        try await controller.logout()
        await fleet.shutdown()
    }

    /// Commands go to the queues in turn, and what they carry is intact
    /// whichever queue carried it: the commands of one large request land on
    /// different connections and complete in any order.
    @Test func commandsSpreadOverTheQueuesAndDataIsIntact() async throws {
        let disk = RAMDisk(blockSize: 4096, capacityBlocks: 4096)
        let fleet = NVMeFleet(disk: disk)
        let controller = try await activatedController(fleet: fleet) { $0.ioQueueCount = 4 }
        #expect(await controller.ioQueueCount == 4)
        #expect(await fleet.connectionsServed == 5)
        #expect(await controller.displayPairs["IOQueues"] == "4")
        let device = NVMeBlockDevice(controller: controller, nsid: 1, maxTransferBytes: 256 << 10)

        // 1 MiB each way is four commands, issued together.
        let payload = Self.pattern(1 << 20, seed: 4)
        try await device.write(offset: 4096 * 16, data: payload)
        #expect(await disk.read(lba: 16, blocks: 256) == payload)
        #expect(try await device.read(offset: 4096 * 16, length: 1 << 20) == payload)

        // And many small ones at once.
        try await withThrowingTaskGroup(of: Void.self) { group in
            for index in 0 ..< 32 {
                group.addTask {
                    let block = Self.pattern(8192, seed: 100 + index)
                    let offset = UInt64(4096 * (1024 + index * 2))
                    try await device.write(offset: offset, data: block)
                    #expect(try await device.read(offset: offset, length: 8192) == block, "block \(index)")
                }
            }
            try await group.waitForAll()
        }
        try await device.flush()

        let seen = await fleet.subsystem.commandsSeen
        for qid: UInt16 in 1 ... 4 {
            #expect((seen[qid] ?? 0) >= 10, "QID \(qid) carried \(seen[qid] ?? 0) commands")
        }
        #expect(seen.keys.allSatisfy { $0 <= 4 })
        try await controller.logout()
        await fleet.shutdown()
    }

    /// The controller says how many queues it allows, and no more are opened.
    @Test func noMoreQueuesThanTheControllerAllows() async throws {
        var config = MockNVMeConfig()
        config.maxIOQueues = 3
        let fleet = NVMeFleet(config: config)
        let controller = try await activatedController(fleet: fleet) { $0.ioQueueCount = 8 }
        #expect(await controller.ioQueueCount == 3)
        #expect(await fleet.connectionsServed == 4)
        let device = NVMeBlockDevice(controller: controller, nsid: 1)
        let payload = Self.pattern(4096 * 8)
        try await device.write(offset: 0, data: payload)
        #expect(try await device.read(offset: 0, length: payload.count) == payload)
        try await controller.logout()
        await fleet.shutdown()
    }

    /// One I/O queue dying takes the controller with it, and recovery brings
    /// the whole set back: a read in flight at the time still comes back
    /// byte-exact.
    @Test func oneQueueDroppingRebuildsThemAll() async throws {
        var config = MockNVMeConfig()
        config.c2hChunkBytes = 4096
        var dropping = MockTargetFaults()
        dropping.dropAfterSentPDUs = 6
        let disk = RAMDisk(blockSize: 4096, capacityBlocks: 4096)
        let stored = Self.pattern(1 << 20, seed: 9)
        #expect(await disk.write(lba: 0, data: stored))
        // Admin, QID 1, then QID 2 which drops a few PDUs into its work;
        // everything after is healthy.
        let fleet = NVMeFleet(config: config, disk: disk,
                              faultScripts: [MockTargetFaults(), MockTargetFaults(), dropping, MockTargetFaults()])
        let controller = try await activatedController(fleet: fleet) { $0.ioQueueCount = 3 }
        #expect(await controller.ioQueueCount == 3)
        let device = NVMeBlockDevice(controller: controller, nsid: 1, maxTransferBytes: 256 << 10)
        #expect(try await device.read(offset: 0, length: 1 << 20) == stored)
        #expect(await controller.recoveryCount == 1)
        #expect(await controller.ioQueueCount == 3)
        // The first set of four connections and the second.
        #expect(await fleet.connectionsServed == 8)
        try await controller.logout()
        await fleet.shutdown(expectingViolations: true)
    }

    /// Logging out leaves no connection behind.
    @Test func logoutClosesEveryQueue() async throws {
        let fleet = NVMeFleet()
        let controller = try await activatedController(fleet: fleet) { $0.ioQueueCount = 4 }
        #expect(await fleet.connectionsServed == 5)
        try await controller.logout()
        _ = await eventually { await fleet.connectionsEnded == 5 }
        #expect(await fleet.connectionsEnded == 5)
        #expect(await controller.ioQueueCount == 0)
        await fleet.shutdown()
    }
}
