import Foundation
import Synchronization
import Testing
@testable import NVMeKit
@testable import NVMeMockTarget

@Suite("Read logging", .timeLimit(.minutes(1)))
struct NVMeReadLoggingTests {
    @Test(arguments: [false, true], [1, 3])
    func chunkedReadsCorrelateTransportAndFunctionLogs(debug: Bool, queueCount: Int) async throws {
        let lines = Mutex<[String]>([])
        let fleet = NVMeFleet()
        let sink: @Sendable (String) -> Void = { line in lines.withLock { $0.append(line) } }
        let config = testControllerConfig {
            $0.debugLog = sink
            $0.ioQueueCount = queueCount
        }
        let controller = NVMeController(config: config, policy: testPolicy()) {
            NVMeTracingTransport(await fleet.makeTransport(),
                                        level: debug ? .debug : .useful,
                                        connectionID: UUID(), sink: sink)
        }
        try await controller.activate()
        let device = NVMeBlockDevice(controller: controller, nsid: 1, maxTransferBytes: 4096)
        #expect(try await device.read(offset: 8192, length: 12288) == Data(count: 12288))
        try await controller.logout()
        await fleet.shutdown()

        let output = lines.withLock { $0 }
        let readEntries = output.filter { $0.contains("opcode=0x02 nsid=1") }
        #expect(readEntries.filter {
            $0.contains("NVMeController.execute") && $0.contains("expectedRead=")
        }.count == 3)
        let submissions = readEntries.filter { $0.contains("NVMeQueue.submit") }
        #expect(submissions.allSatisfy { $0.contains(" cid=") })

        for lba in 2...4 {
            let finished = try #require(output.first {
                $0.contains("NVMeBlockDevice.readChunk") && $0.contains(" finished ")
                    && $0.contains(" lba=\(lba) ") && $0.contains("receivedBytes=4096")
            })
            let fields = finished.split(separator: " ")
            let connection = try #require(fields.first { $0.hasPrefix("connection=") })
            let cid = try #require(fields.first { $0.hasPrefix("cid=") })
            #expect(submissions.filter {
                $0.hasPrefix("\(connection) ") && $0.contains(" \(cid) ")
                    && $0.contains(" lba=\(lba) ")
            }.count == 1)
            #expect(output.contains { $0.contains(" \(connection) ← \(cid) Read nsid=1 ok") })
            #expect(output.contains {
                $0.contains("NVMeController.execute") && $0.contains("finished queue=io")
                    && $0.contains(" \(connection) \(cid) ")
            })
        }
        // The optimized receive path bypasses handle(raw:) for data PDUs.
        #expect(output.filter {
            $0.contains("NVMeQueue.handleC2HData") && $0.contains("queueID=")
                && $0.contains("bytes=4096")
        }.count >= 3)
        #expect(output.contains { $0.contains("C2HData cid=") } == debug)
    }

    @Test(arguments: [false, true])
    func functionLogsMarkMissingConnectionID(tracingTransport: Bool) async throws {
        let lines = Mutex<[String]>([])
        let fleet = NVMeFleet()
        let config = testControllerConfig {
            $0.debugLog = { line in lines.withLock { $0.append(line) } }
        }
        let controller = NVMeController(config: config, policy: testPolicy()) {
            let transport = await fleet.makeTransport()
            if tracingTransport { return NVMeTracingTransport(transport, sink: { _ in }) }
            return transport
        }
        try await controller.activate()
        let command = NVMeCommands.read(commandID: 0, nsid: 1, slba: 0, blocks: 1, blockSize: 4096)
        let completion = try await controller.execute(command, expectedRead: 4096)
        #expect(completion.connectionID == nil)
        #expect(lines.withLock { $0.contains { $0.hasPrefix("connection=- NVMeQueue.submit") } })
        try await controller.logout()
        await fleet.shutdown()
    }

    @Test func untracedReadsDoNotCreateConnectionMetadata() async throws {
        let fleet = NVMeFleet()
        let controller = try await activatedController(fleet: fleet)
        let command = NVMeCommands.read(commandID: 0, nsid: 1, slba: 0, blocks: 1, blockSize: 4096)
        let completion = try await controller.execute(command, expectedRead: 4096)
        #expect(completion.data == Data(count: 4096))
        #expect(completion.receivedBytes == 4096)
        #expect(completion.connectionID == nil)
        try await controller.logout()
        await fleet.shutdown()
    }
}
