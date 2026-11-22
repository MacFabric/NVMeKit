import Foundation

/// Serializes a PDU to wire bytes: CH + PSH [+ HDGST] + data [+ DDGST].
///
/// HPDA and CPDA are 0's based in dwords, so 0 means 4-byte alignment. We
/// send HPDA = 0 and require CPDA = 0 at ICResp; every fixed header length
/// (24, 72) plus an optional 4-byte HDGST already sits on a dword boundary,
/// so PDO is exactly HLEN + HDGST and no padding is ever emitted.
public struct NVMeTCPSerializer: Sendable {
    public var digests: NVMeTCPDigests

    public init(digests: NVMeTCPDigests = NVMeTCPDigests()) {
        self.digests = digests
    }

    /// The same bytes as one buffer, which costs a copy of the data.
    public func serialize(_ raw: RawNVMeTCPPDU) -> Data {
        let parts = serializeParts(raw)
        if parts.count == 1 { return parts[0] }
        var out = Data(capacity: parts.reduce(0) { $0 + $1.count })
        for part in parts { out.append(part) }
        return out
    }

    /// The PDU's wire bytes as up to three buffers, in order: the header
    /// (CH, PSH and HDGST), the data exactly as the caller holds it, and the
    /// DDGST. Sent with `ConnectionTransport.send(contentsOf:)`, write data
    /// reaches the socket without first being copied in behind its header.
    public func serializeParts(_ raw: RawNVMeTCPPDU) -> [Data] {
        let hlen = raw.hlen
        if Self.isTerminationRequest(raw.type) {
            // §3.6.2.4/5: FLAGS and PDO reserved, never a digest, the
            // offending header at byte 24, PLEN at most 152.
            let data = raw.data.prefix(NVMeTCPDeframer.maxTermReqDataBytes)
            var out = Data(capacity: hlen + data.count)
            out.append(NVMeTCPHeader(type: raw.type, flags: [], hlen: UInt8(hlen), pdo: 0,
                                     plen: UInt32(hlen + data.count)).encoded)
            out.append(raw.psh)
            out.append(data)
            return [out]
        }
        let hdgst = digests.header ? 4 : 0
        let hasData = !raw.data.isEmpty
        let ddgst = (digests.data && hasData) ? 4 : 0
        var flags = raw.flags.subtracting([.headerDigest, .dataDigest])
        if hdgst > 0 { flags.insert(.headerDigest) }
        if ddgst > 0 { flags.insert(.dataDigest) }
        let pdo = hasData ? hlen + hdgst : 0
        let plen = hlen + hdgst + raw.data.count + ddgst

        var head = Data(capacity: hlen + hdgst)
        head.append(NVMeTCPHeader(type: raw.type, flags: flags, hlen: UInt8(hlen),
                                  pdo: UInt8(pdo), plen: UInt32(plen)).encoded)
        head.append(raw.psh)
        // HDGST covers CH + PSH only.
        if hdgst > 0 { head.append(CRC32C.wireDigest(head)) }
        guard hasData else { return [head] }
        // DDGST covers the DATA field only — never the header, never padding.
        return ddgst > 0 ? [head, raw.data, CRC32C.wireDigest(raw.data)] : [head, raw.data]
    }
}

extension NVMeTCPSerializer {
    static func isTerminationRequest(_ type: UInt8) -> Bool {
        type == NVMeTCPPDUType.h2cTermReq.rawValue || type == NVMeTCPPDUType.c2hTermReq.rawValue
    }
}

/// Incremental deframer: feed arbitrary byte chunks, pull complete PDUs.
/// Verifies digests, enforces a PLEN ceiling before buffering a byte of the
/// payload, and locates data by PDO (which absorbs the header digest and any
/// controller-side alignment padding) rather than by HLEN.
///
/// A header digest error throws: the header, PLEN included, cannot be
/// trusted, so the stream is lost (NVMe/TCP 1.1 §3.5). A data digest error
/// does not: the PDU is delivered with `dataDigestFailed` set, and the
/// command it belongs to fails while the connection carries on.
///
/// Two ways to pull, as in iSCSIKit's `PDUDeframer`. `next()` returns a
/// whole PDU once all of it has arrived. `nextHead()` returns the header as
/// soon as that has arrived, and the data is then moved with
/// `readData(into:)` straight from the chunks it came in to the buffer of
/// the read it answers, and closed with `finishData()`.
///
/// Received chunks are kept as they arrived (`ReceiveQueue`) and released as
/// they are used up; nothing is compacted.
public struct NVMeTCPDeframer: Sendable {
    public var digests: NVMeTCPDigests
    /// Upper bound accepted for PLEN. Bounds memory per PDU against a hostile
    /// or broken peer; sized by the caller from MAXH2CDATA / the transfer cap.
    public var maxPDUBytes: Int

    private var queue = ReceiveQueue()
    /// A termination request is a 24-byte header plus at most 128 bytes of
    /// the offending PDU header (§3.5).
    static let termReqHeaderBytes = 24
    static let maxTermReqDataBytes = 128

    /// Data whose header `nextHead()` has returned and which has not been
    /// closed yet.
    private struct Segment: Sendable {
        var remaining: Int
        var crc: UInt32
        let checked: Bool
    }

    private var segment: Segment?

    public init(digests: NVMeTCPDigests = NVMeTCPDigests(), maxPDUBytes: Int = 1 << 20) {
        self.digests = digests
        self.maxPDUBytes = maxPDUBytes
    }

    public mutating func append(_ bytes: Data) {
        queue.append(bytes)
    }

    /// Bytes buffered but not yet consumed.
    public var buffered: Int { queue.count }

    /// The header (CH + PSH, at most 128 bytes) of the PDU most recently
    /// returned or being parsed when `next()` threw: what an H2CTermReq
    /// carries as its data (§3.5).
    ///
    /// Put together only when asked for. It is wanted once in a connection's
    /// life, on the error that ends it; while the header is still at the
    /// front of the queue it is read from there, and once consumed it is the
    /// common header and the PSH that were copied out for the PDU anyway.
    public var lastHeader: Data {
        if let length = headerLengthInQueue { return queue.peek(min(length, queue.count)) }
        return (keptCommonHeader + keptPSH).prefix(Self.maxTermReqDataBytes)
    }

    /// Length of `lastHeader` while its bytes are still unconsumed.
    private var headerLengthInQueue: Int?
    private var keptCommonHeader = Data()
    private var keptPSH = Data()

    /// Where everything in the PDU at the front of the queue is.
    private struct Layout {
        let type: UInt8
        /// As they go into the PDU: none for a termination request.
        let flags: NVMeTCPFlags
        let hlen: Int
        let headerDigestLength: Int
        /// Offset of the data; meaningless when `dataLength` is 0.
        let dataStart: Int
        let dataLength: Int
        let dataDigestLength: Int
        let plen: Int
    }

    /// Parse and validate the common header at the front of the queue. nil
    /// until its eight bytes have arrived.
    private mutating func layout() throws -> Layout? {
        let avail = queue.count
        guard avail >= NVMeTCPHeader.size else { return nil }
        let header = try NVMeTCPHeader(bytes: queue.peek(NVMeTCPHeader.size))
        let hlen = Int(header.hlen)
        let pdo = Int(header.pdo)
        let plen = Int(header.plen)
        headerLengthInQueue = min(max(hlen, NVMeTCPHeader.size), avail, Self.maxTermReqDataBytes)

        guard plen <= maxPDUBytes else {
            throw NVMeTCPError.pduTooLarge(length: plen, limit: maxPDUBytes)
        }
        guard hlen >= NVMeTCPHeader.size else {
            throw NVMeTCPError.malformed("HLEN \(hlen) is shorter than the common header")
        }
        if NVMeTCPSerializer.isTerminationRequest(header.type) {
            // Exempt from digests whatever was negotiated; FLAGS and PDO are
            // reserved, so the data is found at byte 24, not by PDO. Outside
            // 24...152 the spec says ignore it and terminate — which a throw
            // does.
            guard hlen == Self.termReqHeaderBytes,
                  plen >= Self.termReqHeaderBytes,
                  plen <= Self.termReqHeaderBytes + Self.maxTermReqDataBytes
            else {
                throw NVMeTCPError.malformed("termination request with HLEN \(hlen) / PLEN \(plen)")
            }
            return Layout(type: header.type, flags: [], hlen: hlen, headerDigestLength: 0,
                          dataStart: hlen, dataLength: plen - hlen, dataDigestLength: 0, plen: plen)
        }
        // The digest bits must agree with what was negotiated; the Linux host
        // treats a disagreement as a protocol error, and so do we.
        guard header.flags.contains(.headerDigest) == digests.header else {
            throw NVMeTCPError.malformed("HDGSTF does not match the negotiated header digest")
        }
        let hdgst = digests.header ? 4 : 0
        guard plen >= hlen + hdgst else {
            throw NVMeTCPError.malformed("PLEN \(plen) is shorter than the header (\(hlen + hdgst))")
        }
        if pdo == 0 {
            guard plen == hlen + hdgst else {
                throw NVMeTCPError.malformed("PDO 0 but PLEN \(plen) exceeds the header (\(hlen + hdgst))")
            }
            guard !header.flags.contains(.dataDigest) else {
                throw NVMeTCPError.malformed("DDGSTF set on a PDU with no data")
            }
            return Layout(type: header.type, flags: header.flags, hlen: hlen, headerDigestLength: hdgst,
                          dataStart: plen, dataLength: 0, dataDigestLength: 0, plen: plen)
        }
        guard header.flags.contains(.dataDigest) == digests.data else {
            throw NVMeTCPError.malformed("DDGSTF does not match the negotiated data digest")
        }
        let ddgst = digests.data ? 4 : 0
        guard pdo >= hlen + hdgst, pdo + ddgst <= plen else {
            throw NVMeTCPError.malformed("PDO \(pdo) is inconsistent with HLEN \(hlen) / PLEN \(plen)")
        }
        return Layout(type: header.type, flags: header.flags, hlen: hlen, headerDigestLength: hdgst,
                      dataStart: pdo, dataLength: plen - pdo - ddgst, dataDigestLength: ddgst, plen: plen)
    }

    /// Copy the PSH out, checking the header digest first. Consumes nothing.
    private func pshChecked(_ layout: Layout) throws -> Data {
        let common = queue.peek(NVMeTCPHeader.size)
        let psh = queue.peek(layout.hlen - NVMeTCPHeader.size, skippingFirst: NVMeTCPHeader.size)
        if layout.headerDigestLength > 0 {
            var crc = common.withUnsafeBytes { CRC32C.update(CRC32C.initial, $0) }
            crc = psh.withUnsafeBytes { CRC32C.update(crc, $0) }
            guard CRC32C.finalize(crc) == queue.peek(4, skippingFirst: layout.hlen).leU32(0) else {
                throw NVMeTCPError.headerDigestMismatch
            }
        }
        return psh
    }

    /// The header is about to leave the queue: keep what `lastHeader` needs.
    private mutating func keepHeader(psh: Data) {
        keptCommonHeader = queue.peek(NVMeTCPHeader.size)
        keptPSH = psh
        headerLengthInQueue = nil
    }

    /// Returns the next complete PDU, or nil if more bytes are needed. On a
    /// thrown error the deframer is poisoned: any framing or digest error
    /// tears the connection down, so no resync is attempted.
    public mutating func next() throws -> RawNVMeTCPPDU? {
        precondition(segment == nil, "data begun with nextHead() has not been finished")
        guard let layout = try layout(), queue.count >= layout.plen else { return nil }
        let psh = try pshChecked(layout)
        var raw = RawNVMeTCPPDU(
            rawType: layout.type, flags: layout.flags, psh: psh,
            data: queue.peek(layout.dataLength, skippingFirst: layout.dataStart))
        if layout.dataDigestLength > 0 {
            let expected = CRC32C.checksum(raw.data)
            raw.dataDigestFailed =
                expected != queue.peek(4, skippingFirst: layout.dataStart + layout.dataLength).leU32(0)
        }
        keepHeader(psh: psh)
        queue.skip(layout.plen)
        return raw
    }

    // MARK: - A PDU in steps

    /// A PDU's header, with the length of the data that follows it.
    public struct Head: Sendable {
        public let type: UInt8
        public let flags: NVMeTCPFlags
        public let psh: Data
        public let dataLength: Int
    }

    /// The next PDU's header, consumed with its digest and any padding before
    /// the data, or nil if that much has not arrived. When `dataLength` is
    /// not zero the data must be taken — `readData(into:)` then
    /// `finishData()`, or `takeData()` — before this is called again.
    public mutating func nextHead() throws -> Head? {
        precondition(segment == nil, "the previous PDU's data has not been finished")
        guard let layout = try layout(), queue.count >= layout.dataStart else { return nil }
        let psh = try pshChecked(layout)
        keepHeader(psh: psh)
        queue.skip(layout.dataStart)
        if layout.dataLength > 0 {
            segment = Segment(remaining: layout.dataLength, crc: CRC32C.initial,
                              checked: layout.dataDigestLength > 0)
        }
        return Head(type: layout.type, flags: layout.flags, psh: psh, dataLength: layout.dataLength)
    }

    /// Data bytes not yet taken.
    public var dataRemaining: Int { segment?.remaining ?? 0 }

    /// Move data bytes that have arrived into `destination`: as many as it
    /// holds, as remain, and as are buffered, whichever is least. Returns how
    /// many. They are not known to be good until `finishData()` says so.
    @discardableResult
    public mutating func readData(into destination: UnsafeMutableRawBufferPointer) -> Int {
        guard var current = segment, current.remaining > 0, destination.count > 0 else { return 0 }
        let room = UnsafeMutableRawBufferPointer(
            rebasing: destination[0 ..< min(current.remaining, destination.count)])
        let moved = queue.read(into: room)
        if current.checked, moved > 0 {
            current.crc = CRC32C.update(current.crc, UnsafeRawBufferPointer(rebasing: room[0 ..< moved]))
        }
        current.remaining -= moved
        segment = current
        return moved
    }

    /// How a PDU's data ended.
    public enum DataEnd: Sendable, Equatable {
        /// The digest has not all arrived.
        case needMore
        case good
        /// The data is not what the controller sent (§3.5): the command
        /// fails, the connection carries on.
        case digestFailed
    }

    /// Close the data once all of it has been taken, checking its digest.
    public mutating func finishData() -> DataEnd {
        guard let current = segment else { return .good }
        precondition(current.remaining == 0, "data bytes not yet taken")
        guard current.checked else {
            segment = nil
            return .good
        }
        guard queue.count >= 4 else { return .needMore }
        let matches = CRC32C.finalize(current.crc) == queue.read(4).leU32(0)
        segment = nil
        return matches ? .good : .digestFailed
    }

    /// The whole of the data as one buffer, closed, for a PDU whose data has
    /// nowhere better to go. nil until all of it has arrived. Not to be mixed
    /// with `readData(into:)` on the same PDU.
    public mutating func takeData() -> (data: Data, digestFailed: Bool)? {
        guard var current = segment else { return (Data(), false) }
        guard queue.count >= current.remaining + (current.checked ? 4 : 0) else { return nil }
        let data = queue.read(current.remaining)
        if current.checked { current.crc = data.withUnsafeBytes { CRC32C.update(current.crc, $0) } }
        current.remaining = 0
        segment = current
        return (data, finishData() == .digestFailed)
    }
}
