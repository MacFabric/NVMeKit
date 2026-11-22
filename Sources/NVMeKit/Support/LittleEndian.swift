import Foundation

/// Little-endian, slice-tolerant accessors over `Data`, the NVMe/TCP
/// counterpart of iSCSIKit's big-endian `beU16`/`setBE32` family (which this
/// module reuses for `u8`, `sub`, `setU8`, `setSub`). Every NVMe field is
/// little-endian, including the CRC32C digests on the wire. All offsets are
/// relative to `startIndex`, so these work uniformly on slices handed out by
/// the deframer.
extension Data {
    /// Trap, as a subscript would, before a raw load or store can touch
    /// bytes outside this buffer: the unsafe accessors check their offsets
    /// only in debug builds, and these fields come off the network.
    @inline(__always)
    private func checkRange(_ offset: Int, _ width: Int) {
        precondition(offset >= 0 && width <= count && offset <= count - width,
                     "field outside the buffer")
    }

    /// One load of the whole field, where a byte at a time through the
    /// subscript cost a bounds check and an access per byte.
    @inline(__always)
    private func loadLE<T: FixedWidthInteger>(_ offset: Int, as type: T.Type) -> T {
        checkRange(offset, MemoryLayout<T>.size)
        return withUnsafeBytes { T(littleEndian: $0.loadUnaligned(fromByteOffset: offset, as: T.self)) }
    }

    @inline(__always)
    private mutating func storeLE<T: FixedWidthInteger>(_ value: T, _ offset: Int) {
        checkRange(offset, MemoryLayout<T>.size)
        withUnsafeMutableBytes { $0.storeBytes(of: value.littleEndian, toByteOffset: offset, as: T.self) }
    }

    package func leU16(_ offset: Int) -> UInt16 { loadLE(offset, as: UInt16.self) }

    package func leU32(_ offset: Int) -> UInt32 { loadLE(offset, as: UInt32.self) }

    package func leU64(_ offset: Int) -> UInt64 { loadLE(offset, as: UInt64.self) }

    package mutating func setLE16(_ v: UInt16, _ offset: Int) { storeLE(v, offset) }

    package mutating func setLE32(_ v: UInt32, _ offset: Int) { storeLE(v, offset) }

    package mutating func setLE64(_ v: UInt64, _ offset: Int) { storeLE(v, offset) }
}
