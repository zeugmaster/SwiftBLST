import Cblst
import Foundation

@inline(__always)
private func withBytes<R>(_ bytes: [UInt8], _ body: (UnsafePointer<UInt8>?, Int) throws -> R)
  rethrows
  -> R
{
  try bytes.withUnsafeBufferPointer { buffer in
    try body(buffer.baseAddress, buffer.count)
  }
}

extension String {
  fileprivate var utf8Bytes: [UInt8] { Array(utf8) }
}

public enum BLST {
  public enum BLSError: Error, Equatable, CustomStringConvertible {
    case badEncoding
    case pointNotOnCurve
    case pointNotInGroup
    case aggregateTypeMismatch
    case verifyFail
    case publicKeyIsInfinity
    case badScalar
    case invalidLength(expected: Int, actual: Int)
    case emptyAggregate
    case invalidInput(String)
    case unknown(Int32)

    init(_ error: BLST_ERROR) {
      switch Int32(error.rawValue) {
      case 0: self = .unknown(0)
      case 1: self = .badEncoding
      case 2: self = .pointNotOnCurve
      case 3: self = .pointNotInGroup
      case 4: self = .aggregateTypeMismatch
      case 5: self = .verifyFail
      case 6: self = .publicKeyIsInfinity
      case 7: self = .badScalar
      default: self = .unknown(Int32(error.rawValue))
      }
    }

    static func throwIfNeeded(_ error: BLST_ERROR) throws {
      if Int32(error.rawValue) != 0 { throw BLSError(error) }
    }

    public var description: String {
      switch self {
      case .badEncoding: return "bad encoding"
      case .pointNotOnCurve: return "point not on curve"
      case .pointNotInGroup: return "point not in subgroup"
      case .aggregateTypeMismatch: return "aggregate type mismatch"
      case .verifyFail: return "signature verification failed"
      case .publicKeyIsInfinity: return "public key is infinity"
      case .badScalar: return "bad scalar"
      case .invalidLength(let expected, let actual):
        return "invalid length: expected \(expected), got \(actual)"
      case .emptyAggregate: return "cannot aggregate an empty collection"
      case .invalidInput(let message): return message
      case .unknown(let code): return "unknown blst error \(code)"
      }
    }
  }

  public enum HashMode: Sendable {
    case hashToCurve
    case encodeToCurve

    var cBool: Bool { self == .hashToCurve }
  }

  public enum BLSScheme: Sendable {
    public static let basic = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_"
    public static let basicEncode = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_NU_NUL_"
    public static let proofOfPossession = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_"
    public static let augmentation = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_AUG_"

    public static let minSigBasic = "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_"
    public static let minSigProofOfPossession = "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_"
    public static let minSigAugmentation = "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_AUG_"

    /// Cashu NUT-00 pairing-based BDHKE v3 hash-to-G1 DST.
    public static let cashu = "CASHU_BLS12_381_G1_XMD:SHA-256_SSWU_RO_"
  }

  public struct SecretKey: Sendable, Equatable {
    var scalar: blst_scalar

    public init(inputKeyMaterial ikm: [UInt8], keyInfo: [UInt8] = []) throws {
      guard ikm.count >= 32 else {
        throw BLSError.invalidInput("input key material must be at least 32 bytes")
      }
      var sk = blst_scalar()
      withBytes(ikm) { ikmPtr, ikmLen in
        withBytes(keyInfo) { infoPtr, infoLen in
          blst_keygen(&sk, ikmPtr, ikmLen, infoPtr, infoLen)
        }
      }
      guard blst_sk_check(&sk) else { throw BLSError.badScalar }
      self.scalar = sk
    }

    public init(bytes: [UInt8]) throws {
      guard bytes.count == 32 else {
        throw BLSError.invalidLength(expected: 32, actual: bytes.count)
      }
      var sk = blst_scalar()
      bytes.withUnsafeBufferPointer { blst_scalar_from_bendian(&sk, $0.baseAddress!) }
      guard blst_sk_check(&sk) else { throw BLSError.badScalar }
      self.scalar = sk
    }

    public var bytes: [UInt8] {
      var s = scalar
      var out = [UInt8](repeating: 0, count: 32)
      out.withUnsafeMutableBufferPointer { blst_bendian_from_scalar($0.baseAddress!, &s) }
      return out
    }

    public func publicKeyG1() -> PublicKeyG1 {
      var projective = blst_p1()
      var affine = blst_p1_affine()
      var s = scalar
      blst_sk_to_pk_in_g1(&projective, &s)
      blst_p1_to_affine(&affine, &projective)
      return PublicKeyG1(affine: affine)
    }

    public func publicKeyG2() -> PublicKeyG2 {
      var projective = blst_p2()
      var affine = blst_p2_affine()
      var s = scalar
      blst_sk_to_pk_in_g2(&projective, &s)
      blst_p2_to_affine(&affine, &projective)
      return PublicKeyG2(affine: affine)
    }

    public func signG2(
      message: [UInt8], domainSeparationTag dst: String = BLSScheme.basic,
      augmentation: [UInt8] = [],
      mode: HashMode = .hashToCurve
    ) -> SignatureG2 {
      var hash = blst_p2()
      let dstBytes = dst.utf8Bytes
      withBytes(message) { msgPtr, msgLen in
        withBytes(dstBytes) { dstPtr, dstLen in
          withBytes(augmentation) { augPtr, augLen in
            if mode == .hashToCurve {
              blst_hash_to_g2(&hash, msgPtr, msgLen, dstPtr, dstLen, augPtr, augLen)
            } else {
              blst_encode_to_g2(&hash, msgPtr, msgLen, dstPtr, dstLen, augPtr, augLen)
            }
          }
        }
      }
      var sig = blst_p2()
      var affine = blst_p2_affine()
      var s = scalar
      blst_sign_pk_in_g1(&sig, &hash, &s)
      blst_p2_to_affine(&affine, &sig)
      return SignatureG2(affine: affine)
    }

    public func proofOfPossessionG2() -> SignatureG2 {
      let pk = publicKeyG1()
      return signG2(message: pk.compressedBytes, domainSeparationTag: BLSScheme.proofOfPossession)
    }

    public func signG1(
      message: [UInt8], domainSeparationTag dst: String = BLSScheme.minSigBasic,
      augmentation: [UInt8] = [], mode: HashMode = .hashToCurve
    ) -> SignatureG1 {
      var hash = blst_p1()
      let dstBytes = dst.utf8Bytes
      withBytes(message) { msgPtr, msgLen in
        withBytes(dstBytes) { dstPtr, dstLen in
          withBytes(augmentation) { augPtr, augLen in
            if mode == .hashToCurve {
              blst_hash_to_g1(&hash, msgPtr, msgLen, dstPtr, dstLen, augPtr, augLen)
            } else {
              blst_encode_to_g1(&hash, msgPtr, msgLen, dstPtr, dstLen, augPtr, augLen)
            }
          }
        }
      }
      var sig = blst_p1()
      var affine = blst_p1_affine()
      var s = scalar
      blst_sign_pk_in_g2(&sig, &hash, &s)
      blst_p1_to_affine(&affine, &sig)
      return SignatureG1(affine: affine)
    }

    public func proofOfPossessionG1() -> SignatureG1 {
      let pk = publicKeyG2()
      return signG1(
        message: pk.compressedBytes, domainSeparationTag: BLSScheme.minSigProofOfPossession)
    }

    public static func == (lhs: SecretKey, rhs: SecretKey) -> Bool { lhs.bytes == rhs.bytes }
  }

  public struct PublicKeyG1: Sendable, Equatable {
    var affine: blst_p1_affine
    init(affine: blst_p1_affine) { self.affine = affine }

    public init(compressed bytes: [UInt8], subgroupCheck: Bool = true) throws {
      guard bytes.count == 48 else {
        throw BLSError.invalidLength(expected: 48, actual: bytes.count)
      }
      var p = blst_p1_affine()
      try bytes.withUnsafeBufferPointer {
        try BLSError.throwIfNeeded(blst_p1_uncompress(&p, $0.baseAddress!))
      }
      if subgroupCheck && !blst_p1_affine_in_g1(&p) { throw BLSError.pointNotInGroup }
      self.affine = p
    }

    public init(uncompressed bytes: [UInt8], subgroupCheck: Bool = true) throws {
      guard bytes.count == 96 else {
        throw BLSError.invalidLength(expected: 96, actual: bytes.count)
      }
      var p = blst_p1_affine()
      try bytes.withUnsafeBufferPointer {
        try BLSError.throwIfNeeded(blst_p1_deserialize(&p, $0.baseAddress!))
      }
      if subgroupCheck && !blst_p1_affine_in_g1(&p) { throw BLSError.pointNotInGroup }
      self.affine = p
    }

    public var compressedBytes: [UInt8] {
      var a = affine
      var out = [UInt8](repeating: 0, count: 48)
      out.withUnsafeMutableBufferPointer { blst_p1_affine_compress($0.baseAddress!, &a) }
      return out
    }
    public var uncompressedBytes: [UInt8] {
      var a = affine
      var out = [UInt8](repeating: 0, count: 96)
      out.withUnsafeMutableBufferPointer { blst_p1_affine_serialize($0.baseAddress!, &a) }
      return out
    }
    public var isInfinity: Bool {
      var a = affine
      return blst_p1_affine_is_inf(&a)
    }
    public var isInGroup: Bool {
      var a = affine
      return blst_p1_affine_in_g1(&a)
    }
    public static func aggregate(_ publicKeys: [PublicKeyG1]) throws -> PublicKeyG1 {
      guard let first = publicKeys.first else { throw BLSError.emptyAggregate }
      var firstAffine = first.affine
      var acc = blst_p1()
      blst_p1_from_affine(&acc, &firstAffine)
      for pk in publicKeys.dropFirst() {
        var pkAffine = pk.affine
        var current = acc
        blst_p1_add_or_double_affine(&acc, &current, &pkAffine)
      }
      var affine = blst_p1_affine()
      blst_p1_to_affine(&affine, &acc)
      return PublicKeyG1(affine: affine)
    }
    public func verifyProofOfPossession(_ proof: SignatureG2) -> Bool {
      verify(
        signature: proof, message: compressedBytes, domainSeparationTag: BLSScheme.proofOfPossession
      )
    }
    public func verify(
      signature: SignatureG2, message: [UInt8], domainSeparationTag dst: String = BLSScheme.basic,
      augmentation: [UInt8] = [], mode: HashMode = .hashToCurve
    ) -> Bool {
      do {
        try verifyOrThrow(
          signature: signature, message: message, domainSeparationTag: dst,
          augmentation: augmentation, mode: mode)
        return true
      } catch { return false }
    }
    public func verifyOrThrow(
      signature: SignatureG2, message: [UInt8], domainSeparationTag dst: String = BLSScheme.basic,
      augmentation: [UInt8] = [], mode: HashMode = .hashToCurve
    ) throws {
      let dstBytes = dst.utf8Bytes
      try withBytes(message) { msgPtr, msgLen in
        try withBytes(dstBytes) { dstPtr, dstLen in
          try withBytes(augmentation) { augPtr, augLen in
            var pk = affine
            var sig = signature.affine
            try BLSError.throwIfNeeded(
              blst_core_verify_pk_in_g1(
                &pk, &sig, mode.cBool, msgPtr, msgLen, dstPtr, dstLen, augPtr, augLen))
          }
        }
      }
    }
    public static func == (lhs: PublicKeyG1, rhs: PublicKeyG1) -> Bool {
      lhs.compressedBytes == rhs.compressedBytes
    }
  }

  public struct PublicKeyG2: Sendable, Equatable {
    var affine: blst_p2_affine
    init(affine: blst_p2_affine) { self.affine = affine }

    public init(compressed bytes: [UInt8], subgroupCheck: Bool = true) throws {
      guard bytes.count == 96 else {
        throw BLSError.invalidLength(expected: 96, actual: bytes.count)
      }
      var p = blst_p2_affine()
      try bytes.withUnsafeBufferPointer {
        try BLSError.throwIfNeeded(blst_p2_uncompress(&p, $0.baseAddress!))
      }
      if subgroupCheck && !blst_p2_affine_in_g2(&p) { throw BLSError.pointNotInGroup }
      self.affine = p
    }

    public init(uncompressed bytes: [UInt8], subgroupCheck: Bool = true) throws {
      guard bytes.count == 192 else {
        throw BLSError.invalidLength(expected: 192, actual: bytes.count)
      }
      var p = blst_p2_affine()
      try bytes.withUnsafeBufferPointer {
        try BLSError.throwIfNeeded(blst_p2_deserialize(&p, $0.baseAddress!))
      }
      if subgroupCheck && !blst_p2_affine_in_g2(&p) { throw BLSError.pointNotInGroup }
      self.affine = p
    }

    public var compressedBytes: [UInt8] {
      var a = affine
      var out = [UInt8](repeating: 0, count: 96)
      out.withUnsafeMutableBufferPointer { blst_p2_affine_compress($0.baseAddress!, &a) }
      return out
    }
    public var uncompressedBytes: [UInt8] {
      var a = affine
      var out = [UInt8](repeating: 0, count: 192)
      out.withUnsafeMutableBufferPointer { blst_p2_affine_serialize($0.baseAddress!, &a) }
      return out
    }
    public var isInfinity: Bool {
      var a = affine
      return blst_p2_affine_is_inf(&a)
    }
    public var isInGroup: Bool {
      var a = affine
      return blst_p2_affine_in_g2(&a)
    }
    public static func aggregate(_ publicKeys: [PublicKeyG2]) throws -> PublicKeyG2 {
      guard let first = publicKeys.first else { throw BLSError.emptyAggregate }
      var firstAffine = first.affine
      var acc = blst_p2()
      blst_p2_from_affine(&acc, &firstAffine)
      for pk in publicKeys.dropFirst() {
        var pkAffine = pk.affine
        var current = acc
        blst_p2_add_or_double_affine(&acc, &current, &pkAffine)
      }
      var affine = blst_p2_affine()
      blst_p2_to_affine(&affine, &acc)
      return PublicKeyG2(affine: affine)
    }
    public func verifyProofOfPossession(_ proof: SignatureG1) -> Bool {
      verify(
        signature: proof, message: compressedBytes,
        domainSeparationTag: BLSScheme.minSigProofOfPossession)
    }
    public func verify(
      signature: SignatureG1, message: [UInt8],
      domainSeparationTag dst: String = BLSScheme.minSigBasic, augmentation: [UInt8] = [],
      mode: HashMode = .hashToCurve
    ) -> Bool {
      do {
        try verifyOrThrow(
          signature: signature, message: message, domainSeparationTag: dst,
          augmentation: augmentation, mode: mode)
        return true
      } catch { return false }
    }
    public func verifyOrThrow(
      signature: SignatureG1, message: [UInt8],
      domainSeparationTag dst: String = BLSScheme.minSigBasic, augmentation: [UInt8] = [],
      mode: HashMode = .hashToCurve
    ) throws {
      let dstBytes = dst.utf8Bytes
      try withBytes(message) { msgPtr, msgLen in
        try withBytes(dstBytes) { dstPtr, dstLen in
          try withBytes(augmentation) { augPtr, augLen in
            var pk = affine
            var sig = signature.affine
            try BLSError.throwIfNeeded(
              blst_core_verify_pk_in_g2(
                &pk, &sig, mode.cBool, msgPtr, msgLen, dstPtr, dstLen, augPtr, augLen))
          }
        }
      }
    }
    public static func == (lhs: PublicKeyG2, rhs: PublicKeyG2) -> Bool {
      lhs.compressedBytes == rhs.compressedBytes
    }
  }

  public struct SignatureG2: Sendable, Equatable {
    var affine: blst_p2_affine
    init(affine: blst_p2_affine) { self.affine = affine }
    public init(compressed bytes: [UInt8], subgroupCheck: Bool = true) throws {
      guard bytes.count == 96 else {
        throw BLSError.invalidLength(expected: 96, actual: bytes.count)
      }
      var p = blst_p2_affine()
      try bytes.withUnsafeBufferPointer {
        try BLSError.throwIfNeeded(blst_p2_uncompress(&p, $0.baseAddress!))
      }
      if subgroupCheck && !blst_p2_affine_in_g2(&p) { throw BLSError.pointNotInGroup }
      self.affine = p
    }
    public init(uncompressed bytes: [UInt8], subgroupCheck: Bool = true) throws {
      guard bytes.count == 192 else {
        throw BLSError.invalidLength(expected: 192, actual: bytes.count)
      }
      var p = blst_p2_affine()
      try bytes.withUnsafeBufferPointer {
        try BLSError.throwIfNeeded(blst_p2_deserialize(&p, $0.baseAddress!))
      }
      if subgroupCheck && !blst_p2_affine_in_g2(&p) { throw BLSError.pointNotInGroup }
      self.affine = p
    }
    public var compressedBytes: [UInt8] {
      var a = affine
      var out = [UInt8](repeating: 0, count: 96)
      out.withUnsafeMutableBufferPointer { blst_p2_affine_compress($0.baseAddress!, &a) }
      return out
    }
    public var uncompressedBytes: [UInt8] {
      var a = affine
      var out = [UInt8](repeating: 0, count: 192)
      out.withUnsafeMutableBufferPointer { blst_p2_affine_serialize($0.baseAddress!, &a) }
      return out
    }
    public static func aggregate(_ signatures: [SignatureG2]) throws -> SignatureG2 {
      guard let first = signatures.first else { throw BLSError.emptyAggregate }
      var firstAffine = first.affine
      var acc = blst_p2()
      blst_p2_from_affine(&acc, &firstAffine)
      for sig in signatures.dropFirst() {
        var sigAffine = sig.affine
        var current = acc
        blst_p2_add_or_double_affine(&acc, &current, &sigAffine)
      }
      var affine = blst_p2_affine()
      blst_p2_to_affine(&affine, &acc)
      return SignatureG2(affine: affine)
    }
    public static func == (lhs: SignatureG2, rhs: SignatureG2) -> Bool {
      lhs.compressedBytes == rhs.compressedBytes
    }
  }

  public struct SignatureG1: Sendable, Equatable {
    var affine: blst_p1_affine
    init(affine: blst_p1_affine) { self.affine = affine }

    public static func hashToCurve(
      message: [UInt8], domainSeparationTag dst: String = BLSScheme.minSigBasic,
      augmentation: [UInt8] = [], mode: HashMode = .hashToCurve
    ) -> SignatureG1 {
      var hash = blst_p1()
      let dstBytes = dst.utf8Bytes
      withBytes(message) { msgPtr, msgLen in
        withBytes(dstBytes) { dstPtr, dstLen in
          withBytes(augmentation) { augPtr, augLen in
            if mode == .hashToCurve {
              blst_hash_to_g1(&hash, msgPtr, msgLen, dstPtr, dstLen, augPtr, augLen)
            } else {
              blst_encode_to_g1(&hash, msgPtr, msgLen, dstPtr, dstLen, augPtr, augLen)
            }
          }
        }
      }
      var affine = blst_p1_affine()
      blst_p1_to_affine(&affine, &hash)
      return SignatureG1(affine: affine)
    }

    public func multiplied(by scalar: SecretKey) -> SignatureG1 {
      var point = blst_p1()
      var source = affine
      blst_p1_from_affine(&point, &source)
      var out = blst_p1()
      var s = scalar.scalar
      blst_sign_pk_in_g2(&out, &point, &s)
      var affine = blst_p1_affine()
      blst_p1_to_affine(&affine, &out)
      return SignatureG1(affine: affine)
    }

    public init(compressed bytes: [UInt8], subgroupCheck: Bool = true) throws {
      guard bytes.count == 48 else {
        throw BLSError.invalidLength(expected: 48, actual: bytes.count)
      }
      var p = blst_p1_affine()
      try bytes.withUnsafeBufferPointer {
        try BLSError.throwIfNeeded(blst_p1_uncompress(&p, $0.baseAddress!))
      }
      if subgroupCheck && !blst_p1_affine_in_g1(&p) { throw BLSError.pointNotInGroup }
      self.affine = p
    }
    public init(uncompressed bytes: [UInt8], subgroupCheck: Bool = true) throws {
      guard bytes.count == 96 else {
        throw BLSError.invalidLength(expected: 96, actual: bytes.count)
      }
      var p = blst_p1_affine()
      try bytes.withUnsafeBufferPointer {
        try BLSError.throwIfNeeded(blst_p1_deserialize(&p, $0.baseAddress!))
      }
      if subgroupCheck && !blst_p1_affine_in_g1(&p) { throw BLSError.pointNotInGroup }
      self.affine = p
    }
    public var compressedBytes: [UInt8] {
      var a = affine
      var out = [UInt8](repeating: 0, count: 48)
      out.withUnsafeMutableBufferPointer { blst_p1_affine_compress($0.baseAddress!, &a) }
      return out
    }
    public var uncompressedBytes: [UInt8] {
      var a = affine
      var out = [UInt8](repeating: 0, count: 96)
      out.withUnsafeMutableBufferPointer { blst_p1_affine_serialize($0.baseAddress!, &a) }
      return out
    }
    public static func aggregate(_ signatures: [SignatureG1]) throws -> SignatureG1 {
      guard let first = signatures.first else { throw BLSError.emptyAggregate }
      var firstAffine = first.affine
      var acc = blst_p1()
      blst_p1_from_affine(&acc, &firstAffine)
      for sig in signatures.dropFirst() {
        var sigAffine = sig.affine
        var current = acc
        blst_p1_add_or_double_affine(&acc, &current, &sigAffine)
      }
      var affine = blst_p1_affine()
      blst_p1_to_affine(&affine, &acc)
      return SignatureG1(affine: affine)
    }
    public static func == (lhs: SignatureG1, rhs: SignatureG1) -> Bool {
      lhs.compressedBytes == rhs.compressedBytes
    }
  }

  public enum AggregateVerification {
    public static func fastAggregateVerifyMinPK(
      publicKeys: [PublicKeyG1], signature: SignatureG2, message: [UInt8],
      domainSeparationTag dst: String = BLSScheme.basic, mode: HashMode = .hashToCurve
    ) throws -> Bool {
      let aggregatePK = try PublicKeyG1.aggregate(publicKeys)
      return aggregatePK.verify(
        signature: signature, message: message, domainSeparationTag: dst, mode: mode)
    }

    public static func fastAggregateVerifyMinSig(
      publicKeys: [PublicKeyG2], signature: SignatureG1, message: [UInt8],
      domainSeparationTag dst: String = BLSScheme.minSigBasic, mode: HashMode = .hashToCurve
    ) throws -> Bool {
      let aggregatePK = try PublicKeyG2.aggregate(publicKeys)
      return aggregatePK.verify(
        signature: signature, message: message, domainSeparationTag: dst, mode: mode)
    }

    public static func verifyMinPK(
      publicKeys: [PublicKeyG1], signature: SignatureG2, messages: [[UInt8]],
      domainSeparationTag dst: String = BLSScheme.basic, mode: HashMode = .hashToCurve
    ) throws -> Bool {
      guard publicKeys.count == messages.count else {
        throw BLSError.invalidInput("public key count must equal message count")
      }
      guard !publicKeys.isEmpty else { throw BLSError.emptyAggregate }
      let dstBytes = dst.utf8Bytes
      let size = blst_pairing_sizeof()
      let raw = UnsafeMutableRawPointer.allocate(
        byteCount: size, alignment: MemoryLayout<UInt64>.alignment)
      defer { raw.deallocate() }
      let ctx = OpaquePointer(raw)
      dstBytes.withUnsafeBufferPointer {
        blst_pairing_init(ctx, mode.cBool, $0.baseAddress, $0.count)
      }
      var aggregateSignature = signature.affine
      for i in publicKeys.indices {
        var pk = publicKeys[i].affine
        try messages[i].withUnsafeBufferPointer { msg in
          if i == 0 {
            try BLSError.throwIfNeeded(
              blst_pairing_chk_n_aggr_pk_in_g1(
                ctx, &pk, true, &aggregateSignature, true, msg.baseAddress, msg.count, nil, 0))
          } else {
            try BLSError.throwIfNeeded(
              blst_pairing_chk_n_aggr_pk_in_g1(
                ctx, &pk, true, nil, true, msg.baseAddress, msg.count, nil, 0))
          }
        }
      }
      blst_pairing_commit(ctx)
      return blst_pairing_finalverify(ctx, nil)
    }

    public static func verifyMinSig(
      publicKeys: [PublicKeyG2], signature: SignatureG1, messages: [[UInt8]],
      domainSeparationTag dst: String = BLSScheme.minSigBasic, mode: HashMode = .hashToCurve
    ) throws -> Bool {
      guard publicKeys.count == messages.count else {
        throw BLSError.invalidInput("public key count must equal message count")
      }
      guard !publicKeys.isEmpty else { throw BLSError.emptyAggregate }
      let dstBytes = dst.utf8Bytes
      let size = blst_pairing_sizeof()
      let raw = UnsafeMutableRawPointer.allocate(
        byteCount: size, alignment: MemoryLayout<UInt64>.alignment)
      defer { raw.deallocate() }
      let ctx = OpaquePointer(raw)
      dstBytes.withUnsafeBufferPointer {
        blst_pairing_init(ctx, mode.cBool, $0.baseAddress, $0.count)
      }
      var aggregateSignature = signature.affine
      for i in publicKeys.indices {
        var pk = publicKeys[i].affine
        try messages[i].withUnsafeBufferPointer { msg in
          if i == 0 {
            try BLSError.throwIfNeeded(
              blst_pairing_chk_n_aggr_pk_in_g2(
                ctx, &pk, true, &aggregateSignature, true, msg.baseAddress, msg.count, nil, 0))
          } else {
            try BLSError.throwIfNeeded(
              blst_pairing_chk_n_aggr_pk_in_g2(
                ctx, &pk, true, nil, true, msg.baseAddress, msg.count, nil, 0))
          }
        }
      }
      blst_pairing_commit(ctx)
      return blst_pairing_finalverify(ctx, nil)
    }
  }
}
