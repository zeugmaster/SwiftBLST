import XCTest

@testable import SwiftBLST

/// Validates the BDHKE primitives (`BDHKE.swift`) against the NUT-00 "BLS12-381 (v3)
/// round-trip" vector from Nutshell PR #999 (`cashu/core/crypto/bls_dhke.py`,
/// `tests/test_crypto.py::test_deterministic_bls_steps`).
final class CashuBDHKETests: XCTestCase {
  // secret = "test_message", r = 3, mint scalar a = 2, K = a·G2.
  private let secret = Array("test_message".utf8)
  private let yHex =
    "860d58e5aeda1376185436ed96412313424cc079e056d1dab595e6db4c2c9685fec7da052c8db68d88985b75a42388ad"
  private let bHex =
    "8e88c5f6a93f653784a66b033a00e52128499e18b095c2a56f080d1c2a937ffc9ef4600804a48d087bbd1f662f6b068f"
  private let kHex =
    "aa4edef9c1ed7f729f520e47730a124fd70662a904ba1074728114d1031e1572c6c886f6b57ec72a6178288c47c335771638533957d540a9d2370f17cc7ed5863bc0b995b8825e0ee1ea1e1e4d00dbae81f14b0bf3611b78c952aacab827a053"
  private let cBlindHex =
    "8d52d7a6cbe5e99858d5c15c092d11a0c387c78917471211082a6e5afc2a79680dfa188fafe5d4a51c5398ce160e7a16"
  private let cHex =
    "b7a4881059133fd91a8753600d9a5e524c65d6224f6fe2d5aef9e59f1507fdad90b3b4d48ee46da5c8dfaa0b88e28b69"
  private let g2GeneratorHex =
    "93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8"

  private func hex(_ bytes: [UInt8]) -> String {
    bytes.map { String(format: "%02x", $0) }.joined()
  }

  /// 32-byte big-endian scalar from a small integer.
  private func scalar(_ n: UInt8) throws -> BLST.Scalar {
    var bytes = [UInt8](repeating: 0, count: 32)
    bytes[31] = n
    return try BLST.Scalar(bytes: bytes)
  }

  func testG2GeneratorMatchesVector() {
    XCTAssertEqual(hex(BLST.G2Point.generator.compressedBytes), g2GeneratorHex)
  }

  func testRoundTripMatchesNutVector() throws {
    let dst = BLST.BLSScheme.cashu

    // Y = hashToCurveG1(secret)
    let Y = BLST.G1Point.hashToCurve(message: secret, domainSeparationTag: dst)
    XCTAssertEqual(hex(Y.compressedBytes), yHex)

    // B_ = r·Y  (wallet blinds, r = 3)
    let r = try scalar(3)
    let B_ = Y.multiplied(by: r)
    XCTAssertEqual(hex(B_.compressedBytes), bHex)

    // K = a·G2  (mint pubkey, a = 2)
    let a = try scalar(2)
    let K2 = a.publicKeyG2()
    XCTAssertEqual(hex(K2.compressedBytes), kHex)

    // C_ = a·B_  (mint blind-signs)
    let C_ = B_.multiplied(by: a)
    XCTAssertEqual(hex(C_.compressedBytes), cBlindHex)

    // C = r⁻¹·C_  (wallet unblinds)
    let C = C_.multiplied(by: r.inverse())
    XCTAssertEqual(hex(C.compressedBytes), cHex)

    // Pairing equality: e(C, G2) == e(Y, K) ⇔ e(-C, G2)·e(Y, K) == 1
    XCTAssertTrue(BLST.Pairing.productIsOne([(C.negated(), .generator), (Y, K2)]))
  }

  func testPairingRejectsWrongSecret() throws {
    let dst = BLST.BLSScheme.cashu
    let Y = BLST.G1Point.hashToCurve(message: secret, domainSeparationTag: dst)
    let r = try scalar(3)
    let a = try scalar(2)
    let C = Y.multiplied(by: r).multiplied(by: a).multiplied(by: r.inverse())
    let K2 = a.publicKeyG2()

    let wrongY = BLST.G1Point.hashToCurve(message: Array("other".utf8), domainSeparationTag: dst)
    XCTAssertFalse(BLST.Pairing.productIsOne([(C.negated(), .generator), (wrongY, K2)]))
  }

  func testScalarInverseRoundTrips() throws {
    // (P · r) · r⁻¹ == P
    let P = BLST.G1Point.hashToCurve(message: secret, domainSeparationTag: BLST.BLSScheme.cashu)
    let r = try scalar(7)
    XCTAssertEqual(P.multiplied(by: r).multiplied(by: r.inverse()), P)
  }
}
