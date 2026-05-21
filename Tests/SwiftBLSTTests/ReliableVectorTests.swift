import XCTest

@testable import SwiftBLST

final class ReliableVectorTests: XCTestCase {
  // Ethereum consensus-spec-tests, tests/general/altair/bls.
  // These vectors exercise the Eth2 BLS proof-of-possession ciphersuite in minimal-pubkey mode.
  func testEthereumConsensusFastAggregateVerifyVectors() throws {
    struct Vector {
      let name: String
      let pubkeys: [String]
      let message: String
      let signature: String
      let expected: Bool
    }

    let vectors = [
      Vector(
        name: "valid_0",
        pubkeys: [
          "0xa491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a"
        ],
        message: "0x0000000000000000000000000000000000000000000000000000000000000000",
        signature:
          "0xb6ed936746e01f8ecf281f020953fbf1f01debd5657c4a383940b020b26507f6076334f91e2366c96e9ab279fb5158090352ea1c5b0c9274504f4f0e7053af24802e51e4568d164fe986834f41e55c8e850ce1f98458c0cfc9ab380b55285a55",
        expected: true
      ),
      Vector(
        name: "valid_1",
        pubkeys: [
          "0xa491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a",
          "0xb301803f8b5ac4a1133581fc676dfedc60d891dd5fa99028805e5ea5b08d3491af75d0707adab3b70c6a6a580217bf81",
        ],
        message: "0x5656565656565656565656565656565656565656565656565656565656565656",
        signature:
          "0x912c3615f69575407db9392eb21fee18fff797eeb2fbe1816366ca2a08ae574d8824dbfafb4c9eaa1cf61b63c6f9b69911f269b664c42947dd1b53ef1081926c1e82bb2a465f927124b08391a5249036146d6f3f1e17ff5f162f779746d830d1",
        expected: true
      ),
      Vector(
        name: "tampered_signature_0",
        pubkeys: [
          "0xa491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a"
        ],
        message: "0x0000000000000000000000000000000000000000000000000000000000000000",
        signature:
          "0xb6ed936746e01f8ecf281f020953fbf1f01debd5657c4a383940b020b26507f6076334f91e2366c96e9ab279fb5158090352ea1c5b0c9274504f4f0e7053af24802e51e4568d164fe986834f41e55c8e850ce1f98458c0cfc9ab380bffffffff",
        expected: false
      ),
    ]

    for vector in vectors {
      do {
        let pubkeys = try vector.pubkeys.map { try BLST.PublicKeyG1(compressed: Array(hex: $0)) }
        let signature = try BLST.SignatureG2(compressed: Array(hex: vector.signature))
        let message = Array(hex: vector.message)
        let actual = try BLST.AggregateVerification.fastAggregateVerifyMinPK(
          publicKeys: pubkeys,
          signature: signature,
          message: message,
          domainSeparationTag: BLST.BLSScheme.proofOfPossession
        )
        XCTAssertEqual(actual, vector.expected, vector.name)
      } catch {
        XCTAssertFalse(vector.expected, "\(vector.name) threw \(error)")
      }
    }
  }

  // Ethereum consensus-spec-tests, tests/general/altair/bls/eth_aggregate_pubkeys.
  func testEthereumConsensusAggregatePubkeyVector() throws {
    let pubkeys = try [
      "0xa491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a",
      "0xb301803f8b5ac4a1133581fc676dfedc60d891dd5fa99028805e5ea5b08d3491af75d0707adab3b70c6a6a580217bf81",
      "0xb53d21a4cfd562c469cc81514d4ce5a6b577d8403d32a394dc265dd190b47fa9f829fdd7963afdf972e5e77854051f6f",
    ].map { try BLST.PublicKeyG1(compressed: Array(hex: $0)) }

    let aggregate = try BLST.PublicKeyG1.aggregate(pubkeys)
    XCTAssertEqual(
      aggregate.compressedBytes.hexString,
      "a095608b35495ca05002b7b5966729dd1ed096568cf2ff24f3318468e0f3495361414a78ebc09574489bc79e48fca969"
    )
  }

  // cashubtc/nuts PR #371 tests/00-tests.md: BLS12-381 (v3) round-trip.
  // These are the canonical Cashu pairing-based BDHKE vectors, cross-checked by
  // cashubtc/cashu-ts PR #661 and cashubtc/nutshell PR #999.
  // Cashu v3 uses G1 points for Y/B_/C_/C and G2 mint public keys.
  func testCashuNUT00BLSV3DeterministicVectors() throws {
    let cashuDST = BLST.BLSScheme.cashu
    XCTAssertEqual(cashuDST, "CASHU_BLS12_381_G1_XMD:SHA-256_SSWU_RO_")
    let secret = Array("test_message".utf8)
    let blindingFactor = try BLST.SecretKey(
      bytes: Array(hex: "0000000000000000000000000000000000000000000000000000000000000003"))
    let mintSecretKey = try BLST.SecretKey(
      bytes: Array(hex: "0000000000000000000000000000000000000000000000000000000000000002"))

    let expectedBaseG2 = try BLST.PublicKeyG2(
      compressed: Array(
        hex:
          "93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8"
      ))
    let expectedMintPublicKey = try BLST.PublicKeyG2(
      compressed: Array(
        hex:
          "aa4edef9c1ed7f729f520e47730a124fd70662a904ba1074728114d1031e1572c6c886f6b57ec72a6178288c47c335771638533957d540a9d2370f17cc7ed5863bc0b995b8825e0ee1ea1e1e4d00dbae81f14b0bf3611b78c952aacab827a053"
      ))

    XCTAssertEqual(
      try BLST.SecretKey(
        bytes: Array(hex: "0000000000000000000000000000000000000000000000000000000000000001")
      ).publicKeyG2(),
      expectedBaseG2
    )
    XCTAssertEqual(mintSecretKey.publicKeyG2(), expectedMintPublicKey)

    let y = BLST.SignatureG1.hashToCurve(message: secret, domainSeparationTag: cashuDST)
    let blindedMessage = y.multiplied(by: blindingFactor)
    XCTAssertEqual(
      blindedMessage.compressedBytes.hexString,
      "8e88c5f6a93f653784a66b033a00e52128499e18b095c2a56f080d1c2a937ffc9ef4600804a48d087bbd1f662f6b068f"
    )

    let blindedSignature = blindedMessage.multiplied(by: mintSecretKey)
    XCTAssertEqual(
      blindedSignature.compressedBytes.hexString,
      "8d52d7a6cbe5e99858d5c15c092d11a0c387c78917471211082a6e5afc2a79680dfa188fafe5d4a51c5398ce160e7a16"
    )

    let unblindedSignature = mintSecretKey.signG1(
      message: secret,
      domainSeparationTag: cashuDST
    )
    XCTAssertEqual(
      unblindedSignature.compressedBytes.hexString,
      "b7a4881059133fd91a8753600d9a5e524c65d6224f6fe2d5aef9e59f1507fdad90b3b4d48ee46da5c8dfaa0b88e28b69"
    )
    XCTAssertTrue(
      expectedMintPublicKey.verify(
        signature: unblindedSignature,
        message: secret,
        domainSeparationTag: cashuDST
      )
    )
  }
}

extension Array where Element == UInt8 {
  init(hex: String) {
    var cleaned = hex
    if cleaned.hasPrefix("0x") { cleaned.removeFirst(2) }
    precondition(cleaned.count.isMultiple(of: 2), "hex string must contain full bytes")

    self = stride(from: 0, to: cleaned.count, by: 2).map { offset in
      let start = cleaned.index(cleaned.startIndex, offsetBy: offset)
      let end = cleaned.index(start, offsetBy: 2)
      return UInt8(cleaned[start..<end], radix: 16)!
    }
  }

  var hexString: String {
    map { String(format: "%02x", $0) }.joined()
  }
}
