import XCTest

@testable import SwiftBLST

final class SwiftBLSTTests: XCTestCase {
  func testMinPKSignVerifyAndSerializationRoundTrip() throws {
    let sk = try SecretKey(inputKeyMaterial: Array(repeating: 42, count: 32))
    let pk = sk.publicKeyG1()
    let message = Array("hello bls".utf8)
    let sig = sk.signG2(message: message)

    XCTAssertTrue(pk.verify(signature: sig, message: message))
    XCTAssertFalse(pk.verify(signature: sig, message: Array("wrong".utf8)))

    let pk2 = try PublicKeyG1(compressed: pk.compressedBytes)
    let sig2 = try SignatureG2(compressed: sig.compressedBytes)
    XCTAssertEqual(pk, pk2)
    XCTAssertEqual(sig, sig2)
    XCTAssertEqual(pk.uncompressedBytes.count, 96)
    XCTAssertEqual(sig.uncompressedBytes.count, 192)
  }

  func testMinSigSignVerifyAndSerializationRoundTrip() throws {
    let sk = try SecretKey(inputKeyMaterial: Array(repeating: 7, count: 32))
    let pk = sk.publicKeyG2()
    let message = Array("minimal signature variant".utf8)
    let sig = sk.signG1(message: message)

    XCTAssertTrue(pk.verify(signature: sig, message: message))
    XCTAssertFalse(pk.verify(signature: sig, message: Array("wrong".utf8)))

    XCTAssertEqual(try PublicKeyG2(compressed: pk.compressedBytes), pk)
    XCTAssertEqual(try SignatureG1(compressed: sig.compressedBytes), sig)
    XCTAssertEqual(pk.uncompressedBytes.count, 192)
    XCTAssertEqual(sig.uncompressedBytes.count, 96)
  }

  func testAggregateVerifyMinPKDistinctMessages() throws {
    let sk1 = try SecretKey(inputKeyMaterial: Array(repeating: 1, count: 32))
    let sk2 = try SecretKey(inputKeyMaterial: Array(repeating: 2, count: 32))
    let messages = [Array("message one".utf8), Array("message two".utf8)]
    let pks = [sk1.publicKeyG1(), sk2.publicKeyG1()]
    let aggregate = try SignatureG2.aggregate([
      sk1.signG2(message: messages[0]),
      sk2.signG2(message: messages[1]),
    ])
    XCTAssertTrue(
      try AggregateVerification.verifyMinPK(
        publicKeys: pks, signature: aggregate, messages: messages))
    XCTAssertFalse(
      try AggregateVerification.verifyMinPK(
        publicKeys: pks, signature: aggregate, messages: [messages[0], Array("tampered".utf8)]))
  }

  func testProofOfPossessionAndFastAggregateMinPK() throws {
    let sk1 = try SecretKey(inputKeyMaterial: Array(repeating: 5, count: 32))
    let sk2 = try SecretKey(inputKeyMaterial: Array(repeating: 6, count: 32))
    let message = Array("same message".utf8)
    let pks = [sk1.publicKeyG1(), sk2.publicKeyG1()]
    XCTAssertTrue(pks[0].verifyProofOfPossession(sk1.proofOfPossessionG2()))
    XCTAssertTrue(pks[1].verifyProofOfPossession(sk2.proofOfPossessionG2()))
    let aggregate = try SignatureG2.aggregate([
      sk1.signG2(message: message), sk2.signG2(message: message),
    ])
    XCTAssertTrue(
      try AggregateVerification.fastAggregateVerifyMinPK(
        publicKeys: pks, signature: aggregate, message: message))
  }

  func testAggregateVerifyMinSigDistinctMessages() throws {
    let sk1 = try SecretKey(inputKeyMaterial: Array(repeating: 3, count: 32))
    let sk2 = try SecretKey(inputKeyMaterial: Array(repeating: 4, count: 32))
    let messages = [Array("alpha".utf8), Array("beta".utf8)]
    let pks = [sk1.publicKeyG2(), sk2.publicKeyG2()]
    let aggregate = try SignatureG1.aggregate([
      sk1.signG1(message: messages[0]),
      sk2.signG1(message: messages[1]),
    ])
    XCTAssertTrue(
      try AggregateVerification.verifyMinSig(
        publicKeys: pks, signature: aggregate, messages: messages))
    XCTAssertFalse(
      try AggregateVerification.verifyMinSig(
        publicKeys: pks, signature: aggregate, messages: [messages[0], Array("tampered".utf8)]))
  }

  func testProofOfPossessionAndFastAggregateMinSig() throws {
    let sk1 = try SecretKey(inputKeyMaterial: Array(repeating: 8, count: 32))
    let sk2 = try SecretKey(inputKeyMaterial: Array(repeating: 9, count: 32))
    let message = Array("same min sig message".utf8)
    let pks = [sk1.publicKeyG2(), sk2.publicKeyG2()]
    XCTAssertTrue(pks[0].verifyProofOfPossession(sk1.proofOfPossessionG1()))
    XCTAssertTrue(pks[1].verifyProofOfPossession(sk2.proofOfPossessionG1()))
    let aggregate = try SignatureG1.aggregate([
      sk1.signG1(message: message), sk2.signG1(message: message),
    ])
    XCTAssertTrue(
      try AggregateVerification.fastAggregateVerifyMinSig(
        publicKeys: pks, signature: aggregate, message: message))
  }

  func testInvalidInputsThrow() throws {
    XCTAssertThrowsError(try SecretKey(inputKeyMaterial: Array(repeating: 1, count: 31)))
    XCTAssertThrowsError(try PublicKeyG1(compressed: []))
    XCTAssertThrowsError(try SignatureG2.aggregate([]))
  }
}
