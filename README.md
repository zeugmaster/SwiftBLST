# SwiftBLST

SwiftBLST is a Swift Package Manager wrapper around Supranational's [`blst`](https://github.com/supranational/blst), a high-performance BLS12-381 signature library written in C and assembly.

This package vendors `blst` and exposes:

- `SwiftBLST`: ergonomic Swift value types for common BLS signature operations.
- `Cblst`: the raw C `blst` module for complete low-level access to field, curve, pairing, hash-to-curve, serialization, and aggregate primitives.

## What was researched

BLS signatures over BLS12-381 use two pairing-friendly groups, G1 and G2. The common IETF variants are:

- **Minimal public key size / PK in G1**: public keys are G1 points, signatures are G2 points. Compressed public key: 48 bytes. Compressed signature: 96 bytes.
- **Minimal signature size / PK in G2**: public keys are G2 points, signatures are G1 points. Compressed public key: 96 bytes. Compressed signature: 48 bytes.

`blst` follows the IETF BLS signature draft and RFC 9380 hash-to-curve conventions. Signing is performed by hashing/encoding a message to the opposite group and multiplying by the secret key. Verification is a pairing check. For aggregate verification, public keys should be subgroup-checked; the Swift API does this when decoding and uses `blst_pairing_chk_n_aggr_*` for aggregate verification.

## Installation

Add this package to `Package.swift`:

```swift
.package(url: "https://github.com/zeugmaster/SwiftBLST.git", from: "0.1.0")
```

Then depend on the Swift target:

```swift
.product(name: "SwiftBLST", package: "SwiftBLST")
```

For raw C APIs, depend on `Cblst` too.

## Usage

### Minimal public key variant (PK in G1, signature in G2)

```swift
import SwiftBLST

let ikm = Array(repeating: UInt8(42), count: 32)
let secretKey = try SecretKey(inputKeyMaterial: ikm)
let publicKey = secretKey.publicKeyG1()
let message = Array("hello bls".utf8)

let signature = secretKey.signG2(message: message)
let ok = publicKey.verify(signature: signature, message: message)
```

### Minimal signature variant (PK in G2, signature in G1)

```swift
let secretKey = try SecretKey(inputKeyMaterial: Array(repeating: UInt8(7), count: 32))
let publicKey = secretKey.publicKeyG2()
let message = Array("minimal signature".utf8)

let signature = secretKey.signG1(message: message)
let ok = publicKey.verify(signature: signature, message: message)
```

### Serialization

```swift
let compressedPK = publicKey.compressedBytes
let decodedPK = try PublicKeyG1(compressed: compressedPK)

let compressedSignature = signature.compressedBytes
let decodedSignature = try SignatureG2(compressed: compressedSignature)
```

### Aggregate verification for distinct messages

```swift
let sk1 = try SecretKey(inputKeyMaterial: Array(repeating: UInt8(1), count: 32))
let sk2 = try SecretKey(inputKeyMaterial: Array(repeating: UInt8(2), count: 32))
let messages = [Array("one".utf8), Array("two".utf8)]

let aggregate = try SignatureG2.aggregate([
    sk1.signG2(message: messages[0]),
    sk2.signG2(message: messages[1])
])

let ok = try AggregateVerification.verifyMinPK(
    publicKeys: [sk1.publicKeyG1(), sk2.publicKeyG1()],
    signature: aggregate,
    messages: messages
)
```

### Fast aggregate verification for same message

Use proof of possession in real protocols before accepting keys for same-message fast aggregate verification.

```swift
let proof = sk1.proofOfPossessionG2()
let proofOK = sk1.publicKeyG1().verifyProofOfPossession(proof)

let sameMessage = Array("same message".utf8)
let aggregate = try SignatureG2.aggregate([
    sk1.signG2(message: sameMessage),
    sk2.signG2(message: sameMessage)
])

let ok = try AggregateVerification.fastAggregateVerifyMinPK(
    publicKeys: [sk1.publicKeyG1(), sk2.publicKeyG1()],
    signature: aggregate,
    message: sameMessage
)
```

## API surface

SwiftBLST provides high-level wrappers for:

- `SecretKey`
  - key generation from IKM via `blst_keygen`
  - serialization/deserialization of 32-byte scalar secret keys
  - public key derivation in G1 or G2
  - signing in G1 or G2
  - proof-of-possession generation
- `PublicKeyG1` / `PublicKeyG2`
  - compressed and uncompressed decoding/encoding
  - subgroup checks
  - individual verification
  - proof-of-possession verification
  - public key aggregation
- `SignatureG1` / `SignatureG2`
  - compressed and uncompressed decoding/encoding
  - signature aggregation
- `AggregateVerification`
  - aggregate verification for distinct messages
  - fast aggregate verification for one shared message
- `Cblst`
  - complete raw `blst.h`/`blst_aux.h` access for advanced field, curve, pairing, hash-to-curve, and multi-scalar APIs.

## Security notes

- Use at least 32 bytes of input key material for `SecretKey(inputKeyMaterial:)`.
- Domain separation tags matter. Defaults are provided for the common IETF ciphersuite strings, but protocols should specify their own exact DSTs.
- Decode public keys/signatures with subgroup checks enabled unless you have already cached and authenticated subgroup-check results.
- Use proof of possession for same-message fast aggregate verification to avoid rogue-key attacks.
- This package does not provide random number generation; generate IKM with a cryptographically secure RNG in your application.

## Test vectors

The XCTest suite includes deterministic vectors from:

- Ethereum `consensus-spec-tests` under `tests/general/altair/bls`, covering minimal-pubkey aggregate public keys and fast aggregate verification with the proof-of-possession DST.
- Draft Cashu BLS v3 work in `cashubtc/nutshell` PR #999 (`feature/bls12-381-v3-keyset`), mapped to minimal-signature mode with the custom `CASHU_BLS12_381_G1_XMD:SHA-256_SSWU_RO_` DST.

## Development

```bash
swift test
swift build -c release
```

Verified on Linux with Swift 6.3.2.

## License

The vendored `blst` code is Apache-2.0; see `LICENSE.blst`.
