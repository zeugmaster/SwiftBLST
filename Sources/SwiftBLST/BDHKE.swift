import Cblst

//
//  BDHKE.swift
//
//  Low-level BLS12-381 primitives needed for pairing-based blind Diffie–Hellman key
//  exchange (e.g. Cashu v3 keysets), beyond the IETF signature operations in
//  SwiftBLST.swift. Everything here is protocol-agnostic: callers pass their own
//  domain-separation tag and scalars.
//
//  Point/scalar vocabulary:
//    - `BLST.G1Point` (= `SignatureG1`): a G1 point — blinded message `B_`, signature
//      `C_`/`C`, or hashed secret `Y = hashToCurve(secret)`.
//    - `BLST.G2Point` (= `PublicKeyG2`): a G2 point — the mint public key `K = a·G2`.
//    - `BLST.Scalar` (= `SecretKey`): a non-zero Fr scalar — blinding factor `r`,
//      batch weight, or mint scalar `a`.
//

extension BLST {
  /// Semantic alias: a G1 point used as a blinded message / signature / hashed secret.
  public typealias G1Point = SignatureG1
  /// Semantic alias: a G2 point used as a mint public key.
  public typealias G2Point = PublicKeyG2
  /// Semantic alias: a non-zero Fr scalar (blinding factor, weight, or mint scalar).
  public typealias Scalar = SecretKey
}

extension BLST.SecretKey {
  /// Wraps a raw, already-validated scalar without re-running `blst_sk_check`.
  init(uncheckedScalar scalar: blst_scalar) { self.scalar = scalar }

  /// The multiplicative inverse `self⁻¹ mod r` in the BLS12-381 scalar field.
  ///
  /// Used for multiplicative unblinding `C = C_ · r⁻¹`. `self` is a valid (non-zero,
  /// in-range) scalar by construction, so the inverse always exists.
  public func inverse() -> BLST.SecretKey {
    var out = blst_scalar()
    var s = scalar
    blst_sk_inverse(&out, &s)
    return BLST.SecretKey(uncheckedScalar: out)
  }
}

extension BLST.SignatureG1 {
  /// Whether this G1 point is the identity (point at infinity). Never valid as a Cashu
  /// blinded message, signature, or hashed secret.
  public var isInfinity: Bool {
    var a = affine
    return blst_p1_affine_is_inf(&a)
  }

  /// The negation `-self` (additive inverse of this G1 point).
  ///
  /// Used to fold a pairing equality `e(A, ·) == e(B, ·)` into the product form
  /// `e(-A, ·) · e(B, ·) == 1` evaluated by ``BLST/Pairing/productIsOne(_:)``.
  public func negated() -> BLST.SignatureG1 {
    var p = blst_p1()
    var a = affine
    blst_p1_from_affine(&p, &a)
    blst_p1_cneg(&p, true)
    var outAffine = blst_p1_affine()
    blst_p1_to_affine(&outAffine, &p)
    return BLST.SignatureG1(affine: outAffine)
  }
}

extension BLST.PublicKeyG2 {
  /// The canonical G2 generator (base point), i.e. the `G2` in `K = a·G2`.
  public static var generator: BLST.PublicKeyG2 {
    var affine = blst_p2_affine()
    blst_p2_to_affine(&affine, blst_p2_generator())
    return BLST.PublicKeyG2(affine: affine)
  }
}

extension BLST {
  /// Pairing checks over BLS12-381.
  public enum Pairing {
    /// Returns `true` iff `∏ᵢ e(g1ᵢ, g2ᵢ) == 1` in the target group `GT`.
    ///
    /// Accumulates one Miller loop per pair and applies a **single** final
    /// exponentiation, which is materially cheaper than evaluating each pairing
    /// independently (final exp dominates the cost of a BLS12-381 pairing).
    ///
    /// To verify a pairing equality `e(A, P) == e(B, Q)`, negate one G1 input and pass
    /// `[(A.negated(), P), (B, Q)]`. An empty list trivially returns `true`.
    public static func productIsOne(_ pairs: [(g1: SignatureG1, g2: PublicKeyG2)]) -> Bool {
      guard !pairs.isEmpty else { return true }
      var acc = blst_fp12()
      for (i, pair) in pairs.enumerated() {
        var q = pair.g2.affine
        var p = pair.g1.affine
        var ml = blst_fp12()
        blst_miller_loop(&ml, &q, &p)
        if i == 0 {
          acc = ml
        } else {
          var current = acc
          blst_fp12_mul(&acc, &current, &ml)
        }
      }
      var result = blst_fp12()
      blst_final_exp(&result, &acc)
      return blst_fp12_is_one(&result)
    }
  }
}
