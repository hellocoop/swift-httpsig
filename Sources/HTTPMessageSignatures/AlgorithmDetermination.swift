import Foundation

/// Determines the signature algorithm for a JWK.
///
/// Per draft-hardt-httpbis-signature-key-08, the algorithm is taken from the
/// JWK `alg` member, which must be a fully-specified identifier (RFC 9864). It
/// is not derived from `kty` and `crv`, which underdetermine it for RSA keys
/// -- no curve, and both padding and hash free -- and for the `AKP` key type.
///
/// This release still accepts a JWK with no `alg` and derives the algorithm
/// from `kty` and `crv`, which is unambiguous for the OKP and EC keys this
/// library supports. That leniency exists so a 1.2 verifier keeps accepting
/// signers that have not been updated yet; a future major version will require
/// the member.
public enum AlgorithmDetermination {
    public enum Error: Swift.Error, Equatable {
        /// The `alg` names a different algorithm depending on the key it is
        /// used with. Deprecated by RFC 9864.
        case polymorphicAlgorithm(String)
        /// The `alg` is not one this library implements.
        case unsupportedAlgorithm(String)
        /// The `alg` disagrees with `kty` or `crv`.
        case inconsistentKey(alg: String, detail: String)
        /// Neither `alg` nor a recognized `kty`/`crv` pair was present.
        case undeterminedAlgorithm(kty: String, crv: String)
        /// A shared secret cannot prove possession to a verifier holding it.
        case symmetricAlgorithm(String)
    }

    /// Fully-specified identifiers this library implements, and the key
    /// structure each requires.
    static let supported: [String: (kty: String, crv: String)] = [
        "Ed25519": (kty: "OKP", crv: "Ed25519"),
        "ES256": (kty: "EC", crv: "P-256"),
        "ES384": (kty: "EC", crv: "P-384"),
        "ES512": (kty: "EC", crv: "P-521"),
    ]

    /// Identifiers that do not fully specify the operation.
    static let polymorphic: Set<String> = ["EdDSA"]

    /// Shared-secret algorithms. Every scheme here distributes a public key.
    static let symmetric: Set<String> = ["HS256", "HS384", "HS512", "none"]

    /// The algorithm implied by a key's structure, where that is unambiguous.
    ///
    /// Unambiguous for OKP and EC because no registered JOSE signing algorithm
    /// pairs a curve with another hash.
    static func derived(kty: String, crv: String) -> String? {
        supported.first { $0.value.kty == kty && $0.value.crv == crv }?.key
    }

    /// Determine the algorithm for a JWK, validating it in the process.
    ///
    /// - Returns: a fully-specified JOSE algorithm identifier.
    public static func determine(_ jwk: JWKParameters) throws -> String {
        guard let alg = jwk.alg, !alg.isEmpty else {
            // No alg: derive it, which this library can do unambiguously for
            // the key types it supports.
            guard let derivedAlg = derived(kty: jwk.kty, crv: jwk.crv) else {
                throw Error.undeterminedAlgorithm(kty: jwk.kty, crv: jwk.crv)
            }
            return derivedAlg
        }

        if symmetric.contains(alg) {
            throw Error.symmetricAlgorithm(alg)
        }

        if polymorphic.contains(alg) {
            throw Error.polymorphicAlgorithm(alg)
        }

        guard let spec = supported[alg] else {
            throw Error.unsupportedAlgorithm(alg)
        }

        // The key-structure members are redundant with a fully-specified alg.
        // Use the redundancy as a check: a key readable two ways is rejected
        // rather than resolved in favour of either reading.
        guard jwk.kty == spec.kty else {
            throw Error.inconsistentKey(
                alg: alg,
                detail: "kty \"\(jwk.kty)\" but \(alg) requires \"\(spec.kty)\""
            )
        }
        guard jwk.crv == spec.crv else {
            throw Error.inconsistentKey(
                alg: alg,
                detail: "crv \"\(jwk.crv)\" but \(alg) requires \"\(spec.crv)\""
            )
        }

        return alg
    }
}
