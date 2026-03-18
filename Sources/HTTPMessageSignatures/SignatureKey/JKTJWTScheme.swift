import Foundation
import CryptoKit

/// JKT-JWT scheme for Signature-Key.
///
/// Provides self-issued key delegation using a JWT whose signing key is
/// embedded in the JWT header. This enables devices with hardware-backed
/// secure enclaves to delegate signing authority to ephemeral keys.
///
///     sig=jkt-jwt;jwt="eyJ..."
///
/// Unlike the `jwt` scheme, the jkt-jwt scheme is fully verified by this library:
/// JWT signature, `iss` thumbprint, and `exp`/`iat` claims are all validated.
public struct JKTJWTScheme: Equatable, Sendable {
    /// The raw JWT string.
    public let jwt: String

    public init(jwt: String) {
        self.jwt = jwt
    }

    /// Parse jkt-jwt parameters.
    ///
    /// Input example: `jwt="eyJ..."`
    static func parse(params: String) throws -> JKTJWTScheme {
        let dict = parseStructuredParams(params)
        guard let jwt = dict["jwt"] else {
            throw SignatureKeyError.missingParameter("jwt")
        }
        return JKTJWTScheme(jwt: jwt)
    }

    /// Serialize to the Signature-Key header value (after the label=).
    func serialize() -> String {
        return "jkt-jwt;jwt=\"\(jwt)\""
    }

    /// Supported JWT `typ` values and their corresponding hash algorithms.
    private static let typMapping: [String: (hashAlgorithm: JWKThumbprint.HashAlgorithm, issPrefix: String)] = [
        "jkt-s256+jwt": (hashAlgorithm: .sha256, issPrefix: "urn:jkt:sha-256:"),
        "jkt-s512+jwt": (hashAlgorithm: .sha512, issPrefix: "urn:jkt:sha-512:"),
    ]

    /// The result of verifying a jkt-jwt JWT.
    public struct VerificationResult: Equatable {
        /// The ephemeral public key from `cnf.jwk` (used for HTTP signature verification).
        public let ephemeralKey: JWKParameters
        /// The identity/enclave public key from the JWT header `jwk`.
        public let identityKey: JWKParameters
        /// The identity thumbprint URI (e.g., `urn:jkt:sha-256:...`).
        public let identityThumbprint: String
        /// The decoded JWT header.
        public let header: [String: Any]
        /// The decoded JWT payload.
        public let payload: [String: Any]

        public static func == (lhs: VerificationResult, rhs: VerificationResult) -> Bool {
            return lhs.ephemeralKey == rhs.ephemeralKey
                && lhs.identityKey == rhs.identityKey
                && lhs.identityThumbprint == rhs.identityThumbprint
        }
    }

    /// Verify the jkt-jwt and extract the ephemeral key.
    ///
    /// Performs full verification per the jkt-jwt specification:
    /// 1. Parse JWT header and payload
    /// 2. Validate `typ` (must be `jkt-s256+jwt` or `jkt-s512+jwt`)
    /// 3. Extract identity key from JWT header `jwk`
    /// 4. Compute thumbprint and verify `iss` matches
    /// 5. Verify JWT signature using identity key
    /// 6. Validate `exp` and `iat`
    /// 7. Extract ephemeral key from `cnf.jwk`
    ///
    /// - Parameter maxClockSkew: Maximum allowed clock skew in seconds (default: 60).
    /// - Returns: The verification result containing ephemeral and identity keys.
    public func verify(maxClockSkew: Int = 60) throws -> VerificationResult {
        let parts = jwt.split(separator: ".")
        guard parts.count == 3 else {
            throw SignatureKeyError.invalidJWT("expected 3 parts separated by '.'")
        }

        let headerPart = String(parts[0])
        let payloadPart = String(parts[1])
        let signaturePart = String(parts[2])

        // 1. Decode header
        guard let headerData = Base64URL.decode(headerPart),
              let header = try JSONSerialization.jsonObject(with: headerData) as? [String: Any] else {
            throw SignatureKeyError.invalidJWT("cannot decode header")
        }

        // 2. Check typ
        guard let typ = header["typ"] as? String else {
            throw SignatureKeyError.invalidJWT("missing 'typ' in header")
        }
        guard let typConfig = Self.typMapping[typ] else {
            throw SignatureKeyError.invalidJWT("unsupported typ: \(typ). Supported: \(Self.typMapping.keys.sorted().joined(separator: ", "))")
        }

        // 3. Extract identity key from header jwk
        guard let jwkDict = header["jwk"] as? [String: Any] else {
            throw SignatureKeyError.invalidJWT("missing 'jwk' in header")
        }
        let jwkData = try JSONSerialization.data(withJSONObject: jwkDict)
        let identityKey = try JSONDecoder().decode(JWKParameters.self, from: jwkData)

        // 4. Compute thumbprint and verify iss
        let thumbprint = try JWKThumbprint.compute(identityKey, algorithm: typConfig.hashAlgorithm)
        let expectedIss = "\(typConfig.issPrefix)\(thumbprint)"

        guard let payloadData = Base64URL.decode(payloadPart),
              let payload = try JSONSerialization.jsonObject(with: payloadData) as? [String: Any] else {
            throw SignatureKeyError.invalidJWT("cannot decode payload")
        }

        guard let iss = payload["iss"] as? String else {
            throw SignatureKeyError.invalidJWT("missing 'iss' claim")
        }
        guard iss == expectedIss else {
            throw SignatureKeyError.invalidJWT("iss mismatch: expected \(expectedIss), got \(iss)")
        }

        // 5. Verify JWT signature using identity key
        let signedData = Data("\(headerPart).\(payloadPart)".utf8)
        guard let signatureData = Base64URL.decode(signaturePart) else {
            throw SignatureKeyError.invalidJWT("cannot decode signature")
        }

        let signatureValid = try HTTPMessageVerifier.verifySignature(
            signatureData,
            base: signedData,
            jwk: identityKey
        )
        guard signatureValid else {
            throw SignatureKeyError.invalidJWT("JWT signature verification failed")
        }

        // 6. Validate exp and iat
        let now = Int(Date().timeIntervalSince1970)

        guard let exp = payload["exp"] as? Int else {
            throw SignatureKeyError.invalidJWT("missing 'exp' claim")
        }
        guard exp + maxClockSkew >= now else {
            throw SignatureKeyError.invalidJWT("JWT expired")
        }

        guard let iat = payload["iat"] as? Int else {
            throw SignatureKeyError.invalidJWT("missing 'iat' claim")
        }
        guard iat - maxClockSkew <= now else {
            throw SignatureKeyError.invalidJWT("JWT iat is in the future")
        }

        // 7. Extract ephemeral key from cnf.jwk
        guard let cnf = payload["cnf"] as? [String: Any] else {
            throw SignatureKeyError.invalidJWT("missing 'cnf' claim")
        }
        guard let cnfJwkDict = cnf["jwk"] as? [String: Any] else {
            throw SignatureKeyError.invalidJWT("missing 'cnf.jwk'")
        }
        let cnfJwkData = try JSONSerialization.data(withJSONObject: cnfJwkDict)
        let ephemeralKey = try JSONDecoder().decode(JWKParameters.self, from: cnfJwkData)

        return VerificationResult(
            ephemeralKey: ephemeralKey,
            identityKey: identityKey,
            identityThumbprint: expectedIss,
            header: header,
            payload: payload
        )
    }

    /// Extract the ephemeral JWK from the JWT's `cnf.jwk` claim without verification.
    ///
    /// Used during signing (the signer already knows the keys are valid).
    public func extractJWK() throws -> JWKParameters {
        let parts = jwt.split(separator: ".")
        guard parts.count >= 2 else {
            throw SignatureKeyError.invalidJWT("expected at least 2 parts separated by '.'")
        }

        guard let payloadData = Base64URL.decode(String(parts[1])),
              let payload = try JSONSerialization.jsonObject(with: payloadData) as? [String: Any] else {
            throw SignatureKeyError.invalidJWT("cannot decode payload")
        }

        guard let cnf = payload["cnf"] as? [String: Any],
              let jwkDict = cnf["jwk"] as? [String: Any] else {
            throw SignatureKeyError.invalidJWT("missing 'cnf.jwk'")
        }

        let jwkData = try JSONSerialization.data(withJSONObject: jwkDict)
        return try JSONDecoder().decode(JWKParameters.self, from: jwkData)
    }
}
