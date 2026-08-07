import Foundation

/// JWT scheme for Signature-Key.
///
/// Carries a JWT whose payload contains a `cnf.jwk` confirmation key:
///
///     sig=jwt;jwt="eyJ..."
///
/// The issuer's signature over the assertion is NOT checked here: the issuer's
/// key is external and the caller resolves it. `exp` IS checked, because it
/// bounds how long the confirmation key the assertion carries stays
/// acceptable, and an assertion without one leaves that key acceptable
/// indefinitely.
public struct JWTScheme: Equatable, Sendable {
    /// The raw JWT string.
    public let jwt: String

    public init(jwt: String) {
        self.jwt = jwt
    }

    /// Parse jwt parameters.
    ///
    /// Input example: `jwt="eyJ..."`
    static func parse(params: String) throws -> JWTScheme {
        let dict = parseStructuredParams(params)
        guard let jwt = dict["jwt"] else {
            throw SignatureKeyError.missingParameter("jwt")
        }
        return JWTScheme(jwt: jwt)
    }

    /// Serialize to the Signature-Key header value (after the label=).
    func serialize() -> String {
        return "jwt;jwt=\"\(jwt)\""
    }

    /// Extract the JWK from the JWT's `cnf.jwk` claim.
    ///
    /// This decodes the JWT payload (without verifying the issuer's
    /// signature), validates `exp`, and extracts the confirmation key.
    ///
    /// - Parameter maxClockSkew: seconds of tolerance on `exp`.
    public func extractJWK(maxClockSkew: Int = 60) throws -> JWKParameters {
        let parts = jwt.split(separator: ".")
        guard parts.count >= 2 else {
            throw SignatureKeyError.invalidJWT("expected at least 2 parts separated by '.'")
        }

        guard let payloadData = Base64URL.decode(String(parts[1])) else {
            throw SignatureKeyError.invalidJWT("cannot decode payload")
        }

        // Parse the payload JSON
        guard let payload = try JSONSerialization.jsonObject(with: payloadData) as? [String: Any] else {
            throw SignatureKeyError.invalidJWT("payload is not a JSON object")
        }

        // exp is REQUIRED as of -08: it is what bounds acceptance of the
        // confirmation key this assertion carries.
        guard let exp = payload["exp"] as? Int else {
            throw SignatureKeyError.invalidJWT("missing 'exp' claim")
        }
        let now = Int(Date().timeIntervalSince1970)
        if exp + maxClockSkew < now {
            throw SignatureKeyError.expiredJWT("exp \(exp) is in the past")
        }

        guard let cnf = payload["cnf"] as? [String: Any] else {
            throw SignatureKeyError.invalidJWT("missing 'cnf' claim")
        }

        guard let jwkDict = cnf["jwk"] as? [String: Any] else {
            throw SignatureKeyError.invalidJWT("missing 'cnf.jwk'")
        }

        // Re-serialize the jwk dict to JSON and decode as JWKParameters
        let jwkData = try JSONSerialization.data(withJSONObject: jwkDict)
        return try JSONDecoder().decode(JWKParameters.self, from: jwkData)
    }
}
