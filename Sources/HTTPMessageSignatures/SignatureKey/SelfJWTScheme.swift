import Foundation

/// Self-issued JWT scheme for Signature-Key.
///
///     sig=self-jwt;jwt="eyJhbGciOiJFUzI1NiIsImtpZCI6InIxIn0..."
///
/// The JWT issuer and the HTTP request signer are the same party. The signing
/// key is discovered from the issuer's JWKS, and that same key verifies both
/// the JWT and the HTTP Message Signature. Unlike the jwt scheme there is no
/// `cnf` claim: the signing key *is* the confirmation key.
///
/// Discovery needs a network fetch, which this library leaves to the caller.
/// The flow is: `decode()` to validate the claims and learn where to look,
/// fetch and validate the metadata with `DiscoveryMetadata`, fetch the JWKS,
/// select by `kid`, then `verify(with:)`.
public struct SelfJWTScheme: Equatable, Sendable {
    public let jwt: String

    public init(jwt: String) {
        self.jwt = jwt
    }

    /// The claims a self-jwt must carry.
    public struct Claims: Equatable, Sendable {
        /// HTTPS URL of the issuer, and the identity the metadata document
        /// must claim.
        public let iss: String
        /// Dot well-known metadata document name.
        public let dwk: String
        /// Selects the signing key from the issuer's JWKS. From the header.
        public let kid: String
        /// Bounds how long the assertion is accepted.
        public let exp: Int
        public let iat: Int?
        public let sub: String?
        public let aud: String?
        /// The `typ` header parameter, for the caller's policy check.
        public let typ: String?

        /// `{iss}/.well-known/{dwk}` -- where the metadata document lives.
        public func discoveryURL() -> URL? {
            let base = iss.hasSuffix("/") ? String(iss.dropLast()) : iss
            return URL(string: "\(base)/.well-known/\(dwk)")
        }
    }

    static func parse(params: String) throws -> SelfJWTScheme {
        let dict = parseStructuredParams(params)
        guard let jwt = dict["jwt"] else {
            throw SignatureKeyError.missingParameter("jwt")
        }
        return SelfJWTScheme(jwt: jwt)
    }

    func serialize() -> String {
        "self-jwt;jwt=\"\(jwt)\""
    }

    /// Decode and validate the assertion's claims.
    ///
    /// Checks everything that needs no network: well-formedness, the required
    /// claims, the absence of `cnf`, and expiry. Doing these first lets a
    /// verifier fail before any cryptographic work or fetch.
    ///
    /// - Parameter maxClockSkew: seconds of tolerance on `exp`.
    public func decode(maxClockSkew: Int = 60) throws -> Claims {
        let parts = jwt.split(separator: ".")
        guard parts.count == 3 else {
            throw SignatureKeyError.invalidJWT("expected three parts")
        }

        guard let headerData = Base64URL.decode(String(parts[0])),
            let payloadData = Base64URL.decode(String(parts[1])),
            let header = try? JSONSerialization.jsonObject(with: headerData) as? [String: Any],
            let payload = try? JSONSerialization.jsonObject(with: payloadData) as? [String: Any]
        else {
            throw SignatureKeyError.invalidJWT("header or payload is not valid JSON")
        }

        // A self-jwt's signing key is its confirmation key. A cnf claim would
        // mean it is a jwt-scheme assertion presented under the wrong scheme.
        guard payload["cnf"] == nil else {
            throw SignatureKeyError.invalidJWT("self-jwt MUST NOT contain a cnf claim")
        }

        guard let iss = payload["iss"] as? String else {
            throw SignatureKeyError.invalidJWT("missing iss claim")
        }
        guard let dwk = payload["dwk"] as? String else {
            throw SignatureKeyError.invalidJWT("missing dwk claim")
        }
        guard let kid = header["kid"] as? String else {
            throw SignatureKeyError.invalidJWT("missing kid header parameter")
        }
        guard let exp = payload["exp"] as? Int else {
            throw SignatureKeyError.invalidJWT("missing exp claim")
        }

        let now = Int(Date().timeIntervalSince1970)
        if exp + maxClockSkew < now {
            throw SignatureKeyError.expiredJWT("exp \(exp) is in the past")
        }
        if let iat = payload["iat"] as? Int, iat - maxClockSkew > now {
            throw SignatureKeyError.invalidJWT("iat \(iat) is in the future")
        }

        return Claims(
            iss: iss,
            dwk: dwk,
            kid: kid,
            exp: exp,
            iat: payload["iat"] as? Int,
            sub: payload["sub"] as? String,
            aud: payload["aud"] as? String,
            typ: header["typ"] as? String
        )
    }

    /// Verify the JWT's own signature with the key discovered from the
    /// issuer's JWKS.
    ///
    /// The caller resolves that key: validate the metadata document with
    /// `DiscoveryMetadata`, fetch the JWKS, and select the entry matching
    /// `Claims.kid`.
    ///
    /// - Returns: the same key, which then verifies the HTTP Message
    ///   Signature. Returning it makes the "same key for both" rule hard to
    ///   get wrong at the call site.
    @discardableResult
    public func verify(with key: JWKParameters) throws -> JWKParameters {
        let parts = jwt.split(separator: ".")
        guard parts.count == 3 else {
            throw SignatureKeyError.invalidJWT("expected three parts")
        }
        guard let signature = Base64URL.decode(String(parts[2])) else {
            throw SignatureKeyError.invalidJWT("signature is not base64url")
        }

        let signingInput = Data("\(parts[0]).\(parts[1])".utf8)
        let valid = try HTTPMessageVerifier.verifySignature(
            signature, base: signingInput, jwk: key)
        guard valid else {
            throw SignatureKeyError.invalidJWT("JWT signature did not verify")
        }
        return key
    }
}
