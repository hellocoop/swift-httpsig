import Foundation

/// Direct JWKS scheme for Signature-Key.
///
///     sig=jwks;url="https://client.example/keys.jwks";kid="key-1"
///
/// Unlike jwks_uri there is no metadata document and no discovery hop: the URL
/// is both the signer's identifier and the location of its keys.
///
/// Because identity and key location are the same string, moving the JWKS
/// changes the signer's identity. A signer needing identity to stay stable
/// while key location changes should use jwks_uri, whose indirection exists
/// for that purpose.
public struct JWKSScheme: Equatable, Sendable {
    /// HTTPS URL of the signer's JWKS. REQUIRED.
    public let url: String

    /// Key identifier selecting a key from the JWKS. REQUIRED.
    public let kid: String

    public init(url: String, kid: String) {
        self.url = url
        self.kid = kid
    }

    /// The JWKS URL, if it is a well-formed HTTPS URL.
    ///
    /// Returns nil for a non-HTTPS scheme. The caller applies the rest of
    /// egress admission -- size and timeout limits, redirect policy, rejecting
    /// private and loopback addresses -- since it owns the fetch.
    public func jwksURL() -> URL? {
        guard let parsed = URL(string: url), parsed.scheme?.lowercased() == "https" else {
            return nil
        }
        return parsed
    }

    static func parse(params: String) throws -> JWKSScheme {
        let dict = parseStructuredParams(params)
        guard let url = dict["url"] else {
            throw SignatureKeyError.missingParameter("url")
        }
        guard let kid = dict["kid"] else {
            throw SignatureKeyError.missingParameter("kid")
        }
        return JWKSScheme(url: url, kid: kid)
    }

    func serialize() -> String {
        "jwks;url=\"\(url)\";kid=\"\(kid)\""
    }

    /// Whether two identifiers name the same signer.
    ///
    /// Byte equality as presented: a verifier must not canonicalize or
    /// normalize, and values differing in any byte name different identities.
    public static func sameIdentity(_ a: String, _ b: String) -> Bool { a == b }
}
