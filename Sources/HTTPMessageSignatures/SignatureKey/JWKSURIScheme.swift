import Foundation

/// JWKS URI discovery scheme for Signature-Key.
///
/// Identifies the signer and discovers its keys through a metadata document:
///
///     sig=jwks_uri;id="https://issuer.example";dwk="aauth-agent";kid="key-1"
///
/// This struct captures the parameters and builds the discovery URL. Network
/// resolution is the caller's, which is why `DiscoveryMetadata` is separate:
/// once the caller has fetched the document, it validates it here.
public struct JWKSURIScheme: Equatable, Sendable {
    /// Signer identifier (HTTPS URL). REQUIRED.
    public let id: String

    /// Dot well-known metadata document name under `/.well-known/`. REQUIRED.
    ///
    /// Named `dwk` since -03. Earlier releases of this library called the
    /// parameter `well-known` and defaulted it to `jwks.json`; neither is in
    /// the specification.
    public let dwk: String

    /// Key identifier selecting a key from the JWKS. REQUIRED.
    public let kid: String

    public init(id: String, dwk: String, kid: String) {
        self.id = id
        self.dwk = dwk
        self.kid = kid
    }

    /// The metadata document URL, `{id}/.well-known/{dwk}`.
    public func discoveryURL() -> URL? {
        let base = id.hasSuffix("/") ? String(id.dropLast()) : id
        return URL(string: "\(base)/.well-known/\(dwk)")
    }

    /// Parse jwks_uri parameters.
    static func parse(params: String) throws -> JWKSURIScheme {
        let dict = parseStructuredParams(params)
        guard let id = dict["id"] else {
            throw SignatureKeyError.missingParameter("id")
        }
        guard let dwk = dict["dwk"] else {
            throw SignatureKeyError.missingParameter("dwk")
        }
        guard let kid = dict["kid"] else {
            throw SignatureKeyError.missingParameter("kid")
        }
        return JWKSURIScheme(id: id, dwk: dwk, kid: kid)
    }

    /// Serialize to the Signature-Key header value (after the label=).
    func serialize() -> String {
        "jwks_uri;id=\"\(id)\";dwk=\"\(dwk)\";kid=\"\(kid)\""
    }
}

/// A fetched discovery metadata document.
///
/// The `issuer` check binds the document to the identity it was fetched under.
/// Without it, a document served at `{id}/.well-known/{dwk}` -- through
/// misconfigured shared hosting or a subdomain takeover -- could point
/// `jwks_uri` at keys that do not belong to `id`, and the verifier would
/// attribute the request accordingly. Same check RFC 8414 Section 3.3 requires
/// of authorization server metadata.
public struct DiscoveryMetadata: Equatable, Sendable, Codable {
    public let issuer: String?
    public let jwks_uri: String?

    public init(issuer: String?, jwksURI: String?) {
        self.issuer = issuer
        self.jwks_uri = jwksURI
    }

    /// Validate a fetched document against the identity it was fetched under,
    /// and return its `jwks_uri`.
    ///
    /// - Parameter identity: the `id` parameter for the jwks_uri scheme, or
    ///   the `iss` claim for the jwt and self-jwt schemes.
    public func validate(fetchedUnder identity: String) throws -> String {
        guard let issuer = issuer else {
            throw SignatureKeyError.issuerMissing(identity)
        }
        // Byte equality as presented. No normalization: a trailing slash is a
        // different identifier.
        guard issuer == identity else {
            throw SignatureKeyError.issuerMismatch(expected: identity, found: issuer)
        }
        guard let jwksURI = jwks_uri else {
            throw SignatureKeyError.missingParameter("jwks_uri")
        }
        return jwksURI
    }

    /// Decode and validate a fetched document in one step.
    public static func validate(_ data: Data, fetchedUnder identity: String) throws -> String {
        let metadata = try JSONDecoder().decode(DiscoveryMetadata.self, from: data)
        return try metadata.validate(fetchedUnder: identity)
    }
}
