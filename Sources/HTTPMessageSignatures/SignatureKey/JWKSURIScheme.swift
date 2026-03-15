import Foundation

/// JWKS URI scheme for Signature-Key.
///
/// References a key via a JWKS discovery endpoint:
///
///     sig=jwks_uri;id="https://issuer.example.com";well-known="aauth-agent";kid="key-1"
///
/// This struct only captures the parameters. Actual network resolution is
/// the caller's responsibility.
public struct JWKSURIScheme: Equatable, Sendable {
    /// The issuer/entity identifier (used to construct the well-known URL).
    public let id: String

    /// The well-known path suffix (e.g., "aauth-agent" -> `/.well-known/aauth-agent`).
    public let wellKnown: String?

    /// The key ID to select from the JWKS.
    public let kid: String?

    public init(id: String, wellKnown: String? = nil, kid: String? = nil) {
        self.id = id
        self.wellKnown = wellKnown
        self.kid = kid
    }

    /// Construct the JWKS discovery URL.
    ///
    /// If `wellKnown` is set, returns `{id}/.well-known/{wellKnown}`.
    /// Otherwise, returns `{id}/.well-known/jwks.json`.
    public func discoveryURL() -> URL? {
        let suffix = wellKnown ?? "jwks.json"
        let base = id.hasSuffix("/") ? id : id + "/"
        return URL(string: "\(base).well-known/\(suffix)")
    }

    /// Parse jwks_uri parameters.
    ///
    /// Input example: `id="https://...";well-known="aauth-agent";kid="key-1"`
    static func parse(params: String) throws -> JWKSURIScheme {
        let dict = parseStructuredParams(params)
        guard let id = dict["id"] else {
            throw SignatureKeyError.missingParameter("id")
        }
        return JWKSURIScheme(
            id: id,
            wellKnown: dict["well-known"],
            kid: dict["kid"]
        )
    }

    /// Serialize to the Signature-Key header value (after the label=).
    func serialize() -> String {
        var parts = ["jwks_uri"]
        parts.append("id=\"\(id)\"")
        if let wellKnown = wellKnown {
            parts.append("well-known=\"\(wellKnown)\"")
        }
        if let kid = kid {
            parts.append("kid=\"\(kid)\"")
        }
        return parts.joined(separator: ";")
    }
}
