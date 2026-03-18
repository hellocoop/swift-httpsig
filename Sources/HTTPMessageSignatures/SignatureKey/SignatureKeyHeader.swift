import Foundation

/// Parsed representation of a Signature-Key header value.
///
/// The Signature-Key header carries the public key or key reference used
/// for a given signature label. The format varies by scheme:
///
/// - `hwk`: inline JWK parameters
/// - `jwt`: JWT with `cnf.jwk` confirmation key
/// - `jwks_uri`: JWKS discovery URI
public enum SignatureKeyValue: Equatable, Sendable {
    case hwk(HWKScheme)
    case jwt(JWTScheme)
    case jktJWT(JKTJWTScheme)
    case jwksURI(JWKSURIScheme)

    /// Parse a Signature-Key header value string.
    ///
    /// Expected format: `label=scheme;param1="value1";param2="value2"`
    public static func parse(_ headerValue: String) throws -> (label: String, value: SignatureKeyValue) {
        // Split on first "="
        guard let eqIndex = headerValue.firstIndex(of: "=") else {
            throw SignatureKeyError.invalidFormat("missing '=' separator")
        }

        let label = String(headerValue[headerValue.startIndex..<eqIndex])
        let rest = String(headerValue[headerValue.index(after: eqIndex)...])

        // Split on first ";"
        let parts = rest.split(separator: ";", maxSplits: 1)
        guard !parts.isEmpty else {
            throw SignatureKeyError.invalidFormat("missing scheme")
        }

        let scheme = String(parts[0])
        let paramsString = parts.count > 1 ? String(parts[1]) : ""

        switch scheme {
        case "hwk":
            let hwk = try HWKScheme.parse(params: paramsString)
            return (label, .hwk(hwk))
        case "jwt":
            let jwt = try JWTScheme.parse(params: paramsString)
            return (label, .jwt(jwt))
        case "jkt-jwt":
            let jktJWT = try JKTJWTScheme.parse(params: paramsString)
            return (label, .jktJWT(jktJWT))
        case "jwks_uri":
            let jwksURI = try JWKSURIScheme.parse(params: paramsString)
            return (label, .jwksURI(jwksURI))
        default:
            throw SignatureKeyError.unknownScheme(scheme)
        }
    }

    /// Serialize to a Signature-Key header value.
    public func serialize(label: String) -> String {
        switch self {
        case .hwk(let hwk):
            return "\(label)=\(hwk.serialize())"
        case .jwt(let jwt):
            return "\(label)=\(jwt.serialize())"
        case .jktJWT(let jktJWT):
            return "\(label)=\(jktJWT.serialize())"
        case .jwksURI(let jwksURI):
            return "\(label)=\(jwksURI.serialize())"
        }
    }

    /// Extract the JWK parameters from this Signature-Key value, if available inline.
    ///
    /// Returns the JWK for `hwk` and `jwt` schemes. Returns nil for `jwks_uri`
    /// (which requires network resolution).
    public func jwkParameters() throws -> JWKParameters? {
        switch self {
        case .hwk(let hwk):
            return hwk.toJWKParameters()
        case .jwt(let jwt):
            return try jwt.extractJWK()
        case .jktJWT(let jktJWT):
            return try jktJWT.extractJWK()
        case .jwksURI:
            return nil
        }
    }
}

/// Errors during Signature-Key header parsing.
public enum SignatureKeyError: Error, Equatable {
    case invalidFormat(String)
    case unknownScheme(String)
    case missingParameter(String)
    case invalidJWT(String)
}
