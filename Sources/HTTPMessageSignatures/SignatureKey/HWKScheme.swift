import Foundation

/// Header Web Key (hwk) scheme for Signature-Key.
///
/// Carries JWK parameters inline as structured field parameters:
///
///     sig=hwk;alg="ES256";kty="EC";crv="P-256";x="base64url...";y="base64url..."
///
/// `alg` is REQUIRED as of draft-hardt-httpbis-signature-key-08 and carries the
/// algorithm; it was forbidden through -07. It is emitted here and accepted but
/// not yet required on parse, so a 1.2 verifier still reads keys from signers
/// that have not been updated.
public struct HWKScheme: Equatable, Sendable {
    public let kty: String
    public let crv: String
    public let x: String
    public let y: String?  // nil for OKP keys
    public let alg: String?

    public init(kty: String, crv: String, x: String, y: String? = nil, alg: String? = nil) {
        self.kty = kty
        self.crv = crv
        self.x = x
        self.y = y
        self.alg = alg ?? AlgorithmDetermination.derived(kty: kty, crv: crv)
    }

    /// Create from JWK parameters.
    public init(jwk: JWKParameters) {
        self.kty = jwk.kty
        self.crv = jwk.crv
        self.x = jwk.x
        self.y = jwk.y
        self.alg = jwk.alg ?? AlgorithmDetermination.derived(kty: jwk.kty, crv: jwk.crv)
    }

    /// Convert to JWK parameters.
    public func toJWKParameters() -> JWKParameters {
        JWKParameters(kty: kty, crv: crv, x: x, y: y, alg: alg)
    }

    /// Parse hwk parameters from a semicolon-delimited parameter string.
    ///
    /// Input example: `kty="EC";crv="P-256";x="...";y="..."`
    static func parse(params: String) throws -> HWKScheme {
        let dict = parseStructuredParams(params)

        guard let kty = dict["kty"] else {
            throw SignatureKeyError.missingParameter("kty")
        }
        guard let crv = dict["crv"] else {
            throw SignatureKeyError.missingParameter("crv")
        }
        guard let x = dict["x"] else {
            throw SignatureKeyError.missingParameter("x")
        }

        let y = dict["y"]

        // Validate: EC requires y, OKP does not
        if kty == "EC" && y == nil {
            throw SignatureKeyError.missingParameter("y")
        }

        return HWKScheme(kty: kty, crv: crv, x: x, y: y, alg: dict["alg"])
    }

    /// Serialize to the Signature-Key header value (after the label=).
    func serialize() -> String {
        var parts = ["hwk"]
        if let alg = alg {
            parts.append("alg=\"\(alg)\"")
        }
        parts.append("kty=\"\(kty)\"")
        parts.append("crv=\"\(crv)\"")
        parts.append("x=\"\(x)\"")
        if let y = y {
            parts.append("y=\"\(y)\"")
        }
        return parts.joined(separator: ";")
    }
}

// MARK: - Structured Parameter Parsing

/// Parse structured field parameters of the form `key="value";key2="value2"`.
///
/// Values are expected to be quoted strings per RFC 8941.
func parseStructuredParams(_ input: String) -> [String: String] {
    var result = [String: String]()

    // Split on ";" and parse each key="value" pair
    let pairs = input.split(separator: ";")
    for pair in pairs {
        let trimmed = pair.trimmingCharacters(in: .whitespaces)
        guard let eqIndex = trimmed.firstIndex(of: "=") else { continue }

        let key = trimmed[trimmed.startIndex..<eqIndex].trimmingCharacters(in: .whitespaces)
        var value = trimmed[trimmed.index(after: eqIndex)...].trimmingCharacters(in: .whitespaces)

        // Strip surrounding quotes
        if value.hasPrefix("\"") && value.hasSuffix("\"") && value.count >= 2 {
            value = String(value.dropFirst().dropLast())
        }

        result[key] = value
    }

    return result
}
