import Foundation

/// Represents JWK (JSON Web Key) parameters for EC and OKP key types.
public struct JWKParameters: Equatable, Sendable {
    public let kty: String
    public let crv: String
    public let x: String
    public let y: String?  // nil for OKP keys

    /// Create EC key parameters (P-256, P-384, P-521).
    public static func ec(crv: String, x: String, y: String) -> JWKParameters {
        JWKParameters(kty: "EC", crv: crv, x: x, y: y)
    }

    /// Create OKP key parameters (Ed25519).
    public static func okp(crv: String, x: String) -> JWKParameters {
        JWKParameters(kty: "OKP", crv: crv, x: x, y: nil)
    }

    public init(kty: String, crv: String, x: String, y: String? = nil) {
        self.kty = kty
        self.crv = crv
        self.x = x
        self.y = y
    }
}

// MARK: - Codable

extension JWKParameters: Codable {
    enum CodingKeys: String, CodingKey {
        case kty, crv, x, y
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.kty = try container.decode(String.self, forKey: .kty)
        self.crv = try container.decode(String.self, forKey: .crv)
        self.x = try container.decode(String.self, forKey: .x)
        self.y = try container.decodeIfPresent(String.self, forKey: .y)
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(kty, forKey: .kty)
        try container.encode(crv, forKey: .crv)
        try container.encode(x, forKey: .x)
        if let y = y {
            try container.encode(y, forKey: .y)
        }
    }
}
