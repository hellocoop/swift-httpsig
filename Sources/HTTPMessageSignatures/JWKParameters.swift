import Foundation

/// Represents JWK (JSON Web Key) parameters for EC and OKP key types.
public struct JWKParameters: Equatable, Sendable {
    public let kty: String
    public let crv: String
    public let x: String
    public let y: String?  // nil for OKP keys

    /// Fully-specified JOSE algorithm identifier (RFC 9864).
    ///
    /// draft-hardt-httpbis-signature-key-08 requires this on a conveyed key:
    /// the algorithm comes from the key, not from `kty` and `crv`. It is
    /// optional here so a key received without one can still be read, and is
    /// always populated on keys this library constructs.
    ///
    /// Not part of the JWK thumbprint (RFC 7638), which covers only the
    /// required members, so adding it does not change a key's identity.
    public let alg: String?

    /// Create EC key parameters (P-256, P-384, P-521).
    public static func ec(crv: String, x: String, y: String, alg: String? = nil) -> JWKParameters {
        JWKParameters(
            kty: "EC", crv: crv, x: x, y: y,
            alg: alg ?? AlgorithmDetermination.derived(kty: "EC", crv: crv))
    }

    /// Create OKP key parameters (Ed25519, Ed448).
    public static func okp(crv: String, x: String, alg: String? = nil) -> JWKParameters {
        JWKParameters(
            kty: "OKP", crv: crv, x: x, y: nil,
            alg: alg ?? AlgorithmDetermination.derived(kty: "OKP", crv: crv))
    }

    public init(kty: String, crv: String, x: String, y: String? = nil, alg: String? = nil) {
        self.kty = kty
        self.crv = crv
        self.x = x
        self.y = y
        self.alg = alg
    }
}

// MARK: - Codable

extension JWKParameters: Codable {
    enum CodingKeys: String, CodingKey {
        case kty, crv, x, y, alg
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.kty = try container.decode(String.self, forKey: .kty)
        self.crv = try container.decode(String.self, forKey: .crv)
        self.x = try container.decode(String.self, forKey: .x)
        self.y = try container.decodeIfPresent(String.self, forKey: .y)
        self.alg = try container.decodeIfPresent(String.self, forKey: .alg)
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(kty, forKey: .kty)
        try container.encode(crv, forKey: .crv)
        try container.encode(x, forKey: .x)
        try container.encodeIfPresent(y, forKey: .y)
        try container.encodeIfPresent(alg, forKey: .alg)
    }
}
