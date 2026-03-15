import Foundation
import CryptoKit

/// An HTTPSigningKey backed by a CryptoKit P-256 private key (software key).
public struct CryptoKitP256SigningKey: HTTPSigningKey {
    private let privateKey: P256.Signing.PrivateKey

    public var algorithm: String { "ES256" }

    public var publicKeyJWK: JWKParameters {
        let publicKey = privateKey.publicKey
        let rawRepresentation = publicKey.x963Representation
        // x963 format: 0x04 || x (32 bytes) || y (32 bytes)
        let x = rawRepresentation[1..<33]
        let y = rawRepresentation[33..<65]
        return .ec(
            crv: "P-256",
            x: Base64URL.encode(Data(x)),
            y: Base64URL.encode(Data(y))
        )
    }

    public init(privateKey: P256.Signing.PrivateKey) {
        self.privateKey = privateKey
    }

    /// Creates a new random P-256 signing key.
    public init() {
        self.privateKey = P256.Signing.PrivateKey()
    }

    public func sign(_ data: Data) throws -> Data {
        let signature = try privateKey.signature(for: data)
        // CryptoKit rawRepresentation is already r||s (64 bytes)
        return signature.rawRepresentation
    }
}

/// An HTTPSigningKey backed by a CryptoKit Curve25519 private key.
public struct CryptoKitCurve25519SigningKey: HTTPSigningKey {
    private let privateKey: Curve25519.Signing.PrivateKey

    public var algorithm: String { "EdDSA" }

    public var publicKeyJWK: JWKParameters {
        let publicKey = privateKey.publicKey
        return .okp(
            crv: "Ed25519",
            x: Base64URL.encode(publicKey.rawRepresentation)
        )
    }

    public init(privateKey: Curve25519.Signing.PrivateKey) {
        self.privateKey = privateKey
    }

    /// Creates a new random Ed25519 signing key.
    public init() {
        self.privateKey = Curve25519.Signing.PrivateKey()
    }

    public func sign(_ data: Data) throws -> Data {
        return try privateKey.signature(for: data)
    }
}
