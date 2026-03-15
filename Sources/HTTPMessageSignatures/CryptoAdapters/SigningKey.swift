import Foundation

/// A protocol for keys that can produce HTTP message signatures.
///
/// Conforming types wrap platform-specific key material (CryptoKit, Secure Enclave)
/// and expose a uniform signing interface.
public protocol HTTPSigningKey {
    /// The JWS algorithm identifier (e.g., "ES256", "EdDSA").
    var algorithm: String { get }

    /// The public key expressed as JWK parameters.
    var publicKeyJWK: JWKParameters { get }

    /// Sign the given data and return the signature bytes.
    ///
    /// For ES256, the returned signature MUST be in raw r||s format (64 bytes),
    /// not DER/X9.62 format.
    func sign(_ data: Data) throws -> Data
}
