import Foundation
import CryptoKit

/// Verifies HTTP message signatures per RFC 9421 with the Signature-Key extension.
///
/// The verifier extracts the three headers (Signature-Input, Signature, Signature-Key),
/// reconstructs the signature base, extracts the public key from Signature-Key, and
/// verifies the signature.
///
/// Example usage:
/// ```swift
/// let result = try HTTPMessageVerifier.verify(request: request)
/// // result.jwk contains the verified public key parameters
/// // result.parameters contains the signature metadata
/// ```
public struct HTTPMessageVerifier {

    /// The result of a successful signature verification.
    public struct VerificationResult {
        /// The signature label that was verified.
        public let label: String

        /// The JWK parameters of the public key that verified the signature.
        public let jwk: JWKParameters

        /// The Signature-Key value (the full scheme, for further inspection).
        public let signatureKeyValue: SignatureKeyValue

        /// The signature parameters (created, alg, keyid, etc.).
        public let parameters: SignatureParameters

        /// The covered component identifiers.
        public let components: [String]
    }

    /// Errors during signature verification.
    public enum Error: Swift.Error {
        case missingHeader(String)
        case signatureVerificationFailed
        case unsupportedAlgorithm(String)
        case unsupportedKeyType(String)
        case signatureKeyMissing
        case signatureKeyNotCovered
        case publicKeyExtractionFailed
    }

    /// Verify the signature on a URLRequest.
    ///
    /// Extracts the Signature-Input, Signature, and Signature-Key headers,
    /// reconstructs the signature base, and verifies the signature against
    /// the public key from the Signature-Key header.
    ///
    /// - Parameter request: The signed HTTP request.
    /// - Returns: A `VerificationResult` with the verified key and metadata.
    public static func verify(request: URLRequest) throws -> VerificationResult {
        // 1. Extract the three headers
        guard let signatureInputHeader = request.value(forHTTPHeaderField: "Signature-Input") else {
            throw Error.missingHeader("Signature-Input")
        }
        guard let signatureHeader = request.value(forHTTPHeaderField: "Signature") else {
            throw Error.missingHeader("Signature")
        }
        guard let signatureKeyHeader = request.value(forHTTPHeaderField: "Signature-Key") else {
            throw Error.missingHeader("Signature-Key")
        }

        // 2. Parse the headers
        let sigInput = try SignatureInput.parse(signatureInputHeader)
        let sigHeader = try SignatureHeader.parse(signatureHeader)
        let (_, sigKeyValue) = try SignatureKeyValue.parse(signatureKeyHeader)

        // 3. Verify that signature-key is a covered component
        guard sigInput.components.contains("signature-key") else {
            throw Error.signatureKeyNotCovered
        }

        // 4. Extract the public key from the Signature-Key header
        guard let jwk = try sigKeyValue.jwkParameters() else {
            throw Error.publicKeyExtractionFailed
        }

        // 5. Reconstruct the signature base
        let base = SignatureBase(
            request: request,
            components: sigInput.components,
            signatureKeyHeader: signatureKeyHeader,
            parameters: sigInput.parameters
        )

        // 6. Verify the signature
        let isValid = try verifySignature(
            sigHeader.signature,
            base: base.dataToSign,
            jwk: jwk
        )

        guard isValid else {
            throw Error.signatureVerificationFailed
        }

        return VerificationResult(
            label: sigInput.label,
            jwk: jwk,
            signatureKeyValue: sigKeyValue,
            parameters: sigInput.parameters,
            components: sigInput.components
        )
    }

    /// Verify a raw signature against data using the given JWK.
    static func verifySignature(
        _ signature: Data,
        base data: Data,
        jwk: JWKParameters
    ) throws -> Bool {
        switch (jwk.kty, jwk.crv) {
        case ("EC", "P-256"):
            return try verifyES256(signature: signature, data: data, jwk: jwk)
        case ("OKP", "Ed25519"):
            return try verifyEdDSA(signature: signature, data: data, jwk: jwk)
        default:
            throw Error.unsupportedKeyType("\(jwk.kty)/\(jwk.crv)")
        }
    }

    /// Verify an ES256 (P-256 + SHA-256) signature.
    private static func verifyES256(signature: Data, data: Data, jwk: JWKParameters) throws -> Bool {
        guard let y = jwk.y,
              let xData = Base64URL.decode(jwk.x),
              let yData = Base64URL.decode(y) else {
            throw Error.publicKeyExtractionFailed
        }

        // Construct x963 representation: 0x04 || x || y
        var x963 = Data([0x04])
        x963.append(xData)
        x963.append(yData)

        let publicKey = try P256.Signing.PublicKey(x963Representation: x963)
        let ecdsaSignature = try P256.Signing.ECDSASignature(rawRepresentation: signature)

        return publicKey.isValidSignature(ecdsaSignature, for: data)
    }

    /// Verify an EdDSA (Ed25519) signature.
    private static func verifyEdDSA(signature: Data, data: Data, jwk: JWKParameters) throws -> Bool {
        guard let xData = Base64URL.decode(jwk.x) else {
            throw Error.publicKeyExtractionFailed
        }

        let publicKey = try Curve25519.Signing.PublicKey(rawRepresentation: xData)
        return publicKey.isValidSignature(signature, for: data)
    }
}
