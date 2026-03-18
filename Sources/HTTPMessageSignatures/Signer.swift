import Foundation

/// Signs HTTP requests per RFC 9421 with the Signature-Key extension.
///
/// The signer adds three headers to a `URLRequest`:
/// - `Signature-Input`: describes which components are covered and parameters
/// - `Signature`: the actual signature bytes
/// - `Signature-Key`: the public key or key reference
///
/// Example usage:
/// ```swift
/// let key = CryptoKitP256SigningKey()
/// let signer = HTTPMessageSigner(
///     key: key,
///     label: "sig",
///     components: ["@method", "@authority", "@path", "signature-key"]
/// )
/// let signedRequest = try signer.sign(request)
/// ```
public struct HTTPMessageSigner {
    /// The signing key.
    public let key: HTTPSigningKey

    /// The signature label (e.g., "sig").
    public let label: String

    /// The component identifiers to cover.
    public let components: [String]

    /// Optional tag parameter.
    public let tag: String?

    /// Signature-Key scheme to use. Defaults to `hwk`.
    public let signatureKeyScheme: SignatureKeyScheme

    /// Which Signature-Key scheme to emit.
    public enum SignatureKeyScheme {
        /// Inline JWK parameters (hwk).
        case hwk
        /// JWT with cnf.jwk (caller provides the JWT string).
        case jwt(String)
        /// Self-issued key delegation JWT (caller provides the JWT string).
        case jktJWT(String)
        /// JWKS URI discovery (caller provides the URI parameters).
        case jwksURI(id: String, wellKnown: String?, kid: String?)
    }

    public init(
        key: HTTPSigningKey,
        label: String = "sig",
        components: [String] = ["@method", "@authority", "@path", "signature-key"],
        tag: String? = nil,
        signatureKeyScheme: SignatureKeyScheme = .hwk
    ) {
        self.key = key
        self.label = label
        self.components = components
        self.tag = tag
        self.signatureKeyScheme = signatureKeyScheme
    }

    /// Sign a URLRequest, adding the three signature headers.
    ///
    /// - Parameter request: The request to sign. A copy is returned with headers added.
    /// - Returns: A new URLRequest with Signature-Input, Signature, and Signature-Key headers set.
    public func sign(_ request: URLRequest) throws -> URLRequest {
        return try sign(request, created: Int(Date().timeIntervalSince1970))
    }

    /// Sign a URLRequest with a specific `created` timestamp (useful for testing).
    public func sign(_ request: URLRequest, created: Int) throws -> URLRequest {
        var signedRequest = request

        // 1. Build the Signature-Key header value
        let signatureKeyValue = buildSignatureKeyValue()
        let signatureKeyHeaderValue = signatureKeyValue.serialize(label: label)

        // 2. Build signature parameters
        let parameters = SignatureParameters(
            created: created,
            tag: tag
        )

        // 3. Build the signature base
        let base = SignatureBase(
            request: request,
            components: components,
            signatureKeyHeader: signatureKeyHeaderValue,
            parameters: parameters
        )

        // 4. Sign the base
        let signatureBytes = try key.sign(base.dataToSign)

        // 5. Build headers
        let signatureInput = SignatureInput(
            label: label,
            components: components,
            parameters: parameters
        )

        let signatureHeader = SignatureHeader(
            label: label,
            signature: signatureBytes
        )

        // 6. Set headers on the request
        signedRequest.setValue(signatureInput.serialize(), forHTTPHeaderField: "Signature-Input")
        signedRequest.setValue(signatureHeader.serialize(), forHTTPHeaderField: "Signature")
        signedRequest.setValue(signatureKeyHeaderValue, forHTTPHeaderField: "Signature-Key")

        return signedRequest
    }

    /// Build the SignatureKeyValue based on the configured scheme.
    private func buildSignatureKeyValue() -> SignatureKeyValue {
        switch signatureKeyScheme {
        case .hwk:
            return .hwk(HWKScheme(jwk: key.publicKeyJWK))
        case .jwt(let jwtString):
            return .jwt(JWTScheme(jwt: jwtString))
        case .jktJWT(let jwtString):
            return .jktJWT(JKTJWTScheme(jwt: jwtString))
        case .jwksURI(let id, let wellKnown, let kid):
            return .jwksURI(JWKSURIScheme(id: id, wellKnown: wellKnown, kid: kid))
        }
    }
}
