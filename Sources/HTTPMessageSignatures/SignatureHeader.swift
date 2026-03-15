import Foundation

/// Parse and create the Signature header per RFC 9421.
///
/// Format: `label=:base64_signature:`
///
/// Example:
///     sig=:dGVzdA==:
public struct SignatureHeader: Equatable, Sendable {
    /// The signature label (e.g., "sig").
    public let label: String

    /// The raw signature bytes.
    public let signature: Data

    public init(label: String, signature: Data) {
        self.label = label
        self.signature = signature
    }

    /// Serialize to a Signature header value.
    ///
    /// Uses base64 encoding wrapped in colons per RFC 8941 byte sequence syntax.
    public func serialize() -> String {
        let encoded = signature.base64EncodedString()
        return "\(label)=:\(encoded):"
    }

    /// Parse a Signature header value.
    ///
    /// Handles the format: `label=:base64data:`
    public static func parse(_ headerValue: String) throws -> SignatureHeader {
        // Split label from the rest
        guard let eqIndex = headerValue.firstIndex(of: "=") else {
            throw SignatureHeaderError.invalidFormat("missing '=' separator")
        }

        let label = String(headerValue[headerValue.startIndex..<eqIndex])
        let rest = String(headerValue[headerValue.index(after: eqIndex)...])

        // Extract base64 content between colons
        guard rest.hasPrefix(":") && rest.hasSuffix(":") && rest.count >= 2 else {
            throw SignatureHeaderError.invalidFormat("signature value must be wrapped in colons")
        }

        let base64String = String(rest.dropFirst().dropLast())

        guard let signatureData = Data(base64Encoded: base64String) else {
            throw SignatureHeaderError.invalidFormat("invalid base64 signature data")
        }

        return SignatureHeader(label: label, signature: signatureData)
    }
}

/// Errors during Signature header parsing.
public enum SignatureHeaderError: Error {
    case invalidFormat(String)
}
