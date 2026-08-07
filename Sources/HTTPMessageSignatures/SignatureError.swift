import Foundation

/// Error codes for the `Signature-Error` response header.
///
/// Registered by draft-hardt-httpbis-signature-key-08. A verifier reports one
/// of these so a client can diagnose a rejection rather than guess at it.
public enum SignatureErrorCode: String, Sendable, CaseIterable {
    /// The signing algorithm is not one the verifier accepts. Also covers a
    /// key whose type the verifier does not implement: absence of support is
    /// a reason to decline, not a parsing failure.
    case unsupportedAlgorithm = "unsupported_algorithm"
    /// The Signature-Key scheme is not one the verifier implements.
    case unsupportedScheme = "unsupported_scheme"
    /// The signature did not verify.
    case invalidSignature = "invalid_signature"
    /// The covered components are missing something the verifier requires.
    case invalidInput = "invalid_input"
    /// The request is malformed in some other way.
    case invalidRequest = "invalid_request"
    /// The key material is malformed, or forbidden by the specification.
    case invalidKey = "invalid_key"
    /// The key was not found where the scheme said it would be.
    case unknownKey = "unknown_key"
    /// The assertion is malformed.
    case invalidJwt = "invalid_jwt"
    /// The assertion is well formed but no longer valid.
    case expiredJwt = "expired_jwt"
    /// The discovery metadata document has no `issuer` member.
    case issuerMissing = "issuer_missing"
    /// The metadata document's `issuer` does not match the identity it was
    /// fetched under.
    case issuerMismatch = "issuer_mismatch"
    /// A cache identifier did not resolve. This library does not implement
    /// assertion caching; the code is here so a client can parse one.
    case cacheMiss = "cache_miss"
}

/// A parsed or constructed `Signature-Error` header.
///
/// The `supported_algorithms` member was removed in -08. What a verifier
/// accepts travels in `Accept-Signature-Alg`, which works on a challenge and
/// on an error alike rather than only after a rejection.
public struct SignatureError: Equatable, Sendable {
    public let error: SignatureErrorCode

    /// Covered components the verifier requires, for `invalid_input`.
    public let requiredInput: [String]?

    public init(error: SignatureErrorCode, requiredInput: [String]? = nil) {
        self.error = error
        self.requiredInput = requiredInput
    }

    /// Serialize to a `Signature-Error` header value.
    public func serialize() -> String {
        var parts = ["error=\(error.rawValue)"]
        if let requiredInput = requiredInput, !requiredInput.isEmpty {
            let list = requiredInput.map { "\"\($0)\"" }.joined(separator: " ")
            parts.append("required_input=(\(list))")
        }
        return parts.joined(separator: ", ")
    }

    /// Parse a `Signature-Error` header value.
    public static func parse(_ header: String) throws -> SignatureError {
        guard let errorRange = header.range(of: #"error=([a-z_]+)"#, options: .regularExpression)
        else {
            throw SignatureKeyError.invalidFormat("Signature-Error missing error member")
        }
        let raw = String(header[errorRange]).replacingOccurrences(of: "error=", with: "")
        guard let code = SignatureErrorCode(rawValue: raw) else {
            throw SignatureKeyError.invalidFormat("Unknown Signature-Error code: \(raw)")
        }

        var requiredInput: [String]?
        if let listRange = header.range(
            of: #"required_input=\(([^)]*)\)"#, options: .regularExpression)
        {
            let inner = String(header[listRange])
                .replacingOccurrences(of: "required_input=(", with: "")
                .replacingOccurrences(of: ")", with: "")
            let items =
                inner
                .split(separator: " ")
                .map { $0.trimmingCharacters(in: CharacterSet(charactersIn: "\"")) }
                .filter { !$0.isEmpty }
            if !items.isEmpty { requiredInput = items }
        }

        return SignatureError(error: code, requiredInput: requiredInput)
    }
}

// MARK: - Mapping library errors to codes

extension SignatureKeyError {
    /// The `Signature-Error` code a verifier reports for this failure.
    public var signatureErrorCode: SignatureErrorCode {
        switch self {
        case .invalidFormat: return .invalidRequest
        case .unknownScheme: return .unsupportedScheme
        case .missingParameter: return .invalidKey
        case .invalidJWT: return .invalidJwt
        case .expiredJWT: return .expiredJwt
        case .forbiddenParameter: return .invalidKey
        case .issuerMissing: return .issuerMissing
        case .issuerMismatch: return .issuerMismatch
        }
    }
}

extension AlgorithmDetermination.Error {
    public var signatureErrorCode: SignatureErrorCode {
        switch self {
        // Forbidden by the specification: the key is malformed for this use.
        case .polymorphicAlgorithm, .symmetricAlgorithm, .inconsistentKey, .missingAlgorithm:
            return .invalidKey
        // Well formed, but this verifier will not or cannot use it.
        case .unsupportedAlgorithm:
            return .unsupportedAlgorithm
        }
    }
}

extension HTTPMessageVerifier.Error {
    public var signatureErrorCode: SignatureErrorCode {
        switch self {
        case .missingHeader, .publicKeyExtractionFailed:
            return .invalidRequest
        case .signatureVerificationFailed:
            return .invalidSignature
        case .unsupportedAlgorithm, .unsupportedKeyType:
            return .unsupportedAlgorithm
        case .signatureKeyMissing:
            return .invalidKey
        case .signatureKeyNotCovered:
            return .invalidInput
        }
    }
}
