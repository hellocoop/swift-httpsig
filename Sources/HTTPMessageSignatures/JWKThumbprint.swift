import Foundation
import CryptoKit

/// Computes RFC 7638 JWK Thumbprints.
public enum JWKThumbprint {

    /// Errors that can occur during thumbprint computation.
    public enum Error: Swift.Error {
        case unsupportedKeyType(String)
        case missingYCoordinate
    }

    /// Hash algorithm for thumbprint computation.
    public enum HashAlgorithm {
        case sha256
        case sha512
    }

    /// Compute the thumbprint of a JWK per RFC 7638.
    ///
    /// The thumbprint is the base64url-encoded hash of the canonical
    /// JSON representation of the JWK's required members, sorted lexicographically.
    ///
    /// For EC keys: `{"crv":"...","kty":"EC","x":"...","y":"..."}`
    /// For OKP keys: `{"crv":"...","kty":"OKP","x":"..."}`
    ///
    /// - Parameters:
    ///   - jwk: The JWK to compute the thumbprint for.
    ///   - algorithm: The hash algorithm to use (default: SHA-256).
    public static func compute(_ jwk: JWKParameters, algorithm: HashAlgorithm = .sha256) throws -> String {
        let canonicalJSON: String

        switch jwk.kty {
        case "EC":
            guard let y = jwk.y else {
                throw Error.missingYCoordinate
            }
            // Lexicographic order: crv, kty, x, y
            canonicalJSON = """
            {"crv":"\(jwk.crv)","kty":"EC","x":"\(jwk.x)","y":"\(y)"}
            """

        case "OKP":
            // Lexicographic order: crv, kty, x
            canonicalJSON = """
            {"crv":"\(jwk.crv)","kty":"OKP","x":"\(jwk.x)"}
            """

        default:
            throw Error.unsupportedKeyType(jwk.kty)
        }

        let data = Data(canonicalJSON.utf8)

        switch algorithm {
        case .sha256:
            let hash = SHA256.hash(data: data)
            return Base64URL.encode(Data(hash))
        case .sha512:
            let hash = SHA512.hash(data: data)
            return Base64URL.encode(Data(hash))
        }
    }
}

// MARK: - Base64URL

/// Base64URL encoding/decoding per RFC 4648 Section 5.
public enum Base64URL {

    /// Encode data to a base64url string (no padding).
    public static func encode(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    /// Decode a base64url string to data.
    public static func decode(_ string: String) -> Data? {
        var base64 = string
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")

        // Add padding if needed
        let remainder = base64.count % 4
        if remainder > 0 {
            base64 += String(repeating: "=", count: 4 - remainder)
        }

        return Data(base64Encoded: base64)
    }
}
