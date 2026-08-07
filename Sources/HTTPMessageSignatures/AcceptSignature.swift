import Foundation

/// The `Accept-Signature-Scheme` and `Accept-Signature-Alg` response headers.
///
/// Both are Lists of Tokens (RFC 8941). They replaced the `sigkey` parameter,
/// which could name only one scheme because a Structured Fields parameter
/// value is a bare Item and cannot be a list.
///
/// A server sends them on a challenge, before the client has signed anything,
/// and on an error, so a client selects a scheme and an algorithm before it
/// signs rather than after a rejection.
public enum AcceptSignature {

    /// Matches an RFC 8941 Token.
    static let tokenPattern = "^[A-Za-z*][A-Za-z0-9!#$%&'*+\\-.^_`|~:/]*$"

    public enum Error: Swift.Error, Equatable {
        case notAToken(String)
    }

    static func isToken(_ value: String) -> Bool {
        value.range(of: tokenPattern, options: .regularExpression) != nil
    }

    /// Serialize a List of Tokens.
    static func serializeList(_ values: [String]) throws -> String {
        for value in values where !isToken(value) {
            throw Error.notAToken(value)
        }
        return values.joined(separator: ", ")
    }

    /// Parse a List of Tokens, dropping anything that is not one.
    static func parseList(_ header: String) -> [String] {
        header
            .split(separator: ",")
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { isToken($0) }
    }

    /// Serialize `Accept-Signature-Scheme`: the Signature-Key schemes the
    /// server accepts, in descending order of preference.
    public static func schemeHeader(_ schemes: [String]) throws -> String {
        try serializeList(schemes)
    }

    /// Parse `Accept-Signature-Scheme`.
    ///
    /// Unrecognized tokens are preserved. A client ignores what it does not
    /// know, so a server may list schemes registered after the client was
    /// written without breaking it.
    public static func parseSchemes(_ header: String) -> [String] {
        parseList(header)
    }

    /// Serialize `Accept-Signature-Alg`: the algorithms the server accepts, as
    /// fully-specified identifiers from the JOSE registry -- the same
    /// identifiers a conveyed key carries in its `alg` member, so a client can
    /// compare the two.
    public static func algHeader(_ algorithms: [String]) throws -> String {
        try serializeList(algorithms)
    }

    /// Parse `Accept-Signature-Alg`.
    public static func parseAlgorithms(_ header: String) -> [String] {
        parseList(header)
    }
}
