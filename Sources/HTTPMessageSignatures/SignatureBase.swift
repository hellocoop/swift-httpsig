import Foundation

/// Builds the HTTP Message Signature base string per RFC 9421 Section 2.5.
///
/// The signature base is the canonical byte sequence that gets signed. It consists
/// of one line per covered component, followed by a `@signature-params` line:
///
///     "@method": POST
///     "@authority": wallet.hello.coop
///     "@path": /api/v1/mobile/register
///     "signature-key": sig=hwk;kty="EC";crv="P-256";x="...";y="..."
///     "@signature-params": ("@method" "@authority" "@path" "signature-key");created=1732210000
///
public struct SignatureBase {

    /// The covered component identifiers in order.
    public let components: [String]

    /// The signature parameters (created timestamp, algorithm, etc.).
    public let parameters: SignatureParameters

    /// The resolved values for each component.
    public let componentValues: [String: String]

    /// Construct a signature base from an HTTP request and its components.
    ///
    /// - Parameters:
    ///   - request: The HTTP request.
    ///   - components: The ordered list of component identifiers to cover.
    ///   - signatureKeyHeader: The Signature-Key header value (used when "signature-key" is a covered component).
    ///   - parameters: Signature parameters (created, algorithm, keyid, etc.).
    public init(
        request: URLRequest,
        components: [String],
        signatureKeyHeader: String?,
        parameters: SignatureParameters
    ) {
        self.components = components
        self.parameters = parameters

        var values = [String: String]()
        for component in components {
            values[component] = Self.resolveComponent(
                component,
                from: request,
                signatureKeyHeader: signatureKeyHeader
            )
        }
        self.componentValues = values
    }

    /// Construct a signature base from pre-resolved component values (for verification).
    public init(
        components: [String],
        componentValues: [String: String],
        parameters: SignatureParameters
    ) {
        self.components = components
        self.parameters = parameters
        self.componentValues = componentValues
    }

    /// Serialize the signature base to the canonical byte string.
    public func serialize() -> String {
        var lines = [String]()

        for component in components {
            let value = componentValues[component] ?? ""
            lines.append("\"\(component)\": \(value)")
        }

        lines.append("\"@signature-params\": \(signatureParamsLine)")
        return lines.joined(separator: "\n")
    }

    /// The serialized @signature-params value.
    public var signatureParamsLine: String {
        let componentList = components.map { "\"\($0)\"" }.joined(separator: " ")
        var result = "(\(componentList))"
        result += parameters.serialize()
        return result
    }

    /// The serialized signature base as raw bytes for signing.
    public var dataToSign: Data {
        Data(serialize().utf8)
    }

    // MARK: - Component Resolution

    /// Resolve a single derived or field component from an HTTP request.
    static func resolveComponent(
        _ identifier: String,
        from request: URLRequest,
        signatureKeyHeader: String?
    ) -> String {
        switch identifier {
        case "@method":
            return request.httpMethod?.uppercased() ?? "GET"

        case "@authority":
            guard let url = request.url, let host = url.host else { return "" }
            if let port = url.port, !isDefaultPort(port, scheme: url.scheme) {
                return "\(host):\(port)"
            }
            return host

        case "@path":
            return request.url?.path ?? "/"

        case "@scheme":
            return request.url?.scheme?.lowercased() ?? "https"

        case "@target-uri":
            return request.url?.absoluteString ?? ""

        case "@request-target":
            let path = request.url?.path ?? "/"
            if let query = request.url?.query {
                return "\(path)?\(query)"
            }
            return path

        case "@query":
            if let query = request.url?.query {
                return "?\(query)"
            }
            return "?"

        case "signature-key":
            return signatureKeyHeader ?? ""

        default:
            // Regular HTTP header field
            let lowercased = identifier.lowercased()
            if let value = request.value(forHTTPHeaderField: lowercased) {
                return value
            }
            // Try case-insensitive match
            if let allHeaders = request.allHTTPHeaderFields {
                for (key, value) in allHeaders {
                    if key.lowercased() == lowercased {
                        return value
                    }
                }
            }
            return ""
        }
    }

    private static func isDefaultPort(_ port: Int, scheme: String?) -> Bool {
        switch scheme {
        case "https": return port == 443
        case "http": return port == 80
        default: return false
        }
    }
}

/// Parameters for a signature (the metadata after the component list).
public struct SignatureParameters: Equatable, Sendable {
    /// Unix timestamp when the signature was created.
    public var created: Int?

    /// Signature algorithm identifier (e.g., "es256").
    public var alg: String?

    /// Key identifier.
    public var keyid: String?

    /// Nonce value.
    public var nonce: String?

    /// Expiration timestamp.
    public var expires: Int?

    /// Signature tag.
    public var tag: String?

    public init(
        created: Int? = nil,
        alg: String? = nil,
        keyid: String? = nil,
        nonce: String? = nil,
        expires: Int? = nil,
        tag: String? = nil
    ) {
        self.created = created
        self.alg = alg
        self.keyid = keyid
        self.nonce = nonce
        self.expires = expires
        self.tag = tag
    }

    /// Serialize the parameters portion (semicolon-separated key=value pairs).
    func serialize() -> String {
        var parts = [String]()
        if let created = created {
            parts.append("created=\(created)")
        }
        if let alg = alg {
            parts.append("alg=\"\(alg)\"")
        }
        if let keyid = keyid {
            parts.append("keyid=\"\(keyid)\"")
        }
        if let nonce = nonce {
            parts.append("nonce=\"\(nonce)\"")
        }
        if let expires = expires {
            parts.append("expires=\(expires)")
        }
        if let tag = tag {
            parts.append("tag=\"\(tag)\"")
        }
        if parts.isEmpty {
            return ""
        }
        return ";" + parts.joined(separator: ";")
    }

    /// Parse parameters from a string like `;created=123;alg="es256"`.
    static func parse(_ input: String) -> SignatureParameters {
        var params = SignatureParameters()
        let dict = parseStructuredParams(input)

        if let createdStr = dict["created"], let created = Int(createdStr) {
            params.created = created
        }
        if let alg = dict["alg"] {
            params.alg = alg
        }
        if let keyid = dict["keyid"] {
            params.keyid = keyid
        }
        if let nonce = dict["nonce"] {
            params.nonce = nonce
        }
        if let expiresStr = dict["expires"], let expires = Int(expiresStr) {
            params.expires = expires
        }
        if let tag = dict["tag"] {
            params.tag = tag
        }

        return params
    }
}
