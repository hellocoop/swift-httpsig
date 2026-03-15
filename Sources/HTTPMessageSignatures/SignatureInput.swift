import Foundation

/// Parse and create the Signature-Input header per RFC 9421.
///
/// Format: `label=("component1" "component2" ...);param1=value1;param2="value2"`
///
/// Example:
///     sig=("@method" "@authority" "@path" "signature-key");created=1732210000
public struct SignatureInput: Equatable, Sendable {
    /// The signature label (e.g., "sig").
    public let label: String

    /// The ordered list of covered component identifiers.
    public let components: [String]

    /// The signature parameters.
    public let parameters: SignatureParameters

    public init(label: String, components: [String], parameters: SignatureParameters) {
        self.label = label
        self.components = components
        self.parameters = parameters
    }

    /// Serialize to a Signature-Input header value.
    public func serialize() -> String {
        let componentList = components.map { "\"\($0)\"" }.joined(separator: " ")
        return "\(label)=(\(componentList))\(parameters.serialize())"
    }

    /// Parse a Signature-Input header value.
    ///
    /// Handles the format: `label=("comp1" "comp2");param1=val1;param2="val2"`
    public static func parse(_ headerValue: String) throws -> SignatureInput {
        // Split label from the rest
        guard let eqIndex = headerValue.firstIndex(of: "=") else {
            throw SignatureInputError.invalidFormat("missing '=' separator")
        }

        let label = String(headerValue[headerValue.startIndex..<eqIndex])
        let rest = String(headerValue[headerValue.index(after: eqIndex)...])

        // Find the component list: (...)
        guard let openParen = rest.firstIndex(of: "("),
              let closeParen = rest.firstIndex(of: ")") else {
            throw SignatureInputError.invalidFormat("missing component list parentheses")
        }

        let componentString = String(rest[rest.index(after: openParen)..<closeParen])
        let components = parseComponentList(componentString)

        // Parse parameters after the closing paren
        let afterParen = String(rest[rest.index(after: closeParen)...])
        let parameters = SignatureParameters.parse(afterParen)

        return SignatureInput(label: label, components: components, parameters: parameters)
    }

    /// Parse a quoted component list like `"@method" "@authority" "@path"`.
    private static func parseComponentList(_ input: String) -> [String] {
        var components = [String]()
        var current = ""
        var inQuotes = false

        for char in input {
            if char == "\"" {
                if inQuotes {
                    components.append(current)
                    current = ""
                }
                inQuotes.toggle()
            } else if inQuotes {
                current.append(char)
            }
        }

        return components
    }
}

/// Errors during Signature-Input parsing.
public enum SignatureInputError: Error {
    case invalidFormat(String)
}
