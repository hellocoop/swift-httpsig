import Foundation
import CryptoKit
import Security

/// An HTTPSigningKey backed by an iOS Secure Enclave P-256 key.
///
/// The Secure Enclave only supports P-256 (ES256). The private key never
/// leaves the hardware; only signing operations are performed through it.
public struct SecureEnclaveSigningKey: HTTPSigningKey {
    private let privateKey: SecureEnclave.P256.Signing.PrivateKey

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

    /// Create a signing key from an existing Secure Enclave key.
    public init(privateKey: SecureEnclave.P256.Signing.PrivateKey) {
        self.privateKey = privateKey
    }

    /// Generate a new Secure Enclave P-256 key with the given access control.
    ///
    /// - Parameter accessControl: Optional access control flags. If nil, uses default.
    public init(accessControl: SecAccessControl? = nil) throws {
        if let accessControl = accessControl {
            self.privateKey = try SecureEnclave.P256.Signing.PrivateKey(
                accessControl: accessControl
            )
        } else {
            self.privateKey = try SecureEnclave.P256.Signing.PrivateKey()
        }
    }

    /// Restore a Secure Enclave key from its data representation.
    ///
    /// - Parameter dataRepresentation: The opaque key data from a previous export.
    public init(dataRepresentation: Data) throws {
        self.privateKey = try SecureEnclave.P256.Signing.PrivateKey(
            dataRepresentation: dataRepresentation
        )
    }

    /// The opaque data representation for persisting the key reference.
    ///
    /// This is NOT the private key itself (which never leaves the Secure Enclave),
    /// but a handle that can be used to access it later.
    public var dataRepresentation: Data {
        privateKey.dataRepresentation
    }

    public func sign(_ data: Data) throws -> Data {
        let signature = try privateKey.signature(for: data)
        // CryptoKit rawRepresentation is already r||s (64 bytes)
        return signature.rawRepresentation
    }
}

// MARK: - DER to Raw Signature Conversion

/// Utilities for converting between DER/X9.62 and raw (r||s) EC signature formats.
///
/// The Security framework (`SecKeyCreateSignature`) returns signatures in X9.62/DER format.
/// JWS/JOSE requires raw r||s concatenation. This converter handles the translation.
public enum DERSignatureConverter {

    public enum Error: Swift.Error {
        case invalidDERStructure
        case unexpectedTag(UInt8)
        case integerTooLong
    }

    /// Convert a DER-encoded ECDSA signature to raw r||s format.
    ///
    /// - Parameters:
    ///   - derSignature: The DER-encoded signature (SEQUENCE { INTEGER r, INTEGER s }).
    ///   - componentLength: The expected byte length of each component (32 for P-256).
    /// - Returns: The raw signature as r||s concatenation.
    public static func derToRaw(_ derSignature: Data, componentLength: Int = 32) throws -> Data {
        var bytes = [UInt8](derSignature)
        var offset = 0

        // SEQUENCE tag
        guard offset < bytes.count, bytes[offset] == 0x30 else {
            throw Error.invalidDERStructure
        }
        offset += 1

        // SEQUENCE length (skip)
        let (_, seqLenSize) = try readDERLength(bytes, offset: offset)
        offset += seqLenSize

        // First INTEGER (r)
        let r = try readDERInteger(&bytes, offset: &offset, componentLength: componentLength)

        // Second INTEGER (s)
        let s = try readDERInteger(&bytes, offset: &offset, componentLength: componentLength)

        return Data(r + s)
    }

    /// Convert a raw r||s signature to DER format.
    ///
    /// - Parameters:
    ///   - rawSignature: The raw signature as r||s concatenation.
    ///   - componentLength: The byte length of each component (32 for P-256).
    /// - Returns: The DER-encoded signature.
    public static func rawToDER(_ rawSignature: Data, componentLength: Int = 32) throws -> Data {
        let bytes = [UInt8](rawSignature)
        guard bytes.count == componentLength * 2 else {
            throw Error.invalidDERStructure
        }

        let r = Array(bytes[0..<componentLength])
        let s = Array(bytes[componentLength..<componentLength * 2])

        let rDER = integerToDER(r)
        let sDER = integerToDER(s)

        var result = [UInt8]()
        let contentLength = rDER.count + sDER.count
        result.append(0x30) // SEQUENCE
        result.append(contentsOf: encodeDERLength(contentLength))
        result.append(contentsOf: rDER)
        result.append(contentsOf: sDER)

        return Data(result)
    }

    // MARK: - Private Helpers

    private static func readDERLength(_ bytes: [UInt8], offset: Int) throws -> (Int, Int) {
        guard offset < bytes.count else { throw Error.invalidDERStructure }

        if bytes[offset] < 0x80 {
            return (Int(bytes[offset]), 1)
        }

        let numLenBytes = Int(bytes[offset] & 0x7F)
        guard offset + numLenBytes < bytes.count else { throw Error.invalidDERStructure }

        var length = 0
        for i in 1...numLenBytes {
            length = (length << 8) | Int(bytes[offset + i])
        }
        return (length, 1 + numLenBytes)
    }

    private static func readDERInteger(
        _ bytes: inout [UInt8],
        offset: inout Int,
        componentLength: Int
    ) throws -> [UInt8] {
        guard offset < bytes.count, bytes[offset] == 0x02 else {
            throw Error.unexpectedTag(offset < bytes.count ? bytes[offset] : 0)
        }
        offset += 1

        let (intLen, lenSize) = try readDERLength(bytes, offset: offset)
        offset += lenSize

        guard offset + intLen <= bytes.count else {
            throw Error.invalidDERStructure
        }

        var intBytes = Array(bytes[offset..<offset + intLen])
        offset += intLen

        // Strip leading zero padding (DER uses it to keep integers positive)
        while intBytes.count > componentLength && intBytes.first == 0x00 {
            intBytes.removeFirst()
        }

        // Pad to component length if shorter
        while intBytes.count < componentLength {
            intBytes.insert(0x00, at: 0)
        }

        guard intBytes.count == componentLength else {
            throw Error.integerTooLong
        }

        return intBytes
    }

    private static func integerToDER(_ value: [UInt8]) -> [UInt8] {
        var trimmed = value
        // Remove leading zeros but keep at least one byte
        while trimmed.count > 1 && trimmed.first == 0x00 {
            trimmed.removeFirst()
        }
        // Add leading zero if high bit is set (to keep the integer positive in DER)
        if let first = trimmed.first, first & 0x80 != 0 {
            trimmed.insert(0x00, at: 0)
        }

        var result = [UInt8]()
        result.append(0x02) // INTEGER tag
        result.append(contentsOf: encodeDERLength(trimmed.count))
        result.append(contentsOf: trimmed)
        return result
    }

    private static func encodeDERLength(_ length: Int) -> [UInt8] {
        if length < 0x80 {
            return [UInt8(length)]
        }
        // For lengths we encounter in EC signatures, single-byte extended is sufficient
        return [0x81, UInt8(length)]
    }
}
