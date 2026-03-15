import XCTest
import CryptoKit
@testable import HTTPMessageSignatures

final class DERConversionTests: XCTestCase {

    // MARK: - DER to Raw Conversion

    func testDERToRaw() throws {
        // A known DER-encoded P-256 ECDSA signature
        // SEQUENCE { INTEGER r (32 bytes), INTEGER s (32 bytes) }
        // This is a hand-crafted example with no leading zeros needed
        var der = Data()
        der.append(0x30) // SEQUENCE
        der.append(0x44) // length 68

        // r: 32-byte integer with leading 0x00 (positive, high bit set)
        der.append(0x02) // INTEGER
        der.append(0x21) // length 33
        der.append(0x00) // leading zero
        der.append(contentsOf: [UInt8](repeating: 0xAB, count: 32))

        // s: 32-byte integer (no leading zero needed)
        der.append(0x02) // INTEGER
        der.append(0x20) // length 32
        der.append(contentsOf: [UInt8](repeating: 0xCD, count: 32))

        let raw = try DERSignatureConverter.derToRaw(der, componentLength: 32)
        XCTAssertEqual(raw.count, 64)

        // r should be the 32 AB bytes
        let r = [UInt8](raw[0..<32])
        XCTAssertEqual(r, [UInt8](repeating: 0xAB, count: 32))

        // s should be the 32 CD bytes
        let s = [UInt8](raw[32..<64])
        XCTAssertEqual(s, [UInt8](repeating: 0xCD, count: 32))
    }

    func testRawToDER() throws {
        var raw = Data()
        raw.append(contentsOf: [UInt8](repeating: 0xAB, count: 32))
        raw.append(contentsOf: [UInt8](repeating: 0xCD, count: 32))

        let der = try DERSignatureConverter.rawToDER(raw, componentLength: 32)

        // Verify DER structure
        let bytes = [UInt8](der)
        XCTAssertEqual(bytes[0], 0x30) // SEQUENCE

        // Convert back and verify round-trip
        let roundTripped = try DERSignatureConverter.derToRaw(der, componentLength: 32)
        XCTAssertEqual(roundTripped, raw)
    }

    func testRoundTripSmallIntegers() throws {
        // Test with small r and s values (lots of leading zeros)
        var raw = Data(count: 64)
        raw[31] = 0x01 // r = 1
        raw[63] = 0x02 // s = 2

        let der = try DERSignatureConverter.rawToDER(raw, componentLength: 32)
        let roundTripped = try DERSignatureConverter.derToRaw(der, componentLength: 32)
        XCTAssertEqual(roundTripped, raw)
    }

    func testRoundTripHighBitSet() throws {
        // r and s with high bit set (requires DER leading zero)
        var raw = Data()
        raw.append(contentsOf: [UInt8](repeating: 0xFF, count: 32))
        raw.append(contentsOf: [UInt8](repeating: 0x80, count: 32))

        let der = try DERSignatureConverter.rawToDER(raw, componentLength: 32)
        let roundTripped = try DERSignatureConverter.derToRaw(der, componentLength: 32)
        XCTAssertEqual(roundTripped, raw)
    }

    // MARK: - Real CryptoKit Signature

    func testCryptoKitSignatureDERConversion() throws {
        // CryptoKit P256 uses rawRepresentation (not DER), but we can test
        // the DER conversion by going raw -> DER -> raw
        let privateKey = P256.Signing.PrivateKey()
        let data = Data("test data for signing".utf8)

        let signature = try privateKey.signature(for: data)
        let rawSig = signature.rawRepresentation

        XCTAssertEqual(rawSig.count, 64)

        // Convert to DER and back
        let der = try DERSignatureConverter.rawToDER(rawSig, componentLength: 32)
        let backToRaw = try DERSignatureConverter.derToRaw(der, componentLength: 32)

        XCTAssertEqual(backToRaw, rawSig)

        // Verify the round-tripped signature still validates
        let ecdsaSig = try P256.Signing.ECDSASignature(rawRepresentation: backToRaw)
        XCTAssertTrue(privateKey.publicKey.isValidSignature(ecdsaSig, for: data))
    }

    // MARK: - Error Cases

    func testInvalidDERTag() {
        // Not a SEQUENCE
        let bad = Data([0x31, 0x04, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02])
        XCTAssertThrowsError(try DERSignatureConverter.derToRaw(bad))
    }

    func testInvalidRawLength() {
        // Wrong length for 32-byte components
        let bad = Data(count: 63)
        XCTAssertThrowsError(try DERSignatureConverter.rawToDER(bad, componentLength: 32))
    }
}
