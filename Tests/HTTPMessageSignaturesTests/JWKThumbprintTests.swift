import XCTest
@testable import HTTPMessageSignatures

final class JWKThumbprintTests: XCTestCase {

    func testECThumbprint() throws {
        // Known test vector: compute thumbprint of a P-256 key
        let jwk = JWKParameters.ec(
            crv: "P-256",
            x: "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
            y: "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"
        )

        let thumbprint = try JWKThumbprint.compute(jwk)

        // Thumbprint should be a base64url string (43 characters for SHA-256)
        XCTAssertEqual(thumbprint.count, 43)
        // Should not contain padding or non-base64url characters
        XCTAssertFalse(thumbprint.contains("="))
        XCTAssertFalse(thumbprint.contains("+"))
        XCTAssertFalse(thumbprint.contains("/"))
    }

    func testOKPThumbprint() throws {
        let jwk = JWKParameters.okp(
            crv: "Ed25519",
            x: "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
        )

        let thumbprint = try JWKThumbprint.compute(jwk)
        XCTAssertEqual(thumbprint.count, 43)
    }

    func testDeterministic() throws {
        let jwk = JWKParameters.ec(
            crv: "P-256",
            x: "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
            y: "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"
        )

        let t1 = try JWKThumbprint.compute(jwk)
        let t2 = try JWKThumbprint.compute(jwk)
        XCTAssertEqual(t1, t2)
    }

    func testDifferentKeysProduceDifferentThumbprints() throws {
        let jwk1 = JWKParameters.ec(crv: "P-256", x: "aaaa", y: "bbbb")
        let jwk2 = JWKParameters.ec(crv: "P-256", x: "cccc", y: "dddd")

        let t1 = try JWKThumbprint.compute(jwk1)
        let t2 = try JWKThumbprint.compute(jwk2)
        XCTAssertNotEqual(t1, t2)
    }

    func testECMissingYThrows() {
        let jwk = JWKParameters(kty: "EC", crv: "P-256", x: "abc", y: nil)
        XCTAssertThrowsError(try JWKThumbprint.compute(jwk))
    }

    func testUnsupportedKeyTypeThrows() {
        let jwk = JWKParameters(kty: "RSA", crv: "", x: "abc")
        XCTAssertThrowsError(try JWKThumbprint.compute(jwk))
    }

    // MARK: - Base64URL

    func testBase64URLEncode() {
        let data = Data([0xFF, 0xFE, 0xFD])
        let encoded = Base64URL.encode(data)
        XCTAssertFalse(encoded.contains("+"))
        XCTAssertFalse(encoded.contains("/"))
        XCTAssertFalse(encoded.contains("="))
    }

    func testBase64URLRoundTrip() {
        let original = Data("Hello, HTTP Signatures!".utf8)
        let encoded = Base64URL.encode(original)
        let decoded = Base64URL.decode(encoded)
        XCTAssertEqual(decoded, original)
    }

    func testBase64URLDecodeWithPadding() {
        // "a" base64 = "YQ==" -> base64url = "YQ"
        let decoded = Base64URL.decode("YQ")
        XCTAssertEqual(decoded, Data("a".utf8))
    }
}
