import XCTest
import CryptoKit
@testable import HTTPMessageSignatures

final class SignerVerifierTests: XCTestCase {

    // MARK: - P-256 (ES256) Round-Trip

    func testP256RoundTrip() throws {
        let key = CryptoKitP256SigningKey()
        let signer = HTTPMessageSigner(key: key, label: "sig")

        var request = URLRequest(url: URL(string: "https://wallet.hello.coop/api/v1/mobile/register")!)
        request.httpMethod = "POST"

        let signed = try signer.sign(request, created: 1732210000)

        // Verify the three headers are present
        XCTAssertNotNil(signed.value(forHTTPHeaderField: "Signature-Input"))
        XCTAssertNotNil(signed.value(forHTTPHeaderField: "Signature"))
        XCTAssertNotNil(signed.value(forHTTPHeaderField: "Signature-Key"))

        // Verify signature
        let result = try HTTPMessageVerifier.verify(request: signed)

        XCTAssertEqual(result.label, "sig")
        XCTAssertEqual(result.jwk, key.publicKeyJWK)
        XCTAssertEqual(result.parameters.created, 1732210000)
        XCTAssertEqual(result.components, ["@method", "@authority", "@path", "signature-key"])
    }

    // MARK: - Ed25519 (EdDSA) Round-Trip

    func testEd25519RoundTrip() throws {
        let key = CryptoKitCurve25519SigningKey()
        let signer = HTTPMessageSigner(key: key, label: "sig")

        var request = URLRequest(url: URL(string: "https://example.com/api/test")!)
        request.httpMethod = "GET"

        let signed = try signer.sign(request, created: 1700000000)

        let result = try HTTPMessageVerifier.verify(request: signed)

        XCTAssertEqual(result.label, "sig")
        XCTAssertEqual(result.jwk, key.publicKeyJWK)
        XCTAssertEqual(result.parameters.created, 1700000000)
    }

    // MARK: - Tampered Request

    func testVerificationFailsOnTamperedMethod() throws {
        let key = CryptoKitP256SigningKey()
        let signer = HTTPMessageSigner(key: key)

        var request = URLRequest(url: URL(string: "https://example.com/api")!)
        request.httpMethod = "POST"

        var signed = try signer.sign(request, created: 1732210000)

        // Tamper with the method
        signed.httpMethod = "PUT"

        XCTAssertThrowsError(try HTTPMessageVerifier.verify(request: signed)) { error in
            guard let verifyError = error as? HTTPMessageVerifier.Error else {
                XCTFail("Expected HTTPMessageVerifier.Error")
                return
            }
            if case .signatureVerificationFailed = verifyError {
                // expected
            } else {
                XCTFail("Expected signatureVerificationFailed, got \(verifyError)")
            }
        }
    }

    func testVerificationFailsOnTamperedPath() throws {
        let key = CryptoKitP256SigningKey()
        let signer = HTTPMessageSigner(key: key)

        var request = URLRequest(url: URL(string: "https://example.com/api/secure")!)
        request.httpMethod = "POST"

        let signed = try signer.sign(request, created: 1732210000)

        // Create a new request with different path but same headers
        var tampered = URLRequest(url: URL(string: "https://example.com/api/admin")!)
        tampered.httpMethod = "POST"
        tampered.setValue(
            signed.value(forHTTPHeaderField: "Signature-Input"),
            forHTTPHeaderField: "Signature-Input"
        )
        tampered.setValue(
            signed.value(forHTTPHeaderField: "Signature"),
            forHTTPHeaderField: "Signature"
        )
        tampered.setValue(
            signed.value(forHTTPHeaderField: "Signature-Key"),
            forHTTPHeaderField: "Signature-Key"
        )

        XCTAssertThrowsError(try HTTPMessageVerifier.verify(request: tampered))
    }

    // MARK: - Missing Headers

    func testVerificationFailsMissingSignatureInput() throws {
        var request = URLRequest(url: URL(string: "https://example.com/")!)
        request.setValue("sig=:dGVzdA==:", forHTTPHeaderField: "Signature")
        request.setValue("sig=hwk;kty=\"EC\";crv=\"P-256\";x=\"a\";y=\"b\"", forHTTPHeaderField: "Signature-Key")

        XCTAssertThrowsError(try HTTPMessageVerifier.verify(request: request)) { error in
            guard let verifyError = error as? HTTPMessageVerifier.Error,
                  case .missingHeader("Signature-Input") = verifyError else {
                XCTFail("Expected missingHeader(Signature-Input)")
                return
            }
        }
    }

    // MARK: - Custom Components

    func testCustomComponentsCovered() throws {
        let key = CryptoKitP256SigningKey()
        let signer = HTTPMessageSigner(
            key: key,
            components: ["@method", "@authority", "@path", "@scheme", "signature-key"]
        )

        var request = URLRequest(url: URL(string: "https://wallet.hello.coop/api/test")!)
        request.httpMethod = "POST"

        let signed = try signer.sign(request, created: 1732210000)
        let result = try HTTPMessageVerifier.verify(request: signed)

        XCTAssertEqual(result.components.count, 5)
        XCTAssertTrue(result.components.contains("@scheme"))
    }

    // MARK: - Tag Parameter

    func testSignerWithTag() throws {
        let key = CryptoKitP256SigningKey()
        let signer = HTTPMessageSigner(key: key, tag: "mobile-app")

        var request = URLRequest(url: URL(string: "https://example.com/api")!)
        request.httpMethod = "POST"

        let signed = try signer.sign(request, created: 1732210000)

        let sigInput = signed.value(forHTTPHeaderField: "Signature-Input")!
        XCTAssertTrue(sigInput.contains("tag=\"mobile-app\""))
    }

    // MARK: - Signature-Key in Signature-Input Header Format

    func testSignatureInputFormat() throws {
        let key = CryptoKitP256SigningKey()
        let signer = HTTPMessageSigner(key: key, label: "sig")

        var request = URLRequest(url: URL(string: "https://example.com/path")!)
        request.httpMethod = "POST"

        let signed = try signer.sign(request, created: 1732210000)

        let sigInput = signed.value(forHTTPHeaderField: "Signature-Input")!
        XCTAssertTrue(sigInput.hasPrefix("sig=("))
        XCTAssertTrue(sigInput.contains("\"@method\""))
        XCTAssertTrue(sigInput.contains("\"signature-key\""))
        XCTAssertTrue(sigInput.contains("created=1732210000"))
    }

    // MARK: - Signature Header Format

    func testSignatureHeaderFormat() throws {
        let key = CryptoKitP256SigningKey()
        let signer = HTTPMessageSigner(key: key, label: "sig")

        var request = URLRequest(url: URL(string: "https://example.com/path")!)
        request.httpMethod = "POST"

        let signed = try signer.sign(request, created: 1732210000)

        let sigHeader = signed.value(forHTTPHeaderField: "Signature")!
        XCTAssertTrue(sigHeader.hasPrefix("sig=:"))
        XCTAssertTrue(sigHeader.hasSuffix(":"))
    }

    // MARK: - HWK Signature-Key Format

    func testSignatureKeyHWKFormat() throws {
        let key = CryptoKitP256SigningKey()
        let signer = HTTPMessageSigner(key: key, label: "sig")

        var request = URLRequest(url: URL(string: "https://example.com/path")!)
        request.httpMethod = "POST"

        let signed = try signer.sign(request, created: 1732210000)

        let skHeader = signed.value(forHTTPHeaderField: "Signature-Key")!
        XCTAssertTrue(skHeader.hasPrefix("sig=hwk;"))
        XCTAssertTrue(skHeader.contains("kty=\"EC\""))
        XCTAssertTrue(skHeader.contains("crv=\"P-256\""))
        XCTAssertTrue(skHeader.contains("x=\""))
        XCTAssertTrue(skHeader.contains("y=\""))
        // alg must NOT be present
        XCTAssertFalse(skHeader.contains("alg="))
    }

    // MARK: - Signature-Key Not Covered Error

    func testVerificationFailsIfSignatureKeyNotCovered() throws {
        let key = CryptoKitP256SigningKey()

        // Manually create a signed request without "signature-key" in components
        let components = ["@method", "@authority", "@path"]
        let params = SignatureParameters(created: 1732210000)

        var request = URLRequest(url: URL(string: "https://example.com/api")!)
        request.httpMethod = "POST"

        let skValue = SignatureKeyValue.hwk(HWKScheme(jwk: key.publicKeyJWK))
        let skHeader = skValue.serialize(label: "sig")

        let base = SignatureBase(
            request: request,
            components: components,
            signatureKeyHeader: skHeader,
            parameters: params
        )

        let signature = try key.sign(base.dataToSign)

        let sigInput = SignatureInput(label: "sig", components: components, parameters: params)
        let sigHeader = SignatureHeader(label: "sig", signature: signature)

        request.setValue(sigInput.serialize(), forHTTPHeaderField: "Signature-Input")
        request.setValue(sigHeader.serialize(), forHTTPHeaderField: "Signature")
        request.setValue(skHeader, forHTTPHeaderField: "Signature-Key")

        XCTAssertThrowsError(try HTTPMessageVerifier.verify(request: request)) { error in
            guard let verifyError = error as? HTTPMessageVerifier.Error,
                  case .signatureKeyNotCovered = verifyError else {
                XCTFail("Expected signatureKeyNotCovered, got \(error)")
                return
            }
        }
    }
}
