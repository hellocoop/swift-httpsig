import XCTest
@testable import HTTPMessageSignatures

final class SignatureBaseTests: XCTestCase {

    func testBasicSignatureBase() throws {
        var request = URLRequest(url: URL(string: "https://wallet.hello.coop/api/v1/mobile/register")!)
        request.httpMethod = "POST"

        let signatureKeyHeader = "sig=hwk;kty=\"EC\";crv=\"P-256\";x=\"test_x\";y=\"test_y\""

        let params = SignatureParameters(created: 1732210000)
        let base = SignatureBase(
            request: request,
            components: ["@method", "@authority", "@path", "signature-key"],
            signatureKeyHeader: signatureKeyHeader,
            parameters: params
        )

        let serialized = base.serialize()

        // Verify each line
        let lines = serialized.split(separator: "\n", omittingEmptySubsequences: false)
        XCTAssertEqual(lines.count, 5)
        XCTAssertEqual(lines[0], "\"@method\": POST")
        XCTAssertEqual(lines[1], "\"@authority\": wallet.hello.coop")
        XCTAssertEqual(lines[2], "\"@path\": /api/v1/mobile/register")
        XCTAssertEqual(lines[3], "\"signature-key\": \(signatureKeyHeader)")
        XCTAssertEqual(
            lines[4],
            "\"@signature-params\": (\"@method\" \"@authority\" \"@path\" \"signature-key\");created=1732210000"
        )
    }

    func testMethodResolution() {
        var request = URLRequest(url: URL(string: "https://example.com/")!)
        request.httpMethod = "GET"

        let value = SignatureBase.resolveComponent("@method", from: request, signatureKeyHeader: nil)
        XCTAssertEqual(value, "GET")
    }

    func testAuthorityWithDefaultPort() {
        let request = URLRequest(url: URL(string: "https://example.com:443/path")!)
        let value = SignatureBase.resolveComponent("@authority", from: request, signatureKeyHeader: nil)
        XCTAssertEqual(value, "example.com")
    }

    func testAuthorityWithNonDefaultPort() {
        let request = URLRequest(url: URL(string: "https://example.com:8443/path")!)
        let value = SignatureBase.resolveComponent("@authority", from: request, signatureKeyHeader: nil)
        XCTAssertEqual(value, "example.com:8443")
    }

    func testPathResolution() {
        let request = URLRequest(url: URL(string: "https://example.com/api/v1/test")!)
        let value = SignatureBase.resolveComponent("@path", from: request, signatureKeyHeader: nil)
        XCTAssertEqual(value, "/api/v1/test")
    }

    func testSchemeResolution() {
        let request = URLRequest(url: URL(string: "https://example.com/")!)
        let value = SignatureBase.resolveComponent("@scheme", from: request, signatureKeyHeader: nil)
        XCTAssertEqual(value, "https")
    }

    func testQueryResolution() {
        let request = URLRequest(url: URL(string: "https://example.com/search?q=hello&page=1")!)
        let value = SignatureBase.resolveComponent("@query", from: request, signatureKeyHeader: nil)
        XCTAssertEqual(value, "?q=hello&page=1")
    }

    func testQueryResolutionNoQuery() {
        let request = URLRequest(url: URL(string: "https://example.com/path")!)
        let value = SignatureBase.resolveComponent("@query", from: request, signatureKeyHeader: nil)
        XCTAssertEqual(value, "?")
    }

    func testSignatureKeyComponent() {
        let request = URLRequest(url: URL(string: "https://example.com/")!)
        let skHeader = "sig=hwk;kty=\"EC\";crv=\"P-256\";x=\"abc\";y=\"def\""
        let value = SignatureBase.resolveComponent("signature-key", from: request, signatureKeyHeader: skHeader)
        XCTAssertEqual(value, skHeader)
    }

    func testCustomHeaderResolution() {
        var request = URLRequest(url: URL(string: "https://example.com/")!)
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")

        let value = SignatureBase.resolveComponent("content-type", from: request, signatureKeyHeader: nil)
        XCTAssertEqual(value, "application/json")
    }

    func testSignatureParamsLine() {
        let params = SignatureParameters(created: 1732210000, alg: "es256")
        let base = SignatureBase(
            components: ["@method", "@path"],
            componentValues: ["@method": "POST", "@path": "/test"],
            parameters: params
        )

        XCTAssertEqual(
            base.signatureParamsLine,
            "(\"@method\" \"@path\");created=1732210000;alg=\"es256\""
        )
    }

    func testSignatureParametersSerialization() {
        let params = SignatureParameters(
            created: 1732210000,
            alg: "es256",
            keyid: "mykey",
            nonce: "abc123",
            expires: 1732213600,
            tag: "myapp"
        )

        let serialized = params.serialize()
        XCTAssertTrue(serialized.contains("created=1732210000"))
        XCTAssertTrue(serialized.contains("alg=\"es256\""))
        XCTAssertTrue(serialized.contains("keyid=\"mykey\""))
        XCTAssertTrue(serialized.contains("nonce=\"abc123\""))
        XCTAssertTrue(serialized.contains("expires=1732213600"))
        XCTAssertTrue(serialized.contains("tag=\"myapp\""))
    }
}
