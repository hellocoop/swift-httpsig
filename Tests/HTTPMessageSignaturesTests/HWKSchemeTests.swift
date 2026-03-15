import XCTest
@testable import HTTPMessageSignatures

final class HWKSchemeTests: XCTestCase {

    func testParseECKey() throws {
        let params = "kty=\"EC\";crv=\"P-256\";x=\"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU\";y=\"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0\""
        let hwk = try HWKScheme.parse(params: params)

        XCTAssertEqual(hwk.kty, "EC")
        XCTAssertEqual(hwk.crv, "P-256")
        XCTAssertEqual(hwk.x, "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU")
        XCTAssertEqual(hwk.y, "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0")
    }

    func testParseOKPKey() throws {
        let params = "kty=\"OKP\";crv=\"Ed25519\";x=\"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo\""
        let hwk = try HWKScheme.parse(params: params)

        XCTAssertEqual(hwk.kty, "OKP")
        XCTAssertEqual(hwk.crv, "Ed25519")
        XCTAssertEqual(hwk.x, "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo")
        XCTAssertNil(hwk.y)
    }

    func testParseMissingKty() {
        let params = "crv=\"P-256\";x=\"abc\";y=\"def\""
        XCTAssertThrowsError(try HWKScheme.parse(params: params)) { error in
            guard let skError = error as? SignatureKeyError,
                  case .missingParameter("kty") = skError else {
                XCTFail("Expected missingParameter(kty)")
                return
            }
        }
    }

    func testParseMissingYForEC() {
        let params = "kty=\"EC\";crv=\"P-256\";x=\"abc\""
        XCTAssertThrowsError(try HWKScheme.parse(params: params)) { error in
            guard let skError = error as? SignatureKeyError,
                  case .missingParameter("y") = skError else {
                XCTFail("Expected missingParameter(y)")
                return
            }
        }
    }

    func testSerializeEC() {
        let hwk = HWKScheme(kty: "EC", crv: "P-256", x: "abc123", y: "def456")
        let serialized = hwk.serialize()

        XCTAssertEqual(serialized, "hwk;kty=\"EC\";crv=\"P-256\";x=\"abc123\";y=\"def456\"")
    }

    func testSerializeOKP() {
        let hwk = HWKScheme(kty: "OKP", crv: "Ed25519", x: "abc123")
        let serialized = hwk.serialize()

        XCTAssertEqual(serialized, "hwk;kty=\"OKP\";crv=\"Ed25519\";x=\"abc123\"")
        XCTAssertFalse(serialized.contains(";y="))
    }

    func testRoundTripThroughSignatureKeyHeader() throws {
        let original = HWKScheme(kty: "EC", crv: "P-256", x: "testX", y: "testY")
        let headerValue = SignatureKeyValue.hwk(original).serialize(label: "sig")

        let (label, parsed) = try SignatureKeyValue.parse(headerValue)
        XCTAssertEqual(label, "sig")

        guard case .hwk(let parsedHWK) = parsed else {
            XCTFail("Expected hwk scheme")
            return
        }

        XCTAssertEqual(parsedHWK.kty, "EC")
        XCTAssertEqual(parsedHWK.crv, "P-256")
        XCTAssertEqual(parsedHWK.x, "testX")
        XCTAssertEqual(parsedHWK.y, "testY")
    }

    func testNoAlgInSerialized() {
        let hwk = HWKScheme(kty: "EC", crv: "P-256", x: "x", y: "y")
        let serialized = hwk.serialize()
        XCTAssertFalse(serialized.contains("alg"))
    }

    func testJWKParametersRoundTrip() {
        let jwk = JWKParameters.ec(crv: "P-256", x: "testX", y: "testY")
        let hwk = HWKScheme(jwk: jwk)
        let roundTripped = hwk.toJWKParameters()

        XCTAssertEqual(roundTripped, jwk)
    }

    // MARK: - Signature-Key Header Parsing

    func testParseJWTScheme() throws {
        let header = "sig=jwt;jwt=\"eyJhbGciOiJFUzI1NiJ9.eyJjbmYiOnsiand7Ijp7Imt0eSI6IkVDIn19fQ.sig\""
        let (label, value) = try SignatureKeyValue.parse(header)

        XCTAssertEqual(label, "sig")
        guard case .jwt(let jwt) = value else {
            XCTFail("Expected jwt scheme")
            return
        }
        XCTAssertTrue(jwt.jwt.hasPrefix("eyJ"))
    }

    func testParseJWKSURIScheme() throws {
        let header = "sig=jwks_uri;id=\"https://issuer.example.com\";well-known=\"aauth-agent\";kid=\"key-1\""
        let (label, value) = try SignatureKeyValue.parse(header)

        XCTAssertEqual(label, "sig")
        guard case .jwksURI(let jwksURI) = value else {
            XCTFail("Expected jwks_uri scheme")
            return
        }
        XCTAssertEqual(jwksURI.id, "https://issuer.example.com")
        XCTAssertEqual(jwksURI.wellKnown, "aauth-agent")
        XCTAssertEqual(jwksURI.kid, "key-1")
    }

    func testJWKSURIDiscoveryURL() {
        let scheme = JWKSURIScheme(id: "https://issuer.example.com", wellKnown: "aauth-agent", kid: "key-1")
        let url = scheme.discoveryURL()
        XCTAssertEqual(url?.absoluteString, "https://issuer.example.com/.well-known/aauth-agent")
    }

    func testUnknownScheme() {
        let header = "sig=unknown;param=\"value\""
        XCTAssertThrowsError(try SignatureKeyValue.parse(header)) { error in
            guard let skError = error as? SignatureKeyError,
                  case .unknownScheme("unknown") = skError else {
                XCTFail("Expected unknownScheme")
                return
            }
        }
    }
}
