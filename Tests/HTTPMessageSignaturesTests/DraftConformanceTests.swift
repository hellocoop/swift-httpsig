import CryptoKit
import XCTest

@testable import HTTPMessageSignatures

/// Conformance to draft-hardt-httpbis-signature-key-08 for the parts added in
/// 2.0: the jwks and self-jwt schemes, the negotiation headers, the error
/// codes, and the rules that tightened from -07.
final class DraftConformanceTests: XCTestCase {

    // MARK: - hwk forbids kid

    func testHwkRejectsKid() {
        // The key is inline, so an identifier selects nothing and one that
        // disagrees with the inline key has no defined resolution.
        let header =
            "sig=hwk;alg=\"Ed25519\";kty=\"OKP\";crv=\"Ed25519\";x=\"abc\";kid=\"k1\""
        XCTAssertThrowsError(try SignatureKeyValue.parse(header)) { error in
            XCTAssertEqual(error as? SignatureKeyError, .forbiddenParameter("kid"))
        }
    }

    func testHwkWithoutKidParses() throws {
        let header = "sig=hwk;alg=\"Ed25519\";kty=\"OKP\";crv=\"Ed25519\";x=\"abc\""
        let (label, value) = try SignatureKeyValue.parse(header)
        XCTAssertEqual(label, "sig")
        guard case .hwk(let hwk) = value else { return XCTFail("expected hwk") }
        XCTAssertEqual(hwk.alg, "Ed25519")
    }

    // MARK: - jwks_uri uses dwk, and all three parameters are required

    func testJwksURIRequiresIdDwkAndKid() {
        for header in [
            "sig=jwks_uri;dwk=\"meta\";kid=\"k1\"",
            "sig=jwks_uri;id=\"https://i.example\";kid=\"k1\"",
            "sig=jwks_uri;id=\"https://i.example\";dwk=\"meta\"",
        ] {
            XCTAssertThrowsError(try SignatureKeyValue.parse(header), header)
        }
    }

    func testJwksURIDiscoveryURL() throws {
        let scheme = JWKSURIScheme(id: "https://issuer.example", dwk: "aauth-agent", kid: "k1")
        XCTAssertEqual(
            scheme.discoveryURL()?.absoluteString,
            "https://issuer.example/.well-known/aauth-agent")
    }

    func testJwksURIDiscoveryURLTolerersTrailingSlash() throws {
        let scheme = JWKSURIScheme(id: "https://issuer.example/", dwk: "meta", kid: "k1")
        XCTAssertEqual(
            scheme.discoveryURL()?.absoluteString,
            "https://issuer.example/.well-known/meta")
    }

    func testJwksURIRoundTrip() throws {
        let header = "sig=jwks_uri;id=\"https://i.example\";dwk=\"meta\";kid=\"k1\""
        let (label, value) = try SignatureKeyValue.parse(header)
        XCTAssertEqual(value.serialize(label: label), header)
    }

    // MARK: - discovery metadata issuer binding

    func testMetadataIssuerMustMatchIdentity() throws {
        let good = DiscoveryMetadata(
            issuer: "https://i.example", jwksURI: "https://i.example/keys")
        XCTAssertEqual(
            try good.validate(fetchedUnder: "https://i.example"), "https://i.example/keys")
    }

    func testMetadataWithoutIssuerIsRejected() {
        let doc = DiscoveryMetadata(issuer: nil, jwksURI: "https://i.example/keys")
        XCTAssertThrowsError(try doc.validate(fetchedUnder: "https://i.example")) { error in
            XCTAssertEqual(error as? SignatureKeyError, .issuerMissing("https://i.example"))
        }
    }

    func testMetadataClaimingAnotherIssuerIsRejected() {
        // The attack: a document served under one identity pointing jwks_uri
        // at keys belonging to another.
        let doc = DiscoveryMetadata(
            issuer: "https://attacker.example", jwksURI: "https://attacker.example/keys")
        XCTAssertThrowsError(try doc.validate(fetchedUnder: "https://i.example")) { error in
            XCTAssertEqual(
                error as? SignatureKeyError,
                .issuerMismatch(expected: "https://i.example", found: "https://attacker.example"))
        }
    }

    func testIssuerComparisonIsByteEquality() {
        // A trailing slash is a different identifier. No normalization.
        let doc = DiscoveryMetadata(
            issuer: "https://i.example/", jwksURI: "https://i.example/keys")
        XCTAssertThrowsError(try doc.validate(fetchedUnder: "https://i.example"))
    }

    // MARK: - jwks scheme

    func testJwksParsesAndRoundTrips() throws {
        let header = "sig=jwks;url=\"https://client.example/keys.jwks\";kid=\"key-1\""
        let (label, value) = try SignatureKeyValue.parse(header)
        guard case .jwks(let jwks) = value else { return XCTFail("expected jwks") }
        XCTAssertEqual(jwks.url, "https://client.example/keys.jwks")
        XCTAssertEqual(jwks.kid, "key-1")
        XCTAssertEqual(value.serialize(label: label), header)
    }

    func testJwksRequiresUrlAndKid() {
        XCTAssertThrowsError(try SignatureKeyValue.parse("sig=jwks;kid=\"k1\""))
        XCTAssertThrowsError(
            try SignatureKeyValue.parse("sig=jwks;url=\"https://c.example/k\""))
    }

    func testJwksRejectsNonHTTPSURL() {
        XCTAssertNil(JWKSScheme(url: "http://c.example/keys", kid: "k1").jwksURL())
        XCTAssertNotNil(JWKSScheme(url: "https://c.example/keys", kid: "k1").jwksURL())
    }

    func testJwksIdentityIsByteEquality() {
        // Identity and key location are the same string, so any byte
        // difference names a different signer.
        XCTAssertTrue(
            JWKSScheme.sameIdentity("https://c.example/k", "https://c.example/k"))
        XCTAssertFalse(
            JWKSScheme.sameIdentity("https://c.example/k", "https://c.example/k/"))
    }

    func testJwksCarriesNoInlineKey() throws {
        let (_, value) = try SignatureKeyValue.parse(
            "sig=jwks;url=\"https://c.example/k\";kid=\"k1\"")
        XCTAssertNil(try value.jwkParameters())
    }

    // MARK: - self-jwt scheme

    /// Build a self-jwt signed by `key`.
    private func makeSelfJWT(
        key: CryptoKitP256SigningKey,
        iss: String = "https://issuer.example",
        dwk: String? = "aauth-issuer",
        kid: String? = "k1",
        expOffset: Int = 3600,
        includeExp: Bool = true,
        includeCnf: Bool = false
    ) throws -> String {
        var header: [String: Any] = ["typ": "self+jwt", "alg": key.algorithm]
        if let kid = kid { header["kid"] = kid }

        var payload: [String: Any] = ["iss": iss, "sub": "agent-1"]
        if let dwk = dwk { payload["dwk"] = dwk }
        if includeExp {
            payload["exp"] = Int(Date().timeIntervalSince1970) + expOffset
        }
        if includeCnf {
            payload["cnf"] = ["jwk": ["kty": "OKP", "crv": "Ed25519", "x": "abc"]]
        }

        let h = Base64URL.encode(
            try JSONSerialization.data(withJSONObject: header, options: [.sortedKeys]))
        let p = Base64URL.encode(
            try JSONSerialization.data(withJSONObject: payload, options: [.sortedKeys]))
        let signature = try key.sign(Data("\(h).\(p)".utf8))
        return "\(h).\(p).\(Base64URL.encode(signature))"
    }

    func testSelfJWTDecodesItsClaims() throws {
        let key = CryptoKitP256SigningKey()
        let scheme = SelfJWTScheme(jwt: try makeSelfJWT(key: key))
        let claims = try scheme.decode()

        XCTAssertEqual(claims.iss, "https://issuer.example")
        XCTAssertEqual(claims.dwk, "aauth-issuer")
        XCTAssertEqual(claims.kid, "k1")
        XCTAssertEqual(
            claims.discoveryURL()?.absoluteString,
            "https://issuer.example/.well-known/aauth-issuer")
    }

    func testSelfJWTRejectsCnf() throws {
        // A self-jwt's signing key is its confirmation key. A cnf claim means
        // it is a jwt-scheme assertion under the wrong scheme.
        let key = CryptoKitP256SigningKey()
        let scheme = SelfJWTScheme(jwt: try makeSelfJWT(key: key, includeCnf: true))
        XCTAssertThrowsError(try scheme.decode())
    }

    func testSelfJWTRequiresIssDwkKidAndExp() throws {
        let key = CryptoKitP256SigningKey()
        for jwt in [
            try makeSelfJWT(key: key, dwk: nil),
            try makeSelfJWT(key: key, kid: nil),
            try makeSelfJWT(key: key, includeExp: false),
        ] {
            XCTAssertThrowsError(try SelfJWTScheme(jwt: jwt).decode())
        }
    }

    func testSelfJWTRejectsExpired() throws {
        let key = CryptoKitP256SigningKey()
        let scheme = SelfJWTScheme(jwt: try makeSelfJWT(key: key, expOffset: -7200))
        XCTAssertThrowsError(try scheme.decode()) { error in
            guard case .expiredJWT = error as? SignatureKeyError else {
                return XCTFail("expected expiredJWT, got \(error)")
            }
        }
    }

    func testSelfJWTVerifiesWithTheDiscoveredKey() throws {
        let key = CryptoKitP256SigningKey()
        let scheme = SelfJWTScheme(jwt: try makeSelfJWT(key: key))
        // The same key verifies the JWT and would verify the HTTP signature.
        let returned = try scheme.verify(with: key.publicKeyJWK)
        XCTAssertEqual(returned, key.publicKeyJWK)
    }

    func testSelfJWTRejectsAWrongKey() throws {
        let key = CryptoKitP256SigningKey()
        let other = CryptoKitP256SigningKey()
        let scheme = SelfJWTScheme(jwt: try makeSelfJWT(key: key))
        XCTAssertThrowsError(try scheme.verify(with: other.publicKeyJWK))
    }

    func testSelfJWTRoundTripsThroughTheHeader() throws {
        let key = CryptoKitP256SigningKey()
        let jwt = try makeSelfJWT(key: key)
        let (label, value) = try SignatureKeyValue.parse("sig=self-jwt;jwt=\"\(jwt)\"")
        guard case .selfJWT = value else { return XCTFail("expected self-jwt") }
        XCTAssertEqual(value.serialize(label: label), "sig=self-jwt;jwt=\"\(jwt)\"")
    }

    // MARK: - jwt scheme now validates exp

    func testJwtSchemeRequiresExp() throws {
        let payload: [String: Any] = [
            "iss": "https://issuer.example",
            "cnf": ["jwk": ["kty": "OKP", "crv": "Ed25519", "x": "abc", "alg": "Ed25519"]],
        ]
        let p = Base64URL.encode(try JSONSerialization.data(withJSONObject: payload))
        let scheme = JWTScheme(jwt: "eyJhbGciOiJFUzI1NiJ9.\(p).sig")
        XCTAssertThrowsError(try scheme.extractJWK())
    }

    func testJwtSchemeRejectsExpired() throws {
        let payload: [String: Any] = [
            "exp": Int(Date().timeIntervalSince1970) - 7200,
            "cnf": ["jwk": ["kty": "OKP", "crv": "Ed25519", "x": "abc", "alg": "Ed25519"]],
        ]
        let p = Base64URL.encode(try JSONSerialization.data(withJSONObject: payload))
        let scheme = JWTScheme(jwt: "eyJhbGciOiJFUzI1NiJ9.\(p).sig")
        XCTAssertThrowsError(try scheme.extractJWK()) { error in
            guard case .expiredJWT = error as? SignatureKeyError else {
                return XCTFail("expected expiredJWT, got \(error)")
            }
        }
    }

    // MARK: - unknown schemes

    func testUnknownSchemeMapsToUnsupportedScheme() {
        XCTAssertThrowsError(try SignatureKeyValue.parse("sig=x509;x5u=\"https://c.example/c\"")) {
            error in
            guard let keyError = error as? SignatureKeyError else {
                return XCTFail("expected SignatureKeyError")
            }
            XCTAssertEqual(keyError.signatureErrorCode, .unsupportedScheme)
        }
    }

    // MARK: - Signature-Error

    func testSignatureErrorSerializes() {
        XCTAssertEqual(
            SignatureError(error: .unsupportedScheme).serialize(),
            "error=unsupported_scheme")
        XCTAssertEqual(
            SignatureError(
                error: .invalidInput,
                requiredInput: ["@method", "signature-key"]
            ).serialize(),
            "error=invalid_input, required_input=(\"@method\" \"signature-key\")")
    }

    func testSignatureErrorRoundTrips() throws {
        for original in [
            SignatureError(error: .expiredJwt),
            SignatureError(error: .issuerMismatch),
            SignatureError(error: .invalidInput, requiredInput: ["@method", "@path"]),
        ] {
            XCTAssertEqual(try SignatureError.parse(original.serialize()), original)
        }
    }

    func testSignatureErrorRejectsUnknownCode() {
        XCTAssertThrowsError(try SignatureError.parse("error=not_a_real_code"))
        XCTAssertThrowsError(try SignatureError.parse("required_input=(\"@method\")"))
    }

    func testAlgorithmErrorsMapToTheRightCode() {
        // Forbidden by the specification is invalid_key; unimplemented is a
        // capability statement, so unsupported_algorithm.
        XCTAssertEqual(
            AlgorithmDetermination.Error.polymorphicAlgorithm("EdDSA").signatureErrorCode,
            .invalidKey)
        XCTAssertEqual(
            AlgorithmDetermination.Error.missingAlgorithm(kty: "EC", crv: "P-256")
                .signatureErrorCode, .invalidKey)
        XCTAssertEqual(
            AlgorithmDetermination.Error.unsupportedAlgorithm("ML-DSA-44").signatureErrorCode,
            .unsupportedAlgorithm)
    }

    func testCoverageFailureMapsToInvalidInput() {
        XCTAssertEqual(
            HTTPMessageVerifier.Error.signatureKeyNotCovered.signatureErrorCode, .invalidInput)
    }

    // MARK: - Accept-Signature-Scheme and Accept-Signature-Alg

    func testSchemeHeaderRoundTrips() throws {
        let header = try AcceptSignature.schemeHeader(["jwks_uri", "jwt", "hwk"])
        XCTAssertEqual(header, "jwks_uri, jwt, hwk")
        XCTAssertEqual(AcceptSignature.parseSchemes(header), ["jwks_uri", "jwt", "hwk"])
    }

    func testAlgHeaderUsesJOSEIdentifiers() throws {
        // The same identifiers a conveyed key carries in alg, so a client can
        // compare the two by string equality.
        let header = try AcceptSignature.algHeader(["Ed25519", "ES256", "ML-DSA-44"])
        XCTAssertEqual(header, "Ed25519, ES256, ML-DSA-44")
        XCTAssertEqual(
            AcceptSignature.parseAlgorithms(header), ["Ed25519", "ES256", "ML-DSA-44"])
    }

    func testParsePreservesUnrecognizedSchemes() {
        // A client ignores what it does not know, so a server may list schemes
        // registered after the client was written.
        XCTAssertEqual(
            AcceptSignature.parseSchemes("hwk, some-future-scheme"),
            ["hwk", "some-future-scheme"])
    }

    func testParseToleratesIrregularWhitespace() {
        XCTAssertEqual(AcceptSignature.parseSchemes("  hwk ,jwt   "), ["hwk", "jwt"])
    }

    func testParseDropsNonTokens() {
        XCTAssertEqual(
            AcceptSignature.parseAlgorithms("Ed25519, \"quoted\", ES256"), ["Ed25519", "ES256"])
    }

    func testEmptyHeaderParsesToEmptyList() {
        XCTAssertEqual(AcceptSignature.parseSchemes(""), [])
        XCTAssertEqual(AcceptSignature.parseAlgorithms(""), [])
    }

    func testSerializeRejectsANonToken() {
        XCTAssertThrowsError(try AcceptSignature.algHeader(["Ed25519", "not a token"])) { error in
            XCTAssertEqual(error as? AcceptSignature.Error, .notAToken("not a token"))
        }
    }
}
