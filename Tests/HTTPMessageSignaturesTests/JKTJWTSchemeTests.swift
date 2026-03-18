import XCTest
import CryptoKit
@testable import HTTPMessageSignatures

final class JKTJWTSchemeTests: XCTestCase {

    // MARK: - Helpers

    /// Create a properly signed jkt-jwt JWT using P-256 identity key delegating to an ephemeral key.
    private func createJktJwt(
        identityKey: P256.Signing.PrivateKey,
        ephemeralJWK: JWKParameters,
        typ: String = "jkt-s256+jwt",
        iatOffset: Int = 0,
        expOffset: Int = 3600,
        overrideIss: String? = nil,
        omitCnf: Bool = false
    ) throws -> String {
        let identityPublicJWK = jwkFromP256(identityKey.publicKey)

        // Compute thumbprint
        let thumbprint = try JWKThumbprint.compute(identityPublicJWK)
        let iss = overrideIss ?? "urn:jkt:sha-256:\(thumbprint)"

        // Build header
        var headerDict: [String: Any] = [
            "typ": typ,
            "alg": "ES256",
            "jwk": [
                "kty": identityPublicJWK.kty,
                "crv": identityPublicJWK.crv,
                "x": identityPublicJWK.x,
                "y": identityPublicJWK.y!,
            ] as [String: Any],
        ]

        // Build payload
        let now = Int(Date().timeIntervalSince1970)
        var payloadDict: [String: Any] = [
            "iss": iss,
            "iat": now + iatOffset,
            "exp": now + expOffset,
        ]

        if !omitCnf {
            var cnfJwk: [String: Any] = [
                "kty": ephemeralJWK.kty,
                "crv": ephemeralJWK.crv,
                "x": ephemeralJWK.x,
            ]
            if let y = ephemeralJWK.y {
                cnfJwk["y"] = y
            }
            payloadDict["cnf"] = ["jwk": cnfJwk]
        }

        let headerData = try JSONSerialization.data(withJSONObject: headerDict)
        let payloadData = try JSONSerialization.data(withJSONObject: payloadDict)

        let headerB64 = Base64URL.encode(headerData)
        let payloadB64 = Base64URL.encode(payloadData)

        let signingInput = "\(headerB64).\(payloadB64)"
        let signature = try identityKey.signature(for: Data(signingInput.utf8))
        let sigB64 = Base64URL.encode(signature.rawRepresentation)

        return "\(headerB64).\(payloadB64).\(sigB64)"
    }

    /// Create a properly signed jkt-jwt JWT using Ed25519 identity key.
    private func createJktJwtEd25519(
        identityKey: Curve25519.Signing.PrivateKey,
        ephemeralJWK: JWKParameters,
        iatOffset: Int = 0,
        expOffset: Int = 3600
    ) throws -> String {
        let identityPublicJWK = JWKParameters.okp(
            crv: "Ed25519",
            x: Base64URL.encode(identityKey.publicKey.rawRepresentation)
        )

        let thumbprint = try JWKThumbprint.compute(identityPublicJWK)
        let iss = "urn:jkt:sha-256:\(thumbprint)"

        let headerDict: [String: Any] = [
            "typ": "jkt-s256+jwt",
            "alg": "EdDSA",
            "jwk": [
                "kty": "OKP",
                "crv": "Ed25519",
                "x": identityPublicJWK.x,
            ],
        ]

        let now = Int(Date().timeIntervalSince1970)
        var cnfJwk: [String: Any] = [
            "kty": ephemeralJWK.kty,
            "crv": ephemeralJWK.crv,
            "x": ephemeralJWK.x,
        ]
        if let y = ephemeralJWK.y {
            cnfJwk["y"] = y
        }
        let payloadDict: [String: Any] = [
            "iss": iss,
            "iat": now + iatOffset,
            "exp": now + expOffset,
            "cnf": ["jwk": cnfJwk],
        ]

        let headerData = try JSONSerialization.data(withJSONObject: headerDict)
        let payloadData = try JSONSerialization.data(withJSONObject: payloadDict)

        let headerB64 = Base64URL.encode(headerData)
        let payloadB64 = Base64URL.encode(payloadData)

        let signingInput = "\(headerB64).\(payloadB64)"
        let signature = try identityKey.signature(for: Data(signingInput.utf8))
        let sigB64 = Base64URL.encode(signature)

        return "\(headerB64).\(payloadB64).\(sigB64)"
    }

    /// Extract JWK parameters from a P-256 public key.
    private func jwkFromP256(_ publicKey: P256.Signing.PublicKey) -> JWKParameters {
        let x963 = publicKey.x963Representation
        let x = x963[1..<33]
        let y = x963[33..<65]
        return JWKParameters.ec(
            crv: "P-256",
            x: Base64URL.encode(x),
            y: Base64URL.encode(y)
        )
    }

    // MARK: - Sign and Verify Round-Trip

    func testJktJwtP256IdentityEd25519EphemeralRoundTrip() throws {
        let identityKey = P256.Signing.PrivateKey()
        let ephemeralKey = CryptoKitCurve25519SigningKey()

        let jwt = try createJktJwt(
            identityKey: identityKey,
            ephemeralJWK: ephemeralKey.publicKeyJWK
        )

        let signer = HTTPMessageSigner(
            key: ephemeralKey,
            label: "sig",
            signatureKeyScheme: .jktJWT(jwt)
        )

        var request = URLRequest(url: URL(string: "https://api.example.com/data")!)
        request.httpMethod = "GET"
        let signed = try signer.sign(request, created: Int(Date().timeIntervalSince1970))

        // Check header format
        let skHeader = signed.value(forHTTPHeaderField: "Signature-Key")!
        XCTAssertTrue(skHeader.hasPrefix("sig=jkt-jwt;"))

        // Verify
        let result = try HTTPMessageVerifier.verify(request: signed)
        XCTAssertEqual(result.label, "sig")
        XCTAssertEqual(result.jwk, ephemeralKey.publicKeyJWK)
        XCTAssertNotNil(result.jktJWT)
        XCTAssertEqual(result.jktJWT?.ephemeralKey, ephemeralKey.publicKeyJWK)
        XCTAssertEqual(result.jktJWT?.identityKey, jwkFromP256(identityKey.publicKey))
        XCTAssertTrue(result.jktJWT?.identityThumbprint.hasPrefix("urn:jkt:sha-256:") == true)
    }

    func testJktJwtEd25519IdentityP256EphemeralRoundTrip() throws {
        let identityKey = Curve25519.Signing.PrivateKey()
        let ephemeralKey = CryptoKitP256SigningKey()

        let jwt = try createJktJwtEd25519(
            identityKey: identityKey,
            ephemeralJWK: ephemeralKey.publicKeyJWK
        )

        let signer = HTTPMessageSigner(
            key: ephemeralKey,
            label: "sig",
            signatureKeyScheme: .jktJWT(jwt)
        )

        var request = URLRequest(url: URL(string: "https://api.example.com/data")!)
        request.httpMethod = "GET"
        let signed = try signer.sign(request, created: Int(Date().timeIntervalSince1970))

        let result = try HTTPMessageVerifier.verify(request: signed)
        XCTAssertEqual(result.jwk, ephemeralKey.publicKeyJWK)
        XCTAssertNotNil(result.jktJWT)
        XCTAssertEqual(result.jktJWT?.identityKey.kty, "OKP")
        XCTAssertEqual(result.jktJWT?.identityKey.crv, "Ed25519")
    }

    // MARK: - Parsing

    func testParseJktJwtScheme() throws {
        let headerValue = "sig=jkt-jwt;jwt=\"eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJ0ZXN0In0.abc\""
        let (label, value) = try SignatureKeyValue.parse(headerValue)
        XCTAssertEqual(label, "sig")
        if case .jktJWT(let scheme) = value {
            XCTAssertEqual(scheme.jwt, "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJ0ZXN0In0.abc")
        } else {
            XCTFail("Expected jktJWT scheme")
        }
    }

    func testSerializeJktJwtScheme() {
        let scheme = JKTJWTScheme(jwt: "eyJ...")
        let value = SignatureKeyValue.jktJWT(scheme)
        let serialized = value.serialize(label: "sig")
        XCTAssertEqual(serialized, "sig=jkt-jwt;jwt=\"eyJ...\"")
    }

    // MARK: - Failure Cases

    func testFailsWithExpiredJWT() throws {
        let identityKey = P256.Signing.PrivateKey()
        let ephemeralKey = CryptoKitCurve25519SigningKey()

        let jwt = try createJktJwt(
            identityKey: identityKey,
            ephemeralJWK: ephemeralKey.publicKeyJWK,
            iatOffset: -7200,
            expOffset: -3600
        )

        let signer = HTTPMessageSigner(
            key: ephemeralKey,
            signatureKeyScheme: .jktJWT(jwt)
        )

        var request = URLRequest(url: URL(string: "https://api.example.com/data")!)
        request.httpMethod = "GET"
        let signed = try signer.sign(request, created: Int(Date().timeIntervalSince1970))

        XCTAssertThrowsError(try HTTPMessageVerifier.verify(request: signed)) { error in
            if case SignatureKeyError.invalidJWT(let msg) = error {
                XCTAssertTrue(msg.contains("expired"), "Expected expired error, got: \(msg)")
            } else {
                XCTFail("Expected invalidJWT error, got \(error)")
            }
        }
    }

    func testFailsWithFutureIat() throws {
        let identityKey = P256.Signing.PrivateKey()
        let ephemeralKey = CryptoKitCurve25519SigningKey()

        let jwt = try createJktJwt(
            identityKey: identityKey,
            ephemeralJWK: ephemeralKey.publicKeyJWK,
            iatOffset: 3600,
            expOffset: 7200
        )

        let signer = HTTPMessageSigner(
            key: ephemeralKey,
            signatureKeyScheme: .jktJWT(jwt)
        )

        var request = URLRequest(url: URL(string: "https://api.example.com/data")!)
        request.httpMethod = "GET"
        let signed = try signer.sign(request, created: Int(Date().timeIntervalSince1970))

        XCTAssertThrowsError(try HTTPMessageVerifier.verify(request: signed)) { error in
            if case SignatureKeyError.invalidJWT(let msg) = error {
                XCTAssertTrue(msg.contains("future"), "Expected future error, got: \(msg)")
            } else {
                XCTFail("Expected invalidJWT error, got \(error)")
            }
        }
    }

    func testFailsWithTamperedIss() throws {
        let identityKey = P256.Signing.PrivateKey()
        let ephemeralKey = CryptoKitCurve25519SigningKey()

        let jwt = try createJktJwt(
            identityKey: identityKey,
            ephemeralJWK: ephemeralKey.publicKeyJWK,
            overrideIss: "urn:jkt:sha-256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        )

        let signer = HTTPMessageSigner(
            key: ephemeralKey,
            signatureKeyScheme: .jktJWT(jwt)
        )

        var request = URLRequest(url: URL(string: "https://api.example.com/data")!)
        request.httpMethod = "GET"
        let signed = try signer.sign(request, created: Int(Date().timeIntervalSince1970))

        XCTAssertThrowsError(try HTTPMessageVerifier.verify(request: signed)) { error in
            if case SignatureKeyError.invalidJWT(let msg) = error {
                XCTAssertTrue(msg.contains("iss mismatch"), "Expected iss mismatch, got: \(msg)")
            } else {
                XCTFail("Expected invalidJWT error, got \(error)")
            }
        }
    }

    func testFailsWithMissingCnfJwk() throws {
        let identityKey = P256.Signing.PrivateKey()
        let ephemeralKey = CryptoKitCurve25519SigningKey()

        let jwt = try createJktJwt(
            identityKey: identityKey,
            ephemeralJWK: ephemeralKey.publicKeyJWK,
            omitCnf: true
        )

        let signer = HTTPMessageSigner(
            key: ephemeralKey,
            signatureKeyScheme: .jktJWT(jwt)
        )

        var request = URLRequest(url: URL(string: "https://api.example.com/data")!)
        request.httpMethod = "GET"
        let signed = try signer.sign(request, created: Int(Date().timeIntervalSince1970))

        XCTAssertThrowsError(try HTTPMessageVerifier.verify(request: signed)) { error in
            if case SignatureKeyError.invalidJWT(let msg) = error {
                XCTAssertTrue(msg.contains("cnf"), "Expected cnf error, got: \(msg)")
            } else {
                XCTFail("Expected invalidJWT error, got \(error)")
            }
        }
    }

    func testFailsWithWrongEphemeralKey() throws {
        let identityKey = P256.Signing.PrivateKey()
        let ephemeralKey = CryptoKitCurve25519SigningKey()
        let wrongKey = CryptoKitCurve25519SigningKey()

        // JWT delegates to ephemeralKey, but we sign HTTP request with wrongKey
        let jwt = try createJktJwt(
            identityKey: identityKey,
            ephemeralJWK: ephemeralKey.publicKeyJWK
        )

        let signer = HTTPMessageSigner(
            key: wrongKey,
            signatureKeyScheme: .jktJWT(jwt)
        )

        var request = URLRequest(url: URL(string: "https://api.example.com/data")!)
        request.httpMethod = "GET"
        let signed = try signer.sign(request, created: Int(Date().timeIntervalSince1970))

        // JWT verification passes but HTTP signature verification fails
        XCTAssertThrowsError(try HTTPMessageVerifier.verify(request: signed)) { error in
            if case HTTPMessageVerifier.Error.signatureVerificationFailed = error {
                // expected
            } else {
                XCTFail("Expected signatureVerificationFailed, got \(error)")
            }
        }
    }

    func testFailsWithUnsupportedTyp() throws {
        let identityKey = P256.Signing.PrivateKey()
        let ephemeralKey = CryptoKitCurve25519SigningKey()

        let jwt = try createJktJwt(
            identityKey: identityKey,
            ephemeralJWK: ephemeralKey.publicKeyJWK,
            typ: "jkt-s384+jwt"
        )

        let signer = HTTPMessageSigner(
            key: ephemeralKey,
            signatureKeyScheme: .jktJWT(jwt)
        )

        var request = URLRequest(url: URL(string: "https://api.example.com/data")!)
        request.httpMethod = "GET"
        let signed = try signer.sign(request, created: Int(Date().timeIntervalSince1970))

        XCTAssertThrowsError(try HTTPMessageVerifier.verify(request: signed)) { error in
            if case SignatureKeyError.invalidJWT(let msg) = error {
                XCTAssertTrue(msg.contains("unsupported typ"), "Expected unsupported typ error, got: \(msg)")
            } else {
                XCTFail("Expected invalidJWT error, got \(error)")
            }
        }
    }
}
