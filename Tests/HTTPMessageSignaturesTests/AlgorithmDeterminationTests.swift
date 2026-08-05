import XCTest

@testable import HTTPMessageSignatures

/// Algorithm determination per draft-hardt-httpbis-signature-key-08.
final class AlgorithmDeterminationTests: XCTestCase {

    // MARK: - alg present

    func testUsesAlgWhenPresent() throws {
        let jwk = JWKParameters(kty: "EC", crv: "P-256", x: "x", y: "y", alg: "ES256")
        XCTAssertEqual(try AlgorithmDetermination.determine(jwk), "ES256")
    }

    func testEd25519IsFullySpecified() throws {
        let jwk = JWKParameters(kty: "OKP", crv: "Ed25519", x: "x", alg: "Ed25519")
        XCTAssertEqual(try AlgorithmDetermination.determine(jwk), "Ed25519")
    }

    // MARK: - alg absent

    func testDerivesWhenAlgAbsent() throws {
        // Leniency retained for 1.x: kty and crv name exactly one algorithm
        // for the key types supported here, so a signer that has not been
        // updated is still readable.
        let ec = JWKParameters(kty: "EC", crv: "P-256", x: "x", y: "y")
        XCTAssertEqual(try AlgorithmDetermination.determine(ec), "ES256")

        let okp = JWKParameters(kty: "OKP", crv: "Ed25519", x: "x")
        XCTAssertEqual(try AlgorithmDetermination.determine(okp), "Ed25519")
    }

    func testRejectsWhenNeitherAlgNorKnownCurve() {
        let jwk = JWKParameters(kty: "OKP", crv: "X25519", x: "x")
        XCTAssertThrowsError(try AlgorithmDetermination.determine(jwk)) { error in
            XCTAssertEqual(
                error as? AlgorithmDetermination.Error,
                .undeterminedAlgorithm(kty: "OKP", crv: "X25519"))
        }
    }

    // MARK: - forbidden identifiers

    func testRejectsPolymorphicEdDSA() {
        // EdDSA names Ed25519 or Ed448 depending on the key. RFC 9864
        // deprecates it; -08 forbids it.
        let jwk = JWKParameters(kty: "OKP", crv: "Ed25519", x: "x", alg: "EdDSA")
        XCTAssertThrowsError(try AlgorithmDetermination.determine(jwk)) { error in
            XCTAssertEqual(
                error as? AlgorithmDetermination.Error, .polymorphicAlgorithm("EdDSA"))
        }
    }

    func testRejectsSymmetricAndNone() {
        for alg in ["HS256", "none"] {
            let jwk = JWKParameters(kty: "OKP", crv: "Ed25519", x: "x", alg: alg)
            XCTAssertThrowsError(try AlgorithmDetermination.determine(jwk)) { error in
                XCTAssertEqual(
                    error as? AlgorithmDetermination.Error, .symmetricAlgorithm(alg))
            }
        }
    }

    func testRejectsUnknownAlgorithm() {
        let jwk = JWKParameters(kty: "OKP", crv: "Ed25519", x: "x", alg: "ML-DSA-44")
        XCTAssertThrowsError(try AlgorithmDetermination.determine(jwk)) { error in
            XCTAssertEqual(
                error as? AlgorithmDetermination.Error, .unsupportedAlgorithm("ML-DSA-44"))
        }
    }

    // MARK: - consistency

    func testRejectsKtyDisagreeingWithAlg() {
        let jwk = JWKParameters(kty: "OKP", crv: "Ed25519", x: "x", alg: "ES256")
        XCTAssertThrowsError(try AlgorithmDetermination.determine(jwk))
    }

    func testRejectsCrvDisagreeingWithAlg() {
        // A key readable two ways is rejected rather than resolved in favour
        // of either reading.
        let jwk = JWKParameters(kty: "EC", crv: "P-384", x: "x", y: "y", alg: "ES256")
        XCTAssertThrowsError(try AlgorithmDetermination.determine(jwk))
    }

    // MARK: - identity must not shift

    func testAlgDoesNotChangeThumbprint() throws {
        // RFC 7638 covers only the required members. If alg changed the
        // thumbprint, every jkt-jwt identity would change with it.
        let withAlg = JWKParameters(
            kty: "OKP", crv: "Ed25519", x: "8s3z0ReaAyxufRDCRiEPkIrPZ8-3X9a2fnKW-upvKP4",
            alg: "Ed25519")
        let withoutAlg = JWKParameters(
            kty: "OKP", crv: "Ed25519", x: "8s3z0ReaAyxufRDCRiEPkIrPZ8-3X9a2fnKW-upvKP4")

        XCTAssertEqual(
            try JWKThumbprint.compute(withAlg),
            try JWKThumbprint.compute(withoutAlg))
    }

    // MARK: - constructed keys carry alg

    func testFactoriesPopulateAlg() {
        XCTAssertEqual(JWKParameters.okp(crv: "Ed25519", x: "x").alg, "Ed25519")
        XCTAssertEqual(JWKParameters.ec(crv: "P-256", x: "x", y: "y").alg, "ES256")
        XCTAssertEqual(JWKParameters.ec(crv: "P-384", x: "x", y: "y").alg, "ES384")
    }

    func testSigningKeysNameAFullySpecifiedAlgorithm() {
        // The Curve25519 adapter previously reported the polymorphic "EdDSA".
        XCTAssertEqual(CryptoKitCurve25519SigningKey().algorithm, "Ed25519")
        XCTAssertEqual(CryptoKitP256SigningKey().algorithm, "ES256")
        XCTAssertEqual(CryptoKitCurve25519SigningKey().publicKeyJWK.alg, "Ed25519")
    }

    func testDecodedKeyPreservesAbsentAlg() throws {
        // Decoding must not invent an alg the sender did not send, or a
        // verifier could not tell a conforming signer from a legacy one.
        let json = #"{"kty":"OKP","crv":"Ed25519","x":"abc"}"#
        let jwk = try JSONDecoder().decode(JWKParameters.self, from: Data(json.utf8))
        XCTAssertNil(jwk.alg)
    }

    func testEncodedKeyIncludesAlg() throws {
        let jwk = JWKParameters.okp(crv: "Ed25519", x: "abc")
        let encoded = String(data: try JSONEncoder().encode(jwk), encoding: .utf8)!
        XCTAssertTrue(encoded.contains("\"alg\""))
        XCTAssertTrue(encoded.contains("Ed25519"))
    }
}
