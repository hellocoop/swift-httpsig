import Foundation
import CryptoKit
import HTTPMessageSignatures

// Cross-library test tool for HTTP Message Signatures.
//
// Usage:
//   swift run CrossTest generate <output.json>   — sign requests, write test vectors
//   swift run CrossTest verify <input.json>       — read test vectors, verify signatures

guard CommandLine.arguments.count >= 3 else {
    fputs("Usage: CrossTest <generate|verify> <file.json>\n", stderr)
    exit(1)
}

let mode = CommandLine.arguments[1]
let filePath = CommandLine.arguments[2]

// MARK: - Helpers

func jwkFromP256(_ publicKey: P256.Signing.PublicKey) -> JWKParameters {
    let x963 = publicKey.x963Representation
    let x = x963[1..<33]
    let y = x963[33..<65]
    return JWKParameters.ec(crv: "P-256", x: Base64URL.encode(x), y: Base64URL.encode(y))
}

func privateJwkFromP256(_ privateKey: P256.Signing.PrivateKey) -> [String: Any] {
    let pubJwk = jwkFromP256(privateKey.publicKey)
    return [
        "kty": pubJwk.kty,
        "crv": pubJwk.crv,
        "x": pubJwk.x,
        "y": pubJwk.y!,
        "d": Base64URL.encode(privateKey.rawRepresentation),
    ]
}

func privateJwkFromEd25519(_ privateKey: Curve25519.Signing.PrivateKey) -> [String: Any] {
    return [
        "kty": "OKP",
        "crv": "Ed25519",
        "x": Base64URL.encode(privateKey.publicKey.rawRepresentation),
        "d": Base64URL.encode(privateKey.rawRepresentation),
    ]
}

// MARK: - Generate

func generate() throws {
    var testVectors: [[String: Any]] = []

    // Test 1: HWK with P-256
    do {
        let key = CryptoKitP256SigningKey()
        let signer = HTTPMessageSigner(key: key, label: "sig", signatureKeyScheme: .hwk)

        var request = URLRequest(url: URL(string: "https://api.example.com/cross-test")!)
        request.httpMethod = "GET"
        let created = Int(Date().timeIntervalSince1970)
        let signed = try signer.sign(request, created: created)

        testVectors.append([
            "name": "hwk-p256-swift",
            "scheme": "hwk",
            "method": "GET",
            "url": "https://api.example.com/cross-test",
            "headers": [
                "signature-input": signed.value(forHTTPHeaderField: "Signature-Input")!,
                "signature": signed.value(forHTTPHeaderField: "Signature")!,
                "signature-key": signed.value(forHTTPHeaderField: "Signature-Key")!,
            ],
        ])
    }

    // Test 2: HWK with Ed25519
    do {
        let key = CryptoKitCurve25519SigningKey()
        let signer = HTTPMessageSigner(key: key, label: "sig", signatureKeyScheme: .hwk)

        var request = URLRequest(url: URL(string: "https://api.example.com/cross-test")!)
        request.httpMethod = "POST"
        let created = Int(Date().timeIntervalSince1970)
        let signed = try signer.sign(request, created: created)

        testVectors.append([
            "name": "hwk-ed25519-swift",
            "scheme": "hwk",
            "method": "POST",
            "url": "https://api.example.com/cross-test",
            "headers": [
                "signature-input": signed.value(forHTTPHeaderField: "Signature-Input")!,
                "signature": signed.value(forHTTPHeaderField: "Signature")!,
                "signature-key": signed.value(forHTTPHeaderField: "Signature-Key")!,
            ],
        ])
    }

    // Test 3: jkt-jwt with P-256 identity, Ed25519 ephemeral
    do {
        let identityKey = P256.Signing.PrivateKey()
        let ephemeralKey = CryptoKitCurve25519SigningKey()
        let identityPublicJWK = jwkFromP256(identityKey.publicKey)

        let thumbprint = try JWKThumbprint.compute(identityPublicJWK)
        let iss = "urn:jkt:sha-256:\(thumbprint)"
        let now = Int(Date().timeIntervalSince1970)

        let headerDict: [String: Any] = [
            "typ": "jkt-s256+jwt",
            "alg": "ES256",
            "jwk": [
                "kty": identityPublicJWK.kty,
                "crv": identityPublicJWK.crv,
                "x": identityPublicJWK.x,
                "y": identityPublicJWK.y!,
            ] as [String: Any],
        ]

        let payloadDict: [String: Any] = [
            "iss": iss,
            "iat": now,
            "exp": now + 3600,
            "cnf": ["jwk": [
                "kty": ephemeralKey.publicKeyJWK.kty,
                "crv": ephemeralKey.publicKeyJWK.crv,
                "x": ephemeralKey.publicKeyJWK.x,
            ]],
        ]

        let headerData = try JSONSerialization.data(withJSONObject: headerDict)
        let payloadData = try JSONSerialization.data(withJSONObject: payloadDict)
        let headerB64 = Base64URL.encode(headerData)
        let payloadB64 = Base64URL.encode(payloadData)
        let signingInput = "\(headerB64).\(payloadB64)"
        let jwtSig = try identityKey.signature(for: Data(signingInput.utf8))
        let jwt = "\(headerB64).\(payloadB64).\(Base64URL.encode(jwtSig.rawRepresentation))"

        let signer = HTTPMessageSigner(
            key: ephemeralKey,
            label: "sig",
            signatureKeyScheme: .jktJWT(jwt)
        )

        var request = URLRequest(url: URL(string: "https://api.example.com/cross-test/jkt-jwt")!)
        request.httpMethod = "GET"
        let signed = try signer.sign(request, created: now)

        testVectors.append([
            "name": "jkt-jwt-p256-ed25519-swift",
            "scheme": "jkt_jwt",
            "method": "GET",
            "url": "https://api.example.com/cross-test/jkt-jwt",
            "headers": [
                "signature-input": signed.value(forHTTPHeaderField: "Signature-Input")!,
                "signature": signed.value(forHTTPHeaderField: "Signature")!,
                "signature-key": signed.value(forHTTPHeaderField: "Signature-Key")!,
            ],
        ])
    }

    // Test 4: jkt-jwt with Ed25519 identity, P-256 ephemeral
    do {
        let identityKey = Curve25519.Signing.PrivateKey()
        let ephemeralKey = CryptoKitP256SigningKey()
        let identityPublicJWK = JWKParameters.okp(
            crv: "Ed25519",
            x: Base64URL.encode(identityKey.publicKey.rawRepresentation)
        )

        let thumbprint = try JWKThumbprint.compute(identityPublicJWK)
        let iss = "urn:jkt:sha-256:\(thumbprint)"
        let now = Int(Date().timeIntervalSince1970)

        let headerDict: [String: Any] = [
            "typ": "jkt-s256+jwt",
            "alg": "EdDSA",
            "jwk": [
                "kty": "OKP",
                "crv": "Ed25519",
                "x": identityPublicJWK.x,
            ],
        ]

        let ephJwk = ephemeralKey.publicKeyJWK
        let payloadDict: [String: Any] = [
            "iss": iss,
            "iat": now,
            "exp": now + 3600,
            "cnf": ["jwk": [
                "kty": ephJwk.kty,
                "crv": ephJwk.crv,
                "x": ephJwk.x,
                "y": ephJwk.y!,
            ]],
        ]

        let headerData = try JSONSerialization.data(withJSONObject: headerDict)
        let payloadData = try JSONSerialization.data(withJSONObject: payloadDict)
        let headerB64 = Base64URL.encode(headerData)
        let payloadB64 = Base64URL.encode(payloadData)
        let signingInput = "\(headerB64).\(payloadB64)"
        let jwtSig = try identityKey.signature(for: Data(signingInput.utf8))
        let jwt = "\(headerB64).\(payloadB64).\(Base64URL.encode(jwtSig))"

        let signer = HTTPMessageSigner(
            key: ephemeralKey,
            label: "sig",
            signatureKeyScheme: .jktJWT(jwt)
        )

        var request = URLRequest(url: URL(string: "https://api.example.com/cross-test/jkt-jwt-ed")!)
        request.httpMethod = "POST"
        let signed = try signer.sign(request, created: now)

        testVectors.append([
            "name": "jkt-jwt-ed25519-p256-swift",
            "scheme": "jkt_jwt",
            "method": "POST",
            "url": "https://api.example.com/cross-test/jkt-jwt-ed",
            "headers": [
                "signature-input": signed.value(forHTTPHeaderField: "Signature-Input")!,
                "signature": signed.value(forHTTPHeaderField: "Signature")!,
                "signature-key": signed.value(forHTTPHeaderField: "Signature-Key")!,
            ],
        ])
    }

    let json = try JSONSerialization.data(
        withJSONObject: testVectors,
        options: [.prettyPrinted, .sortedKeys]
    )
    try json.write(to: URL(fileURLWithPath: filePath))
    print("Generated \(testVectors.count) test vectors → \(filePath)")
}

// MARK: - Verify

func verify() throws {
    let data = try Data(contentsOf: URL(fileURLWithPath: filePath))
    let vectors = try JSONSerialization.jsonObject(with: data) as! [[String: Any]]

    var passed = 0
    var failed = 0

    for vector in vectors {
        let name = vector["name"] as! String
        let method = vector["method"] as! String
        let urlString = vector["url"] as! String
        let headers = vector["headers"] as! [String: String]

        var request = URLRequest(url: URL(string: urlString)!)
        request.httpMethod = method
        request.setValue(headers["signature-input"], forHTTPHeaderField: "Signature-Input")
        request.setValue(headers["signature"], forHTTPHeaderField: "Signature")
        request.setValue(headers["signature-key"], forHTTPHeaderField: "Signature-Key")

        do {
            let result = try HTTPMessageVerifier.verify(request: request)
            print("✓ \(name) — verified (label=\(result.label), kty=\(result.jwk.kty))")
            if result.jktJWT != nil {
                print("  jkt-jwt identity: \(result.jktJWT!.identityThumbprint)")
            }
            passed += 1
        } catch {
            print("✗ \(name) — FAILED: \(error)")
            failed += 1
        }
    }

    print("\n\(passed) passed, \(failed) failed out of \(vectors.count) vectors")
    if failed > 0 { exit(1) }
}

// MARK: - Main

do {
    switch mode {
    case "generate":
        try generate()
    case "verify":
        try verify()
    default:
        fputs("Unknown mode: \(mode). Use 'generate' or 'verify'.\n", stderr)
        exit(1)
    }
} catch {
    fputs("Error: \(error)\n", stderr)
    exit(1)
}
