# swift-httpsig

Swift implementation of [RFC 9421 HTTP Message Signatures](https://www.rfc-editor.org/rfc/rfc9421) with the [Signature-Key header extension](https://datatracker.ietf.org/doc/draft-hardt-httpbis-signature-key/).

## Requirements

- iOS 17.4+ / macOS 14+
- Swift 5.9+
- No external dependencies (uses CryptoKit and Security frameworks)

## Installation

Add to your `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/hellocoop/swift-httpsig.git", from: "0.1.0"),
],
targets: [
    .target(
        name: "YourTarget",
        dependencies: [
            .product(name: "HTTPMessageSignatures", package: "swift-httpsig"),
        ]
    ),
]
```

## Usage

### Signing a Request

```swift
import HTTPMessageSignatures

// Create a signing key (Secure Enclave on device, CryptoKit for testing)
let key = CryptoKitP256SigningKey()

// Create a signer with default components
let signer = HTTPMessageSigner(
    key: key,
    label: "sig",
    components: ["@method", "@authority", "@path", "signature-key"]
)

// Sign a request (adds Signature-Input, Signature, and Signature-Key headers)
var request = URLRequest(url: URL(string: "https://wallet.hello.coop/api/v1/mobile/register")!)
request.httpMethod = "POST"
let signedRequest = try signer.sign(request)
```

### Verifying a Request

```swift
let result = try HTTPMessageVerifier.verify(request: signedRequest)
// result.jwk - the public key that verified the signature
// result.parameters.created - when the signature was created
// result.components - which components were covered
```

### Secure Enclave Key (iOS)

```swift
let key = try SecureEnclaveSigningKey()

// Persist the key handle for later use
let keyData = key.dataRepresentation
UserDefaults.standard.set(keyData, forKey: "deviceKey")

// Restore later
let restored = try SecureEnclaveSigningKey(dataRepresentation: keyData)
```

### JWK Thumbprint

```swift
let thumbprint = try JWKThumbprint.compute(key.publicKeyJWK)
```

## Signature-Key Schemes

| Scheme | Format | Use Case |
|--------|--------|----------|
| `hwk` | Inline JWK parameters | Device-bound keys |
| `jwt` | JWT with `cnf.jwk` | Delegated/attested keys |
| `jwks_uri` | JWKS discovery URI | Server keys |

## License

MIT
