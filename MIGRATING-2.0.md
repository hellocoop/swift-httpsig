# Migrating to 2.0

2.0 tracks `draft-hardt-httpbis-signature-key-08`, published to the IETF
datatracker on 2026-08-05. It is not wire compatible with earlier revisions in
either direction, and the protocol has no version negotiation, so both ends of
a deployment move together.

## `alg` is required on every JWK

1.2 accepted a JWK without `alg` and derived the algorithm from `kty` and
`crv`. 2.0 rejects it.

`kty` and `crv` do determine the algorithm for the OKP and EC keys this library
supports — no registered JOSE signing algorithm pairs the Ed25519 curve with
anything but `Ed25519`, or P-256 with anything but `ES256`. They do not for
RSA, which has no curve and leaves both padding and hash free, nor for `AKP`,
which covers several ML-DSA parameter sets. Requiring it uniformly keeps one
code path in the verifier and lets `Accept-Signature-Alg` be compared against a
key by string equality.

Keys built by `JWKParameters.ec()` / `.okp()` and by the signing key adapters
already carry it. A JWK you assemble by hand must set it.

## `hwk` must not carry `kid`

Rejected with `SignatureKeyError.forbiddenParameter("kid")`. The key is inline,
so an identifier selects nothing, and one that disagrees with the inline key has
no defined resolution.

## `jwks_uri` renamed `well-known` to `dwk`, and requires all three parameters

```
# 1.x
sig=jwks_uri;id="https://issuer.example";well-known="aauth-agent";kid="key-1"

# 2.x
sig=jwks_uri;id="https://issuer.example";dwk="aauth-agent";kid="key-1"
```

`dwk` has been the parameter name since `-03`; `well-known` was never in the
specification, and neither was defaulting it to `jwks.json`. `id`, `dwk` and
`kid` are all REQUIRED, and the default is gone.

```swift
// 1.x
JWKSURIScheme(id: id, wellKnown: "aauth-agent", kid: "key-1")
// 2.x
JWKSURIScheme(id: id, dwk: "aauth-agent", kid: "key-1")
```

## Discovery metadata must carry a matching `issuer`

New in `-08`. The document at `{id}/.well-known/{dwk}` must contain an `issuer`
equal to the identity it was fetched under, compared by byte equality with no
normalization — a trailing slash is a different identifier.

Without it a document served under one identity, through misconfigured shared
hosting or a subdomain takeover, could point `jwks_uri` at keys belonging to
someone else, and the verifier would attribute the request accordingly. It is
the check RFC 8414 Section 3.3 requires of authorization server metadata.

```swift
let jwksURI = try DiscoveryMetadata.validate(fetchedData, fetchedUnder: scheme.id)
```

Throws `issuerMissing` or `issuerMismatch`.

## The `jwt` scheme validates `exp`

`extractJWK()` now requires `exp` and rejects an expired assertion. `exp` bounds
how long the confirmation key the assertion carries stays acceptable; without it
that key is acceptable indefinitely.

The issuer's signature over the assertion is still the caller's to check — the
issuer's key is external to the library.

## New schemes

**`jwks`** — a direct JWKS fetch whose HTTPS `url` is both the signer's identity
and the key location.

```swift
let (label, value) = try SignatureKeyValue.parse(header)
guard case .jwks(let jwks) = value, let url = jwks.jwksURL() else { … }
// fetch url, select the key matching jwks.kid
```

`jwksURL()` returns nil for a non-HTTPS scheme. The caller applies the rest of
egress admission, since it owns the fetch.

**`self-jwt`** — the JWT issuer and the HTTP signer are the same party, and the
signing key is the confirmation key, so there is no `cnf` claim.

```swift
let claims = try selfJWT.decode()            // validates iss, dwk, kid, exp, no cnf
// fetch claims.discoveryURL(), validate with DiscoveryMetadata,
// fetch the JWKS, select by claims.kid
let key = try selfJWT.verify(with: resolvedKey)   // returns the same key
```

`verify(with:)` returns the key so the "same key verifies both the JWT and the
HTTP signature" rule is hard to get wrong at the call site.

## `Signature-Error` and the negotiation headers

New: `SignatureErrorCode`, `SignatureError`, and `AcceptSignature`.

```swift
SignatureError(error: .invalidInput, requiredInput: ["@method", "signature-key"]).serialize()
// error=invalid_input, required_input=("@method" "signature-key")

try AcceptSignature.schemeHeader(["jwks_uri", "jwt", "hwk"])   // jwks_uri, jwt, hwk
try AcceptSignature.algHeader(["Ed25519", "ES256"])            // Ed25519, ES256
```

`Accept-Signature-Alg` carries JOSE identifiers — the same ones a conveyed key
carries in `alg` — so a client can compare what a server accepts against the
keys it holds.

Library errors map to codes via `.signatureErrorCode`. Forbidden by the
specification reports `invalid_key`; unimplemented reports
`unsupported_algorithm`, because absence of support is a reason to decline, not
a parsing failure.

## Not implemented

`x509`, and assertion caching — the draft carries an Editor's Note calling
caching a straw man.
