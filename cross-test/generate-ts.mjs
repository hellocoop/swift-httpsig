/**
 * Generate signed HTTP request test vectors using the TypeScript httpsig library.
 * Usage: node generate-ts.mjs <output.json>
 */

import { createRequire } from 'module'
const require = createRequire(import.meta.url)
const { fetch } = require('@hellocoop/httpsig')
import { writeFileSync } from 'fs'

const outputFile = process.argv[2]
if (!outputFile) {
    console.error('Usage: node generate-ts.mjs <output.json>')
    process.exit(1)
}

// Inline helpers (not exported from @hellocoop/httpsig public API)

function base64urlEncode(data) {
    const bytes = typeof data === 'string' ? new TextEncoder().encode(data) : data
    return Buffer.from(bytes).toString('base64')
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '')
}

async function sha256(data) {
    const bytes = typeof data === 'string' ? new TextEncoder().encode(data) : data
    const hash = await crypto.subtle.digest('SHA-256', bytes)
    return new Uint8Array(hash)
}

async function calculateThumbprint(jwk) {
    let canonical
    if (jwk.kty === 'EC') {
        canonical = JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y })
    } else if (jwk.kty === 'OKP') {
        canonical = JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x })
    } else {
        throw new Error(`Unsupported key type: ${jwk.kty}`)
    }
    const hash = await sha256(canonical)
    return base64urlEncode(hash)
}

// Key generation

async function generateP256KeyPair() {
    const keyPair = await crypto.subtle.generateKey(
        { name: 'ECDSA', namedCurve: 'P-256' },
        true,
        ['sign', 'verify'],
    )
    const privateJwk = await crypto.subtle.exportKey('jwk', keyPair.privateKey)
    const publicJwk = await crypto.subtle.exportKey('jwk', keyPair.publicKey)
    return { privateJwk, publicJwk }
}

async function generateEd25519KeyPair() {
    const keyPair = await crypto.subtle.generateKey(
        { name: 'Ed25519' },
        true,
        ['sign', 'verify'],
    )
    const privateJwk = await crypto.subtle.exportKey('jwk', keyPair.privateKey)
    const publicJwk = await crypto.subtle.exportKey('jwk', keyPair.publicKey)
    return { privateJwk, publicJwk }
}

async function createJktJwt({ identityPrivateJwk, identityPublicJwk, ephemeralPublicJwk }) {
    const { d, p, q, dp, dq, qi, ...cleanPubJwk } = identityPublicJwk

    const alg = cleanPubJwk.kty === 'OKP' ? 'EdDSA' : 'ES256'
    const thumbprint = await calculateThumbprint(cleanPubJwk)
    const now = Math.floor(Date.now() / 1000)

    const header = {
        typ: 'jkt-s256+jwt',
        alg,
        jwk: cleanPubJwk,
    }

    const payload = {
        iss: `urn:jkt:sha-256:${thumbprint}`,
        iat: now,
        exp: now + 3600,
        cnf: { jwk: ephemeralPublicJwk },
    }

    const encodedHeader = base64urlEncode(JSON.stringify(header))
    const encodedPayload = base64urlEncode(JSON.stringify(payload))
    const signingInput = `${encodedHeader}.${encodedPayload}`

    const algorithm = alg === 'EdDSA'
        ? { name: 'Ed25519' }
        : { name: 'ECDSA', hash: 'SHA-256' }

    const importAlg = alg === 'EdDSA'
        ? { name: 'Ed25519' }
        : { name: 'ECDSA', namedCurve: 'P-256' }

    const key = await crypto.subtle.importKey('jwk', identityPrivateJwk, importAlg, false, ['sign'])
    const sig = await crypto.subtle.sign(algorithm, key, new TextEncoder().encode(signingInput))
    const encodedSig = base64urlEncode(new Uint8Array(sig))

    return `${encodedHeader}.${encodedPayload}.${encodedSig}`
}

async function signRequest(url, method, signingKey, signatureKey) {
    const result = await fetch(url, {
        method,
        signingKey,
        signatureKey,
        dryRun: true,
    })
    return {
        'signature-input': result.headers.get('signature-input'),
        'signature': result.headers.get('signature'),
        'signature-key': result.headers.get('signature-key'),
    }
}

async function main() {
    const vectors = []

    // Test 1: HWK with P-256
    {
        const { privateJwk } = await generateP256KeyPair()
        const headers = await signRequest(
            'https://api.example.com/cross-test',
            'GET',
            privateJwk,
            { type: 'hwk' },
        )
        vectors.push({
            name: 'hwk-p256-ts',
            scheme: 'hwk',
            method: 'GET',
            url: 'https://api.example.com/cross-test',
            headers,
        })
    }

    // Test 2: HWK with Ed25519
    {
        const { privateJwk } = await generateEd25519KeyPair()
        const headers = await signRequest(
            'https://api.example.com/cross-test',
            'POST',
            privateJwk,
            { type: 'hwk' },
        )
        vectors.push({
            name: 'hwk-ed25519-ts',
            scheme: 'hwk',
            method: 'POST',
            url: 'https://api.example.com/cross-test',
            headers,
        })
    }

    // Test 3: jkt-jwt with P-256 identity, Ed25519 ephemeral
    {
        const identity = await generateP256KeyPair()
        const ephemeral = await generateEd25519KeyPair()
        const jwt = await createJktJwt({
            identityPrivateJwk: identity.privateJwk,
            identityPublicJwk: identity.publicJwk,
            ephemeralPublicJwk: ephemeral.publicJwk,
        })
        const headers = await signRequest(
            'https://api.example.com/cross-test/jkt-jwt',
            'GET',
            ephemeral.privateJwk,
            { type: 'jkt_jwt', jwt },
        )
        vectors.push({
            name: 'jkt-jwt-p256-ed25519-ts',
            scheme: 'jkt_jwt',
            method: 'GET',
            url: 'https://api.example.com/cross-test/jkt-jwt',
            headers,
        })
    }

    // Test 4: jkt-jwt with Ed25519 identity, P-256 ephemeral
    {
        const identity = await generateEd25519KeyPair()
        const ephemeral = await generateP256KeyPair()
        const jwt = await createJktJwt({
            identityPrivateJwk: identity.privateJwk,
            identityPublicJwk: identity.publicJwk,
            ephemeralPublicJwk: ephemeral.publicJwk,
        })
        const headers = await signRequest(
            'https://api.example.com/cross-test/jkt-jwt-ed',
            'POST',
            ephemeral.privateJwk,
            { type: 'jkt_jwt', jwt },
        )
        vectors.push({
            name: 'jkt-jwt-ed25519-p256-ts',
            scheme: 'jkt_jwt',
            method: 'POST',
            url: 'https://api.example.com/cross-test/jkt-jwt-ed',
            headers,
        })
    }

    writeFileSync(outputFile, JSON.stringify(vectors, null, 2))
    console.log(`Generated ${vectors.length} test vectors → ${outputFile}`)
}

main().catch(err => {
    console.error(err)
    process.exit(1)
})
