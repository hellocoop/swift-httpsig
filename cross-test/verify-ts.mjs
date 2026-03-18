/**
 * Verify signed HTTP request test vectors using the TypeScript httpsig library.
 * Usage: node verify-ts.mjs <input.json>
 */

import { createRequire } from 'module'
const require = createRequire(import.meta.url)
const { verify } = require('@hellocoop/httpsig')
import { readFileSync } from 'fs'

const inputFile = process.argv[2]
if (!inputFile) {
    console.error('Usage: node verify-ts.mjs <input.json>')
    process.exit(1)
}

async function main() {
    const vectors = JSON.parse(readFileSync(inputFile, 'utf-8'))

    let passed = 0
    let failed = 0

    for (const vector of vectors) {
        const { name, method, url, headers } = vector
        const urlObj = new URL(url)

        const result = await verify({
            method,
            authority: urlObj.host,
            path: urlObj.pathname,
            query: urlObj.search ? urlObj.search.substring(1) : undefined,
            headers,
        })

        if (result.verified) {
            console.log(`✓ ${name} — verified (label=${result.label}, kty=${result.publicKey.kty})`)
            if (result.jkt_jwt) {
                console.log(`  jkt-jwt identity: ${result.jkt_jwt.identityThumbprint}`)
            }
            passed++
        } else {
            console.log(`✗ ${name} — FAILED: ${result.error}`)
            failed++
        }
    }

    console.log(`\n${passed} passed, ${failed} failed out of ${vectors.length} vectors`)
    if (failed > 0) process.exit(1)
}

main().catch(err => {
    console.error(err)
    process.exit(1)
})
