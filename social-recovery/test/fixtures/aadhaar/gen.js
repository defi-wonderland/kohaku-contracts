// SPDX-License-Identifier: GPL-3.0-or-later
//
// Makes fixture.json: one real Anon Aadhaar Groth16 proof over upstream's test QR data, binding a chosen digest as
// its signal. It is kept to show how the frozen fixture was made, not to run in CI. Groth16 proving is randomized,
// so a new run gives different points a, b and c, and fixture.json must not be replaced by a fresh run.
//
// Needs, outside this repository:
//   npm install @anon-aadhaar/core@2.4.3 snarkjs@0.7.6
//   ANON_AADHAAR  a checkout of anon-aadhaar/anon-aadhaar at 4dad918761cfb1d7d5ed9918dcd796d0cb23ae82
//   WASM, ZKEY, VKEY  the v2.0.0 artifacts aadhaar-verifier.wasm, circuit_final.zkey and vkey.json
// Run with: node --max-old-space-size=12000 gen.js   (about 15 seconds and 6 GB of memory)
// DIGEST, SEED and OUT override the digest, the nullifier seed and the output path.
const fs = require('fs')
const path = require('path')
const snarkjs = require('snarkjs')
const core = require('@anon-aadhaar/core')

const assets = path.join(process.env.ANON_AADHAAR || '../anon-aadhaar', 'packages/circuits/assets')
const wasm = process.env.WASM || '../artifacts/aadhaar-verifier.wasm'
const zkey = process.env.ZKEY || '../artifacts/circuit_final.zkey'
const vkey = process.env.VKEY || '../vkey.json'
const digest = process.env.DIGEST || '0x17498ba208aefe001e6e2f2adec41cd16d0285e23660df6e310d3daac040c339'
const seed = BigInt(process.env.SEED || '77')

;(async () => {
  const { testQRData } = JSON.parse(fs.readFileSync(path.join(assets, 'dataInput.json')))
  const certificate = fs.readFileSync(path.join(assets, 'testCertificate.pem')).toString()
  // Passing the digest's hex string as the signal makes upstream bind keccak256(digest) >> 3 as input 8.
  const args = await core.generateArgs({ qrData: testQRData, certificateFile: certificate, nullifierSeed: seed, signal: digest })
  const witness = {}
  for (const [k, v] of Object.entries(args)) witness[k] = v.value
  console.log('signalHash', witness.signalHash, 'hash(digest)', core.hash(digest))
  const t0 = Date.now()
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(witness, wasm, zkey)
  console.log('prove ms', Date.now() - t0)
  console.log('offchain verify', await snarkjs.groth16.verify(JSON.parse(fs.readFileSync(vkey)), publicSignals, proof))
  // packGroth16Proof swaps each coordinate pair of b into the order the generated Solidity verifier expects.
  const packed = core.packGroth16Proof(proof)
  const out = { digest, nullifierSeed: seed.toString(), testPublicKeyHash: core.testPublicKeyHash, proof, publicSignals, packed }
  fs.writeFileSync(process.env.OUT || 'fixture.json', JSON.stringify(out, null, 2))
  process.exit(0)
})().catch(e => {
  console.error(e)
  process.exit(1)
})
