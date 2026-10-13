# Anon Aadhaar real-proof fixture

Generated on 2026-10-02. `fixture.json` holds one real Anon Aadhaar Groth16 proof, made for this repository, that verifies on the live Sepolia verifier `0xCBd85cd69C4779aA9a7AB9B6D6A9f6FEd61504F0`. The fork tests in `test/method-aadhaar/AadhaarMethodFork.t.sol` run it through the Aadhaar method on a Sepolia fork pinned to block 11,831,100.

## What the proof is

- Identity: upstream's `testQRData` from `packages/circuits/assets/dataInput.json`, UIDAI's public sample identity re-signed with upstream's published test private key. Certificate: `packages/circuits/assets/testCertificate.pem`. Both from `anon-aadhaar/anon-aadhaar` at commit `4dad918761cfb1d7d5ed9918dcd796d0cb23ae82` with sha256 `f1e4e7e477d06d0461e821a4e73d47e1fde73d922be6fab4ed0e39e2c597b0f9` (`dataInput.json`) and `a025f6e83f50885299d91a881ab667fe08aa8206062ea560e81d06a59bfdaae6` (`testCertificate.pem`).
- Signal: the digest `0x17498ba208aefe001e6e2f2adec41cd16d0285e23660df6e310d3daac040c339`, the same digest as the frozen Aadhaar proof vector, so public input 8 equals the vector's `signalHash`.
- Nullifier seed: 77.
- Public input 0 is upstream's TEST public-key hash `15134874015316324267425466444584014077184337590635665158241104437045239495873`. Anyone holding the published test private key can sign any identity under it, so it must never enter a deployment. The tests use it only inside a method they deploy on the fork.
- Nothing is disclosed: inputs 3 to 6 are zero. Input 2, the signing time, is 1552023000 (2019-03-08 05:30 UTC).

## How it was made

`gen.js`, with Node 23, `@anon-aadhaar/core@2.4.3` and `snarkjs@0.7.6`, and the v2.0.0 artifacts from `https://anon-aadhaar-artifacts.s3.eu-central-1.amazonaws.com/v2.0.0/`:

| Artifact | Bytes | sha256 |
|---|---|---|
| `aadhaar-verifier.wasm` | 10,469,686 | `4894923663fafda95beb70abca4112ea97a62058c9a46419a274f04236f10d4f` |
| `circuit_final.zkey` | 612,082,146 | `0d443ea85279b0370b53202f5e768ca9098cfcb5bb14f8ca8323d2266822c492` |
| `vkey.json` | | `40f2ea24b56ffe2b6e6e3578053cbda15e773cb560697bac883a404077fcf177` |

Proving took about 15 seconds and 6 GB of memory, and `snarkjs.groth16.verify` with `vkey.json` returned true. The zkey is never committed. Groth16 proving is randomized, so a second run gives different points with the same public inputs: `fixture.json` was generated once and is frozen. Do not replace it with a new run.

## Files

- `fixture.json`: the raw snarkjs proof, the nine public signals and `packed`, the eight words `packGroth16Proof` returns (a, then b with each coordinate pair swapped into the order the Solidity verifier expects, then c).
- `gen.js`: the generator, kept as a record. It does not run in CI.
- `AadhaarRealProofFixture.sol`: the same values as Solidity constants, one per field. Tests may read files only under `test/fixtures/kats` and `out`, so they inherit these constants instead of reading `fixture.json`.
- `generate.py`: writes `AadhaarRealProofFixture.sol` from `fixture.json`, and refuses a file whose packed proof, key or seed disagree with its raw proof and public signals.

## Regenerating the constants

From the repository root:

```sh
python3 test/fixtures/aadhaar/generate.py
forge fmt --check test/fixtures/aadhaar/AadhaarRealProofFixture.sol
git diff --exit-code test/fixtures/aadhaar/AadhaarRealProofFixture.sol
```

The script needs only the Python 3 standard library. On an unchanged `fixture.json` the last command finds no difference.
