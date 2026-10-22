# zkPassport bind fixture

Verified on 2026-10-02. The three data files are byte-identical (sha256) to upstream's `src/solidity/test/fixtures/valid_*` at the commit below. `generate.py` reproduces `ZkPassportBindFixture.sol` exactly. The proof verifies against the live 0.21.0 route on Sepolia, with only the certificate root check mocked. To repeat: run `python3 test/fixtures/zkpassport/generate.py` and check that `git diff` shows nothing, then run `forge test --match-path test/method-zkpassport/fork/ZkPassportMethodFork.t.sol` with `SEPOLIA_RPC_URL` set to an archive endpoint.

The Sepolia fork tests in `test/method-zkpassport/fork/` run the zkPassport method against zkPassport's deployed contracts with a real proof. The proof is zkPassport's own 0.21.0 bind fixture from `zkpassport/circuits` at commit `7b3614442419b5ee6fefe8b2bc077cb956284ad1`, the 0.21.0 release commit, under the Apache License 2.0. `NOTICE` gives the source and the attribution, and `LICENSE` is upstream's licence text.

## Files

- `valid_proof.hex` (9,888 bytes), `valid_public_inputs.json` (ten inputs), `valid_committed_inputs.hex` (695 bytes): copied unchanged from `src/solidity/test/fixtures/` upstream. The committed inputs ship with the fixture, so nothing was rebuilt.
- `ZkPassportBindFixture.sol`: the same bytes as Solidity constants, one constant per field, which the tests inherit. Tests may read files only under `test/fixtures/kats` and `out`, so they cannot read the data files directly.
- `generate.py`: writes `ZkPassportBindFixture.sol` from the three data files.

## Regenerating the constants

From the repository root:

```sh
python3 test/fixtures/zkpassport/generate.py
forge fmt --check test/fixtures/zkpassport/ZkPassportBindFixture.sol
git diff --exit-code test/fixtures/zkpassport/ZkPassportBindFixture.sol
```

The script needs only the Python 3 standard library. On unchanged data files the last command finds no difference.

## What the fixture is

The proof is an outer proof over five subproofs, the last two a disclosure and a bind, for a fake test passport whose certificates upstream's generator made locally. It was proved under zkPassport 0.21.0 on 2026-09-15, the date in public input 2. It binds a sender address, chain id 31337 and the custom data `email:test@test.com,customer_id:1234567890`. Its scoped nullifier, second from the end of the public inputs, is the identifier the root verifier returns, `0x171de101deed3f056917faecfe6cc04db2ef02689a8a483962a688948ce44461`, and its nullifier type, third from the end, is 0. Its domain is `zkpassport.id` and its scope `bigproof`.

The tests fork Sepolia at block 11,830,700, where the root verifier routes 0.21.0 to the sub-verifier `0x78e111D6e8b655E5231ABAE8bFDC3e063084a5Ab` and names the verifier helper `0xe8AE97eF2fFF59597D1B6882286754FEC200F3a9`.

Two things the fork tests work around, and only the first takes a mock:

- The certificate root, public input 0, is a local test root no live registry holds. The tests mock the root registry's `isRootValid` for exactly that root at the proof's date. The circuit root, public input 1, is the latest root of the live circuit registry at the pinned block, so its check runs unmocked, and one test shows the live registry accepts it. Everything else runs live.
- Upstream's `config.json` labels the fixture with the verification key hash `0x2db0280427677f605ab03da584627a2c43c5f3e65ef50155cd7ee9740622c041`, which no deployed sub-verifier registers, so the root verifier would not find a verifier for it. The hash the 0.21.0 sub-verifier registers for a five-subproof outer proof is `0x2eae578482e200bb70139dbe6e49450b9082f50321be975fd86f0e768a85be9f`, the five-subproof entry of `src/solidity/script/DeploySubVerifier.s.sol` at the same commit. The tests use that hash.

The custom data is not a digest rendering, so the method answers this proof with zero. A proof that binds a digest rendering would need upstream's generator rerun with that custom data, or a real document.
