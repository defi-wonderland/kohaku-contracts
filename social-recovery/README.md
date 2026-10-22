# Social recovery

On-chain contracts that let a smart account holder who lost their signing key take the account back through guardians or credentials they already hold. A policy manager judges recovery requests against the rule the holder committed, method modules check each kind of credential, and a recovery action carries out the handover on one account implementation.

The full technical design is in [`docs/contracts.md`](docs/contracts.md). [`docs/scenarios.md`](docs/scenarios.md) walks through what users do with the kit, step by step, and [`docs/invariants.md`](docs/invariants.md) lists the properties that must always hold. Both name the tests that check them.

## Layout

- `contracts/interfaces/`: the kit's shared interfaces.
- `contracts/libraries/`: the setup body codec and the binding digests.
- `contracts/manager/`: the policy manager.
- `contracts/methods/`: one module per credential kind (`ecdsa`, `passkey`, `zkpassport`, `aadhaar`), plus `roles`, the admin and pause base the identity methods share.
- `contracts/actions/ambire/`: the recovery action for Ambire's `AmbireAccount`.
- `script/`: the deployment scripts. [`script/README.md`](script/README.md) is the runbook.
- `test/`: unit, fuzz, invariant, symbolic and fork tests, known-answer vector replays under `test/kat/`, end-to-end walks under `test/integration/`, and gas measurements under `test/gas/`. The vectors live in `test/fixtures/kats/`.

## Build and test

Foundry 1.7.1 and solc 0.8.30, with `evm_version = "osaka"` for the P256VERIFY precompile the passkey method calls. Run from this folder.

```sh
git submodule update --init lib/forge-std lib/openzeppelin-contracts
npm ci --ignore-scripts                                        # only for the vector reference script
forge build
forge test --no-match-test invariant_                          # unit and fuzz tests
FOUNDRY_PROFILE=standard forge test --match-test invariant_    # invariant campaigns
halmos --function check_                                       # symbolic tests, halmos 0.3.3
node test/fixtures/kats/reference-contract-kats.mjs --check    # the vectors match their reference
```

Fork tests read `MAINNET_RPC_URL` and `SEPOLIA_RPC_URL`. They skip when the variables are unset, and need an endpoint that serves historical state.

## License

GPL-3.0-or-later. See [`LICENSE`](LICENSE).
