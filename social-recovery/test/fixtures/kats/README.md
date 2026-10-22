# Known-answer vectors

Each JSON file here fixes the exact bytes of one format the contracts and their SDK must agree on: a digest a guardian signs, a commitment the manager stores, a proof a method decodes, the batch the action sends. Each side tests itself, so a contract and an SDK can both pass their own suites and still disagree on the bytes. A vector file breaks that symmetry: both sides replay the same inputs and must produce the same outputs. The replay tests on this side are under `test/kat/`.

The rules:

- **The code under test never generates a vector.** A vector produced by the implementation it checks can never fail against it. The expected values come from `reference-contract-kats.mjs`, which computes them with `viem` and `ox`, independently of the Solidity code.
- **A change to a vector is a change to a wire format.** It breaks every SDK that replays the old one, so it goes in its own pull request, with the SDK updated alongside.
- **The vectors cover the edges:** zero values, maximum widths and empty payloads, not only the common case.

To check that every file matches its reference, from `social-recovery/`:

```sh
npm ci --ignore-scripts
node test/fixtures/kats/reference-contract-kats.mjs --check
```

CI runs the same check.

| File | Format | Bytes | Vectors |
|---|---|---|---|
| `ambire-handover.json` | `ambire-handover-v1` | `abi.encode(address newAuthority, address removedAuthority)` | 2 |
| `ambire-kit-slot.json` | `ambire-kit-slot-v1` | `slot = low20(keccak256(abi.encode("kit", action))); binding = keccak256(abi.encode(action, bytes("")))` | 1 |
| `approval-digest.json` | `approval-digest-v1` | `EIP-712 Approval under PolicyManager domain version 1` | 7 |
| `attempt-request.json` | `attempt-request-v1` | `abi.encodeWithSelector(IPolicyManager.startAttempt.selector, AttemptRequest)` | 1 |
| `cancel-request.json` | `cancel-request-v1` | `abi.encodeWithSelector(IPolicyManager.cancelByProofs.selector, CancelRequest)` | 1 |
| `cancellation-digest.json` | `cancellation-digest-v1` | `EIP-712 Cancellation under PolicyManager domain version 1` | 6 |
| `credential-commitment.json` | `credential-commitment-v1` | `keccak256(abi.encode(address method, bytes config, bytes32 salt))` | 2 |
| `manager-events.json` | `manager-events-v1` | `keccak256(event signature) in topic0; indexed account and action in topics; remaining fields ABI encoded in data` | 5 |
| `method-aadhaar-config.json` | `method-aadhaar-config-v2` | `abi.encode(uint256 nullifier, uint256 nullifierSeed, uint256 freshnessWindow)` | 1 |
| `method-aadhaar-proof.json` | `method-aadhaar-proof-v1` | `abi.encode(uint256[2] a, uint256[2][2] b, uint256[2] c, uint256[9] inputs)` | 1 |
| `method-ecdsa-config.json` | `method-ecdsa-config-v1` | `abi.encode(address signer)` | 2 |
| `method-ecdsa-proof.json` | `method-ecdsa-proof-v1` | `raw signature bytes over the place digest; not abi.encode(bytes)` | 2 |
| `method-events.json` | `method-events-v1` | `keccak256(event signature) in topic0; indexed role addresses in topics; remaining fields ABI encoded in data` | 6 |
| `method-passkey-config.json` | `method-passkey-config-v1` | `abi.encode(uint256 x, uint256 y, bytes32 rpIdHash)` | 1 |
| `method-passkey-proof.json` | `method-passkey-proof-v1` | `abi.encode(bytes authenticatorData, bytes clientDataJSON, uint256 r, uint256 s)` | 8 |
| `method-verdict.json` | `method-verdict-v1` | `bytes4(keccak256("verify(bytes,bytes32,bytes)"))` | 1 |
| `method-zkpassport-config.json` | `method-zkpassport-config-v2` | `abi.encode(bytes32 uniqueIdentifier, string domain, string scope, uint256 validityPeriodInSeconds)` | 1 |
| `method-zkpassport-proof.json` | `method-zkpassport-proof-v1` | `abi.encode(ProofVerificationData(bytes32 vkeyHash,bytes proof,bytes32[] publicInputs), bytes committedInputs)` | 1 |
| `payment-order.json` | `payment-order-v1` | `abi.encode(address token, uint256 amount, address payee)` | 2 |
| `proof-place.json` | `proof-place-v1` | `abi.encode(ProofPlace(uint256 place,address method,bytes config,bytes32 salt,bytes proof))` | 2 |
| `setup-body.json` | `setup-body-v1` | `abi.encode(uint48 wait, bool ignoresPause, Clause[] clauses)` | 3 |
| `setup-commitment.json` | `setup-commitment-v1` | `keccak256(abi.encode(address account, address action, uint64 nonce, bytes setupBody))` | 2 |
