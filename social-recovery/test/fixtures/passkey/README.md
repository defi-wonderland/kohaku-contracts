# Real passkey assertions

Collected on 2026-10-12. `fixture.json` holds eight WebAuthn ES256 assertions that real authenticators produced, copied from the test data three WebAuthn libraries publish. `test/method-passkey/PasskeyMethodRealAssertions.t.sol` replays them through the passkey method's `verify`, so the suite shows what real devices emit passes the method, and not only the vectors the tests sign themselves.

## The assertions

Every challenge decodes to exactly 32 bytes, the length of a digest. Every relying-party hash, the first 32 bytes of the authenticator data, equals sha256 of the relying-party id the source names. Every signature verifies under its key, which `generate.py` checks.

| Name | Authenticator | Source entry | Flags | Counter | s half | Verdict |
|---|---|---|---|---|---|---|
| `appleIos` | Apple platform authenticator on iOS | Yubico `AppleAttestationIos` | 0x05 | 0 | low | accepted |
| `appleMacos` | Apple platform authenticator on macOS | Yubico `AppleAttestationMacos` | 0x05 | 0 | low | accepted |
| `yubikeyBio` | YubiKey Bio, firmware 5.5.4 | Yubico `YubikeyBio_5_5_4` | 0x05 | 4 | high | accepted |
| `webauthnSolChrome` | not stated by the source; one credential through Chrome | webauthn-sol `test_chrome` | 0x05 | 266 | low | accepted |
| `webauthnSolSafari` | the same credential through Safari | webauthn-sol `test_safari` | 0x05 | 257 | low | accepted |
| `yubikey5Nfc` | YubiKey 5 NFC | Yubico `YubiKey5Nfc` | 0x01 | 58 | high | refused: user verified is clear |
| `yubikey5cNfcLegacy` | YubiKey 5C NFC through a browser of the pre-standard era | Yubico `YubiKey5cNfc` | 0x01 | 1 | high | refused: challenge before type, and user verified is clear |
| `chromeTouchIdLegacy` | Chrome's Touch ID platform authenticator on macOS, 2019 | go-webauthn `testAssertionResponses["success"]` | 0x45 | 1553097241 | high | refused: challenge before type |

`chromeTouchIdLegacy` is the one real output the method refuses for its member order alone. Chrome of that time wrote the client data with its members sorted, `{"challenge":...,"new_keys_may_be_added_here":...,"origin":...,"type":"webauthn.get"}`, before WebAuthn Level 2 fixed the order to type first and challenge second. Its flags carry user present and user verified, and backup state is clear, so only the fixed prefix refuses it. The authenticator data also carries attested credential data (flag 0x40), as that Chrome's Touch ID authenticator returned in assertions. The source labels it "None Attestation - MacOS TouchID", and its AAGUID `adce0002-35bc-c60a-648b-0b25f1f05503` is Chrome's Touch ID authenticator. Current browsers write type first, which `appleIos`, `appleMacos`, `yubikeyBio` and the two webauthn-sol assertions show.

No assertion here sets backup eligibility or backup state. The one real assertion found with flags 0x1d, a synced passkey, is in daimo-eth/p256-verifier `test/WebAuthn.t.sol`, and its challenge is the 4 bytes `test`, so it cannot stand for a digest and is left out.

## Sources

| Repository | Commit | Path | Licence |
|---|---|---|---|
| https://github.com/Yubico/java-webauthn-server | `e63ea7d98a4974c29ad42084d2704a4e400b7c3a` | `webauthn-server-core/src/test/scala/com/yubico/webauthn/test/RealExamples.scala` | BSD-2-Clause |
| https://github.com/base-org/webauthn-sol | `619f20ab0f074fef41066ee4ab24849a913263b2` | `test/WebAuthn.t.sol` | MIT |
| https://github.com/go-webauthn/webauthn | `7ae82c9ad5f84c997a1f9acd72460dbbdfbfce3c` | `protocol/assertion_test.go` | BSD-3-Clause |

`NOTICE` carries each licence's text.

## Fields of `fixture.json`

Each entry of `assertions` keeps its values in the encoding the source published:

- `name`: the fixture's name, which the generated getter takes as `_real<Name>`.
- `source`: repository, commit, licence, path and the entry or test name inside the file.
- `authenticator`, `note`: what produced it and what is notable about it.
- `expected`: `accepted` or `refused`, the verdict the tests assert.
- `rpId`: the relying-party id the source names.
- `publicKey`: for Yubico and go-webauthn, a COSE key in unpadded base64url. For Yubico it is the `credentialPublicKey` inside the attested credential data of the entry's attestation object, the bytes after the 2-byte credential id length and the credential id. For webauthn-sol, `xy` holds the two decimal coordinates the test states.
- `authenticatorData`, `clientDataJSON`: the exact bytes, unpadded base64url. For webauthn-sol the client data is the string the test builds with `string.concat`, with the challenge rendered in unpadded base64url.
- `signature`: `der` holds the DER signature in unpadded base64url; `rs` holds the two decimal scalars.

## Files

- `fixture.json`: the assertions as copied.
- `generate.py`: derives x, y, r, s, the digest and the relying-party hash from `fixture.json`, refuses an entry whose challenge is not 32 bytes, whose relying-party hash does not match its id, or whose signature does not verify, and writes `PasskeyRealAssertionFixture.sol`.
- `PasskeyRealAssertionFixture.sol`: one getter per assertion and `_acceptedRealAssertions()`. Tests may read files only under `test/fixtures/kats` and `out`, so they take the assertions from this contract rather than reading `fixture.json`.

## Regenerating the contract

From the repository root:

```sh
python3 test/fixtures/passkey/generate.py
forge fmt --check test/fixtures/passkey/PasskeyRealAssertionFixture.sol
git diff --exit-code test/fixtures/passkey/PasskeyRealAssertionFixture.sol
```

The script needs only the Python 3 standard library. On an unchanged `fixture.json` the last command finds no difference.
