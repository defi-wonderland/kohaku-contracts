// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {IPolicyMethod} from 'interfaces/IPolicyMethod.sol';
import {PasskeyMethodFixture} from 'test/utils/PasskeyMethodFixture.sol';

/// @notice The passkey method's verify, one check at a time, against the real P256VERIFY precompile.
///         A refusal is a successful answer of one word that is not the verify selector, since the
///         method declares no error and every failed check answers; only a proof that is not the ABI
///         layout may revert instead. The client data must begin with exactly
///         {"type":"webauthn.get","challenge":"<unpadded base64url digest>", the order browsers write,
///         and members after that prefix are signed bytes the method does not inspect.
contract PasskeyMethodVerifyTest is PasskeyMethodFixture {
  /*///////////////////////////////////////////////////////////////
                             ACCEPTED
  ///////////////////////////////////////////////////////////////*/

  /// A passkey assertion over the digest, signed by the committed key with both flags set, is accepted.
  /// This is the path every passkey guardian takes to fill a place in a recovery.
  function test_WhenTheAssertionIsWellFormed() external view {
    // it should return the verify selector
    _assertAccepted(_guardianConfig, _placeDigest, _guardianProof(_standardClientData(_placeDigest)));
  }

  /// A digest whose rendering uses the url safe characters `-` and `_` is accepted.
  /// Browsers render the challenge in base64url, so a method using standard base64 would refuse real guardians.
  function test_WhenTheDigestRendersWithTheUrlSafeCharacters() external view {
    // it should return the verify selector
    // Every sextet of this digest is 63, rendered `_` in base64url and `/` in standard base64.
    bytes32 _digest = bytes32(type(uint256).max);
    bytes memory _clientDataJSON = _standardClientData(_digest);
    assertTrue(_contains(_clientDataJSON, '"challenge":"___'), 'fixture: the challenge is not url safe');
    _assertAccepted(_guardianConfig, _digest, _guardianProof(_clientDataJSON));
  }

  /// Client data with an extra member after the canonical members is accepted.
  /// Browsers may add members, and refusing them would lock out guardians whose browser does.
  function test_WhenTheClientDataCarriesAnExtraTrailingField() external view {
    // it should return the verify selector
    _assertAccepted(_guardianConfig, _placeDigest, _guardianProof(_extraFieldClientData(_placeDigest)));
  }

  /// Client data that is exactly the 80 byte prefix, with nothing after it, is accepted.
  /// The method checks only the prefix, so the rest of the document is signed bytes and nothing more.
  function test_WhenTheClientDataIsExactlyThePrefix() external view {
    // it should return the verify selector
    // Only the prefix is checked; what follows it, here nothing, is signed bytes.
    string memory _challenge = _renderChallenge(_placeDigest);
    bytes memory _clientDataJSON = bytes(string.concat('{"type":"webauthn.get","challenge":"', _challenge, '"'));
    assertEq(_clientDataJSON.length, 80, 'fixture: the prefix is not 80 bytes');
    _assertAccepted(_guardianConfig, _placeDigest, _guardianProof(_clientDataJSON));
  }

  /// An assertion with backup eligibility 0x08 set beside user present and user verified, flags 0x0d, is accepted.
  /// A passkey that may be synced sets that bit, and the method must read each required flag as a bit.
  function test_WhenTheFlagsCarryBackupEligibilityBesideUserPresentAndUserVerified() external view {
    // it should return the verify selector
    bytes1 _flags = _FLAGS_UP_UV | _FLAG_BE;
    assertEq(_flags, bytes1(0x0d), 'fixture: the flags are not 0x0d');
    _assertAccepted(
      _guardianConfig,
      _placeDigest,
      _signedProof(_GUARDIAN_KEY, _buildAuthenticatorData(_guardianRpIdHash, _flags), _standardClientData(_placeDigest))
    );
  }

  /// An assertion with backup eligibility 0x08 and backup state 0x10 both set beside user present and user
  /// verified, flags 0x1d, is accepted. Synced passkeys set both, and they are the passkeys most guardians have.
  function test_WhenTheFlagsCarryBackupEligibilityAndBackupState() external view {
    // it should return the verify selector
    bytes1 _flags = _FLAGS_UP_UV | _FLAG_BE | _FLAG_BS;
    assertEq(_flags, bytes1(0x1d), 'fixture: the flags are not 0x1d');
    _assertAccepted(
      _guardianConfig,
      _placeDigest,
      _signedProof(_GUARDIAN_KEY, _buildAuthenticatorData(_guardianRpIdHash, _flags), _standardClientData(_placeDigest))
    );
  }

  /// Assertions whose signature counter is 1, and the largest four-byte value, signed over that counter, are
  /// accepted. Authenticators count their uses, so a nonzero counter is normal and must not lose the place.
  function test_WhenTheSignatureCounterIsNonzero() external view {
    // it should return the verify selector
    bytes memory _clientDataJSON = _standardClientData(_placeDigest);
    bytes memory _one = _buildAuthenticatorData(_guardianRpIdHash, _FLAGS_UP_UV, bytes4(uint32(1)));
    bytes memory _max = _buildAuthenticatorData(_guardianRpIdHash, _FLAGS_UP_UV, bytes4(type(uint32).max));
    _assertAccepted(_guardianConfig, _placeDigest, _signedProof(_GUARDIAN_KEY, _one, _clientDataJSON));
    _assertAccepted(_guardianConfig, _placeDigest, _signedProof(_GUARDIAN_KEY, _max, _clientDataJSON));
  }

  /// Authenticator data of 37 bytes plus 1 to 256 bytes of extension output, with flags 0x85 (user present, user
  /// verified, extension data) right after the relying party hash, is accepted. `_lengthSeed` picks the output's
  /// length and `_byteSeed` its bytes. Real authenticators append extension output, so a method that took only
  /// exactly 37 bytes, or read the flags from the end, would refuse guardians whose authenticator adds it.
  function test_WhenExtensionOutputOfAnyLengthFollowsTheSignatureCounter(uint256 _lengthSeed, bytes32 _byteSeed)
    external
    view
  {
    // it should return the verify selector
    uint256 _length = bound(_lengthSeed, 1, 256);
    bytes memory _extensions = new bytes(_length);
    for (uint256 _i; _i < _length; ++_i) {
      _extensions[_i] = keccak256(abi.encode(_byteSeed, _i))[0];
    }
    bytes memory _authenticatorData = abi.encodePacked(_guardianRpIdHash, bytes1(0x85), bytes4(0), _extensions);
    assertEq(_authenticatorData.length, 37 + _length, 'fixture: the front is not 37 bytes');
    _assertAccepted(
      _guardianConfig, _placeDigest, _signedProof(_GUARDIAN_KEY, _authenticatorData, _standardClientData(_placeDigest))
    );
  }

  /// Under a static call, as the manager makes it, an accepted proof returns exactly one word holding the verify
  /// selector.
  /// The manager counts a verdict only in that exact shape, so anything longer or shorter loses the place.
  function test_WhenCalledThroughAStaticCall() external view {
    // it should return exactly one word holding the verify selector
    bytes memory _proof = _guardianProof(_standardClientData(_placeDigest));
    (bool _success, bytes memory _returned) =
      address(_method).staticcall(abi.encodeCall(IPolicyMethod.verify, (_guardianConfig, _placeDigest, _proof)));
    assertTrue(_success, 'the static call failed');
    assertEq(_returned.length, 32, 'the return is not one word');
    assertEq(abi.decode(_returned, (bytes32)), bytes32(bytes4(0x024ad318)), 'the word is not the verify selector');
  }

  /// The method asks the P256VERIFY precompile at 0x100 about sha256(authenticatorData || sha256(clientDataJSON)), the
  /// signature and the committed key.
  /// That hash is what a passkey signs, so checking any other message would accept signatures the guardian never made.
  function test_WhenTheSignatureIsChecked() external {
    // it should call the P256VERIFY precompile with the signed hash the signature and the committed key
    bytes memory _authenticatorData = _buildAuthenticatorData(_guardianRpIdHash, _FLAGS_UP_UV);
    bytes memory _clientDataJSON = _extraFieldClientData(_placeDigest);
    (uint256 _r, uint256 _s) = _signAssertion(_GUARDIAN_KEY, _authenticatorData, _clientDataJSON);
    (uint256 _x, uint256 _y) = vm.publicKeyP256(_GUARDIAN_KEY);
    bytes32 _signedHash = _hashAssertion(_authenticatorData, _clientDataJSON);
    vm.expectCall(_P256_VERIFY, abi.encode(_signedHash, _r, _s, _x, _y));
    bytes4 _magicValue =
      _method.verify(_guardianConfig, _placeDigest, _encodeProof(_authenticatorData, _clientDataJSON, _r, _s));
    assertEq(_magicValue, IPolicyMethod.verify.selector);
  }

  /*///////////////////////////////////////////////////////////////
                             CHALLENGE
  ///////////////////////////////////////////////////////////////*/

  /// A challenge that renders a digest one bit away from the one verify is asked about is refused, and a proof
  /// built for the digest is refused when verify is asked about the next digest or zero. The verdict binds the
  /// proof to the exact digest the manager passes, so an approval for one place cannot be replayed on another.
  function test_WhenVerifyIsAskedAboutAnotherDigest() external view {
    // it should refuse the proof
    bytes32 _otherDigest = bytes32(uint256(_placeDigest) ^ 1);
    _assertRejected(_guardianConfig, _placeDigest, _guardianProof(_standardClientData(_otherDigest)));
    bytes memory _proof = _guardianProof(_standardClientData(_placeDigest));
    _assertRejected(_guardianConfig, bytes32(uint256(_placeDigest) + 1), _proof);
    _assertRejected(_guardianConfig, bytes32(0), _proof);
  }

  /// A challenge carrying a base64 padding character is refused.
  /// The challenge is the unpadded rendering, and any other text is a different challenge.
  function test_WhenTheChallengeCarriesBase64Padding() external view {
    // it should refuse the proof
    bytes memory _clientDataJSON = _clientData(
      'webauthn.get', string.concat(_renderChallenge(_placeDigest), '='), string.concat(_ORIGIN_FIELDS, _EXTRA_FIELD)
    );
    _assertRejected(_guardianConfig, _placeDigest, _guardianProof(_clientDataJSON));
  }

  /// A challenge rendered with the standard base64 alphabet, with or without padding, is refused.
  /// Only the base64url rendering is the digest's challenge.
  function test_WhenTheChallengeUsesTheStandardBase64Alphabet() external view {
    // it should refuse the proof
    bytes32 _digest = bytes32(type(uint256).max);
    string memory _standard = _base64NoPad(abi.encodePacked(_digest), _BASE64_ALPHABET);
    _assertRejected(_guardianConfig, _digest, _guardianProof(_clientData('webauthn.get', _standard, _ORIGIN_FIELDS)));
    _assertRejected(
      _guardianConfig,
      _digest,
      _guardianProof(_clientData('webauthn.get', string.concat(_standard, '='), _ORIGIN_FIELDS))
    );
  }

  /// A challenge missing the last character of the digest's rendering is refused.
  /// A shortened challenge does not render the digest.
  function test_WhenTheChallengeIsTruncated() external view {
    // it should refuse the proof
    bytes memory _full = bytes(_renderChallenge(_placeDigest));
    bytes memory _truncated = new bytes(_full.length - 1);
    for (uint256 _i = 0; _i < _truncated.length; ++_i) {
      _truncated[_i] = _full[_i];
    }
    _assertRejected(
      _guardianConfig, _placeDigest, _guardianProof(_clientData('webauthn.get', string(_truncated), _ORIGIN_FIELDS))
    );
  }

  /// Client data with a member between type and challenge is refused.
  /// The method accepts only the order browsers write, type then challenge at the very start.
  function test_WhenAnExtraFieldSitsBetweenTheTypeAndTheChallenge() external view {
    // it should refuse the proof
    bytes memory _clientDataJSON = bytes(
      string.concat(
        '{"type":"webauthn.get","extra":"kept","challenge":"', _renderChallenge(_placeDigest), '"', _ORIGIN_FIELDS, '}'
      )
    );
    _assertRejected(_guardianConfig, _placeDigest, _guardianProof(_clientDataJSON));
  }

  /// Client data with a member before type is refused.
  /// The canonical members must open the document, so moved members are never parsed as the real ones.
  function test_WhenAnExtraFieldSitsBeforeTheType() external view {
    // it should refuse the proof
    bytes memory _clientDataJSON = bytes(
      string.concat(
        '{"extra":"',
        _letterRun(77),
        '","type":"webauthn.get","challenge":"',
        _renderChallenge(_placeDigest),
        '"',
        _ORIGIN_FIELDS,
        '}'
      )
    );
    _assertRejected(_guardianConfig, _placeDigest, _guardianProof(_clientDataJSON));
  }

  /// Client data that opens with another challenge member before the canonical members is refused, whatever that member
  /// holds.
  /// A JSON reader could take either duplicate, so the method accepts only the canonical opening.
  function test_WhenADuplicateChallengeMemberPrecedesTheCanonicalPrefix() external view {
    // it should refuse the proof
    string memory _challenge = _renderChallenge(_placeDigest);
    string memory _canonical = string.concat('"type":"webauthn.get","challenge":"', _challenge, '"');
    string memory _otherChallenge = _renderChallenge(keccak256('another place'));
    _assertRejected(
      _guardianConfig,
      _placeDigest,
      _guardianProof(bytes(string.concat('{"challenge":"', _otherChallenge, '",', _canonical, _ORIGIN_FIELDS, '}')))
    );
    _assertRejected(
      _guardianConfig,
      _placeDigest,
      _guardianProof(
        bytes(string.concat('{"challenge":"', _renderChallenge(_placeDigest), '",', _canonical, _ORIGIN_FIELDS, '}'))
      )
    );
  }

  /// Client data with whitespace anywhere inside or before the prefix is refused.
  /// The prefix is compared byte for byte, and browsers write it with no whitespace.
  function test_WhenThePrefixCarriesWhitespace() external view {
    // it should refuse the proof
    string memory _challenge = _renderChallenge(_placeDigest);
    string memory _tail = string.concat(_ORIGIN_FIELDS, '}');
    _assertRejected(
      _guardianConfig,
      _placeDigest,
      _guardianProof(bytes(string.concat('{"type": "webauthn.get","challenge":"', _challenge, '"', _tail)))
    );
    _assertRejected(
      _guardianConfig,
      _placeDigest,
      _guardianProof(bytes(string.concat('{ "type":"webauthn.get","challenge":"', _challenge, '"', _tail)))
    );
    _assertRejected(
      _guardianConfig,
      _placeDigest,
      _guardianProof(bytes(string.concat('{"type":"webauthn.get", "challenge":"', _challenge, '"', _tail)))
    );
    _assertRejected(
      _guardianConfig,
      _placeDigest,
      _guardianProof(bytes(string.concat('{"type":"webauthn.get","challenge": "', _challenge, '"', _tail)))
    );
    _assertRejected(
      _guardianConfig,
      _placeDigest,
      _guardianProof(bytes(string.concat(' {"type":"webauthn.get","challenge":"', _challenge, '"', _tail)))
    );
  }

  /// Client data shorter than the prefix, down to one byte and empty, is refused.
  /// One byte short of the prefix is the boundary where the comparison cannot complete.
  function test_WhenTheClientDataIsShorterThanThePrefix() external view {
    // it should refuse the proof
    bytes memory _prefix =
      bytes(string.concat('{"type":"webauthn.get","challenge":"', _renderChallenge(_placeDigest), '"'));
    bytes memory _short = new bytes(_prefix.length - 1);
    for (uint256 _i = 0; _i < _short.length; ++_i) {
      _short[_i] = _prefix[_i];
    }
    _assertRejected(_guardianConfig, _placeDigest, _guardianProof(_short));
    _assertRejected(_guardianConfig, _placeDigest, _guardianProof(bytes('{"type":"webauthn.get","challenge":"')));
    _assertRejected(_guardianConfig, _placeDigest, _guardianProof(bytes('{')));
    _assertRejected(_guardianConfig, _placeDigest, _guardianProof(''));
  }

  /*///////////////////////////////////////////////////////////////
                               TYPE
  ///////////////////////////////////////////////////////////////*/

  /// Client data typed webauthn.create is refused.
  /// That is a registration, not an assertion, and it must never approve a recovery.
  function test_WhenTheTypeIsWebauthnCreate() external view {
    // it should refuse the proof
    _assertRejected(
      _guardianConfig,
      _placeDigest,
      _guardianProof(_clientData('webauthn.create', _renderChallenge(_placeDigest), _ORIGIN_FIELDS))
    );
  }

  /// A type value that starts with webauthn.get and continues is refused.
  /// The closing quote after the type value belongs to the prefix.
  function test_WhenTheTypeValueExtendsWebauthnGet() external view {
    // it should refuse the proof
    _assertRejected(
      _guardianConfig,
      _placeDigest,
      _guardianProof(_clientData('webauthn.getx', _renderChallenge(_placeDigest), _ORIGIN_FIELDS))
    );
  }

  /// Client data with no type member, including one with webauthn.get only as another member's value, is refused.
  /// The method checks the type member itself, not the text anywhere in the document.
  function test_WhenTheTypeFieldIsMissing() external view {
    // it should refuse the proof
    bytes memory _clientDataJSON = bytes(
      string.concat('{"kind":"webauthn.get","challenge":"', _renderChallenge(_placeDigest), '"', _ORIGIN_FIELDS, '}')
    );
    _assertRejected(_guardianConfig, _placeDigest, _guardianProof(_clientDataJSON));
    bytes memory _createdWithDecoy = _clientData(
      'webauthn.create', _renderChallenge(_placeDigest), string.concat(_ORIGIN_FIELDS, ',"extra":"webauthn.get"')
    );
    _assertRejected(_guardianConfig, _placeDigest, _guardianProof(_createdWithDecoy));
  }

  /*///////////////////////////////////////////////////////////////
                        AUTHENTICATOR DATA
  ///////////////////////////////////////////////////////////////*/

  /// An assertion made for another relying party is refused, while the same assertion passes under a config committing
  /// that party.
  /// A passkey enrolled for one site must not approve through a credential enrolled under another.
  function test_WhenTheRelyingPartyHashDiffersFromTheCommittedOne() external view {
    // it should refuse the proof
    bytes32 _otherRpIdHash = sha256(bytes('evil.example'));
    bytes memory _proof = _signedProof(
      _GUARDIAN_KEY, _buildAuthenticatorData(_otherRpIdHash, _FLAGS_UP_UV), _standardClientData(_placeDigest)
    );
    _assertRejected(_guardianConfig, _placeDigest, _proof);
    // The same assertion verifies under a config committing that hash, so the refusal is the hash's.
    _assertAccepted(_buildConfig(_GUARDIAN_KEY, _otherRpIdHash), _placeDigest, _proof);
  }

  /// An assertion without the user present flag is refused, even with every other flag set.
  /// The guardian must have touched the authenticator for the approval to count.
  function test_WhenTheUserPresentFlagIsMissing() external view {
    // it should refuse the proof
    _assertRejected(
      _guardianConfig,
      _placeDigest,
      _signedProof(
        _GUARDIAN_KEY, _buildAuthenticatorData(_guardianRpIdHash, _FLAG_UV), _standardClientData(_placeDigest)
      )
    );
    _assertRejected(
      _guardianConfig,
      _placeDigest,
      _signedProof(
        _GUARDIAN_KEY, _buildAuthenticatorData(_guardianRpIdHash, bytes1(0xfe)), _standardClientData(_placeDigest)
      )
    );
  }

  /// An assertion without the user verified flag is refused, even with every other flag set.
  /// The guardian must have unlocked the passkey with a PIN or biometric for the approval to count.
  function test_WhenTheUserVerifiedFlagIsMissing() external view {
    // it should refuse the proof
    _assertRejected(
      _guardianConfig,
      _placeDigest,
      _signedProof(
        _GUARDIAN_KEY, _buildAuthenticatorData(_guardianRpIdHash, _FLAG_UP), _standardClientData(_placeDigest)
      )
    );
    _assertRejected(
      _guardianConfig,
      _placeDigest,
      _signedProof(
        _GUARDIAN_KEY, _buildAuthenticatorData(_guardianRpIdHash, bytes1(0xfb)), _standardClientData(_placeDigest)
      )
    );
  }

  /// Authenticator data of 32 bytes, holding the relying party hash only, and empty authenticator data are refused.
  /// Without the flags byte the method cannot see user presence or verification.
  function test_WhenTheAuthenticatorDataEndsBeforeTheFlagsByte() external view {
    // it should refuse the proof
    bytes memory _clientDataJSON = _standardClientData(_placeDigest);
    _assertRejected(
      _guardianConfig, _placeDigest, _signedProof(_GUARDIAN_KEY, abi.encodePacked(_guardianRpIdHash), _clientDataJSON)
    );
    _assertRejected(_guardianConfig, _placeDigest, _signedProof(_GUARDIAN_KEY, '', _clientDataJSON));
  }

  /// Authenticator data of 33 and of 36 bytes, the relying party hash and flags 0x05 followed by a counter cut
  /// short, each validly signed as given, is refused with one word that is not the verify selector. The front
  /// is 37 bytes, so data ending inside the counter is malformed, and the refusal is an answer, not a revert.
  function test_WhenTheAuthenticatorDataEndsInsideTheSignatureCounter() external view {
    // it should answer with one word that is not the verify selector
    bytes memory _clientDataJSON = _standardClientData(_placeDigest);
    bytes memory _thirtyThree = abi.encodePacked(_guardianRpIdHash, _FLAGS_UP_UV);
    bytes memory _thirtySix = abi.encodePacked(_guardianRpIdHash, _FLAGS_UP_UV, bytes3(0));
    assertEq(_thirtyThree.length, 33, 'fixture: not 33 bytes');
    assertEq(_thirtySix.length, 36, 'fixture: not 36 bytes');
    _assertRejected(_guardianConfig, _placeDigest, _signedProof(_GUARDIAN_KEY, _thirtyThree, _clientDataJSON));
    _assertRejected(_guardianConfig, _placeDigest, _signedProof(_GUARDIAN_KEY, _thirtySix, _clientDataJSON));
  }

  /// A valid signature over flags 0x15, backup state 0x10 set with backup eligibility 0x08 clear, is refused
  /// with one word that is not the verify selector. WebAuthn forbids that pair, so an authenticator sending it
  /// is broken or forged and must not fill a place, and the refusal is an answer rather than a revert.
  function test_WhenTheFlagsCarryBackupStateWithoutBackupEligibility() external view {
    // it should answer with one word that is not the verify selector
    bytes1 _flags = _FLAGS_UP_UV | _FLAG_BS;
    assertEq(_flags, bytes1(0x15), 'fixture: the flags are not 0x15');
    _assertRejected(
      _guardianConfig,
      _placeDigest,
      _signedProof(_GUARDIAN_KEY, _buildAuthenticatorData(_guardianRpIdHash, _flags), _standardClientData(_placeDigest))
    );
  }

  /// Authenticator data with flags 0x81 (user present and extension data, user verified clear) right after the
  /// relying party hash, followed by 18 bytes of extension output whose fifth byte from the end is 0x05, is refused.
  /// The flags byte is the one at offset 32, so a security key used without its PIN must not fill a place through
  /// a later byte that happens to read as user present and user verified.
  function test_WhenExtensionOutputFollowsFlagsWithoutUserVerification() external view {
    // it should refuse the proof
    bytes memory _extensions = hex'a16b686d61632d7365637265740500000000';
    bytes memory _authenticatorData = abi.encodePacked(_guardianRpIdHash, bytes1(0x81), bytes4(0), _extensions);
    assertEq(_authenticatorData[_authenticatorData.length - 5], bytes1(0x05), 'fixture: no 0x05 near the end');
    _assertRejected(
      _guardianConfig, _placeDigest, _signedProof(_GUARDIAN_KEY, _authenticatorData, _standardClientData(_placeDigest))
    );
  }

  /*///////////////////////////////////////////////////////////////
                             SIGNATURE
  ///////////////////////////////////////////////////////////////*/

  /// An assertion signed by a key other than the committed one is refused.
  /// The precompile answers a failed check with a successful empty return, so a method reading success as approval
  /// accepts this proof.
  function test_WhenTheSignatureIsUnderAnotherKey() external view {
    // it should refuse the proof
    bytes memory _proof = _signedProof(
      _OTHER_KEY, _buildAuthenticatorData(_guardianRpIdHash, _FLAGS_UP_UV), _standardClientData(_placeDigest)
    );
    _assertRejected(_guardianConfig, _placeDigest, _proof);
  }

  /// A proof by the guardian's key is refused under a config committing another key.
  /// The committed key alone decides whose passkey fills the place.
  function test_WhenTheConfigCommitsAnotherKey() external view {
    // it should refuse the proof
    _assertRejected(
      _buildConfig(_OTHER_KEY, _guardianRpIdHash), _placeDigest, _guardianProof(_standardClientData(_placeDigest))
    );
  }

  /// A signature over client data that differs by one byte in an extra member is refused.
  /// Extra members are signed bytes, so a changed member means the guardian never signed that document.
  function test_WhenTheSignatureCoversOtherClientDataBytes() external view {
    // it should refuse the proof
    bytes memory _authenticatorData = _buildAuthenticatorData(_guardianRpIdHash, _FLAGS_UP_UV);
    bytes memory _signed = _extraFieldClientData(_placeDigest);
    bytes memory _submitted =
      _clientData('webauthn.get', _renderChallenge(_placeDigest), string.concat(_ORIGIN_FIELDS, ',"extra":"kepT"'));
    (uint256 _r, uint256 _s) = _signAssertion(_GUARDIAN_KEY, _authenticatorData, _signed);
    _assertRejected(_guardianConfig, _placeDigest, _encodeProof(_authenticatorData, _submitted, _r, _s));
  }

  /// A signature over the client data without its extra member is refused when the member is added.
  /// The method hashes the exact bytes it receives, never a trimmed copy.
  function test_WhenTheSignatureCoversTheClientDataWithoutItsExtraField() external view {
    // it should refuse the proof
    bytes memory _authenticatorData = _buildAuthenticatorData(_guardianRpIdHash, _FLAGS_UP_UV);
    (uint256 _r, uint256 _s) = _signAssertion(_GUARDIAN_KEY, _authenticatorData, _standardClientData(_placeDigest));
    _assertRejected(
      _guardianConfig, _placeDigest, _encodeProof(_authenticatorData, _extraFieldClientData(_placeDigest), _r, _s)
    );
  }

  /// A signature over authenticator data with another signature counter is refused.
  /// Every authenticator data byte is signed, so none can change after signing.
  function test_WhenTheSignatureCoversOtherAuthenticatorData() external view {
    // it should refuse the proof
    bytes memory _clientDataJSON = _standardClientData(_placeDigest);
    bytes memory _signed = _buildAuthenticatorData(_guardianRpIdHash, _FLAGS_UP_UV);
    bytes memory _submitted = abi.encodePacked(_guardianRpIdHash, _FLAGS_UP_UV, bytes4(uint32(1)));
    (uint256 _r, uint256 _s) = _signAssertion(_GUARDIAN_KEY, _signed, _clientDataJSON);
    _assertRejected(_guardianConfig, _placeDigest, _encodeProof(_submitted, _clientDataJSON, _r, _s));
  }

  /// A signature over the raw digest, or over the unhashed client data, is refused.
  /// Only the hash a passkey really signs may count as the guardian's approval.
  function test_WhenTheSignatureCoversTheDigestDirectly() external view {
    // it should refuse the proof
    bytes memory _authenticatorData = _buildAuthenticatorData(_guardianRpIdHash, _FLAGS_UP_UV);
    bytes memory _clientDataJSON = _standardClientData(_placeDigest);
    (uint256 _r, uint256 _s) = _signLow(_GUARDIAN_KEY, _placeDigest);
    _assertRejected(_guardianConfig, _placeDigest, _encodeProof(_authenticatorData, _clientDataJSON, _r, _s));
    // Nor over the concatenation without hashing the client data first.
    (_r, _s) = _signLow(_GUARDIAN_KEY, sha256(abi.encodePacked(_authenticatorData, _clientDataJSON)));
    _assertRejected(_guardianConfig, _placeDigest, _encodeProof(_authenticatorData, _clientDataJSON, _r, _s));
  }

  /// A signature with r or s equal to zero is refused.
  /// Zero scalars are never valid signatures and must not pass by accident.
  function test_WhenASignatureScalarIsZero() external view {
    // it should refuse the proof
    bytes memory _authenticatorData = _buildAuthenticatorData(_guardianRpIdHash, _FLAGS_UP_UV);
    bytes memory _clientDataJSON = _standardClientData(_placeDigest);
    (uint256 _r, uint256 _s) = _signAssertion(_GUARDIAN_KEY, _authenticatorData, _clientDataJSON);
    _assertRejected(_guardianConfig, _placeDigest, _encodeProof(_authenticatorData, _clientDataJSON, 0, _s));
    _assertRejected(_guardianConfig, _placeDigest, _encodeProof(_authenticatorData, _clientDataJSON, _r, 0));
    _assertRejected(_guardianConfig, _placeDigest, _encodeProof(_authenticatorData, _clientDataJSON, 0, 0));
  }

  /// A signature with r or s equal to the P-256 group order or at the largest word is refused.
  /// Scalars must be below the group order to be a signature at all.
  function test_WhenASignatureScalarIsNotBelowTheGroupOrder() external view {
    // it should refuse the proof
    bytes memory _authenticatorData = _buildAuthenticatorData(_guardianRpIdHash, _FLAGS_UP_UV);
    bytes memory _clientDataJSON = _standardClientData(_placeDigest);
    (uint256 _r, uint256 _s) = _signAssertion(_GUARDIAN_KEY, _authenticatorData, _clientDataJSON);
    _assertRejected(
      _guardianConfig, _placeDigest, _encodeProof(_authenticatorData, _clientDataJSON, type(uint256).max, _s)
    );
    _assertRejected(
      _guardianConfig, _placeDigest, _encodeProof(_authenticatorData, _clientDataJSON, _r, type(uint256).max)
    );
    _assertRejected(_guardianConfig, _placeDigest, _encodeProof(_authenticatorData, _clientDataJSON, _P256_N, _s));
    _assertRejected(_guardianConfig, _placeDigest, _encodeProof(_authenticatorData, _clientDataJSON, _r, _P256_N));
  }

  /*///////////////////////////////////////////////////////////////
                         CONFIG AND LAYOUT
  ///////////////////////////////////////////////////////////////*/

  /// An empty proof, a packed proof and a proof with its two byte fields swapped are refused.
  /// The proof is abi.encode(authenticatorData, clientDataJSON, r, s) and nothing else.
  function test_WhenTheProofIsNotTheAbiEncodedLayout() external view {
    // it should refuse the proof
    bytes memory _authenticatorData = _buildAuthenticatorData(_guardianRpIdHash, _FLAGS_UP_UV);
    bytes memory _clientDataJSON = _standardClientData(_placeDigest);
    (uint256 _r, uint256 _s) = _signAssertion(_GUARDIAN_KEY, _authenticatorData, _clientDataJSON);
    _assertRejectedOrReverted(_guardianConfig, _placeDigest, '');
    _assertRejectedOrReverted(
      _guardianConfig, _placeDigest, abi.encodePacked(_authenticatorData, _clientDataJSON, _r, _s)
    );
    _assertRejectedOrReverted(_guardianConfig, _placeDigest, abi.encode(_clientDataJSON, _authenticatorData, _r, _s));
  }

  /// An empty config beside a valid assertion is refused with one word that is not the verify selector.
  /// A credential with no committed key cannot approve anything, and the refusal is an answer, not a revert.
  function test_WhenTheConfigIsEmpty() external view {
    // it should answer with one word that is not the verify selector
    _assertRejected('', _placeDigest, _guardianProof(_standardClientData(_placeDigest)));
  }

  /// The guardian's config cut to 95 bytes, beside the guardian's valid assertion, is refused with one word that
  /// is not the verify selector. A config is exactly three words, and one byte short is not a credential.
  function test_WhenTheConfigIsOneByteShort() external view {
    // it should answer with one word that is not the verify selector
    bytes memory _config = _guardianConfigOfLength(95, bytes32(0));
    _assertRejected(_config, _placeDigest, _guardianProof(_standardClientData(_placeDigest)));
  }

  /// The guardian's config followed by 4 extra bytes, and by 32 extra bytes, beside the guardian's valid
  /// assertion, is refused with one word that is not the verify selector. The extra bytes would give one
  /// passkey many credential hashes, so only the exact 96 byte config counts.
  function test_WhenTheConfigCarriesExtraBytes() external view {
    // it should answer with one word that is not the verify selector
    bytes memory _proof = _guardianProof(_standardClientData(_placeDigest));
    _assertRejected(bytes.concat(_guardianConfig, bytes4(0xdeadbeef)), _placeDigest, _proof);
    _assertRejected(bytes.concat(_guardianConfig, bytes32(0)), _placeDigest, _proof);
  }

  /*///////////////////////////////////////////////////////////////
                              HELPERS
  ///////////////////////////////////////////////////////////////*/

  /// @notice Whether `_haystack` contains `_needle` anywhere, used only to check a fixture.
  function _contains(bytes memory _haystack, bytes memory _needle) internal pure returns (bool _found) {
    if (_needle.length > _haystack.length) return false;
    for (uint256 _i = 0; _i < _haystack.length - _needle.length + 1; ++_i) {
      bool _matches = true;
      for (uint256 _j = 0; _j < _needle.length; ++_j) {
        if (_haystack[_i + _j] != _needle[_j]) {
          _matches = false;
          break;
        }
      }
      if (_matches) return true;
    }
  }
}
