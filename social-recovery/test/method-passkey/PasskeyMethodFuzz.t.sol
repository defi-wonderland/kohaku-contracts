// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {PasskeyMethodFixture} from 'test/utils/PasskeyMethodFixture.sol';

/// @notice The passkey method's verify over fuzzed keys, digests, relying party hashes, flags, extra
///         members and byte changes, on the real P256VERIFY precompile. Each test stays inside one
///         outcome: inputs are shaped with `bound` or built so they cannot leave it.
/// @dev A `_keySeed` builds a P-256 private key between 1 and the group order minus 1. A `_digest` is
///      the hash the proof must approve. An `_rpIdHash` is the relying party hash the config commits.
contract PasskeyMethodFuzzTest is PasskeyMethodFixture {
  /*///////////////////////////////////////////////////////////////
                             ACCEPTED
  ///////////////////////////////////////////////////////////////*/

  /// Any key that signs a well formed assertion over any digest, under any committed relying party
  /// hash, gets the verify selector. Every guardian's passkey must work whatever place it approves.
  function test_WhenAnyKeySignsAWellFormedAssertionOverAnyDigest(uint256 _keySeed, bytes32 _digest, bytes32 _rpIdHash)
    external
    view
  {
    // it should return the verify selector
    uint256 _privateKey = _boundKey(_keySeed);
    bytes memory _authenticatorData = _buildAuthenticatorData(_rpIdHash, _FLAGS_UP_UV);
    bytes memory _proof = _signedProof(_privateKey, _authenticatorData, _extraFieldClientData(_digest));
    _assertAccepted(_buildConfig(_privateKey, _rpIdHash), _digest, _proof);
  }

  /// Any key's signature is accepted in its high form, s replaced by the group order minus s.
  /// The precompile accepts both forms, so a guardian whose authenticator signs high still counts.
  function test_WhenAnyKeySignsWithTheHighHalf(uint256 _keySeed, bytes32 _digest, bytes32 _rpIdHash) external view {
    // it should return the verify selector
    uint256 _privateKey = _boundKey(_keySeed);
    bytes memory _authenticatorData = _buildAuthenticatorData(_rpIdHash, _FLAGS_UP_UV);
    bytes memory _clientDataJSON = _standardClientData(_digest);
    (uint256 _r, uint256 _s) = _signAssertion(_privateKey, _authenticatorData, _clientDataJSON);
    _assertAccepted(
      _buildConfig(_privateKey, _rpIdHash), _digest, _encodeProof(_authenticatorData, _clientDataJSON, _r, _P256_N - _s)
    );
  }

  /// Extra members of any length, right after the challenge and at the end of the document, are accepted.
  /// Members after the prefix are signed bytes, so browsers that add members keep working.
  function test_WhenExtraMembersOfAnyLengthFollowThePrefix(bytes32 _digest, uint8 _afterChallenge, uint8 _atEnd)
    external
    view
  {
    // it should return the verify selector
    string memory _middle = string.concat(',"mid":"', _letterRun(_afterChallenge), '"');
    string memory _tail = string.concat(',"tail":"', _letterRun(_atEnd), '"');
    bytes memory _clientDataJSON = bytes(
      string.concat(
        '{"type":"webauthn.get","challenge":"', _renderChallenge(_digest), '"', _middle, _ORIGIN_FIELDS, _tail, '}'
      )
    );
    _assertAccepted(_guardianConfig, _digest, _guardianProof(_clientDataJSON));
  }

  /// Any consistent backup bits beside user present and user verified are accepted: none, backup eligibility
  /// 0x08 alone, or 0x08 with backup state 0x10. `_backupBits` picks bits 0x08 and 0x10, and backup state
  /// always brings eligibility with it. Synced passkeys set these bits, so each required flag is read as a bit.
  function test_WhenAnyConsistentBackupBitsAccompanyUserPresentAndUserVerified(uint8 _backupBits) external view {
    // it should return the verify selector
    bytes1 _backup = bytes1(_backupBits) & (_FLAG_BE | _FLAG_BS);
    if (_backup & _FLAG_BS != 0) _backup |= _FLAG_BE;
    bytes1 _flags = _FLAGS_UP_UV | _backup;
    _assertAccepted(
      _guardianConfig,
      _placeDigest,
      _signedProof(_GUARDIAN_KEY, _buildAuthenticatorData(_guardianRpIdHash, _flags), _standardClientData(_placeDigest))
    );
  }

  /// An assertion carrying any four-byte signature counter, signed over that counter, is accepted.
  /// `_counter` is the counter the authenticator reports; the method must not care which use this is.
  function test_WhenTheAssertionCarriesAnySignatureCounter(bytes4 _counter) external view {
    // it should return the verify selector
    bytes memory _authenticatorData = _buildAuthenticatorData(_guardianRpIdHash, _FLAGS_UP_UV, _counter);
    _assertAccepted(
      _guardianConfig, _placeDigest, _signedProof(_GUARDIAN_KEY, _authenticatorData, _standardClientData(_placeDigest))
    );
  }

  /*///////////////////////////////////////////////////////////////
                            CLIENT DATA
  ///////////////////////////////////////////////////////////////*/

  /// A challenge rendering any digest other than the one verify is asked about is refused.
  /// `_delta` is a nonzero word XORed into the digest, so the two digests always differ.
  function test_WhenTheChallengeRendersAnyOtherDigest(uint256 _keySeed, bytes32 _digest, uint256 _delta) external view {
    // it should refuse the proof
    uint256 _privateKey = _boundKey(_keySeed);
    bytes32 _otherDigest = _digest ^ bytes32(bound(_delta, 1, type(uint256).max));
    bytes memory _proof = _signedProof(
      _privateKey, _buildAuthenticatorData(_guardianRpIdHash, _FLAGS_UP_UV), _standardClientData(_otherDigest)
    );
    _assertRejected(_buildConfig(_privateKey, _guardianRpIdHash), _digest, _proof);
  }

  /// One to eight base64url characters appended to the challenge value, before its closing quote, are refused.
  /// `_suffixSeed` picks each appended character from the base64url alphabet.
  function test_WhenTheChallengeValueCarriesAnyExtraCharacters(bytes8 _suffixSeed, uint8 _suffixLength) external view {
    // it should refuse the proof
    uint256 _length = bound(_suffixLength, 1, 8);
    bytes memory _suffix = new bytes(_length);
    for (uint256 _i = 0; _i < _length; ++_i) {
      _suffix[_i] = _BASE64URL_ALPHABET[uint8(_suffixSeed[_i]) % 64];
    }
    bytes memory _clientDataJSON =
      _clientData('webauthn.get', string.concat(_renderChallenge(_placeDigest), string(_suffix)), _ORIGIN_FIELDS);
    _assertRejected(_guardianConfig, _placeDigest, _guardianProof(_clientDataJSON));
  }

  /// Client data typed webauthn.create is refused for any key and digest.
  /// A registration ceremony must never count as an approval.
  function test_WhenAnyDigestIsAssertedAsWebauthnCreate(uint256 _keySeed, bytes32 _digest) external view {
    // it should refuse the proof
    uint256 _privateKey = _boundKey(_keySeed);
    bytes memory _clientDataJSON = _clientData('webauthn.create', _renderChallenge(_digest), _ORIGIN_FIELDS);
    bytes memory _proof =
      _signedProof(_privateKey, _buildAuthenticatorData(_guardianRpIdHash, _FLAGS_UP_UV), _clientDataJSON);
    _assertRejected(_buildConfig(_privateKey, _guardianRpIdHash), _digest, _proof);
  }

  /*///////////////////////////////////////////////////////////////
                        AUTHENTICATOR DATA
  ///////////////////////////////////////////////////////////////*/

  /// An assertion carrying any relying party hash other than the committed one is refused.
  /// `_delta` is a nonzero word XORed into the committed hash, so the two hashes always differ.
  function test_WhenTheAssertionNamesAnyOtherRelyingParty(uint256 _keySeed, bytes32 _rpIdHash, uint256 _delta)
    external
    view
  {
    // it should refuse the proof
    uint256 _privateKey = _boundKey(_keySeed);
    bytes32 _otherRpIdHash = _rpIdHash ^ bytes32(bound(_delta, 1, type(uint256).max));
    bytes memory _proof = _signedProof(
      _privateKey, _buildAuthenticatorData(_otherRpIdHash, _FLAGS_UP_UV), _standardClientData(_placeDigest)
    );
    _assertRejected(_buildConfig(_privateKey, _rpIdHash), _placeDigest, _proof);
  }

  /// Any flags byte with the user present bit 0x01 cleared is refused, whatever else it sets.
  /// The guardian must have touched the authenticator for the approval to count.
  function test_WhenAnyFlagsByteLacksUserPresent(uint8 _flags) external view {
    // it should refuse the proof
    bytes1 _cleared = bytes1(_flags) & ~_FLAG_UP;
    _assertRejected(
      _guardianConfig,
      _placeDigest,
      _signedProof(
        _GUARDIAN_KEY, _buildAuthenticatorData(_guardianRpIdHash, _cleared), _standardClientData(_placeDigest)
      )
    );
  }

  /// Any flags byte with the user verified bit 0x04 cleared is refused, whatever else it sets.
  /// The guardian must have unlocked the passkey with a PIN or biometric for the approval to count.
  function test_WhenAnyFlagsByteLacksUserVerified(uint8 _flags) external view {
    // it should refuse the proof
    bytes1 _cleared = bytes1(_flags) & ~_FLAG_UV;
    _assertRejected(
      _guardianConfig,
      _placeDigest,
      _signedProof(
        _GUARDIAN_KEY, _buildAuthenticatorData(_guardianRpIdHash, _cleared), _standardClientData(_placeDigest)
      )
    );
  }

  /// Any flags byte with user present, user verified and backup state 0x10 set but backup eligibility 0x08
  /// clear, under a valid signature, is answered with one word that is not the verify selector. `_otherBits`
  /// fills the four bits no check here names. WebAuthn forbids backup state without eligibility.
  function test_WhenAnyFlagsByteCarriesBackupStateWithoutBackupEligibility(uint8 _otherBits) external view {
    // it should answer with one word that is not the verify selector
    bytes1 _flags = (bytes1(_otherBits) | _FLAGS_UP_UV | _FLAG_BS) & ~_FLAG_BE;
    _assertRejected(
      _guardianConfig,
      _placeDigest,
      _signedProof(_GUARDIAN_KEY, _buildAuthenticatorData(_guardianRpIdHash, _flags), _standardClientData(_placeDigest))
    );
  }

  /*///////////////////////////////////////////////////////////////
                             SIGNATURE
  ///////////////////////////////////////////////////////////////*/

  /// An assertion signed by any key other than the committed one is refused.
  /// `_otherSeed` picks a key in the valid range and skips over the committed key.
  function test_WhenAnyOtherKeySigns(uint256 _keySeed, uint256 _otherSeed) external view {
    // it should refuse the proof
    uint256 _privateKey = _boundKey(_keySeed);
    uint256 _otherKey = bound(_otherSeed, 1, _P256_N - 2);
    if (_otherKey > _privateKey - 1) ++_otherKey;
    bytes memory _proof = _signedProof(
      _otherKey, _buildAuthenticatorData(_guardianRpIdHash, _FLAGS_UP_UV), _standardClientData(_placeDigest)
    );
    _assertRejected(_buildConfig(_privateKey, _guardianRpIdHash), _placeDigest, _proof);
  }

  /// Flipping any bits of any one client data byte after signing makes the proof refused.
  /// Every client data byte is signed, extra members included, so none can change afterwards.
  function test_WhenAnyClientDataByteChangesAfterSigning(uint256 _index, uint8 _mask) external view {
    // it should refuse the proof
    bytes memory _authenticatorData = _buildAuthenticatorData(_guardianRpIdHash, _FLAGS_UP_UV);
    bytes memory _clientDataJSON = _extraFieldClientData(_placeDigest);
    (uint256 _r, uint256 _s) = _signAssertion(_GUARDIAN_KEY, _authenticatorData, _clientDataJSON);
    _index = bound(_index, 0, _clientDataJSON.length - 1);
    _clientDataJSON[_index] ^= bytes1(uint8(bound(_mask, 1, 255)));
    _assertRejected(_guardianConfig, _placeDigest, _encodeProof(_authenticatorData, _clientDataJSON, _r, _s));
  }

  /// Flipping any bits of any one authenticator data byte after signing makes the proof refused.
  /// Every authenticator data byte is signed, so the hash, the flags and the counter are all fixed.
  function test_WhenAnyAuthenticatorDataByteChangesAfterSigning(uint256 _index, uint8 _mask) external view {
    // it should refuse the proof
    bytes memory _authenticatorData = _buildAuthenticatorData(_guardianRpIdHash, _FLAGS_UP_UV);
    bytes memory _clientDataJSON = _extraFieldClientData(_placeDigest);
    (uint256 _r, uint256 _s) = _signAssertion(_GUARDIAN_KEY, _authenticatorData, _clientDataJSON);
    _index = bound(_index, 0, _authenticatorData.length - 1);
    _authenticatorData[_index] ^= bytes1(uint8(bound(_mask, 1, 255)));
    _assertRejected(_guardianConfig, _placeDigest, _encodeProof(_authenticatorData, _clientDataJSON, _r, _s));
  }

  /*///////////////////////////////////////////////////////////////
                              CONFIG
  ///////////////////////////////////////////////////////////////*/

  /// A config of any length from 0 to 512 bytes other than 96, beside the guardian's valid assertion, is answered
  /// with one word that is not the verify selector. `_lengthSeed` picks the length, skipping 96, and `_fill`
  /// draws the bytes past the guardian's real config. Only the exact three word config is a credential.
  function test_WhenTheConfigHasAnyLengthOtherThanNinetySixBytes(uint256 _lengthSeed, bytes32 _fill) external view {
    // it should answer with one word that is not the verify selector
    uint256 _length = bound(_lengthSeed, 0, 511);
    if (_length > 95) ++_length;
    _assertRejected(
      _guardianConfigOfLength(_length, _fill), _placeDigest, _guardianProof(_standardClientData(_placeDigest))
    );
  }
}
