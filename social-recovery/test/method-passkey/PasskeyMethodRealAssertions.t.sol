// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {PasskeyRealAssertionFixture} from 'test/fixtures/passkey/PasskeyRealAssertionFixture.sol';
import {PasskeyMethodFixture} from 'test/utils/PasskeyMethodFixture.sol';

/// @notice The passkey method's verify on assertions real authenticators produced, replayed from the
///         test data other WebAuthn libraries publish. The synthetic suites sign with keys the tests
///         hold; these show that what Apple, YubiKey and browser authenticators actually emit passes
///         the method byte for byte, and that the same bytes with any one part changed do not.
///         Each assertion's digest is the 32 bytes its challenge decodes to, and its config commits
///         the authenticator's public key and the first 32 bytes of its authenticator data.
contract PasskeyMethodRealAssertionsTest is PasskeyMethodFixture, PasskeyRealAssertionFixture {
  /*///////////////////////////////////////////////////////////////
                             ACCEPTED
  ///////////////////////////////////////////////////////////////*/

  /// An assertion from an Apple platform authenticator on iOS is accepted as it was produced.
  /// iPhone users are the guardians most likely to hold a passkey, so their real output must fill a place.
  function test_WhenTheAppleIosAssertionIsReplayed() external view {
    // it should return the verify selector
    _assertRealAccepted(_realAppleIos());
  }

  /// An assertion from an Apple platform authenticator on macOS is accepted as it was produced.
  /// A guardian enrolled on a Mac must be able to approve from it.
  function test_WhenTheAppleMacosAssertionIsReplayed() external view {
    // it should return the verify selector
    _assertRealAccepted(_realAppleMacos());
  }

  /// An assertion from a YubiKey Bio, whose s is in the high half and whose signature counter is 4, is
  /// accepted as it was produced. Security keys sign with either half of s and count their uses, and
  /// a method that refused either would lock out the guardians who chose a hardware key.
  function test_WhenTheYubikeyBioAssertionIsReplayed() external view {
    // it should return the verify selector
    RealAssertion memory _assertion = _realYubikeyBio();
    assertGt(_assertion.s, _P256_N / 2, 'fixture: the YubiKey Bio signature is not in the high half');
    _assertRealAccepted(_assertion);
  }

  /// An assertion made through Chrome, whose client data carries origin and crossOrigin members after
  /// the challenge, is accepted as it was produced. Chrome is the browser most guardians assert through.
  function test_WhenTheChromeAssertionOfTheWebauthnSolCredentialIsReplayed() external view {
    // it should return the verify selector
    _assertRealAccepted(_realWebauthnSolChrome());
  }

  /// An assertion made through Safari with the same credential, whose client data carries only an origin
  /// member after the challenge, is accepted as it was produced. A guardian's browser must not decide
  /// whether their approval counts.
  function test_WhenTheSafariAssertionOfTheWebauthnSolCredentialIsReplayed() external view {
    // it should return the verify selector
    _assertRealAccepted(_realWebauthnSolSafari());
  }

  /// Every accepted real assertion is also accepted with s replaced by the group order minus s, its
  /// signature in the other half. Both halves verify the same message, and the method accepts both, so
  /// a client that normalizes s, or one that does not, submits a proof that still counts.
  function test_WhenEachAcceptedAssertionCarriesSInTheOtherHalf() external view {
    // it should return the verify selector
    RealAssertion[] memory _assertions = _acceptedRealAssertions();
    for (uint256 _i; _i < _assertions.length; ++_i) {
      RealAssertion memory _assertion = _assertions[_i];
      _assertion.s = _P256_N - _assertion.s;
      _assertRealAccepted(_assertion);
    }
  }

  /*///////////////////////////////////////////////////////////////
                       REFUSED: ONE PART CHANGED
  ///////////////////////////////////////////////////////////////*/

  /// Every accepted real assertion is refused when verify is asked about a digest one bit away from the
  /// one its challenge carries. An approval of one request must never fill a place in another.
  function test_WhenEachAcceptedAssertionIsAskedAboutAnotherDigest() external view {
    // it should refuse the proof
    RealAssertion[] memory _assertions = _acceptedRealAssertions();
    for (uint256 _i; _i < _assertions.length; ++_i) {
      RealAssertion memory _assertion = _assertions[_i];
      _assertRejected(_realConfig(_assertion), _assertion.digest ^ bytes32(uint256(1)), _realProof(_assertion));
    }
  }

  /// Every accepted real assertion is refused under a config that commits the sha256 of another
  /// relying-party id. A passkey enrolled for one domain must not count for a credential bound to another.
  function test_WhenTheConfigCommitsAnotherRelyingParty() external view {
    // it should refuse the proof
    bytes32 _otherRpIdHash = sha256('another.example');
    RealAssertion[] memory _assertions = _acceptedRealAssertions();
    for (uint256 _i; _i < _assertions.length; ++_i) {
      RealAssertion memory _assertion = _assertions[_i];
      assertNotEq(_assertion.rpIdHash, _otherRpIdHash, 'fixture: the other relying party is the real one');
      bytes memory _otherConfig = abi.encode(_assertion.x, _assertion.y, _otherRpIdHash);
      _assertRejected(_otherConfig, _assertion.digest, _realProof(_assertion));
    }
  }

  /// Every accepted real assertion is refused under a config that commits the fixture guardian's key in
  /// place of the authenticator's. Only the committed key may fill the place.
  function test_WhenTheConfigCommitsAnotherKey() external view {
    // it should refuse the proof
    RealAssertion[] memory _assertions = _acceptedRealAssertions();
    for (uint256 _i; _i < _assertions.length; ++_i) {
      RealAssertion memory _assertion = _assertions[_i];
      _assertRejected(_buildConfig(_GUARDIAN_KEY, _assertion.rpIdHash), _assertion.digest, _realProof(_assertion));
    }
  }

  /// Every accepted real assertion is refused when the last byte of its signature counter, byte 36 of the
  /// authenticator data, is flipped. The flags and relying-party hash still pass, so only the signature
  /// over the authenticator data can refuse it, and every signed byte must count.
  function test_WhenOneByteOfTheSignatureCounterChanges() external view {
    // it should refuse the proof
    RealAssertion[] memory _assertions = _acceptedRealAssertions();
    for (uint256 _i; _i < _assertions.length; ++_i) {
      RealAssertion memory _assertion = _assertions[_i];
      _assertion.authenticatorData[36] = _assertion.authenticatorData[36] ^ 0x01;
      _assertRejected(_realConfig(_assertion), _assertion.digest, _realProof(_assertion));
    }
  }

  /// Every accepted real assertion is refused when the last byte of its client data, the closing brace
  /// 0x7d after the challenge, becomes a space. The prefix and challenge still match, so only the signature over
  /// the client data can refuse it, and members after the prefix must stay signed bytes.
  function test_WhenTheLastByteOfTheClientDataChanges() external view {
    // it should refuse the proof
    RealAssertion[] memory _assertions = _acceptedRealAssertions();
    for (uint256 _i; _i < _assertions.length; ++_i) {
      RealAssertion memory _assertion = _assertions[_i];
      uint256 _last = _assertion.clientDataJSON.length - 1;
      assertEq(_assertion.clientDataJSON[_last], bytes1(0x7d), 'fixture: the client data does not end in a brace');
      _assertion.clientDataJSON[_last] = bytes1(0x20);
      _assertRejected(_realConfig(_assertion), _assertion.digest, _realProof(_assertion));
    }
  }

  /// Every accepted real assertion is refused when r is increased by one. A signature that does not
  /// verify must never count, however close it is to a real one.
  function test_WhenRChanges() external view {
    // it should refuse the proof
    RealAssertion[] memory _assertions = _acceptedRealAssertions();
    for (uint256 _i; _i < _assertions.length; ++_i) {
      RealAssertion memory _assertion = _assertions[_i];
      assertLt(_assertion.r + 1, _P256_N, 'fixture: r plus one is not below the group order');
      _assertion.r = _assertion.r + 1;
      _assertRejected(_realConfig(_assertion), _assertion.digest, _realProof(_assertion));
    }
  }

  /// Every accepted real assertion is refused when s is increased by one. A signature that does not
  /// verify must never count, however close it is to a real one.
  function test_WhenSChanges() external view {
    // it should refuse the proof
    RealAssertion[] memory _assertions = _acceptedRealAssertions();
    for (uint256 _i; _i < _assertions.length; ++_i) {
      RealAssertion memory _assertion = _assertions[_i];
      assertLt(_assertion.s + 1, _P256_N, 'fixture: s plus one is not below the group order');
      _assertion.s = _assertion.s + 1;
      _assertRejected(_realConfig(_assertion), _assertion.digest, _realProof(_assertion));
    }
  }

  /*///////////////////////////////////////////////////////////////
                   REFUSED: REAL OUTPUT THE METHOD RULES OUT
  ///////////////////////////////////////////////////////////////*/

  /// A YubiKey 5 NFC assertion that the key really signed, in the standard member order, is refused
  /// because its flags are 0x01, user present without user verified. The method requires the
  /// authenticator to have verified its holder, so a key used without its PIN fills no place.
  function test_WhenTheYubikey5NfcAssertionLacksUserVerification() external view {
    // it should refuse the proof
    RealAssertion memory _assertion = _realYubikey5Nfc();
    assertTrue(_precompileVerifies(_assertion), 'fixture: the signature does not verify');
    assertEq(_assertion.authenticatorData[32], bytes1(0x01), 'fixture: the flags are not 0x01');
    assertTrue(_startsWithPrefix(_assertion.clientDataJSON), 'fixture: the client data is not in standard order');
    _assertRealRejected(_assertion);
  }

  /// An assertion that Chrome's Touch ID authenticator on macOS really signed in 2019, with user verified
  /// set, is refused because that Chrome wrote the challenge member before the type member. The method
  /// reads the type and challenge through one fixed prefix in the order the standard later fixed, so
  /// client data serialized in another order fills no place even when its signature verifies.
  function test_WhenTheChromeTouchIdAssertionWritesTheChallengeBeforeTheType() external view {
    // it should refuse the proof
    RealAssertion memory _assertion = _realChromeTouchIdLegacy();
    assertTrue(_precompileVerifies(_assertion), 'fixture: the signature does not verify');
    bytes1 _flags = _assertion.authenticatorData[32];
    assertEq(_flags & _FLAGS_UP_UV, _FLAGS_UP_UV, 'fixture: user present or user verified is clear');
    assertEq(_flags & _FLAG_BS, bytes1(0), 'fixture: backup state is set');
    assertFalse(_startsWithPrefix(_assertion.clientDataJSON), 'fixture: the client data is in standard order');
    _assertRealRejected(_assertion);
  }

  /// An assertion that a YubiKey 5C NFC really signed through a browser of the pre-standard era is
  /// refused. Its client data writes the challenge first and the type last, and its flags are 0x01, so
  /// two rules refuse it, the fixed prefix and the user-verified flag.
  function test_WhenTheYubikey5cNfcAssertionWritesTheChallengeBeforeTheTypeWithoutUserVerification() external view {
    // it should refuse the proof
    RealAssertion memory _assertion = _realYubikey5cNfcLegacy();
    assertTrue(_precompileVerifies(_assertion), 'fixture: the signature does not verify');
    assertEq(_assertion.authenticatorData[32], bytes1(0x01), 'fixture: the flags are not 0x01');
    assertFalse(_startsWithPrefix(_assertion.clientDataJSON), 'fixture: the client data is in standard order');
    _assertRealRejected(_assertion);
  }

  /*///////////////////////////////////////////////////////////////
                              HELPERS
  ///////////////////////////////////////////////////////////////*/

  /// @notice The config committing a real assertion's key and relying-party hash.
  function _realConfig(RealAssertion memory _assertion) internal pure returns (bytes memory _config) {
    _config = abi.encode(_assertion.x, _assertion.y, _assertion.rpIdHash);
  }

  /// @notice The proof carrying a real assertion's bytes and signature.
  function _realProof(RealAssertion memory _assertion) internal pure returns (bytes memory _proof) {
    _proof = _encodeProof(_assertion.authenticatorData, _assertion.clientDataJSON, _assertion.r, _assertion.s);
  }

  /// @notice Assert the method accepts a real assertion over its own digest under its own config.
  function _assertRealAccepted(RealAssertion memory _assertion) internal view {
    _assertAccepted(_realConfig(_assertion), _assertion.digest, _realProof(_assertion));
  }

  /// @notice Assert the method refuses a real assertion over its own digest under its own config.
  function _assertRealRejected(RealAssertion memory _assertion) internal view {
    _assertRejected(_realConfig(_assertion), _assertion.digest, _realProof(_assertion));
  }

  /// @notice Whether the P256VERIFY precompile accepts the assertion's signature over
  ///         sha256(authenticatorData || sha256(clientDataJSON)). Used only to show a refused fixture
  ///         was genuinely signed, so its refusal comes from the method's rules and not from bad data.
  function _precompileVerifies(RealAssertion memory _assertion) internal view returns (bool _verified) {
    bytes32 _signedHash = _hashAssertion(_assertion.authenticatorData, _assertion.clientDataJSON);
    (bool _success, bytes memory _returned) =
      _P256_VERIFY.staticcall(abi.encode(_signedHash, _assertion.r, _assertion.s, _assertion.x, _assertion.y));
    _verified = _success && _returned.length == 32 && abi.decode(_returned, (uint256)) == 1;
  }

  /// @notice Whether client data begins with the members in the order the standard fixes, type then
  ///         challenge. Used only to describe a fixture.
  function _startsWithPrefix(bytes memory _clientDataJSON) internal pure returns (bool _starts) {
    bytes memory _prefix = bytes('{"type":"webauthn.get","challenge":"');
    if (_clientDataJSON.length < _prefix.length) return false;
    for (uint256 _i; _i < _prefix.length; ++_i) {
      if (_clientDataJSON[_i] != _prefix[_i]) return false;
    }
    _starts = true;
  }
}
