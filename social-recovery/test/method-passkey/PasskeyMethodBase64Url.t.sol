// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {PasskeyMethodHelpers} from 'test/utils/PasskeyMethodHelpers.sol';

/// @notice Checks the test fixture's own base64 renderer, which builds every challenge the passkey
///         suites send, against the RFC 4648 examples and the frozen passkey vector. A wrong renderer
///         would make the passkey suites test the method against the wrong challenge text.
contract PasskeyMethodBase64UrlTest is PasskeyMethodHelpers {
  /// The renderer reproduces the RFC 4648 section 10 examples with the padding removed.
  /// WebAuthn renders the challenge as unpadded base64url, so these are the expected outputs.
  function test_WhenRenderingTheRFCExamples() external pure {
    // it should match the unpadded RFC outputs
    assertEq(_base64Url(''), '');
    assertEq(_base64Url('f'), 'Zg');
    assertEq(_base64Url('fo'), 'Zm8');
    assertEq(_base64Url('foo'), 'Zm9v');
    assertEq(_base64Url('foob'), 'Zm9vYg');
    assertEq(_base64Url('fooba'), 'Zm9vYmE');
    assertEq(_base64Url('foobar'), 'Zm9vYmFy');
  }

  /// Bytes 0xfbff render as `-_8` in the url alphabet of RFC 4648 section 5 and `+/8` in the standard one.
  /// These are the two characters that differ between the alphabets, so the suites can tell them apart.
  function test_WhenRenderingBytesThatReachTheLastTwoAlphabetEntries() external pure {
    // it should use dash and underscore in the url alphabet and plus and slash in the standard one
    assertEq(_base64Url(hex'fbff'), '-_8');
    assertEq(_base64NoPad(hex'fbff', _BASE64_ALPHABET), '+/8');
  }

  /// The renderer turns the frozen passkey vector's digest into the challenge text that vector freezes.
  /// The vector is the format the SDK writes, so the suites send challenges in the SDK's exact shape.
  function test_WhenRenderingTheDigestOfTheFrozenPasskeyVector() external view {
    // it should equal the challenge the vector freezes
    string memory _json = vm.readFile('test/fixtures/kats/method-passkey-proof.json');
    bytes32 _digest = vm.parseJsonBytes32(_json, '.vectors[0].input.digest');
    string memory _expected = vm.parseJsonString(_json, '.vectors[0].expected.challengeBase64url');
    assertEq(_renderChallenge(_digest), _expected);
  }
}
