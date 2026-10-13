// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {Base64} from '@openzeppelin/contracts/utils/Base64.sol';
import {PasskeyMethod} from 'contracts/methods/passkey/PasskeyMethod.sol';
import {MethodKatBase} from 'test/kat/MethodKatBase.sol';

/// @notice Replays test/fixtures/kats/method-passkey-config.json and test/fixtures/kats/method-passkey-proof.json
///         through the passkey method and the P256VERIFY precompile at 0x100, which the Osaka EVM the suite runs on
///         carries. The SDK writes the config at enrolment and packs the assertion off chain, and the method reads both
///         at every verification, so a layout or check the two sides disagree on turns a guardian's yes into a
///         rejection. Every expected value is read from the files. Tree: PasskeyMethodKat.tree.
contract PasskeyMethodKatTest is MethodKatBase {
  /// @dev The address of the P256VERIFY precompile.
  address internal constant _P256_VERIFY = address(0x100);

  PasskeyMethod internal _method;

  /// @dev Deploys the passkey method the replays call.
  function setUp() external {
    _method = new PasskeyMethod();
  }

  /// Every config row's frozen bytes are abi.encode of the row's x, y and relying-party hash, in that order, and the
  /// relying-party hash is the SHA-256 of the row's relying-party id, as WebAuthn defines it. A different field order
  /// or hash would commit a key the method reads wrongly.
  function test_WhenReplayingTheConfigVectors() external view {
    string memory _json = vm.readFile(_PASSKEY_CONFIG_FILE);
    uint256 _rows = _rowCount(_json);
    assertGt(_rows, 0, 'no config vector');
    for (uint256 _i; _i < _rows; ++_i) {
      string memory _row = _rowPath(_i);
      string memory _id = _rowId(_json, _row);
      uint256 _x = vm.parseJsonUint(_json, string.concat(_row, '.input.x'));
      uint256 _y = vm.parseJsonUint(_json, string.concat(_row, '.input.y'));
      string memory _rpId = vm.parseJsonString(_json, string.concat(_row, '.input.rpId'));
      bytes32 _rpIdHash = vm.parseJsonBytes32(_json, string.concat(_row, '.input.rpIdHash'));
      bytes memory _encoded = vm.parseJsonBytes(_json, string.concat(_row, '.expected.encoded'));

      // it should encode x, y and the relying-party hash as three ABI words.
      assertEq(abi.encode(_x, _y, _rpIdHash), _encoded, _message(_id, 'encoded'));
      // it should hash the relying-party id with SHA-256.
      assertEq(sha256(bytes(_rpId)), _rpIdHash, _message(_id, 'rpIdHash'));
    }
  }

  /// The method reads the frozen config bytes the proof rows were signed under: every accepted proof row verifies
  /// under them, and is refused once x and y swap places or the relying-party hash changes. So the method reads the
  /// three words in the frozen order and binds the relying party the config commits.
  function test_WhenReplayingTheConfigVectorThroughTheMethod() external view {
    bytes memory _config = _passkeyConfig();
    (uint256 _x, uint256 _y, bytes32 _rpIdHash) = abi.decode(_config, (uint256, uint256, bytes32));
    string memory _json = vm.readFile(_PASSKEY_PROOF_FILE);
    uint256 _rows = _rowCount(_json);
    bytes4 _magic = _vectorMagic();
    uint256 _replayed;

    for (uint256 _i; _i < _rows; ++_i) {
      string memory _row = _rowPath(_i);
      if (!vm.parseJsonBool(_json, string.concat(_row, '.expected.verification'))) continue;
      string memory _id = _rowId(_json, _row);
      bytes32 _digest = vm.parseJsonBytes32(_json, string.concat(_row, '.input.digest'));
      bytes memory _proof = vm.parseJsonBytes(_json, string.concat(_row, '.expected.encoded'));

      // it should verify under the frozen config and under no reordered or rebound one.
      assertEq(_method.verify(_config, _digest, _proof), _magic, _message(_id, 'frozen config'));
      assertNotEq(
        _method.verify(abi.encode(_y, _x, _rpIdHash), _digest, _proof), _magic, _message(_id, 'x and y swapped')
      );
      assertNotEq(
        _method.verify(abi.encode(_x, _y, ~_rpIdHash), _digest, _proof), _magic, _message(_id, 'other rpIdHash')
      );
      ++_replayed;
    }
    assertGt(_replayed, 0, 'accepted rows replayed');
  }

  /// Every proof row's frozen bytes are abi.encode of the row's authenticator data, client data document, r and s, in
  /// that order. The client data is the exact text the authenticator signed, an extra member included. A row that
  /// freezes its required flags carries them in the flags byte at offset 32: bit 0 for user present, bit 2 for user
  /// verified, so the SDK and the method read the same bits as the two flags the method requires.
  function test_WhenReplayingTheProofEncodingVectors() external view {
    string memory _json = vm.readFile(_PASSKEY_PROOF_FILE);
    uint256 _rows = _rowCount(_json);
    assertGt(_rows, 0, 'no proof vector');
    for (uint256 _i; _i < _rows; ++_i) {
      string memory _row = _rowPath(_i);
      string memory _id = _rowId(_json, _row);

      // it should encode the four proof fields in the frozen order.
      assertEq(
        abi.encode(
          vm.parseJsonBytes(_json, string.concat(_row, '.input.authenticatorData')),
          bytes(vm.parseJsonString(_json, string.concat(_row, '.input.clientDataJSON'))),
          uint256(vm.parseJsonBytes32(_json, string.concat(_row, '.input.r'))),
          uint256(vm.parseJsonBytes32(_json, string.concat(_row, '.input.s')))
        ),
        vm.parseJsonBytes(_json, string.concat(_row, '.expected.encoded')),
        _message(_id, 'encoded')
      );

      // it should carry the required flags in the flags byte at offset 32.
      if (vm.keyExistsJson(_json, string.concat(_row, '.expected.requiredFlags'))) {
        _assertRequiredFlags(_json, _row, _id);
      }
    }
  }

  /// Every proof row that freezes a challenge text has it equal to the unpadded base64url rendering of the row's
  /// digest by OpenZeppelin's Base64.encodeURL, the renderer the method compares the client data against. A padded or
  /// standard alphabet rendering on either side would refuse every passkey proof.
  function test_WhenReplayingTheProofChallengeVectors() external view {
    string memory _json = vm.readFile(_PASSKEY_PROOF_FILE);
    uint256 _rows = _rowCount(_json);
    uint256 _replayed;
    for (uint256 _i; _i < _rows; ++_i) {
      string memory _row = _rowPath(_i);
      if (!vm.keyExistsJson(_json, string.concat(_row, '.expected.challengeBase64url'))) continue;
      bytes32 _digest = vm.parseJsonBytes32(_json, string.concat(_row, '.input.digest'));

      // it should render the digest as the frozen challenge.
      assertEq(
        Base64.encodeURL(abi.encodePacked(_digest)),
        vm.parseJsonString(_json, string.concat(_row, '.expected.challengeBase64url')),
        _message(_rowId(_json, _row), 'challengeBase64url')
      );
      ++_replayed;
    }
    assertGt(_replayed, 0, 'challenge rows replayed');
  }

  /// Every proof row's signed hash is the SHA-256 of the authenticator data followed by the SHA-256 of the client data
  /// bytes, the message WebAuthn has the authenticator sign. This fixes which bytes the passkey signature covers.
  function test_WhenReplayingTheProofSignedHashVectors() external view {
    string memory _json = vm.readFile(_PASSKEY_PROOF_FILE);
    uint256 _rows = _rowCount(_json);
    assertGt(_rows, 0, 'no proof vector');
    for (uint256 _i; _i < _rows; ++_i) {
      string memory _row = _rowPath(_i);
      bytes memory _authenticatorData = vm.parseJsonBytes(_json, string.concat(_row, '.input.authenticatorData'));
      bytes memory _clientData = bytes(vm.parseJsonString(_json, string.concat(_row, '.input.clientDataJSON')));

      // it should hash the authenticator data and the client data hash with SHA-256.
      assertEq(
        sha256(abi.encodePacked(_authenticatorData, sha256(_clientData))),
        vm.parseJsonBytes32(_json, string.concat(_row, '.expected.signedHash')),
        _message(_rowId(_json, _row), 'signedHash')
      );
    }
  }

  /// Every proof row's r and s over the row's signed hash verify under the frozen config's key through the real
  /// P256VERIFY precompile exactly as the row expects. A row that freezes signatureVerification uses it, and a row
  /// that does not uses its overall verdict. So each refused row with a valid signature is refused by a method check
  /// other than the signature, the one its reason names.
  function test_WhenReplayingTheProofSignatureVectors() external view {
    (uint256 _x, uint256 _y,) = abi.decode(_passkeyConfig(), (uint256, uint256, bytes32));
    string memory _json = vm.readFile(_PASSKEY_PROOF_FILE);
    uint256 _rows = _rowCount(_json);
    assertGt(_rows, 0, 'no proof vector');
    for (uint256 _i; _i < _rows; ++_i) {
      string memory _row = _rowPath(_i);
      string memory _expectedPath = vm.keyExistsJson(_json, string.concat(_row, '.expected.signatureVerification'))
        ? string.concat(_row, '.expected.signatureVerification')
        : string.concat(_row, '.expected.verification');
      bool _expected = vm.parseJsonBool(_json, _expectedPath);
      (bool _success, bytes memory _returned) = _P256_VERIFY.staticcall(
        abi.encode(
          vm.parseJsonBytes32(_json, string.concat(_row, '.expected.signedHash')),
          uint256(vm.parseJsonBytes32(_json, string.concat(_row, '.input.r'))),
          uint256(vm.parseJsonBytes32(_json, string.concat(_row, '.input.s'))),
          _x,
          _y
        )
      );

      // it should answer one exactly as the row expects.
      assertTrue(_success, _message(_rowId(_json, _row), 'precompile call'));
      assertEq(
        _returned.length == 32 && abi.decode(_returned, (uint256)) == 1,
        _expected,
        _message(_rowId(_json, _row), 'signatureVerification')
      );
    }
  }

  /// Every proof row is replayed through verify with the frozen config, the row's digest and the row's encoded
  /// proof, and the method answers the magic value exactly when the row expects an accepted proof. The accepted row
  /// carries an extra client data member, and each refused row changes one checked field: the user-verified flag,
  /// the user-present flag, the challenge, the client data type or the relying-party hash. A refused row returns a
  /// word rather than reverting.
  function test_WhenReplayingTheProofVerdictVectors() external view {
    bytes memory _config = _passkeyConfig();
    string memory _json = vm.readFile(_PASSKEY_PROOF_FILE);
    uint256 _rows = _rowCount(_json);
    assertGt(_rows, 0, 'no proof vector');
    bytes4 _magic = _vectorMagic();
    for (uint256 _i; _i < _rows; ++_i) {
      string memory _row = _rowPath(_i);
      bool _expected = vm.parseJsonBool(_json, string.concat(_row, '.expected.verification'));
      bytes4 _answer = _method.verify(
        _config,
        vm.parseJsonBytes32(_json, string.concat(_row, '.input.digest')),
        vm.parseJsonBytes(_json, string.concat(_row, '.expected.encoded'))
      );

      // it should answer the magic value exactly for the accepted rows.
      assertEq(_answer == _magic, _expected, _message(_rowId(_json, _row), 'verification'));
    }
  }

  /*///////////////////////////////////////////////////////////////
                               HELPERS
  ///////////////////////////////////////////////////////////////*/

  /// @dev Asserts the authenticator data of the row at `_row` has bit 0 of its flags byte set exactly when the row's
  ///      requiredFlags.userPresent is true, and bit 2 set exactly when requiredFlags.userVerified is true.
  function _assertRequiredFlags(string memory _json, string memory _row, string memory _id) internal pure {
    bytes memory _authenticatorData = vm.parseJsonBytes(_json, string.concat(_row, '.input.authenticatorData'));
    assertGt(_authenticatorData.length, 32, _message(_id, 'flags byte present'));
    bytes1 _flags = _authenticatorData[32];
    assertEq(
      _flags & 0x01 == 0x01,
      vm.parseJsonBool(_json, string.concat(_row, '.expected.requiredFlags.userPresent')),
      _message(_id, 'userPresent')
    );
    assertEq(
      _flags & 0x04 == 0x04,
      vm.parseJsonBool(_json, string.concat(_row, '.expected.requiredFlags.userVerified')),
      _message(_id, 'userVerified')
    );
  }
}
