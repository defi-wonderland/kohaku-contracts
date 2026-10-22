// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {IPolicyMethod} from 'interfaces/IPolicyMethod.sol';
import {PasskeyMethod} from 'contracts/methods/passkey/PasskeyMethod.sol';
import {PasskeyMethodHelpers} from 'test/utils/PasskeyMethodHelpers.sol';

/// @notice The deployed passkey method, a guardian key and the assertion the suites mutate.
abstract contract PasskeyMethodFixture is PasskeyMethodHelpers {
  /// @dev The guardian's passkey private key.
  uint256 internal constant _GUARDIAN_KEY = 0xA11CE;
  /// @dev A key the credential does not commit.
  uint256 internal constant _OTHER_KEY = 0xB0B;
  /// @dev The relying-party id the credential was enrolled under, as in the vectors.
  string internal constant _RP_ID = 'recover.example';

  /// @dev The method under test.
  PasskeyMethod internal _method;
  /// @dev sha256 of the relying-party id.
  bytes32 internal _guardianRpIdHash;
  /// @dev The place digest the assertions approve.
  bytes32 internal _placeDigest;
  /// @dev The committed config of the guardian's credential.
  bytes internal _guardianConfig;

  function setUp() public virtual {
    _method = new PasskeyMethod();
    _guardianRpIdHash = sha256(bytes(_RP_ID));
    _placeDigest = keccak256('passkey method digest');
    _guardianConfig = _buildConfig(_GUARDIAN_KEY, _guardianRpIdHash);
  }

  /// @notice The verdict on a proof for the fixture's credential and digest.
  function _accepts(bytes memory _proof) internal view returns (bool _accepted) {
    _accepted = _verdict(address(_method), _guardianConfig, _placeDigest, _proof);
  }

  /// @notice Assert the method returns exactly the magic value, and that the manager's read accepts it.
  function _assertAccepted(bytes memory _config, bytes32 _digest, bytes memory _proof) internal view {
    assertEq(
      _method.verify(_config, _digest, _proof), IPolicyMethod.verify.selector, 'verify did not return the magic value'
    );
    assertTrue(_verdict(address(_method), _config, _digest, _proof), 'the manager read does not accept the verdict');
  }

  /// @notice Assert the method refuses by answering, not by reverting: the static call succeeds and returns
  ///         exactly one word, and that word is not the verify selector. Every failed check answers this way.
  function _assertRejected(bytes memory _config, bytes32 _digest, bytes memory _proof) internal view {
    (bool _success, bytes memory _returned) =
      address(_method).staticcall(abi.encodeCall(IPolicyMethod.verify, (_config, _digest, _proof)));
    assertTrue(_success, 'the method reverted instead of answering');
    assertEq(_returned.length, 32, 'the answer is not one word');
    assertNotEq(abi.decode(_returned, (bytes32)), bytes32(IPolicyMethod.verify.selector), 'the answer is the selector');
  }

  /// @notice Assert the method's verdict is a refusal of any shape: a revert, an empty return or another
  ///         value. Used only for a proof that is not the ABI layout, which the decoder may revert on.
  function _assertRejectedOrReverted(bytes memory _config, bytes32 _digest, bytes memory _proof) internal view {
    assertFalse(_verdict(address(_method), _config, _digest, _proof), 'the method accepted a proof it must refuse');
  }

  /// @notice A config of `_length` bytes: the guardian's 96 byte config cut short, or followed by bytes
  ///         drawn from `_fill` when `_length` is above 96, so its first bytes are always the real credential.
  function _guardianConfigOfLength(uint256 _length, bytes32 _fill) internal view returns (bytes memory _config) {
    _config = new bytes(_length);
    for (uint256 _i = 0; _i < _length; ++_i) {
      _config[_i] = _i < _guardianConfig.length ? _guardianConfig[_i] : keccak256(abi.encode(_fill, _i))[0];
    }
  }

  /// @notice Sign a client data document under the guardian key with the committed rpIdHash and UP|UV.
  function _guardianProof(bytes memory _clientDataJSON) internal view returns (bytes memory _proof) {
    _proof = _signedProof(_GUARDIAN_KEY, _buildAuthenticatorData(_guardianRpIdHash, _FLAGS_UP_UV), _clientDataJSON);
  }
}
