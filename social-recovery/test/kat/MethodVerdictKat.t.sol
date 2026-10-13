// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {IPolicyMethod} from 'interfaces/IPolicyMethod.sol';
import {EcdsaMethod} from 'contracts/methods/ecdsa/EcdsaMethod.sol';
import {PasskeyMethod} from 'contracts/methods/passkey/PasskeyMethod.sol';
import {MethodKatBase} from 'test/kat/MethodKatBase.sol';

/// @notice Replays test/fixtures/kats/method-verdict.json, the magic value every method answers for an accepted proof.
///         Every method author reproduces that constant, and the manager counts a place only on exactly one returned
///         word holding it, so a method that answers any other word rejects every proof. Tree: MethodVerdictKat.tree.
contract MethodVerdictKatTest is MethodKatBase {
  EcdsaMethod internal _ecdsa;
  PasskeyMethod internal _passkey;

  /// @dev Deploys the two shipped methods whose answers the replay reads.
  function setUp() external {
    _ecdsa = new EcdsaMethod();
    _passkey = new PasskeyMethod();
  }

  /// The selector of verify in the frozen interface is the vector's selector, and it is the first four bytes of the
  /// keccak256 of the vector's signature string. An SDK or a third-party method that derives the constant from that
  /// string gets the same four bytes the manager compares against.
  function test_WhenReplayingTheVerdictVectorAgainstTheInterface() external view {
    string memory _json = vm.readFile(_VERDICT_FILE);
    uint256 _rows = _rowCount(_json);
    assertEq(_rows, 1, 'the verdict file holds exactly one row');
    for (uint256 _i; _i < _rows; ++_i) {
      string memory _row = _rowPath(_i);
      string memory _id = _rowId(_json, _row);
      string memory _signature = vm.parseJsonString(_json, string.concat(_row, '.input.signature'));
      bytes memory _selector = vm.parseJsonBytes(_json, string.concat(_row, '.expected.selector'));
      bytes32 _word = vm.parseJsonBytes32(_json, string.concat(_row, '.expected.abiWord'));

      // it should match the selector of verify in the interface.
      assertEq(_selector.length, 4, _message(_id, 'selector length'));
      assertEq(_selector, abi.encodePacked(IPolicyMethod.verify.selector), _message(_id, 'interface selector'));
      // it should be the hash prefix of the signature string.
      bytes32 _hash = keccak256(bytes(_signature));
      for (uint256 _b; _b < 4; ++_b) {
        assertEq(_selector[_b], _hash[_b], _message(_id, 'signature hash prefix'));
      }
      // it should left-align the selector in the ABI word.
      assertEq(abi.encodePacked(_word), bytes.concat(_selector, new bytes(28)), _message(_id, 'abi word'));
    }
  }

  /// Every accepted row of the wallet and passkey proof files makes its method answer exactly 32 bytes equal to the
  /// vector's ABI word, the only answer the manager accepts. A method that padded, wrapped or returned a bool would
  /// fail here even when its own unit tests compare selectors.
  function test_WhenReplayingTheVerdictVectorAgainstAcceptedProofs() external view {
    bytes32 _word = _vectorWord();
    uint256 _accepted;

    string memory _json = vm.readFile(_ECDSA_PROOF_FILE);
    uint256 _rows = _rowCount(_json);
    for (uint256 _i; _i < _rows; ++_i) {
      string memory _row = _rowPath(_i);
      if (!vm.parseJsonBool(_json, string.concat(_row, '.expected.eoaVerification'))) continue;
      (bool _success, bytes memory _returned) = _rawVerify(
        address(_ecdsa),
        abi.encode(vm.parseJsonAddress(_json, string.concat(_row, '.input.signer'))),
        vm.parseJsonBytes32(_json, string.concat(_row, '.input.digest')),
        vm.parseJsonBytes(_json, string.concat(_row, '.expected.proof'))
      );
      // it should return exactly the magic word.
      _assertMagicAnswer(_success, _returned, _word, _rowId(_json, _row));
      ++_accepted;
    }

    _json = vm.readFile(_PASSKEY_PROOF_FILE);
    _rows = _rowCount(_json);
    bytes memory _config = _passkeyConfig();
    for (uint256 _i; _i < _rows; ++_i) {
      string memory _row = _rowPath(_i);
      if (!vm.parseJsonBool(_json, string.concat(_row, '.expected.verification'))) continue;
      (bool _success, bytes memory _returned) = _rawVerify(
        address(_passkey),
        _config,
        vm.parseJsonBytes32(_json, string.concat(_row, '.input.digest')),
        vm.parseJsonBytes(_json, string.concat(_row, '.expected.encoded'))
      );
      // it should return exactly the magic word.
      _assertMagicAnswer(_success, _returned, _word, _rowId(_json, _row));
      ++_accepted;
    }
    assertGt(_accepted, 1, 'accepted rows replayed');
  }

  /// Every refused row of the wallet and passkey proof files makes its method return normally with one word other
  /// than the vector's ABI word. A refusal is a plain answer the manager reads as false, so no row the vectors refuse
  /// can be read as an approval.
  function test_WhenReplayingTheVerdictVectorAgainstRefusedProofs() external view {
    bytes32 _word = _vectorWord();
    uint256 _refused;

    string memory _json = vm.readFile(_ECDSA_PROOF_FILE);
    uint256 _rows = _rowCount(_json);
    for (uint256 _i; _i < _rows; ++_i) {
      string memory _row = _rowPath(_i);
      if (vm.parseJsonBool(_json, string.concat(_row, '.expected.eoaVerification'))) continue;
      (bool _success, bytes memory _returned) = _rawVerify(
        address(_ecdsa),
        abi.encode(vm.parseJsonAddress(_json, string.concat(_row, '.input.signer'))),
        vm.parseJsonBytes32(_json, string.concat(_row, '.input.digest')),
        vm.parseJsonBytes(_json, string.concat(_row, '.expected.proof'))
      );
      // it should return one word other than the magic word.
      _assertOtherAnswer(_success, _returned, _word, _rowId(_json, _row));
      ++_refused;
    }

    _json = vm.readFile(_PASSKEY_PROOF_FILE);
    _rows = _rowCount(_json);
    bytes memory _config = _passkeyConfig();
    for (uint256 _i; _i < _rows; ++_i) {
      string memory _row = _rowPath(_i);
      if (vm.parseJsonBool(_json, string.concat(_row, '.expected.verification'))) continue;
      (bool _success, bytes memory _returned) = _rawVerify(
        address(_passkey),
        _config,
        vm.parseJsonBytes32(_json, string.concat(_row, '.input.digest')),
        vm.parseJsonBytes(_json, string.concat(_row, '.expected.encoded'))
      );
      // it should return one word other than the magic word.
      _assertOtherAnswer(_success, _returned, _word, _rowId(_json, _row));
      ++_refused;
    }
    assertGt(_refused, 1, 'refused rows replayed');
  }

  /*///////////////////////////////////////////////////////////////
                               HELPERS
  ///////////////////////////////////////////////////////////////*/

  /// @dev Asserts a call returned normally with exactly the one word `_word`.
  function _assertMagicAnswer(bool _success, bytes memory _returned, bytes32 _word, string memory _id) internal pure {
    assertTrue(_success, _message(_id, 'call returned'));
    assertEq(_returned.length, 32, _message(_id, 'one word returned'));
    assertEq(abi.decode(_returned, (bytes32)), _word, _message(_id, 'magic word'));
  }

  /// @dev Asserts a call returned normally with one word that is not `_word`.
  function _assertOtherAnswer(bool _success, bytes memory _returned, bytes32 _word, string memory _id) internal pure {
    assertTrue(_success, _message(_id, 'call returned'));
    assertEq(_returned.length, 32, _message(_id, 'one word returned'));
    assertNotEq(abi.decode(_returned, (bytes32)), _word, _message(_id, 'not the magic word'));
  }
}
