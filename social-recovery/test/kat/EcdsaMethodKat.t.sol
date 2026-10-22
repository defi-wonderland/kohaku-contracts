// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {EcdsaMethod} from 'contracts/methods/ecdsa/EcdsaMethod.sol';
import {MethodKatBase} from 'test/kat/MethodKatBase.sol';

/// @notice Replays test/fixtures/kats/method-ecdsa-config.json and test/fixtures/kats/method-ecdsa-proof.json through
///         the wallet method. The SDK writes the config at setup and gathers the signature off chain, and the method
///         reads both at every verification, so a byte the two sides lay out differently turns a guardian's yes into a
///         rejection. Every expected value is read from the files. Tree: EcdsaMethodKat.tree.
contract EcdsaMethodKatTest is MethodKatBase {
  EcdsaMethod internal _method;

  /// @dev Deploys the wallet method the replays call.
  function setUp() external {
    _method = new EcdsaMethod();
  }

  /// Every config row's frozen bytes are the one ABI word of the row's signer, and the method reads those bytes as
  /// that signer: each proof row verifies under a config row exactly when the two rows name the same signer and the
  /// proof row is an accepted one. The zero signer row accepts none of them.
  function test_WhenReplayingTheConfigVectors() external view {
    string memory _configs = vm.readFile(_ECDSA_CONFIG_FILE);
    string memory _proofs = vm.readFile(_ECDSA_PROOF_FILE);
    uint256 _configRows = _rowCount(_configs);
    uint256 _proofRows = _rowCount(_proofs);
    assertGt(_configRows, 0, 'no config vector');
    assertGt(_proofRows, 0, 'no proof vector');
    bytes4 _magic = _vectorMagic();

    for (uint256 _i; _i < _configRows; ++_i) {
      string memory _row = _rowPath(_i);
      string memory _id = _rowId(_configs, _row);
      address _signer = vm.parseJsonAddress(_configs, string.concat(_row, '.input.signer'));
      bytes memory _encoded = vm.parseJsonBytes(_configs, string.concat(_row, '.expected.encoded'));

      // it should encode the signer as one ABI word.
      assertEq(abi.encode(_signer), _encoded, _message(_id, 'encoded'));

      // it should verify a proof under the config exactly when the proof row is accepted and names its signer.
      for (uint256 _j; _j < _proofRows; ++_j) {
        _assertProofUnderConfig(_proofs, _rowPath(_j), _encoded, _signer, _id, _magic);
      }
    }
  }

  /// A config row that freezes a verification note, the zero signer row's "cannot recover zero signer", accepts no
  /// signature: the 65 bytes with zero r and s and v 27, for which ecrecover answers the zero address, are refused
  /// under it. Otherwise any malformed signature would fill a place whose guardian is the zero address.
  function test_WhenReplayingTheZeroSignerConfigVector() external view {
    string memory _configs = vm.readFile(_ECDSA_CONFIG_FILE);
    string memory _proofs = vm.readFile(_ECDSA_PROOF_FILE);
    uint256 _rows = _rowCount(_configs);
    bytes32 _digest = vm.parseJsonBytes32(_proofs, '.vectors[0].input.digest');
    bytes4 _magic = _vectorMagic();
    uint256 _replayed;

    for (uint256 _i; _i < _rows; ++_i) {
      string memory _row = _rowPath(_i);
      if (!vm.keyExistsJson(_configs, string.concat(_row, '.expected.verification'))) continue;
      string memory _id = _rowId(_configs, _row);
      bytes memory _encoded = vm.parseJsonBytes(_configs, string.concat(_row, '.expected.encoded'));
      assertEq(
        vm.parseJsonAddress(_configs, string.concat(_row, '.input.signer')), address(0), _message(_id, 'zero signer')
      );

      // it should refuse the signature whose ecrecover answers the zero address.
      bytes memory _zeroRecovering = abi.encodePacked(bytes32(0), bytes32(0), uint8(27));
      assertNotEq(_method.verify(_encoded, _digest, _zeroRecovering), _magic, _message(_id, 'zero recovery'));
      ++_replayed;
    }
    assertGt(_replayed, 0, 'zero signer row replayed');
  }

  /// Every proof row is replayed through verify with the row's signer, the digest the signer's wallet signed and the
  /// row's proof bytes, and the method answers the magic value exactly when the row expects an accepted proof. A
  /// refused row returns a word rather than reverting. This fixes the raw signature layout over the place digest.
  function test_WhenReplayingTheProofVectors() external view {
    string memory _json = vm.readFile(_ECDSA_PROOF_FILE);
    uint256 _rows = _rowCount(_json);
    assertGt(_rows, 0, 'no proof vector');
    bytes4 _magic = _vectorMagic();

    for (uint256 _i; _i < _rows; ++_i) {
      string memory _row = _rowPath(_i);
      string memory _id = _rowId(_json, _row);
      bytes memory _config = abi.encode(vm.parseJsonAddress(_json, string.concat(_row, '.input.signer')));
      bytes32 _digest = vm.parseJsonBytes32(_json, string.concat(_row, '.input.digest'));
      bytes memory _proof = vm.parseJsonBytes(_json, string.concat(_row, '.expected.proof'));
      bool _expected = vm.parseJsonBool(_json, string.concat(_row, '.expected.eoaVerification'));

      // it should answer the magic value exactly for the accepted rows.
      assertEq(_method.verify(_config, _digest, _proof) == _magic, _expected, _message(_id, 'verdict'));
    }
  }

  /// Every accepted proof row is the raw signature, not its abi.encode wrapping. The row's 65 bytes verify, and the
  /// same signature wrapped as abi.encode(bytes) is refused, so an SDK that wraps the signature gets a rejection.
  function test_WhenReplayingTheAcceptedProofVectorsWrapped() external view {
    string memory _json = vm.readFile(_ECDSA_PROOF_FILE);
    uint256 _rows = _rowCount(_json);
    bytes4 _magic = _vectorMagic();
    uint256 _replayed;

    for (uint256 _i; _i < _rows; ++_i) {
      string memory _row = _rowPath(_i);
      if (!vm.parseJsonBool(_json, string.concat(_row, '.expected.eoaVerification'))) continue;
      string memory _id = _rowId(_json, _row);
      bytes memory _config = abi.encode(vm.parseJsonAddress(_json, string.concat(_row, '.input.signer')));
      bytes32 _digest = vm.parseJsonBytes32(_json, string.concat(_row, '.input.digest'));
      bytes memory _proof = vm.parseJsonBytes(_json, string.concat(_row, '.expected.proof'));

      // it should accept the raw 65 bytes and refuse their abi.encode wrapping.
      assertEq(_proof.length, 65, _message(_id, 'raw signature length'));
      assertEq(_method.verify(_config, _digest, _proof), _magic, _message(_id, 'raw signature'));
      assertNotEq(_method.verify(_config, _digest, abi.encode(_proof)), _magic, _message(_id, 'wrapped signature'));
      ++_replayed;
    }
    assertGt(_replayed, 0, 'accepted rows replayed');
  }

  /*///////////////////////////////////////////////////////////////
                               HELPERS
  ///////////////////////////////////////////////////////////////*/

  /// @dev Asserts the proof row at `_proofRow` verifies under the config bytes `_encoded` of signer `_signer` exactly
  ///      when the proof row is accepted and names that same signer.
  function _assertProofUnderConfig(
    string memory _proofs,
    string memory _proofRow,
    bytes memory _encoded,
    address _signer,
    string memory _id,
    bytes4 _magic
  ) internal view {
    bool _expected = vm.parseJsonBool(_proofs, string.concat(_proofRow, '.expected.eoaVerification'))
    && vm.parseJsonAddress(_proofs, string.concat(_proofRow, '.input.signer')) == _signer;
    bytes4 _answer = _method.verify(
      _encoded,
      vm.parseJsonBytes32(_proofs, string.concat(_proofRow, '.input.digest')),
      vm.parseJsonBytes(_proofs, string.concat(_proofRow, '.expected.proof'))
    );
    assertEq(
      _answer == _magic, _expected, _message(_id, string.concat('verdict on proof ', _rowId(_proofs, _proofRow)))
    );
  }
}
