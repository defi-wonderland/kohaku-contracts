// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {IPolicyManager} from 'interfaces/IPolicyManager.sol';
import {ManagerKatBase} from 'test/kat/ManagerKatBase.sol';
import {PolicyManagerHarness} from 'test/utils/PolicyManagerHarness.sol';

/// @notice Replays the preimage fields of credential-commitment.json and setup-commitment.json, and the manager's
///         refusal the zero-length body row records. The commitments themselves are replayed through the binding
///         digest library in BindingDigestKat.t.sol; this file adds the bytes hashed, which an SDK assembles before
///         it hashes, and the row that tells the manager what to refuse. Tree: PolicyManagerCommitmentKat.tree.
contract PolicyManagerCommitmentKatTest is ManagerKatBase {
  /// The abi.encode of a credential's method, config and salt reproduces every row's preimage, and that preimage
  /// hashes to the row's commitment, the zero method, empty config and zero salt row included. A client that packs
  /// the three differently commits a credential no proof can ever fill.
  function test_WhenEncodingTheCredentialCommitmentPreimages() external view {
    // it should reproduce every expected preimage and its commitment.
    string memory _json = vm.readFile(_CREDENTIAL_COMMITMENT_FILE);
    uint256 _rows = _rowCount(_json);
    assertGt(_rows, 0, 'no credential commitment vector');
    for (uint256 _i; _i < _rows; ++_i) {
      string memory _row = _rowPath(_i);
      string memory _id = _rowId(_json, _row);
      bytes memory _preimage = abi.encode(
        vm.parseJsonAddress(_json, string.concat(_row, '.input.method')),
        vm.parseJsonBytes(_json, string.concat(_row, '.input.config')),
        vm.parseJsonBytes32(_json, string.concat(_row, '.input.salt'))
      );
      assertEq(_preimage, vm.parseJsonBytes(_json, string.concat(_row, '.expected.preimage')), _what('preimage', _id));
      assertEq(
        keccak256(_preimage),
        vm.parseJsonBytes32(_json, string.concat(_row, '.expected.commitment')),
        _what('commitment', _id)
      );
    }
  }

  /// The abi.encode of the account, the action, the nonce as a uint64 and the setup body reproduces every row's
  /// preimage, and that preimage hashes to the row's commitment, the zero-length body row included. A client that
  /// encodes the nonce at another width commits a setup the manager never matches.
  function test_WhenEncodingTheSetupCommitmentPreimages() external view {
    // it should reproduce every expected preimage and its commitment.
    string memory _json = vm.readFile(_SETUP_COMMITMENT_FILE);
    uint256 _rows = _rowCount(_json);
    assertGt(_rows, 0, 'no setup commitment vector');
    for (uint256 _i; _i < _rows; ++_i) {
      string memory _row = _rowPath(_i);
      string memory _id = _rowId(_json, _row);
      bytes memory _preimage = abi.encode(
        vm.parseJsonAddress(_json, string.concat(_row, '.input.account')),
        vm.parseJsonAddress(_json, string.concat(_row, '.input.action')),
        _uint64At(_json, string.concat(_row, '.input.nonce')),
        vm.parseJsonBytes(_json, string.concat(_row, '.input.setupBody'))
      );
      assertEq(_preimage, vm.parseJsonBytes(_json, string.concat(_row, '.expected.preimage')), _what('preimage', _id));
      assertEq(
        keccak256(_preimage),
        vm.parseJsonBytes32(_json, string.concat(_row, '.expected.commitment')),
        _what('commitment', _id)
      );
    }
  }

  /// Every setup commitment row that records a manager refusal names PolicyManager_InvalidCommitment, and the
  /// deployed manager refuses that commitment with that error when the row's account commits it at the row's
  /// nonce. A setup no body can produce must never be stored, since it would arm a recovery that never opens.
  function test_WhenCommittingARowTheManagerRefuses() external {
    // it should revert with PolicyManager_InvalidCommitment carrying the row's commitment.
    string memory _json = vm.readFile(_SETUP_COMMITMENT_FILE);
    uint256 _rows = _rowCount(_json);
    uint256 _replayed;
    for (uint256 _i; _i < _rows; ++_i) {
      string memory _row = _rowPath(_i);
      string memory _acceptance = string.concat(_row, '.expected.managerAcceptance');
      if (!vm.keyExistsJson(_json, _acceptance)) continue;
      string memory _id = _rowId(_json, _row);
      assertTrue(
        vm.contains(vm.parseJsonString(_json, _acceptance), 'PolicyManager_InvalidCommitment'),
        _what('refusal named', _id)
      );

      address _account = vm.parseJsonAddress(_json, string.concat(_row, '.input.account'));
      address _action = vm.parseJsonAddress(_json, string.concat(_row, '.input.action'));
      uint64 _nonce = _uint64At(_json, string.concat(_row, '.input.nonce'));
      bytes32 _commitment = vm.parseJsonBytes32(_json, string.concat(_row, '.expected.commitment'));
      PolicyManagerHarness _manager = new PolicyManagerHarness();
      _manager.harnessWriteSetup(
        _account,
        _action,
        IPolicyManager.Setup({commitment: bytes32(0), nonce: _nonce - 1, attemptCounter: 0, setupCommittedAtBlock: 0})
      );

      vm.expectRevert(abi.encodeWithSelector(IPolicyManager.PolicyManager_InvalidCommitment.selector, _commitment));
      vm.prank(_account);
      _manager.commitSetup(_action, _commitment, _nonce, '', '');
      ++_replayed;
    }
    assertGt(_replayed, 0, 'no row records a refusal');
  }
}
