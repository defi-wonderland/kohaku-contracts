// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {BindingDigestMemberChanges} from 'test/utils/BindingDigestMemberChanges.sol';
import {BindingDigestTestBase} from 'test/utils/BindingDigestTestBase.sol';

/// @notice Unit tests for the setup commitment, `setupCommitment(_account, _action, _nonce, _body)`, the hash the
///         manager stores for a holder's setup. Tree: BindingDigestSetupCommitment.tree.
contract BindingDigestSetupCommitmentTest is BindingDigestTestBase {
  /*///////////////////////////////////////////////////////////////
                             TREE TESTS
  ///////////////////////////////////////////////////////////////*/

  /// The setup commitment changes with the account, the action, the nonce and the body, and swapping the account and
  /// the action changes it too. A body committed under one account, action or nonce therefore never verifies under
  /// another.
  function test_WhenComputingTheSetupCommitment() external view {
    address _account = address(0x1111111111111111111111111111111111111111);
    address _action = address(0x2222222222222222222222222222222222222222);
    bytes memory _body = hex'0102030405';
    bytes32 _commitment = _harness.setupCommitment(_account, _action, 7, _body);

    // it should change with any one member.
    for (uint256 _which; _which < BindingDigestMemberChanges.SETUP_MEMBERS; ++_which) {
      (address _newAccount, address _newAction, uint64 _newNonce, bytes memory _newBody) =
        BindingDigestMemberChanges.changeSetup(_account, _action, 7, _body, _which, 1);
      assertTrue(
        _harness.setupCommitment(_newAccount, _newAction, _newNonce, _newBody) != _commitment,
        string.concat('setup member ignored: ', vm.toString(_which))
      );
    }

    // it should tell the account from the action.
    assertTrue(_harness.setupCommitment(_action, _account, 7, _body) != _commitment, 'account and action swapped');
  }
}
