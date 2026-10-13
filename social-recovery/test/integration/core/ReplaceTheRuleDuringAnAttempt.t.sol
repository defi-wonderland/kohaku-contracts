// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {Vm} from 'forge-std/Vm.sol';
import {IPolicyManager} from 'interfaces/IPolicyManager.sol';
import {IRecoveryAction} from 'interfaces/IRecoveryAction.sol';
import {IntegrationDemoKitTestBase} from 'test/utils/IntegrationDemoKitTestBase.sol';

/// @notice A recovery the holder did not want is waiting. The holder still has their key and
///         replaces the rule instead of only cancelling. The new setup cancels the attempt and makes
///         every approval signed under the old setup useless.
contract ReplaceTheRuleDuringAnAttemptTest is IntegrationDemoKitTestBase {
  /// @notice The window of the request that opened the unwanted attempt.
  uint48 internal _openedWindow;

  function setUp() public override {
    super.setUp();
    _authorizeAndCommit();
    _openedWindow = _open(_openingSet()).validUntil;
  }

  /// @notice A new setup, even with the same rule, first cancels the waiting attempt and then raises
  ///         the nonce. Old approvals are then refused. A spend or a cancel aimed at the old attempt
  ///         reverts.
  function test_WhenTheHolderCommitsANewSetupDuringAnAttempt() external {
    // it should cancel the attempt first, move the nonce and leave no old approval counting
    bytes memory _sameRule = _body();
    bytes32 _newCommitment = _commitmentOf(2, _sameRule);

    vm.recordLogs();
    vm.expectEmit(true, true, true, true, address(_manager));
    emit IPolicyManager.AttemptCancelled(_account, address(_action), 1, address(0), address(0), 1, new uint256[](0));
    vm.expectEmit(true, true, true, true, address(_manager));
    emit IPolicyManager.SetupCommitted(
      _account, address(_action), 2, _newCommitment, _PUBLIC_METADATA, _PRIVATE_METADATA
    );
    _asHolder(_one(_commitCall(2, _newCommitment)));
    Vm.Log[] memory _logs = vm.getRecordedLogs();
    assertLt(
      _indexOfLog(_logs, IPolicyManager.AttemptCancelled.selector),
      _indexOfLog(_logs, IPolicyManager.SetupCommitted.selector),
      'the attempt was not cancelled before the nonce moved'
    );

    IPolicyManager.ActionState memory _replaced = _state();
    assertEq(_replaced.setupNonce, 2, 'the nonce did not rise by one');
    assertEq(_replaced.setupCommitment, _newCommitment, 'the new commitment is not stored');
    assertEq(uint256(_replaced.attempt.state), uint256(IPolicyManager.AttemptState.Cancelled), 'an attempt runs');

    // An old request fails on the nonce before any proof is read.
    IPolicyManager.AttemptRequest memory _old = _request(_openingSet(), 1, 1, _openedWindow);
    _sendRefusedBeforeAnyMethod(_old, _wrongNonce(1, 2));
    // Old signatures in a request for the new nonce are refused, even though the rule is the same.
    IPolicyManager.AttemptRequest memory _restamped = _request(_openingSet(), 2, 2, _openedWindow);
    for (uint256 _i; _i < _restamped.proofs.length; ++_i) {
      _restamped.proofs[_i].proof = _old.proofs[_i].proof;
    }
    vm.expectRevert(
      abi.encodeWithSelector(IPolicyManager.PolicyManager_ProofRejected.selector, _ALICE, address(_ecdsa))
    );
    _send(_restamped);

    // A spend and a cancellation aimed at the old attempt revert.
    _assertTheOldAttemptIsGone(_replaced.attempt);
  }

  /// @notice A new rule applies at once, with no wait of its own. In the same block, a request signed
  ///         under the new rule opens an attempt with the new rule's delay.
  function test_WhenTheEditTakesEffectAtOnce() external {
    // it should judge a request under the new rule in the same block
    bytes memory _newRule = _rule(1 days, false);
    uint256 _editedAt = block.timestamp;
    uint64 _nonce = _commitNext(_newRule);
    IPolicyManager.AttemptRequest memory _req = _requestOver(_newRule, _openingSet(), 2, _nonce, _window());
    _send(_req);

    assertEq(block.timestamp, _editedAt, 'time passed between the edit and the request');
    assertEq(_state().attempt.setupNonce, _nonce, 'the attempt was judged under another setup');
    assertEq(_state().attempt.consumableAfter, _editedAt + 1 days, 'the new rule wait does not apply');
  }

  /// @notice Clearing the setup also cancels the attempt and moves the nonce, and nothing is left to
  ///         spend. The account still authorizes the action, because the manager cannot change the
  ///         account.
  function test_WhenTheHolderClearsInsteadOfEditing() external {
    // it should cancel the attempt, leave nothing to release and keep the authorization
    vm.expectEmit(true, true, true, true, address(_manager));
    emit IPolicyManager.AttemptCancelled(_account, address(_action), 1, address(0), address(0), 1, new uint256[](0));
    vm.expectEmit(true, true, true, true, address(_manager));
    emit IPolicyManager.SetupCleared(_account, address(_action), 2);
    _asHolder(_one(_managerCall(abi.encodeCall(IPolicyManager.clearSetup, (address(_action))))));

    IPolicyManager.ActionState memory _cleared = _state();
    assertEq(_cleared.setupCommitment, bytes32(0), 'a setup is still stored');
    assertEq(_cleared.setupNonce, 2, 'the clear did not move the nonce');
    vm.warp(_cleared.attempt.consumableAfter);
    bytes memory _consume = abi.encodeCall(IPolicyManager.consume, (address(_action), 1, keccak256(_payload())));
    vm.expectRevert(
      abi.encodeWithSelector(IPolicyManager.PolicyManager_NoActiveAttempt.selector, _account, address(_action))
    );
    _asHolder(_one(_managerCall(_consume)));
    assertTrue(_action.isAuthorized(_account), 'the clear removed the authorization on the account');
  }

  /// @notice Waits out the old attempt's delay and asserts that a handover, a direct spend from the
  ///         account and a cancel by proofs all revert for that attempt.
  function _assertTheOldAttemptIsGone(IPolicyManager.Attempt memory _old) internal {
    vm.warp(_old.consumableAfter);
    vm.expectRevert(
      abi.encodeWithSelector(
        IRecoveryAction.RecoveryAction_NotConsumable.selector,
        _account,
        IPolicyManager.AttemptState.Cancelled,
        _old.consumableAfter,
        keccak256(_payload())
      )
    );
    _executeHandover();
    bytes memory _consume = abi.encodeCall(IPolicyManager.consume, (address(_action), 1, keccak256(_payload())));
    vm.expectRevert(
      abi.encodeWithSelector(IPolicyManager.PolicyManager_NoActiveAttempt.selector, _account, address(_action))
    );
    _asHolder(_one(_managerCall(_consume)));
    IPolicyManager.CancelRequest memory _oldCancel = _cancelRequest(_places(_ALICE, _CAROL, _PHONE), 1, 1, _window());
    vm.expectRevert(
      abi.encodeWithSelector(IPolicyManager.PolicyManager_NoActiveAttempt.selector, _account, address(_action))
    );
    vm.prank(_executor);
    _manager.cancelByProofs(_oldCancel);
  }
}
