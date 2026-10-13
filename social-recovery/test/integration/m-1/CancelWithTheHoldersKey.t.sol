// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {Vm} from 'forge-std/Vm.sol';
import {IPolicyManager} from 'interfaces/IPolicyManager.sol';
import {ActionAmbireAccountFixture} from 'test/mocks/ActionAmbireAccountFixture.sol';
import {IntegrationDemoKitTestBase} from 'test/utils/IntegrationDemoKitTestBase.sol';

/// @notice A recovery the holder did not start is waiting. The holder still has their key, cancels
///         the recovery from the account, and then replaces the rule that let it open.
contract CancelWithTheHoldersKeyTest is IntegrationDemoKitTestBase {
  /// @notice The window of the request that opened the unwanted attempt.
  uint48 internal _hostileWindow;
  /// @notice The opening event, as the watcher read it.
  StartedLog internal _seen;

  function setUp() public override {
    super.setUp();
    _authorizeAndCommit();
    vm.recordLogs();
    _hostileWindow = _open(_openingSet()).validUntil;
    _seen = _startedLog(vm.getRecordedLogs());
  }

  /// @notice The holder's account cancels without naming an attempt id. The manager records the
  ///         account as the canceller and the attempt counter does not change. A new setup then makes
  ///         every approval signed under the old setup useless.
  function test_WhenTheHolderCancelsWithTheirKey() external {
    // it should cancel the attempt, keep the counter and refuse every approval signed under the old setup
    assertEq(_seen.attemptId, 1, 'the watcher read another attempt');
    assertEq(_seen.payload, _payload(), 'the watcher read another payload');

    vm.expectEmit(true, true, true, true, address(_manager));
    emit IPolicyManager.AttemptCancelled(_account, address(_action), 1, _account, address(0), 1, new uint256[](0));
    _asHolder(_one(_managerCall(abi.encodeCall(IPolicyManager.cancelByOwner, (address(_action))))));

    IPolicyManager.ActionState memory _cancelled = _state();
    assertEq(uint256(_cancelled.attempt.state), uint256(IPolicyManager.AttemptState.Cancelled), 'the attempt runs');
    assertEq(_cancelled.nextAttemptId, 2, 'the cancelled id can be allocated again');

    uint64 _nonce = _commitNext(_body());
    assertEq(_nonce, 2, 'the new setup did not raise the nonce');
    assertEq(_state().nextAttemptId, 2, 'the new setup moved the attempt counter');

    IPolicyManager.AttemptRequest memory _oldApproval = _request(_openingSet(), 1, 1, _hostileWindow);
    vm.expectRevert(_wrongNonce(1, 2));
    _send(_oldApproval);
    _oldApproval = _request(_openingSet(), 2, 1, _hostileWindow);
    vm.expectRevert(_wrongNonce(1, 2));
    _send(_oldApproval);
    assertEq(uint256(_state().attempt.state), uint256(IPolicyManager.AttemptState.Cancelled), 'an attempt runs');
  }

  /// @notice When guardians already cancelled the attempt, the holder's cancel reverts because nothing
  ///         is left to cancel.
  function test_RevertWhen_TheAttemptEndedFirst() external {
    // it should revert
    IPolicyManager.CancelRequest memory _cancel = _cancelRequest(_places(_ALICE, _CAROL, _PHONE), 1, 1, _window());
    vm.prank(_executor);
    _manager.cancelByProofs(_cancel);

    vm.expectRevert(
      abi.encodeWithSelector(IPolicyManager.PolicyManager_NoActiveAttempt.selector, _account, address(_action))
    );
    _asHolder(_one(_managerCall(abi.encodeCall(IPolicyManager.cancelByOwner, (address(_action))))));
  }

  /// @notice Once the handover has run, the holder's key is no longer a key of the account and
  ///         nothing is left to cancel. The holder can only cancel during the wait.
  function test_RevertWhen_TheHandoverRanFirst() external {
    // it should revert
    vm.warp(_state().attempt.consumableAfter);
    _executeHandover();

    vm.expectRevert(bytes('INSUFFICIENT_PRIVILEGE'));
    _asHolder(_one(_managerCall(abi.encodeCall(IPolicyManager.cancelByOwner, (address(_action))))));
    vm.expectRevert(
      abi.encodeWithSelector(IPolicyManager.PolicyManager_NoActiveAttempt.selector, _account, address(_action))
    );
    vm.prank(_newKey);
    ActionAmbireAccountFixture(payable(_account))
      .executeBySender(_one(_managerCall(abi.encodeCall(IPolicyManager.cancelByOwner, (address(_action))))));
  }

  /// @notice A hook on the account can make the holder's own cancel revert. Guardians can still
  ///         cancel with signed proofs, because that cancel never calls the account.
  function test_WhenTheAccountsOwnPathReverts() external {
    // it should still let a satisfying set cancel without touching the account
    vm.mockCallRevert(
      _account, abi.encodeWithSelector(ActionAmbireAccountFixture.executeBySender.selector), bytes('HOOK_REFUSED')
    );
    vm.expectRevert(bytes('HOOK_REFUSED'));
    _asHolder(_one(_managerCall(abi.encodeCall(IPolicyManager.cancelByOwner, (address(_action))))));

    IPolicyManager.CancelRequest memory _cancel = _cancelRequest(_places(_ALICE, _CAROL, _PHONE), 1, 1, _window());
    vm.startStateDiffRecording();
    vm.prank(_executor);
    _manager.cancelByProofs(_cancel);
    Vm.AccountAccess[] memory _accesses = vm.stopAndReturnStateDiff();

    assertEq(uint256(_state().attempt.state), uint256(IPolicyManager.AttemptState.Cancelled), 'the attempt runs');
    for (uint256 _i; _i < _accesses.length; ++_i) {
      assertTrue(_accesses[_i].account != _account, 'the cancel by proofs reached the account');
    }
  }
}
