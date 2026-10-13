// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {Vm} from 'forge-std/Vm.sol';
import {IPolicyManager} from 'interfaces/IPolicyManager.sol';
import {PolicyManagerTestBase} from 'test/utils/PolicyManagerTestBase.sol';

/// @notice cancelByOwner, the holder's own cancel of a waiting recovery attempt. A holder who still
///         has their key must always be able to stop a recovery against them, so this call reads
///         no method and no pause and checks nothing but that an attempt is waiting.
contract PolicyManagerCancelByOwnerTest is PolicyManagerTestBase {
  /*///////////////////////////////////////////////////////////////
                             TREE TESTS
  ///////////////////////////////////////////////////////////////*/

  /// @notice With no setup and no attempt ever recorded the cancel reverts, since it would report a
  ///         cancellation that did not happen. `_anAction` is any action address.
  function test_WhenNoSetupAndNoAttemptWasEverRecorded(address _anAction) external {
    vm.expectRevert(abi.encodeWithSelector(IPolicyManager.PolicyManager_NoActiveAttempt.selector, _account, _anAction));
    vm.prank(_account);
    _manager.cancelByOwner(_anAction);
  }

  /// @notice A committed setup alone is not an attempt: with no attempt ever opened under it the
  ///         cancel still reverts, so a setup write never reads as a recovery in progress.
  ///         `_actionSeed` builds a fresh action that serves every account.
  function test_WhenASetupExistsButNoAttemptWasEverRecorded(uint256 _actionSeed) external {
    address _anAction = _servingActionFrom(_actionSeed);
    _commit(_account, _anAction);

    vm.expectRevert(abi.encodeWithSelector(IPolicyManager.PolicyManager_NoActiveAttempt.selector, _account, _anAction));
    vm.prank(_account);
    _manager.cancelByOwner(_anAction);
  }

  /// @notice An attempt already cancelled or consumed cannot be cancelled again, and its record stays
  ///         as it was. `_consumed` picks which of the two ended states is planted.
  function test_WhenTheLastAttemptIsCancelledOrConsumed(bool _consumed, uint64 _attemptId) external {
    (uint64 _nonce,) = _commit(_account, _action);
    IPolicyManager.Attempt memory _planted = _attempt(
      _attemptId,
      _nonce,
      _consumed ? IPolicyManager.AttemptState.Consumed : IPolicyManager.AttemptState.Cancelled,
      false,
      _methods()
    );
    _plant(_account, _action, _planted);

    vm.expectRevert(abi.encodeWithSelector(IPolicyManager.PolicyManager_NoActiveAttempt.selector, _account, _action));
    vm.prank(_account);
    _manager.cancelByOwner(_action);

    assertEq(abi.encode(_state(_account, _action).attempt), abi.encode(_planted), 'record untouched');
  }

  /// @notice The holder's cancel ends a waiting attempt, keeps the rest of its record, names the
  ///         account as canceller in its one event and leaves the setup alone.
  function test_WhenAnAttemptIsWaiting(uint64 _attemptId, bool _ignoresPause) external {
    _commit(_account, _action);
    IPolicyManager.Attempt memory _planted = _plantWaiting(_account, _action, _attemptId, _ignoresPause);
    IPolicyManager.ActionState memory _before = _state(_account, _action);

    vm.recordLogs();
    vm.prank(_account);
    _manager.cancelByOwner(_action);
    Vm.Log[] memory _logs = vm.getRecordedLogs();

    IPolicyManager.ActionState memory _actionState = _state(_account, _action);
    // it should set the attempt to Cancelled and keep the rest of its record
    _assertRecordKept(_actionState.attempt, _planted, IPolicyManager.AttemptState.Cancelled);
    // it should emit AttemptCancelled alone with the account as canceller and no places
    assertEq(_logs.length, 1, 'one event');
    _assertCancelledLog(_logs[0], _account, _action, _attemptId, _account, _planted.setupNonce);
    // it should leave the setup and the attempt counter unchanged
    assertEq(_actionState.setupCommitment, _before.setupCommitment, 'commitment');
    assertEq(_actionState.setupNonce, _before.setupNonce, 'nonce');
    assertEq(_actionState.setupCommittedAtBlock, _before.setupCommittedAtBlock, 'setupCommittedAtBlock');
    assertEq(_actionState.nextAttemptId, _before.nextAttemptId, 'attempt counter');
    // it should refuse a second cancel with nothing left to cancel
    vm.expectRevert(abi.encodeWithSelector(IPolicyManager.PolicyManager_NoActiveAttempt.selector, _account, _action));
    vm.prank(_account);
    _manager.cancelByOwner(_action);
  }

  /// @notice An action that stopped serving the account after the commit, as an upgraded account
  ///         sees it, cannot trap the holder: the cancel asks the action nothing, so it still ends
  ///         the waiting attempt and reaches no other contract. `_answerSeed` picks how the action
  ///         stopped serving: it answers false, it reverts, or its code is gone.
  function test_WhenTheActionStoppedServingTheAccount(uint256 _answerSeed) external {
    _commit(_account, _action);
    IPolicyManager.Attempt memory _planted = _plantWaiting(_account, _action, 1, false);
    _stopServing(_action, _answerSeed);

    vm.startStateDiffRecording();
    vm.prank(_account);
    _manager.cancelByOwner(_action);
    Vm.AccountAccess[] memory _accesses = vm.stopAndReturnStateDiff();

    // it should cancel the attempt
    _assertRecordKept(_state(_account, _action).attempt, _planted, IPolicyManager.AttemptState.Cancelled);
    // it should not ask the action
    _assertReachedNoOtherContract(_accesses);
  }

  /// @notice The cancel succeeds while the attempt's methods report a stop or revert on every call,
  ///         and it touches no contract but the manager, so no method can block the holder.
  function test_WhenTheAttemptsMethodsReportAStopOrRevertOnEveryCall(bool _ignoresPause) external {
    _commit(_account, _action);
    IPolicyManager.Attempt memory _planted = _plantWaiting(_account, _action, 1, _ignoresPause);

    vm.startStateDiffRecording();
    vm.prank(_account);
    _manager.cancelByOwner(_action);
    Vm.AccountAccess[] memory _accesses = vm.stopAndReturnStateDiff();

    _assertReachedNoOtherContract(_accesses);
    _assertRecordKept(_state(_account, _action).attempt, _planted, IPolicyManager.AttemptState.Cancelled);
  }

  /// @notice The holder's cancel reads no nonce: it ends a waiting attempt even when the attempt's
  ///         setup nonce differs from the stored one. `_offsetSeed` builds any nonce but the stored one.
  function test_WhenTheAttemptCarriesASetupNonceOtherThanTheStoredOne(uint64 _offsetSeed) external {
    (uint64 _nonce,) = _commit(_account, _action);
    uint64 _judgedUnder = _otherThan(_nonce, _offsetSeed);
    IPolicyManager.Attempt memory _planted =
      _attempt(3, _judgedUnder, IPolicyManager.AttemptState.Waiting, false, _methods());
    _plant(_account, _action, _planted);

    vm.recordLogs();
    vm.prank(_account);
    _manager.cancelByOwner(_action);
    Vm.Log[] memory _logs = vm.getRecordedLogs();

    _assertRecordKept(_state(_account, _action).attempt, _planted, IPolicyManager.AttemptState.Cancelled);
    assertEq(_logs.length, 1, 'one event');
    _assertCancelledLog(_logs[0], _account, _action, 3, _account, _judgedUnder);
  }

  /// @notice Once a new commit has ended the attempt, the holder's cancel finds nothing to cancel and
  ///         reverts, which is the attempt already gone rather than the holder refused, and the ended
  ///         record stays as the commit left it.
  function test_WhenANewSetupAlreadyEndedTheAttempt() external {
    _commit(_account, _action);
    _plantWaiting(_account, _action, 1, false);
    _commit(_account, _action);
    IPolicyManager.Attempt memory _ended = _state(_account, _action).attempt;

    vm.expectRevert(abi.encodeWithSelector(IPolicyManager.PolicyManager_NoActiveAttempt.selector, _account, _action));
    vm.prank(_account);
    _manager.cancelByOwner(_action);

    assertEq(abi.encode(_state(_account, _action).attempt), abi.encode(_ended), 'record untouched');
  }

  /// @notice Once a clear has ended the attempt, the holder's cancel finds nothing to cancel and
  ///         reverts, which is the attempt already gone rather than the holder refused, and the ended
  ///         record stays as the clear left it.
  function test_WhenAClearAlreadyEndedTheAttempt() external {
    _commit(_account, _action);
    _plantWaiting(_account, _action, 1, false);
    _clear(_account, _action);
    IPolicyManager.Attempt memory _ended = _state(_account, _action).attempt;

    vm.expectRevert(abi.encodeWithSelector(IPolicyManager.PolicyManager_NoActiveAttempt.selector, _account, _action));
    vm.prank(_account);
    _manager.cancelByOwner(_action);

    assertEq(abi.encode(_state(_account, _action).attempt), abi.encode(_ended), 'record untouched');
  }

  /// @notice Another address reaches only its own empty attempt slot and reverts, so it cannot end
  ///         the account's attempt. `_callerSeed` builds that address.
  function test_WhenAnAddressOtherThanTheAccountCalls(uint256 _callerSeed) external {
    address _caller = _addressFrom('caller', _callerSeed);
    _commit(_account, _action);
    IPolicyManager.Attempt memory _planted = _plantWaiting(_account, _action, 1, false);

    // it should revert with PolicyManager_NoActiveAttempt carrying that address and the action
    vm.expectRevert(abi.encodeWithSelector(IPolicyManager.PolicyManager_NoActiveAttempt.selector, _caller, _action));
    vm.prank(_caller);
    _manager.cancelByOwner(_action);

    // it should leave the account's attempt waiting
    assertEq(abi.encode(_state(_account, _action).attempt), abi.encode(_planted), 'still waiting, untouched');
  }
}
