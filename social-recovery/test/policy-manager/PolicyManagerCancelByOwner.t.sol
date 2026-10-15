// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {Vm} from 'forge-std/Vm.sol';
import {IPolicyManager} from 'interfaces/IPolicyManager.sol';
import {PolicyManagerTestBase} from 'test/utils/PolicyManagerTestBase.sol';

/// @notice cancelByOwner, the holder's own cancel of a waiting recovery attempt. A holder who still
///         has their key must always be able to stop a recovery against them, so this call reads
///         no method and no pause and checks nothing but that an attempt is waiting and that it is
///         the one the holder named. Naming the attempt matters because a signed account batch whose
///         cancel reverted stays valid, and sent again later it must not end a later attempt.
contract PolicyManagerCancelByOwnerTest is PolicyManagerTestBase {
  /*///////////////////////////////////////////////////////////////
                             TREE TESTS
  ///////////////////////////////////////////////////////////////*/

  /// @notice With no setup and no attempt ever recorded the cancel reverts, since it would report a
  ///         cancellation that did not happen. `_anAction` is any action address and `_namedId` any
  ///         attempt id the holder names.
  function test_WhenNoSetupAndNoAttemptWasEverRecorded(address _anAction, uint64 _namedId) external {
    vm.expectRevert(abi.encodeWithSelector(IPolicyManager.PolicyManager_NoActiveAttempt.selector, _account, _anAction));
    vm.prank(_account);
    _manager.cancelByOwner(_anAction, _namedId);
  }

  /// @notice A committed setup alone is not an attempt: with no attempt ever opened under it the
  ///         cancel still reverts, so a setup write never reads as a recovery in progress.
  ///         `_actionSeed` builds a fresh action that serves every account, and `_namedId` is any
  ///         attempt id the holder names.
  function test_WhenASetupExistsButNoAttemptWasEverRecorded(uint256 _actionSeed, uint64 _namedId) external {
    address _anAction = _servingActionFrom(_actionSeed);
    _commit(_account, _anAction);

    vm.expectRevert(abi.encodeWithSelector(IPolicyManager.PolicyManager_NoActiveAttempt.selector, _account, _anAction));
    vm.prank(_account);
    _manager.cancelByOwner(_anAction, _namedId);
  }

  /// @notice An attempt already cancelled or consumed cannot be cancelled again, even by a cancel
  ///         naming its own id, and its record stays as it was. `_consumed` picks which of the two
  ///         ended states is planted.
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
    _manager.cancelByOwner(_action, _attemptId);

    assertEq(abi.encode(_state(_account, _action).attempt), abi.encode(_planted), 'record untouched');
  }

  /// @notice With no attempt waiting, a cancel naming an id other than the last attempt's still
  ///         reports that nothing waits, the more fundamental refusal, rather than a wrong id: there
  ///         is no live id the named one could be wrong against. `_offsetSeed` builds the named id,
  ///         any value but the ended attempt's.
  function test_WhenNoAttemptIsWaitingAndTheNamedIdIsNotTheLastAttempts(uint64 _attemptId, uint64 _offsetSeed)
    external
  {
    (uint64 _nonce,) = _commit(_account, _action);
    IPolicyManager.Attempt memory _planted =
      _attempt(_attemptId, _nonce, IPolicyManager.AttemptState.Cancelled, false, _methods());
    _plant(_account, _action, _planted);
    uint64 _namedId = _otherThan(_attemptId, _offsetSeed);

    vm.expectRevert(abi.encodeWithSelector(IPolicyManager.PolicyManager_NoActiveAttempt.selector, _account, _action));
    vm.prank(_account);
    _manager.cancelByOwner(_action, _namedId);

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
    _manager.cancelByOwner(_action, _attemptId);
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
    _manager.cancelByOwner(_action, _attemptId);
  }

  /// @notice A cancel naming any id but the waiting attempt's reverts with both ids and leaves the
  ///         attempt waiting, so a signed cancel can only end the attempt it was signed for.
  ///         `_offsetSeed` builds the named id, any value but the waiting attempt's.
  function test_WhenTheNamedIdIsNotTheWaitingAttemptsId(uint64 _attemptId, uint64 _offsetSeed) external {
    _commit(_account, _action);
    _plantWaiting(_account, _action, _attemptId, false);
    IPolicyManager.ActionState memory _before = _state(_account, _action);
    uint64 _namedId = _otherThan(_attemptId, _offsetSeed);

    // it should revert with PolicyManager_WrongAttemptId carrying the named id and the waiting id
    vm.expectRevert(abi.encodeWithSelector(IPolicyManager.PolicyManager_WrongAttemptId.selector, _namedId, _attemptId));
    vm.prank(_account);
    _manager.cancelByOwner(_action, _namedId);

    // it should leave the attempt waiting and the state untouched
    assertEq(abi.encode(_state(_account, _action)), abi.encode(_before), 'a refused cancel changes nothing');
  }

  /// @notice A cancel naming an attempt the holder already ended reverts once a later attempt waits,
  ///         and the later attempt keeps waiting. This is the replay a reverted signed cancel would
  ///         make weeks later: it must not stop a recovery the holder never saw. `_earlierSeed` and
  ///         `_laterSeed` build the two ids, the later one larger, as ids only grow.
  function test_WhenTheNamedIdIsAnEarlierAttemptsId(uint64 _earlierSeed, uint64 _laterSeed) external {
    uint64 _earlierId = uint64(bound(_earlierSeed, 1, type(uint64).max - 1));
    uint64 _laterId = uint64(bound(_laterSeed, uint256(_earlierId) + 1, type(uint64).max));
    _commit(_account, _action);
    _plantWaiting(_account, _action, _earlierId, false);
    vm.prank(_account);
    _manager.cancelByOwner(_action, _earlierId);
    IPolicyManager.Attempt memory _later = _plantWaiting(_account, _action, _laterId, false);

    // it should revert with PolicyManager_WrongAttemptId carrying the earlier id and the waiting id
    vm.expectRevert(abi.encodeWithSelector(IPolicyManager.PolicyManager_WrongAttemptId.selector, _earlierId, _laterId));
    vm.prank(_account);
    _manager.cancelByOwner(_action, _earlierId);

    // it should leave the later attempt waiting
    assertEq(abi.encode(_state(_account, _action).attempt), abi.encode(_later), 'later attempt still waiting');
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
    _manager.cancelByOwner(_action, 1);
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
    _manager.cancelByOwner(_action, 1);
    Vm.AccountAccess[] memory _accesses = vm.stopAndReturnStateDiff();

    _assertReachedNoOtherContract(_accesses);
    _assertRecordKept(_state(_account, _action).attempt, _planted, IPolicyManager.AttemptState.Cancelled);
  }

  /// @notice The holder's cancel reads no setup nonce: it ends a waiting attempt even when the
  ///         attempt's setup nonce differs from the stored one. `_offsetSeed` builds any nonce but the
  ///         stored one.
  function test_WhenTheAttemptCarriesASetupNonceOtherThanTheStoredOne(uint64 _offsetSeed) external {
    (uint64 _nonce,) = _commit(_account, _action);
    uint64 _judgedUnder = _otherThan(_nonce, _offsetSeed);
    IPolicyManager.Attempt memory _planted =
      _attempt(3, _judgedUnder, IPolicyManager.AttemptState.Waiting, false, _methods());
    _plant(_account, _action, _planted);

    vm.recordLogs();
    vm.prank(_account);
    _manager.cancelByOwner(_action, 3);
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
    _manager.cancelByOwner(_action, 1);

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
    _manager.cancelByOwner(_action, 1);

    assertEq(abi.encode(_state(_account, _action).attempt), abi.encode(_ended), 'record untouched');
  }

  /// @notice Another address reaches only its own empty attempt slot and reverts, so it cannot end
  ///         the account's attempt even when it names that attempt's id. `_callerSeed` builds that
  ///         address.
  function test_WhenAnAddressOtherThanTheAccountCalls(uint256 _callerSeed) external {
    address _caller = _addressFrom('caller', _callerSeed);
    _commit(_account, _action);
    IPolicyManager.Attempt memory _planted = _plantWaiting(_account, _action, 1, false);

    // it should revert with PolicyManager_NoActiveAttempt carrying that address and the action
    vm.expectRevert(abi.encodeWithSelector(IPolicyManager.PolicyManager_NoActiveAttempt.selector, _caller, _action));
    vm.prank(_caller);
    _manager.cancelByOwner(_action, 1);

    // it should leave the account's attempt waiting
    assertEq(abi.encode(_state(_account, _action).attempt), abi.encode(_planted), 'still waiting, untouched');
  }
}
