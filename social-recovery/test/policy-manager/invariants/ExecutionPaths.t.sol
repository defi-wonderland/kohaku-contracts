// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {IPolicyManager} from 'interfaces/IPolicyManager.sol';
import {PolicyManagerInvariantSetup} from 'test/policy-manager/invariants/Setup.t.sol';

/// @notice Walks whole sequences of handler calls with chosen arguments, to prove each handler
///         reaches the manager call it names and lands in the state it aims for instead of
///         returning early or reverting, and that a correct sequence raises no ghost flag.
/// @dev Alice is caller 0 and the recovery action is action 0, so their entry is entry 0. Bob is
///      caller 1 and the other action is action 1, so their entry is entry 3. A set seed of 0x10100
///      builds a set with no surplus, nothing dropped and no hostile place; 0x10101 adds every
///      other honest place.
contract PolicyManagerExecutionPaths is PolicyManagerInvariantSetup {
  /// @notice No seed from `_firstSeed` to 49 above it builds a rule without a hostile method.
  /// @param _firstSeed The first seed tried.
  error PolicyManagerExecutionPaths_NoHonestRule(uint256 _firstSeed);

  /// @notice The method is not in the handler's pool of honest methods.
  /// @param _method The method looked up.
  error PolicyManagerExecutionPaths_NotInPool(address _method);

  /// @notice The set seed of a clean set with no surplus.
  uint256 internal constant _CLEAN_SET = 0x10100;
  /// @notice The set seed of a clean set with every honest place.
  uint256 internal constant _FULL_SET = 0x10101;
  /// @notice The time seed of a spend sent one second before the end of the wait, with no steering.
  uint256 internal constant _A_SECOND_EARLY = 1;
  /// @notice The time seed of a spend sent exactly at the end of the wait, with no steering.
  uint256 internal constant _AT_THE_END = 2;
  /// @notice The stop seed that makes a method answer the pause read with exactly true.
  uint256 internal constant _STOP = 0;
  /// @notice The stop seed that makes a method answer the pause read with a false word.
  uint256 internal constant _LIFT = 1;
  /// @notice The first rule seed whose rule ignores stops: bits 200 and 201 of the seed read 1.
  uint256 internal constant _IGNORES_STOPS = 1 << 200;

  /*///////////////////////////////////////////////////////////////
                            EXECUTION PATHS
  ///////////////////////////////////////////////////////////////*/

  /// @notice Commit a rule, open an attempt with a valid set, cancel it by proofs from another
  ///         sender, open a second attempt, and cancel that one with the holder's own key.
  function test_CommitStartCancelByProofsThenOwnerCancel() external {
    address _alice = makeAddr('alice');
    address _action = makeAddr('recoveryAction');
    uint64 _nonce = _commitHonestRule(0, 0, 0);

    _handler.handler_startAttempt(0, 0, 0, _CLEAN_SET, 'new key', 5, 1);
    IPolicyManager.ActionState memory _state = _manager.stateOf(_alice, _action);
    assertEq(uint8(_state.attempt.state), uint8(IPolicyManager.AttemptState.Waiting), 'start: state');
    assertEq(_state.attempt.attemptId, 1, 'start: attempt id');
    assertEq(_state.attempt.setupNonce, _nonce, 'start: nonce');
    assertEq(_state.nextAttemptId, 2, 'start: next attempt id');

    _handler.handler_cancelByProofs(0, 0, 0, _FULL_SET, 2);
    _state = _manager.stateOf(_alice, _action);
    assertEq(uint8(_state.attempt.state), uint8(IPolicyManager.AttemptState.Cancelled), 'cancel by proofs: state');
    assertEq(_state.nextAttemptId, 2, 'cancel by proofs: counter kept');

    _handler.handler_warp(1 hours);
    _handler.handler_startAttempt(0, 0, 1, _FULL_SET, 'another key', 0, 2);
    _state = _manager.stateOf(_alice, _action);
    assertEq(uint8(_state.attempt.state), uint8(IPolicyManager.AttemptState.Waiting), 'second start: state');
    assertEq(_state.attempt.attemptId, 2, 'second start: attempt id');

    _handler.handler_cancelByOwner(0, 0);
    _state = _manager.stateOf(_alice, _action);
    assertEq(uint8(_state.attempt.state), uint8(IPolicyManager.AttemptState.Cancelled), 'owner cancel: state');

    _assertNoGhostRaised();
  }

  /// @notice With every honest method stopped, a rule that honours stops opens nothing; once the
  ///         stops lift it opens; the spend at the end of the wait then leaves nothing for a cancel
  ///         by proofs.
  function test_StopsRefuseThenLift() external {
    address _alice = makeAddr('alice');
    address _action = makeAddr('recoveryAction');
    _commitHonestRule(0, 0, 0);
    assertFalse(_handler.ruleOf(0).ignoresPause, 'the rule honours stops');
    for (uint256 _i; _i < 3; ++_i) {
      _handler.handler_setStopped(_i, _STOP);
    }

    _handler.handler_startAttempt(0, 0, 2, _CLEAN_SET, 'new key', 1, 1);
    IPolicyManager.ActionState memory _state = _manager.stateOf(_alice, _action);
    assertEq(_state.nextAttemptId, 1, 'stopped: opens nothing');

    for (uint256 _i; _i < 3; ++_i) {
      _handler.handler_setStopped(_i, _LIFT);
    }
    _handler.handler_startAttempt(0, 0, 3, _CLEAN_SET, 'new key', 1, 1);
    _state = _manager.stateOf(_alice, _action);
    assertEq(uint8(_state.attempt.state), uint8(IPolicyManager.AttemptState.Waiting), 'lifted: state');

    _handler.handler_consume(0, 0, 0, _AT_THE_END, 0);
    _handler.handler_cancelByProofs(0, 0, 0, _CLEAN_SET, 2);
    _state = _manager.stateOf(_alice, _action);
    assertEq(uint8(_state.attempt.state), uint8(IPolicyManager.AttemptState.Consumed), 'consumed: state');

    _assertNoGhostRaised();
  }

  /// @notice Prepare a request, open and cancel an attempt, replay the accepted request, then commit
  ///         the identical rule again and replay the prepared request moved to the new nonce: no
  ///         replay opens anything.
  function test_ReplaysOpenNothing() external {
    address _bob = makeAddr('bob');
    address _action = makeAddr('otherAction');
    _commitHonestRule(1, 1, 7);

    _handler.handler_startAttempt(1, 1, 10, _CLEAN_SET, 'prepared', 0, 0);
    _handler.handler_startAttempt(1, 1, 0, _CLEAN_SET, 'sent', 0, 0);
    _handler.handler_cancelByProofs(1, 1, 0, _CLEAN_SET, 0);
    _handler.handler_replayApproval(1, 0, 0, 0);
    _handler.handler_replayCancel(0, 1, 0, 0);
    IPolicyManager.ActionState memory _state = _manager.stateOf(_bob, _action);
    assertEq(uint8(_state.attempt.state), uint8(IPolicyManager.AttemptState.Cancelled), 'replays: still cancelled');
    assertEq(_state.nextAttemptId, 2, 'replays: no new attempt');
    assertEq(_handler.ghost_replaysRefused(), 2, 'replays: both reached the manager and were refused');

    _handler.handler_commitSetup(1, 1, 0, 0, 3, bytes32(0), '', '');
    _handler.handler_replayApproval(0, 1, 0, 0);
    _state = _manager.stateOf(_bob, _action);
    assertEq(_state.nextAttemptId, 2, 'retired: no new attempt');
    assertEq(_handler.ghost_replaysRefused(), 3, 'retired: the replay reached the manager and was refused');

    _assertNoGhostRaised();
  }

  /// @notice Open an attempt, commit over it so the write cancels it first, open again and clear over
  ///         the second attempt.
  function test_WritesOverAWaitingAttempt() external {
    address _bob = makeAddr('bob');
    address _action = makeAddr('otherAction');
    _commitHonestRule(1, 1, 20);
    _handler.handler_startAttempt(1, 1, 0, _CLEAN_SET, 'first', 0, 2);
    _handler.handler_roll(5);
    uint64 _nonce = _commitHonestRule(1, 1, 40);
    IPolicyManager.ActionState memory _state = _manager.stateOf(_bob, _action);
    assertEq(_state.setupNonce, _nonce, 'second commit: nonce');
    assertEq(uint8(_state.attempt.state), uint8(IPolicyManager.AttemptState.Cancelled), 'second commit: state');

    _handler.handler_startAttempt(1, 1, 0, _CLEAN_SET, 'second', 0, 2);
    assertEq(_manager.stateOf(_bob, _action).attempt.attemptId, 2, 'second start: attempt id');
    _handler.handler_clearSetup(1, 1);
    _state = _manager.stateOf(_bob, _action);
    assertEq(_state.setupNonce, _nonce + 1, 'clear: nonce');
    assertEq(uint8(_state.attempt.state), uint8(IPolicyManager.AttemptState.Cancelled), 'clear: state');

    _assertNoGhostRaised();
  }

  /// @notice Open an attempt under a rule with a wait, spend it one second early and be refused,
  ///         spend it at the end of the wait, and be refused when spending it again.
  function test_OpenWaitConsume() external {
    address _alice = makeAddr('alice');
    address _action = makeAddr('recoveryAction');
    _commitHonestRule(0, 0, 0);
    assertGt(_handler.ruleOf(0).wait, 0, 'the rule has a wait');
    _handler.handler_startAttempt(0, 0, 0, _CLEAN_SET, 'new key', 5, 1);
    _handler.handler_consume(0, 0, 0, _A_SECOND_EARLY, 0);
    assertEq(_handler.ghost_spendsRefused(), 1, 'early: refused');
    assertEq(uint8(_manager.stateOf(_alice, _action).attempt.state), uint8(IPolicyManager.AttemptState.Waiting));

    _handler.handler_consume(0, 0, 0, _AT_THE_END, 0);
    assertEq(_handler.ghost_spendsConsumed(), 1, 'end: consumed');
    assertEq(uint8(_manager.stateOf(_alice, _action).attempt.state), uint8(IPolicyManager.AttemptState.Consumed));

    _handler.handler_consume(0, 0, 0, _AT_THE_END, 0);
    assertEq(_handler.ghost_spendsRefused(), 2, 'again: refused');

    _assertNoGhostRaised();
  }

  /// @notice Open an attempt, stop the first method it used, see the spend at the end of the wait
  ///         refused as vetoed, then cancel the attempt by that method's veto from another sender.
  function test_OpenStopVetoedThenCancelByVeto() external {
    address _alice = makeAddr('alice');
    address _action = makeAddr('recoveryAction');
    _commitHonestRule(0, 0, 0);
    assertFalse(_handler.ruleOf(0).ignoresPause, 'the rule honours stops');
    _handler.handler_startAttempt(0, 0, 0, _CLEAN_SET, 'new key', 5, 1);
    _handler.handler_setStopped(_poolIndexOf(_manager.stateOf(_alice, _action).attempt.usedMethods[0]), _STOP);

    _handler.handler_consume(0, 0, 0, _AT_THE_END, 0);
    assertEq(_handler.ghost_spendsVetoed(), 1, 'spend: vetoed');
    assertEq(uint8(_manager.stateOf(_alice, _action).attempt.state), uint8(IPolicyManager.AttemptState.Waiting));

    _handler.handler_cancelByVeto(0, 0, 0, 0, 2);
    assertEq(_handler.ghost_vetoCancels(), 1, 'veto: accepted');
    IPolicyManager.ActionState memory _state = _manager.stateOf(_alice, _action);
    assertEq(uint8(_state.attempt.state), uint8(IPolicyManager.AttemptState.Cancelled), 'veto: state');
    assertEq(_state.nextAttemptId, 2, 'veto: counter kept');

    _assertNoGhostRaised();
  }

  /// @notice Open an attempt, cancel it by proofs, and see the spend at the end of the wait refused.
  function test_OpenCancelByProofsThenConsumeRefused() external {
    address _alice = makeAddr('alice');
    address _action = makeAddr('recoveryAction');
    _commitHonestRule(0, 0, 0);
    _handler.handler_startAttempt(0, 0, 0, _CLEAN_SET, 'new key', 5, 1);
    _handler.handler_cancelByProofs(0, 0, 0, _FULL_SET, 2);
    assertEq(uint8(_manager.stateOf(_alice, _action).attempt.state), uint8(IPolicyManager.AttemptState.Cancelled));

    _handler.handler_consume(0, 0, 0, _AT_THE_END, 0);
    assertEq(_handler.ghost_spendsRefused(), 1, 'spend: refused');
    assertEq(_handler.ghost_spendsConsumed(), 0, 'spend: nothing consumed');
    assertEq(uint8(_manager.stateOf(_alice, _action).attempt.state), uint8(IPolicyManager.AttemptState.Cancelled));

    _assertNoGhostRaised();
  }

  /// @notice Under a rule that ignores stops, a veto of the attempt's stopped method is refused and
  ///         the spend at the end of the wait goes through the stop.
  function test_IgnoringStopsSpendsThroughAStop() external {
    address _alice = makeAddr('alice');
    address _action = makeAddr('recoveryAction');
    _commitHonestRule(0, 0, _IGNORES_STOPS);
    assertTrue(_handler.ruleOf(0).ignoresPause, 'the rule ignores stops');
    _handler.handler_startAttempt(0, 0, 0, _CLEAN_SET, 'new key', 5, 1);

    _handler.handler_cancelByVeto(0, 0, 1, 0, 2);
    assertEq(_handler.ghost_vetoCancels(), 0, 'veto: refused');
    assertEq(uint8(_manager.stateOf(_alice, _action).attempt.state), uint8(IPolicyManager.AttemptState.Waiting));

    // Mode 4 stops a method the attempt used during the spend, so the spend really runs through a stop.
    _handler.handler_consume(0, 0, 4, _AT_THE_END, 0);
    assertEq(_handler.ghost_spendsConsumed(), 1, 'spend: consumed through the stop');
    assertEq(uint8(_manager.stateOf(_alice, _action).attempt.state), uint8(IPolicyManager.AttemptState.Consumed));

    _assertNoGhostRaised();
  }

  /*///////////////////////////////////////////////////////////////
                                HELPERS
  ///////////////////////////////////////////////////////////////*/

  /// @notice Commits, for the picked entry, the first rule built from seeds `_firstSeed` upward that
  ///         names no hostile method, and returns the nonce it holds.
  function _commitHonestRule(uint256 _callerSeed, uint256 _actionSeed, uint256 _firstSeed)
    private
    returns (uint64 _nonce)
  {
    uint256 _entry = _callerSeed * 2 + _actionSeed;
    for (uint256 _seed = _firstSeed; _seed < _firstSeed + 50; ++_seed) {
      _handler.handler_commitSetup(_callerSeed, _actionSeed, 0, 0, 0, bytes32(_seed), '', '');
      if (_handler.hostilePlaces(_entry) == 0) return _handler.ruleOf(_entry).nonce;
    }
    revert PolicyManagerExecutionPaths_NoHonestRule(_firstSeed);
  }

  /// @notice The index of `_method` in the handler's pool of honest methods.
  function _poolIndexOf(address _method) private view returns (uint256 _index) {
    address[] memory _pool = _handler.honestMethods();
    for (; _index < _pool.length; ++_index) {
      if (_pool[_index] == _method) return _index;
    }
    revert PolicyManagerExecutionPaths_NotInPool(_method);
  }

  /// @notice Asserts that no handler raised a ghost flag.
  function _assertNoGhostRaised() private view {
    assertFalse(_handler.ghost_foreignEntryChanged(), 'foreign entry changed');
    assertFalse(_handler.ghost_acceptedCallWrong(), 'accepted call wrong');
    assertFalse(_handler.ghost_unexplainedRevert(), 'unexplained revert');
    assertFalse(_handler.ghost_wrongEvents(), 'wrong events');
    assertFalse(_handler.ghost_ownerCancelRefused(), 'owner cancel refused');
    assertFalse(_handler.ghost_reachedOtherContract(), 'reached other contract');
    assertFalse(_handler.ghost_counterMovedWrongly(), 'counter moved wrongly');
    assertFalse(_handler.ghost_stateMovedWithoutACall(), 'state moved without a call');
    assertFalse(_handler.ghost_incompleteSetAccepted(), 'incomplete set accepted');
    assertFalse(_handler.ghost_unnamedMethodCounted(), 'unnamed method counted');
    assertFalse(_handler.ghost_swappedCredentialAccepted(), 'swapped credential accepted');
    assertFalse(_handler.ghost_uncommittedModuleReached(), 'uncommitted module reached');
    assertFalse(_handler.ghost_honestRequestRefused(), 'honest request refused');
    assertFalse(_handler.ghost_stopIgnored(), 'stop ignored');
    assertFalse(_handler.ghost_replayAccepted(), 'replay accepted');
    assertFalse(_handler.ghost_retiredProofAccepted(), 'retired proof accepted');
    assertFalse(_handler.ghost_expiredAccepted(), 'expired accepted');
    assertFalse(_handler.ghost_windowNotCheckedFirst(), 'window not checked first');
    assertFalse(_handler.ghost_nonStaticMethodCall(), 'non-static method call');
    assertFalse(_handler.ghost_methodWroteState(), 'method wrote state');
    assertFalse(_handler.ghost_methodHandedForeignInput(), 'method handed foreign input');
    assertFalse(_handler.ghost_storageRevealsRule(), 'storage reveals rule');
    assertFalse(_handler.ghost_releaseWithoutRequirements(), 'release without requirements');
    assertFalse(_handler.ghost_spentBeforeWait(), 'spent before wait');
    assertFalse(_handler.ghost_honestSpendRefused(), 'honest spend refused');
    assertFalse(_handler.ghost_spendVetoIgnored(), 'spend veto ignored');
    assertFalse(_handler.ghost_spendRefusedWithoutAVeto(), 'spend refused without a veto');
    assertFalse(_handler.ghost_outsideCallBeforeLocalChecks(), 'outside call before local checks');
    assertFalse(_handler.ghost_pauseReadWrong(), 'pause read wrong');
    assertFalse(_handler.ghost_vetoCancelWrong(), 'veto cancel wrong');
    assertFalse(_handler.ghost_vetoCancelRefused(), 'veto cancel refused');
    assertFalse(_handler.ghost_waitingAttemptDisplaced(), 'waiting attempt displaced');
    assertFalse(_handler.ghost_finishedAttemptMoved(), 'finished attempt moved');
    assertFalse(_handler.ghost_phantomEvent(), 'phantom event');
  }
}
