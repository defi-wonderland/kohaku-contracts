// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {IPolicyManager} from 'interfaces/IPolicyManager.sol';
import {PolicyManagerInvariantSetup} from 'test/policy-manager/invariants/Setup.t.sol';

/// @notice Properties of the manager that hold after any sequence of calls from any caller. The
///         handlers write and clear setups, open attempts, cancel them by proofs, by veto and as
///         the holder, spend them and replay old proofs. Between calls, time passes, methods are
///         stopped, new methods are deployed, and methods answer the pause read in every shape.
/// @dev An entry is the state the manager keeps for one account and one action. The rule is what a
///      setup commits: clauses, each a threshold over places, where each place names a method, its
///      config and a salt. An opening starts an attempt from a set of proofs that meets the rule, and a
///      spend releases an attempt once its wait is over. A method is stopped when it answers the
///      pause read, paused(), with exactly true. A veto is the cancel anyone can send while a
///      method the attempt used is stopped.
contract PolicyManagerInvariants is PolicyManagerInvariantSetup {
  /// @notice Logs how far the run reached into the spend and the veto. It counts spends consumed,
  ///         spends refused as vetoed, and attempts cancelled by a veto. The invariants below prove
  ///         something about those paths only when these counts are above zero.
  function afterInvariant() external {
    emit log_named_uint('spends consumed', _handler.ghost_spendsConsumed());
    emit log_named_uint('spends vetoed', _handler.ghost_spendsVetoed());
    emit log_named_uint('veto cancels', _handler.ghost_vetoCancels());
  }

  /*///////////////////////////////////////////////////////////////
                              INVARIANTS
  ///////////////////////////////////////////////////////////////*/

  /// @notice Only an account changes its own setup. A call changes no entry but its caller's entry
  ///         for the action it names. So no other address can take over an account's recovery.
  function invariant_onlyTheAccountChangesItsSetup() external view {
    assertFalse(_handler.ghost_foreignEntryChanged(), 'a call changed an entry that is not its caller own');
  }

  /// @notice A setup write is accepted exactly when it names the stored nonce plus one and a
  ///         commitment that is neither zero nor the hash of an empty body. It then moves the nonce
  ///         by exactly one, and every accepted call leaves its entry as its arguments say. A
  ///         refused call fails with the error the state before it explains, so a write prepared
  ///         against a nonce another write has since used never lands.
  function invariant_acceptedWritesNameTheNextNonce() external view {
    assertFalse(_handler.ghost_acceptedCallWrong(), 'an accepted call left a state its arguments forbid');
    assertFalse(_handler.ghost_unexplainedRevert(), 'a call reverted without the reason its state gives');
  }

  /// @notice Every accepted call emits exactly its own events, in order. A setup write emits one
  ///         event, and when an attempt was waiting it first emits AttemptCancelled, so a watcher
  ///         sees the attempt end before the setup changes. An opening emits one AttemptStarted,
  ///         and a cancel by proofs one AttemptCancelled.
  function invariant_oneEventPerWriteAndTheCancelFirst() external view {
    assertFalse(_handler.ghost_wrongEvents(), 'events');
  }

  /// @notice While an attempt is waiting, the account's cancelByOwner call always succeeds. It
  ///         calls no method and reads no pause, so whatever the methods answer, the account's
  ///         current key can always stop a recovery in progress. A clear over a waiting attempt reaches
  ///         no other contract either, and a commit reaches only its own action, asked by a static call
  ///         whether it serves the account, so no method can block those ways of ending an attempt.
  function invariant_currentKeyCancels() external view {
    assertFalse(_handler.ghost_ownerCancelRefused(), 'the holder was refused while an attempt waited');
    assertFalse(_handler.ghost_reachedOtherContract(), 'an account call reached another contract');
  }

  /// @notice Only an accepted opening moves the attempt counter, by exactly one, to the id its
  ///         request named. Setup writes, clears and every cancel leave the counter as it was. So
  ///         an attempt id is never handed out twice, and a proof signed for an old attempt never
  ///         matches a new one.
  function invariant_attemptCounterMovesOnlyOnAnOpening() external view {
    assertFalse(_handler.ghost_counterMovedWrongly(), 'the attempt counter moved outside an opening');
  }

  /// @notice An attempt opens only on a complete set of proofs, one that meets the threshold of
  ///         every clause of the rule, and a cancel by proofs needs the same. A set one proof short
  ///         is never accepted. Time passing, a stop or a new method changes no entry, so an
  ///         accepted attempt never goes back on its own.
  function invariant_attemptsOpenOnlyOnACompleteSet() external view {
    assertFalse(_handler.ghost_incompleteSetAccepted(), 'an incomplete set was accepted');
    assertFalse(_handler.ghost_stateMovedWithoutACall(), 'an entry changed with no manager call');
  }

  /// @notice A proof fills a place in the rule only when the rule names its method at that place. A
  ///         proof from any other method is never counted, and an accepted attempt records as used
  ///         only methods its rule names.
  function invariant_unnamedMethodsNeverCount() external view {
    assertFalse(_handler.ghost_unnamedMethodCounted(), 'a method the rule does not name counted');
  }

  /// @notice The method that judges a proof is the one the holder committed, reading the config the
  ///         holder committed. The manager never calls a method no rule names, even one that would
  ///         approve. It never counts a proof whose config or salt differs from the committed one.
  function invariant_theCommittedModuleIsTheOneThatRuns() external view {
    assertFalse(_handler.ghost_uncommittedModuleReached(), 'the manager called an uncommitted module');
    assertFalse(_handler.ghost_swappedCredentialAccepted(), 'a proof with another config counted');
  }

  /// @notice Any method works as soon as a rule names it, whoever deployed it. A request that meets
  ///         every committed check is accepted, including one naming methods deployed during the
  ///         run. A stopped method's proofs are refused unless the setup ignores stops, and a stop
  ///         blocks nothing else.
  function invariant_anyMethodWorksWithoutPermission() external view {
    assertFalse(_handler.ghost_honestRequestRefused(), 'a request every check allows was refused');
    assertFalse(_handler.ghost_stopIgnored(), 'a stopped method counted for a setup that honours stops');
  }

  /// @notice A proof counts only for the one request it was made for, which names one attempt,
  ///         account, action, place and outcome. A request sent again, or moved to the next attempt
  ///         id or to another entry, is refused. So is a proof sealed for another payload, and an
  ///         approval offered as a cancel.
  function invariant_aProofWorksForExactlyOneAttempt() external view {
    assertFalse(_handler.ghost_replayAccepted(), 'a proof counted outside the request it was made for');
  }

  /// @notice A proof made under one setup never counts after the account writes its setup again.
  ///         This holds even when the new setup commits the same rule, so an approval collected
  ///         earlier never comes back.
  function invariant_aSetupWriteRetiresEveryProof() external view {
    assertFalse(_handler.ghost_retiredProofAccepted(), 'a proof from a retired setup counted');
  }

  /// @notice A request or a cancellation past its validUntil opens nothing and cancels nothing.
  ///         When every check before the expiry holds, it fails on the expiry and on nothing else.
  function invariant_anExpiredRequestDoesNothing() external view {
    assertFalse(_handler.ghost_expiredAccepted(), 'an expired request was accepted');
    assertFalse(_handler.ghost_windowNotCheckedFirst(), 'an expired request failed on something else');
  }

  /// @notice The manager calls methods only through static calls, so no method writes any state
  ///         while it judges. Each method receives only its own config, the digest of its own place
  ///         and its own proof.
  function invariant_methodsRunIsolated() external view {
    assertFalse(_handler.ghost_nonStaticMethodCall(), 'a method was called other than statically');
    assertFalse(_handler.ghost_methodWroteState(), 'a method wrote state during a manager call');
    assertFalse(_handler.ghost_methodHandedForeignInput(), 'a method received input that is not its own');
  }

  /// @notice Storage never holds the rule itself. An opening writes no credential hash, no salt and
  ///         no body hash, and the setup keeps only its commitment. The attempt keeps what the
  ///         opening event already made public: the payload hash, the payment order, the used
  ///         methods and the pause choice.
  function invariant_storageHoldsOnlyTheCommitment() external view {
    assertFalse(_handler.ghost_storageRevealsRule(), 'storage holds part of the rule');
  }

  /// @notice An attempt is spent only when everything the holder committed to still holds. A
  ///         complete set of proofs opened it under the setup the account still has, the spend
  ///         names its id and payload, and its wait is over. No method it used may be stopped,
  ///         unless the holder chose to ignore stops.
  function invariant_aReleaseMeetsEveryRequirementOfTheCommittedSetup() external view {
    assertFalse(_handler.ghost_releaseWithoutRequirements(), 'a spend released an attempt its setup does not allow');
    assertFalse(_handler.ghost_spentBeforeWait(), 'a spend came before the wait');
    assertFalse(_handler.ghost_spendVetoIgnored(), 'a spend went through a veto');
    assertFalse(_handler.ghost_incompleteSetAccepted(), 'an incomplete set was accepted');
  }

  /// @notice No attempt is spent before its wait is over. The end of the wait is fixed when the
  ///         attempt is accepted, as that moment plus the rule's wait, and nothing changes it
  ///         afterwards.
  function invariant_noSpendBeforeTheWaitHasPassed() external view {
    assertFalse(_handler.ghost_spentBeforeWait(), 'a spend came before the wait');
    address[] memory _callers = _handler.callers();
    address[] memory _actions = _handler.actions();
    for (uint256 _i; _i < _callers.length; ++_i) {
      for (uint256 _j; _j < _actions.length; ++_j) {
        (bool _known, uint64 _attemptId,, uint256 _acceptedAt, uint48 _wait,,) =
          _handler.ghost_acceptedOpening(_i * _actions.length + _j);
        IPolicyManager.Attempt memory _record = _manager.stateOf(_callers[_i], _actions[_j]).attempt;
        if (!_known || _record.attemptId != _attemptId) continue;
        assertEq(_record.consumableAfter, _acceptedAt + _wait, 'the end of a wait moved');
      }
    }
  }

  /// @notice Without the account's key, an attempt ends only in two ways: a proof set that
  ///         satisfies the rule and cancels that exact attempt, or the veto of a stopped method the
  ///         attempt used. A veto reads no proof and never touches an attempt whose setup ignores
  ///         stops. A cancel that every condition allows is never refused, so a hostile recovery
  ///         can always be stopped.
  function invariant_anAttemptEndsWithoutTheKeyOnlyByTheRuleOrAStop() external view {
    assertFalse(_handler.ghost_incompleteSetAccepted(), 'a cancel by a set weaker than the rule');
    assertFalse(_handler.ghost_replayAccepted(), 'an approval or a cancel for another attempt counted');
    assertFalse(_handler.ghost_vetoCancelWrong(), 'a veto cancelled an attempt it may not');
    assertFalse(_handler.ghost_vetoCancelRefused(), 'a veto every condition allows was refused');
    assertFalse(_handler.ghost_honestRequestRefused(), 'a cancel by proofs every check allows was refused');
    assertFalse(_handler.ghost_ownerCancelRefused(), 'the holder was refused while an attempt waited');
    assertFalse(_handler.ghost_pauseReadWrong(), 'a veto read a proof or a method the attempt did not use');
  }

  /// @notice At most one attempt waits per account and action, so no second recovery races the
  ///         first. A new attempt never replaces one that still waits, and attempt ids never go
  ///         back. A cancelled or spent attempt never changes state again, so an ended recovery
  ///         never comes back.
  function invariant_oneAttemptAtATimeAndEndedAttemptsStayEnded() external view {
    assertFalse(_handler.ghost_waitingAttemptDisplaced(), 'a waiting attempt was replaced');
    assertFalse(_handler.ghost_finishedAttemptMoved(), 'an ended attempt moved');
  }

  /// @notice A stop can only refuse, never let a recovery through. A spend is refused as vetoed
  ///         exactly when the setup honours stops and a used method answers the pause read with
  ///         exactly true, and the refusal names the first such method. A stopped method's proofs
  ///         never count where the setup honours stops, and a stop moving changes no entry.
  function invariant_aStopOnlyRefuses() external view {
    assertFalse(_handler.ghost_stopIgnored(), 'a stopped method counted');
    assertFalse(_handler.ghost_spendVetoIgnored(), 'a spend went through a veto');
    assertFalse(_handler.ghost_spendRefusedWithoutAVeto(), 'a spend was vetoed without an exact true');
    assertFalse(_handler.ghost_honestSpendRefused(), 'a spend every requirement allows was refused');
    assertFalse(_handler.ghost_stateMovedWithoutACall(), 'an entry changed with no manager call');
  }

  /// @notice A spend checks its own storage before it calls anything. It checks the attempt's
  ///         state, id, setup nonce, wait and payload, and a spend refused on one of those checks
  ///         made no outside call. The only outside calls a spend or a veto makes are static pause
  ///         reads of the methods the attempt used.
  function invariant_theSpendChecksItsOwnStorageFirst() external view {
    assertFalse(_handler.ghost_outsideCallBeforeLocalChecks(), 'a local refusal came after an outside call');
    assertFalse(_handler.ghost_pauseReadWrong(), 'a spend or a veto made a call other than a pause read');
    assertFalse(_handler.ghost_nonStaticMethodCall(), 'a method was called other than statically');
  }

  /// @notice The manager's events alone rebuild its whole state. Applying each setup write and
  ///         attempt change from the event that names it gives what stateOf returns for every
  ///         entry, and no event claims a change the rebuilt state does not allow. So a watcher
  ///         reading the events knows everything the manager holds.
  function invariant_theEventStreamRebuildsTheState() external view {
    assertFalse(_handler.ghost_phantomEvent(), 'an event claimed a transition that did not occur');
    assertFalse(_handler.ghost_wrongEvents(), 'a call emitted other events than its own');
    address[] memory _callers = _handler.callers();
    address[] memory _actions = _handler.actions();
    for (uint256 _i; _i < _callers.length; ++_i) {
      for (uint256 _j; _j < _actions.length; ++_j) {
        assertEq(
          keccak256(abi.encode(_manager.stateOf(_callers[_i], _actions[_j]))),
          keccak256(_handler.ghost_rebuiltEntry(_i * _actions.length + _j)),
          'the state rebuilt from events differs from storage'
        );
      }
    }
  }
}
