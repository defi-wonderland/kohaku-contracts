// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {IPolicyManager} from 'interfaces/IPolicyManager.sol';

/// @notice Every ghost variable of the policy manager's invariant suite. Most are flags a handler
///         raises when a call breaks a property, and the invariants read. The rest are what the
///         handlers recorded themselves: each opening they built and saw accepted, the last attempt
///         they saw per entry, and each entry's state rebuilt from the manager's events alone.
/// @dev One flag per property keeps each invariant's failure message exact, so the flags outnumber
///      the linter's cap on state variables.
// solhint-disable-next-line max-states-count
abstract contract PolicyManagerGhostStorage {
  /// @notice An opening the handler built to be accepted and saw accepted, recorded as the handler
  ///         built it. It holds the id and nonce it named, when it was accepted, the wait and pause
  ///         choice of its rule, and the hash of the payload it approved. `known` is false until the
  ///         entry's first such opening.
  // solhint-disable-next-line gas-struct-packing
  struct AcceptedOpening {
    bool known;
    uint64 attemptId;
    uint64 setupNonce;
    uint256 acceptedAt;
    uint48 wait;
    bool ignoresPause;
    bytes32 payloadHash;
  }

  /// @notice The id and state of an entry's attempt record as the handlers last saw it.
  struct SeenAttempt {
    uint64 attemptId;
    IPolicyManager.AttemptState state;
  }

  /*///////////////////////////////////////////////////////////////
                            GHOST VARIABLES
  ///////////////////////////////////////////////////////////////*/

  /// @notice A call changed an entry of an account other than its caller, or of another action.
  bool public ghost_foreignEntryChanged;
  /// @notice An accepted call left its own entry in a state its arguments do not allow.
  bool public ghost_acceptedCallWrong;
  /// @notice A call reverted with an error the state before it does not explain.
  bool public ghost_unexplainedRevert;
  /// @notice An accepted call emitted other events than its own, or in another order.
  bool public ghost_wrongEvents;
  /// @notice The account's own cancel reverted while its attempt was waiting.
  bool public ghost_ownerCancelRefused;
  /// @notice One of the account's own calls, a commit, a clear or a cancel, reached a contract
  ///         other than the manager.
  bool public ghost_reachedOtherContract;
  /// @notice The attempt counter moved on a call other than an accepted opening, or an accepted
  ///         opening moved it by anything but one.
  bool public ghost_counterMovedWrongly;
  /// @notice Some entry changed while no manager call was made: time passed, a method's stop moved
  ///         or a method was deployed.
  bool public ghost_stateMovedWithoutACall;

  /// @notice An opening or a cancel by proofs was accepted with a proof set that does not meet
  ///         every clause's threshold.
  bool public ghost_incompleteSetAccepted;
  /// @notice An accepted opening or cancel by proofs counted a proof from a method the committed
  ///         rule does not name at that place, or recorded such a method as used.
  bool public ghost_unnamedMethodCounted;
  /// @notice An accepted opening or cancel by proofs counted a proof whose config or salt is not the
  ///         one committed at its place.
  bool public ghost_swappedCredentialAccepted;
  /// @notice The manager called a method no committed rule names.
  bool public ghost_uncommittedModuleReached;
  /// @notice A request that every committed check allows, from methods anybody deployed, was
  ///         refused.
  bool public ghost_honestRequestRefused;
  /// @notice A stopped method's proof counted for a setup that does not ignore stops.
  bool public ghost_stopIgnored;
  /// @notice A proof prepared for one attempt, place, outcome, account or action was accepted for
  ///         another, or a cancel was accepted with proofs that approved an opening.
  bool public ghost_replayAccepted;
  /// @notice A proof prepared under a setup nonce the account has since moved past was accepted.
  bool public ghost_retiredProofAccepted;
  /// @notice A request or cancellation past its validUntil was accepted.
  bool public ghost_expiredAccepted;
  /// @notice A request past its validUntil, whose earlier checks all held, was refused on something
  ///         other than its window.
  bool public ghost_windowNotCheckedFirst;
  /// @notice The manager called a method other than through a static call.
  bool public ghost_nonStaticMethodCall;
  /// @notice A method's storage changed during a manager call.
  bool public ghost_methodWroteState;
  /// @notice A method received a config, digest or proof that is not its own for this request.
  bool public ghost_methodHandedForeignInput;
  /// @notice An opening wrote a credential hash, a salt or the body hash of the rule into storage.
  bool public ghost_storageRevealsRule;
  /// @notice A spend was accepted for an attempt its setup does not allow. The attempt was not an
  ///         accepted opening under the entry's current setup, or the spend named another id or
  ///         another payload than that opening.
  bool public ghost_releaseWithoutRequirements;
  /// @notice A spend was accepted before the committed wait had passed since the opening was accepted.
  bool public ghost_spentBeforeWait;
  /// @notice A spend that every requirement allows, with no used method answering exactly true, was
  ///         refused.
  bool public ghost_honestSpendRefused;
  /// @notice A spend was accepted while a used method answered exactly true, for a setup that honours
  ///         stops.
  bool public ghost_spendVetoIgnored;
  /// @notice A spend was refused as vetoed when no veto applied. Its local checks failed, its setup
  ///         ignores stops, or the named method is not the first used method answering exactly true.
  bool public ghost_spendRefusedWithoutAVeto;
  /// @notice A spend refused on one of its own storage checks had already called a method.
  bool public ghost_outsideCallBeforeLocalChecks;
  /// @notice A spend or a cancel by veto made a call other than a pause read of a method the attempt
  ///         used. The flag also rises when it read a pause its setup opted out of.
  bool public ghost_pauseReadWrong;
  /// @notice A cancel by veto was accepted that should have been refused. Its attempt, its setup's
  ///         pause choice, its used methods or the named method's answer did not allow it.
  bool public ghost_vetoCancelWrong;
  /// @notice A cancel by veto that every condition allows was refused.
  bool public ghost_vetoCancelRefused;
  /// @notice An attempt record changed to another id while the previous attempt still waited.
  bool public ghost_waitingAttemptDisplaced;
  /// @notice A cancelled or consumed attempt changed state, or an attempt id went backwards.
  bool public ghost_finishedAttemptMoved;
  /// @notice The manager emitted an event the rebuild cannot apply. It names an entry the suite does
  ///         not use, a transition the rebuilt state does not allow, or a topic the rebuild does not
  ///         know.
  bool public ghost_phantomEvent;

  /// @notice How many replays, of openings or of cancellations, the manager refused. The execution
  ///         paths read it to prove a replay reached the manager.
  uint256 public ghost_replaysRefused;
  /// @notice How many spends the manager accepted.
  uint256 public ghost_spendsConsumed;
  /// @notice How many spends the manager refused as vetoed.
  uint256 public ghost_spendsVetoed;
  /// @notice How many spends the manager refused on one of its own storage checks.
  uint256 public ghost_spendsRefused;
  /// @notice How many cancels by veto the manager accepted.
  uint256 public ghost_vetoCancels;

  /// @notice The last opening per entry, in callers-then-actions order, that the handler built to be
  ///         accepted and saw accepted.
  mapping(uint256 _entry => AcceptedOpening _opening) public ghost_acceptedOpening;
  /// @notice The distinct methods of that opening's proofs, in the order the proofs named them.
  mapping(uint256 _entry => address[] _methods) public ghost_acceptedUsedMethods;
  /// @notice Each entry's attempt as the handlers last saw it.
  mapping(uint256 _entry => SeenAttempt _attempt) public ghost_seenAttempt;
  /// @notice Each entry's state rebuilt from the manager's events alone, abi-encoded as the
  ///         ActionState stateOf returns.
  mapping(uint256 _entry => bytes _state) public ghost_rebuiltEntry;
}
