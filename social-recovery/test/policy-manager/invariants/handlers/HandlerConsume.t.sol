// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {Vm} from 'forge-std/Vm.sol';
import {IPolicyManager} from 'interfaces/IPolicyManager.sol';
import {PolicyManagerMockDigestMethod} from 'test/mocks/PolicyManagerMockDigestMethod.sol';
import {PolicyManagerBaseHandler} from 'test/policy-manager/invariants/handlers/BaseHandler.t.sol';

/// @notice The handler for consume, the spend. It names the attempt and payload the handler saw
///         accepted for an entry, usually steered to an entry whose attempt waits, moves time to
///         around the end of that attempt's wait, and sends the spend as the account or, now and
///         then, with one corruption the manager must refuse.
abstract contract PolicyManagerHandlerConsume is PolicyManagerBaseHandler {
  /// @notice One spend the handler builds and sends, with what it knows about it. `entry` is the
  ///         caller's own entry, the one consume reads, and `before` is that entry as stateOf
  ///         returned it just before the call.
  // solhint-disable-next-line gas-struct-packing
  struct Spend {
    uint256 entry;
    uint256 mode;
    address caller;
    address action;
    uint64 attemptId;
    bytes32 payloadHash;
    bool honest;
    address stopped;
    uint8 priorAnswer;
    IPolicyManager.ActionState before;
  }

  /// @notice A spend naming the accepted attempt's id plus one.
  uint256 internal constant _SPEND_WRONG_ID = 1;
  /// @notice A spend naming the hash of another payload.
  uint256 internal constant _SPEND_WRONG_PAYLOAD = 2;
  /// @notice A spend sent by another caller than the account, naming the account's attempt.
  uint256 internal constant _SPEND_BY_ANOTHER_CALLER = 3;
  /// @notice A spend that first makes a method the attempt used answer the pause read with exactly
  ///         true.
  uint256 internal constant _SPEND_AFTER_A_STOP = 4;

  /*///////////////////////////////////////////////////////////////
                                HANDLER
  ///////////////////////////////////////////////////////////////*/

  /// @notice consume for the entry `_accountSeed` and `_actionSeed` pick, steered to an entry with an
  ///         opening the handler saw accepted, one that waits when there is one. `_modeSeed` picks a
  ///         valid spend twice in eight, a spend at or after the end of the wait once one of the
  ///         attempt's methods stopped three times in eight, that stop lifted again after the call,
  ///         and one corruption otherwise.
  ///         `_timeSeed` picks whether time moves first: not at all, to one second before the end of
  ///         the wait the handler recorded, to exactly its end (twice as often), or past it.
  ///         `_callerSeed` picks the other caller of the corruption that needs one, and its bits 8 to 10
  ///         whether to open an attempt first when none the handler saw accepted still waits.
  function handler_consume(
    uint256 _accountSeed,
    uint256 _actionSeed,
    uint256 _modeSeed,
    uint256 _timeSeed,
    uint256 _callerSeed
  ) external {
    _openOneIfNoneWaits(_callerSeed >> 8);
    Spend memory _spend = _buildSpend(_accountSeed, _actionSeed, _modeSeed, _timeSeed, _callerSeed);
    _sendSpend(_spend);
    if (_spend.stopped != address(0)) {
      PolicyManagerMockDigestMethod(_spend.stopped).setPauseAnswer(_spend.priorAnswer);
      _checkNothingChanged();
    }
  }

  /*///////////////////////////////////////////////////////////////
                                 BUILD
  ///////////////////////////////////////////////////////////////*/

  /// @notice Builds the spend from the handler's own record of the entry's accepted opening, moves
  ///         time as `_timeSeed` picks, and reads the caller's own entry.
  function _buildSpend(
    uint256 _accountSeed,
    uint256 _actionSeed,
    uint256 _modeSeed,
    uint256 _timeSeed,
    uint256 _callerSeed
  ) private returns (Spend memory _spend) {
    (,, uint256 _picked) = _pick(_accountSeed, _actionSeed);
    (, address _action, uint256 _named) = _steerToOpening(_picked);
    AcceptedOpening memory _opening = ghost_acceptedOpening[_named];
    _spend.mode = bound(_modeSeed, 0, 7);
    if (_spend.mode == 5 || _spend.mode == 6) _spend.mode = _SPEND_AFTER_A_STOP;
    if (_spend.mode > _SPEND_AFTER_A_STOP) _spend.mode = 0;
    address[] memory _used = ghost_acceptedUsedMethods[_named];
    if (_spend.mode == _SPEND_AFTER_A_STOP && _used.length > 0) {
      PolicyManagerMockDigestMethod _method =
        PolicyManagerMockDigestMethod(_used[bound(_modeSeed >> 8, 0, _used.length - 1)]);
      _spend.stopped = address(_method);
      _spend.priorAnswer = _method.pauseAnswer();
      _method.setPauseAnswer(_method.ANSWER_TRUE());
      _checkNothingChanged();
    }
    _spend.attemptId = _opening.attemptId;
    _spend.payloadHash = _opening.payloadHash;
    if (_spend.mode == _SPEND_WRONG_ID) ++_spend.attemptId;
    if (_spend.mode == _SPEND_WRONG_PAYLOAD) _spend.payloadHash = keccak256(abi.encode(_spend.payloadHash, 'another'));
    uint256 _callerIndex = _named / _actions.length;
    if (_spend.mode == _SPEND_BY_ANOTHER_CALLER) {
      _callerIndex = (_callerIndex + 1 + bound(_callerSeed, 0, _callers.length - 2)) % _callers.length;
    }
    _spend.caller = _callers[_callerIndex];
    _spend.action = _action;
    _spend.entry = _callerIndex * _actions.length + _named % _actions.length;
    _moveTime(_opening, _timeSeed, _spend.mode == _SPEND_AFTER_A_STOP);
    _spend.before = manager.stateOf(_spend.caller, _action);
    _spend.honest = (_spend.mode == 0 || _spend.mode == _SPEND_AFTER_A_STOP) && _spendable(_spend.entry, _spend.before);
  }

  /// @notice Moves time forward, never back, to around the end of the wait the handler recorded for
  ///         `_opening`, as `_timeSeed` picks, and at least to that end when `_reachTheEnd` is set.
  function _moveTime(AcceptedOpening memory _opening, uint256 _timeSeed, bool _reachTheEnd) private {
    if (!_opening.known) return;
    uint256 _end = _opening.acceptedAt + _opening.wait;
    uint256 _timeMode = bound(_timeSeed, 0, 4);
    if (_timeMode == 4 || (_reachTheEnd && _timeMode < 2)) _timeMode = 2;
    uint256 _target = _now();
    if (_timeMode == 1 && _end > 0) _target = _end - 1;
    if (_timeMode == 2) _target = _end;
    if (_timeMode == 3) _target = _end + bound(_timeSeed >> 32, 1, 3 days);
    if (_target > _now()) vm.warp(_target);
  }

  /// @notice Whether every requirement of the spend holds for entry `_entry`, judged against the
  ///         handler's own record: its attempt is the opening the handler saw accepted and it still
  ///         waits, the setup is the one that opening was judged under, the committed wait has passed
  ///         since acceptance, and no used method answers exactly true unless the setup ignores
  ///         stops.
  function _spendable(uint256 _entry, IPolicyManager.ActionState memory _before) private view returns (bool _ok) {
    AcceptedOpening memory _opening = ghost_acceptedOpening[_entry];
    _ok = _opening.known && _before.attempt.state == IPolicyManager.AttemptState.Waiting
      && _before.attempt.attemptId == _opening.attemptId && _before.setupNonce == _opening.setupNonce
      && _before.setupCommitment != bytes32(0) && _opening.acceptedAt + _opening.wait < _now() + 1
      && (_opening.ignoresPause || _firstStopped(ghost_acceptedUsedMethods[_entry]) == address(0));
  }

  /*///////////////////////////////////////////////////////////////
                              SEND AND CHECK
  ///////////////////////////////////////////////////////////////*/

  /// @notice Sends the spend and checks what it did, whether it was accepted or refused.
  function _sendSpend(Spend memory _spend) private {
    vm.recordLogs();
    vm.startStateDiffRecording();
    vm.prank(_spend.caller);
    try manager.consume(_spend.action, _spend.attemptId, _spend.payloadHash) {
      Vm.AccountAccess[] memory _accesses = vm.stopAndReturnStateDiff();
      Vm.Log[] memory _logs = _observe();
      ++ghost_spendsConsumed;
      _checkSpent(_spend, _accesses, _logs);
    } catch (bytes memory _reason) {
      Vm.AccountAccess[] memory _accesses = vm.stopAndReturnStateDiff();
      vm.getRecordedLogs();
      _checkSpendRefused(_spend, _reason, _accesses);
    }
  }

  /// @notice Checks an accepted spend. Its attempt must be the opening the handler saw accepted under
  ///         the current setup, named by its own id and payload, still waiting, with the committed
  ///         wait passed and no used method answering exactly true unless the setup ignores stops.
  ///         The record must turn Consumed and keep every other field, the setup and counter must
  ///         stay, one AttemptConsumed must be emitted, and every outside call must be a pause read of
  ///         a used method.
  function _checkSpent(Spend memory _spend, Vm.AccountAccess[] memory _accesses, Vm.Log[] memory _logs) private {
    AcceptedOpening memory _opening = ghost_acceptedOpening[_spend.entry];
    address[] memory _used = ghost_acceptedUsedMethods[_spend.entry];
    IPolicyManager.Attempt memory _prior = _spend.before.attempt;
    if (_prior.state != IPolicyManager.AttemptState.Waiting) ghost_finishedAttemptMoved = true;
    if (
      !_opening.known || _prior.attemptId != _opening.attemptId || _spend.attemptId != _opening.attemptId
        || _spend.payloadHash != _opening.payloadHash || _spend.before.setupNonce != _opening.setupNonce
        || _spend.before.setupCommitment == bytes32(0)
    ) ghost_releaseWithoutRequirements = true;
    if (_now() < _opening.acceptedAt + _opening.wait) ghost_spentBeforeWait = true;
    if (!_opening.ignoresPause && _firstStopped(_used) != address(0)) ghost_spendVetoIgnored = true;

    IPolicyManager.ActionState memory _after = _checkEntries(_spend.entry);
    IPolicyManager.Attempt memory _expected = _prior;
    _expected.state = IPolicyManager.AttemptState.Consumed;
    if (_hash(_after.attempt) != _hash(_expected)) ghost_acceptedCallWrong = true;
    if (
      _after.setupCommitment != _spend.before.setupCommitment || _after.setupNonce != _spend.before.setupNonce
        || _after.setupCommittedAtBlock != _spend.before.setupCommittedAtBlock
    ) ghost_acceptedCallWrong = true;
    _checkCounterKept(_spend.before, _after);
    if (
      _logs.length != 1
        || !_isLog(
          _logs[0], IPolicyManager.AttemptConsumed.selector, _spend.caller, _spend.action, abi.encode(_spend.attemptId)
        )
    ) ghost_wrongEvents = true;
    _checkPauseReadsOnly(_accesses, _opening.ignoresPause ? new address[](0) : _used);
  }

  /// @notice Checks a refused spend. A spend every requirement allows must not be refused. A veto
  ///         must come only after every local check held, from a setup that honours stops, naming the
  ///         first used method that answers exactly true. Any other refusal must be one of the local
  ///         errors the state before the call explains, reached before any outside call.
  function _checkSpendRefused(Spend memory _spend, bytes memory _reason, Vm.AccountAccess[] memory _accesses) private {
    if (_spend.honest) ghost_honestSpendRefused = true;
    IPolicyManager.Attempt memory _prior = _spend.before.attempt;
    // casting to 'bytes4' is safe because it reads the selector at the front of the revert data
    // forge-lint: disable-next-line(unsafe-typecast)
    if (_reason.length > 3 && bytes4(_reason) == IPolicyManager.PolicyManager_MethodVetoedSpend.selector) {
      ++ghost_spendsVetoed;
      address _first = _firstStopped(_prior.usedMethods);
      bool _localChecksHeld = _prior.state == IPolicyManager.AttemptState.Waiting
        && _prior.attemptId == _spend.attemptId && _prior.setupNonce == _spend.before.setupNonce
        && _prior.consumableAfter < _now() + 1 && _prior.payloadHash == _spend.payloadHash;
      bytes memory _veto = abi.encodeWithSelector(IPolicyManager.PolicyManager_MethodVetoedSpend.selector, _first);
      if (!_localChecksHeld || _prior.ignoresPause || _first == address(0) || !_eq(_reason, _veto)) {
        ghost_spendRefusedWithoutAVeto = true;
      }
      _checkPauseReadsOnly(_accesses, _prior.usedMethods);
      return;
    }
    ++ghost_spendsRefused;
    if (_outsideCalls(_accesses) != 0) ghost_outsideCallBeforeLocalChecks = true;
    if (!_localRefusalExplained(_spend, _reason)) ghost_unexplainedRevert = true;
  }

  /// @notice Whether `_reason` is one of the spend's local errors, carrying the values the state
  ///         before the call gives, with its condition true in that state.
  function _localRefusalExplained(Spend memory _spend, bytes memory _reason) private view returns (bool _explained) {
    IPolicyManager.Attempt memory _prior = _spend.before.attempt;
    if (_eq(
        _reason,
        abi.encodeWithSelector(IPolicyManager.PolicyManager_NoActiveAttempt.selector, _spend.caller, _spend.action)
      )) return _prior.state != IPolicyManager.AttemptState.Waiting;
    if (_eq(
        _reason,
        abi.encodeWithSelector(IPolicyManager.PolicyManager_WrongAttemptId.selector, _spend.attemptId, _prior.attemptId)
      )) return _spend.attemptId != _prior.attemptId;
    if (_eq(
        _reason,
        abi.encodeWithSelector(
          IPolicyManager.PolicyManager_StaleAttempt.selector, _prior.setupNonce, _spend.before.setupNonce
        )
      )) return _prior.setupNonce != _spend.before.setupNonce;
    if (_eq(
        _reason,
        abi.encodeWithSelector(
          IPolicyManager.PolicyManager_WaitNotOver.selector, uint48(block.timestamp), _prior.consumableAfter
        )
      )) return _now() < _prior.consumableAfter;
    if (_eq(
        _reason,
        abi.encodeWithSelector(
          IPolicyManager.PolicyManager_WrongPayload.selector, _spend.payloadHash, _prior.payloadHash
        )
      )) return _spend.payloadHash != _prior.payloadHash;
  }

  /// @notice The block's timestamp.
  function _now() private view returns (uint256 _timestamp) {
    _timestamp = block.timestamp;
  }
}
