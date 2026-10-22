// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {Vm} from 'forge-std/Vm.sol';
import {IPolicyManager} from 'interfaces/IPolicyManager.sol';
import {PolicyManagerMockDigestMethod} from 'test/mocks/PolicyManagerMockDigestMethod.sol';
import {PolicyManagerBaseHandler} from 'test/policy-manager/invariants/handlers/BaseHandler.t.sol';

/// @notice The handler for cancelByVeto, sent by anyone, steered to an entry with an opening the
///         handler saw accepted, one that waits when there is one. It names a method the handler saw
///         that attempt's accepted set use, often stopping it first and lifting that stop again after
///         the call, or, now and then, a wrong id or a method the attempt never used.
abstract contract PolicyManagerHandlerCancelByVeto is PolicyManagerBaseHandler {
  /// @notice One cancel by veto the handler builds and sends, with what it knows about it. `before`
  ///         is the entry as stateOf returned it just before the call.
  // solhint-disable-next-line gas-struct-packing
  struct Veto {
    uint256 entry;
    uint256 mode;
    address caller;
    address account;
    address action;
    uint64 attemptId;
    address method;
    bool honest;
    address stopped;
    uint8 priorAnswer;
    IPolicyManager.ActionState before;
  }

  /// @notice A veto that first makes the named used method answer the pause read with exactly true.
  uint256 internal constant _VETO_STOP_FIRST = 1;
  /// @notice A veto naming the accepted attempt's id plus one.
  uint256 internal constant _VETO_WRONG_ID = 2;
  /// @notice A veto naming the always-stopped method, which no accepted set ever uses.
  uint256 internal constant _VETO_UNUSED_METHOD = 3;

  /*///////////////////////////////////////////////////////////////
                                HANDLER
  ///////////////////////////////////////////////////////////////*/

  /// @notice cancelByVeto for the entry `_accountSeed` and `_actionSeed` pick, sent by a caller
  ///         `_callerSeed` picks, whose bits 8 to 10 also pick whether to open an attempt first when none
  ///         the handler saw accepted still waits. `_modeSeed` picks a plain veto, a veto that stops its method first
  ///         (three times in six), or one corruption. `_methodSeed` picks which used method it names.
  function handler_cancelByVeto(
    uint256 _accountSeed,
    uint256 _actionSeed,
    uint256 _modeSeed,
    uint256 _methodSeed,
    uint256 _callerSeed
  ) external {
    _openOneIfNoneWaits(_callerSeed >> 8);
    Veto memory _veto = _buildVeto(_accountSeed, _actionSeed, _modeSeed, _methodSeed);
    (_veto.caller,,) = _pick(_callerSeed, 0);
    _sendVeto(_veto);
    if (_veto.stopped != address(0)) {
      PolicyManagerMockDigestMethod(_veto.stopped).setPauseAnswer(_veto.priorAnswer);
      _checkNothingChanged();
    }
  }

  /*///////////////////////////////////////////////////////////////
                                 BUILD
  ///////////////////////////////////////////////////////////////*/

  /// @notice Builds the veto from the handler's own record of the entry's accepted opening, and stops
  ///         the named method first in the mode that asks for it.
  function _buildVeto(uint256 _accountSeed, uint256 _actionSeed, uint256 _modeSeed, uint256 _methodSeed)
    private
    returns (Veto memory _veto)
  {
    (,, uint256 _picked) = _pick(_accountSeed, _actionSeed);
    (_veto.account, _veto.action, _veto.entry) = _steerToOpening(_picked);
    AcceptedOpening memory _opening = ghost_acceptedOpening[_veto.entry];
    address[] memory _used = ghost_acceptedUsedMethods[_veto.entry];
    _veto.mode = bound(_modeSeed, 0, 5);
    if (_veto.mode > _VETO_UNUSED_METHOD) _veto.mode = _VETO_STOP_FIRST;
    _veto.attemptId = _opening.attemptId;
    if (_veto.mode == _VETO_WRONG_ID) ++_veto.attemptId;
    _veto.method = _used.length > 0 ? _used[bound(_methodSeed, 0, _used.length - 1)] : stoppedMethod;
    if (_veto.mode == _VETO_UNUSED_METHOD) _veto.method = stoppedMethod;
    if (_veto.mode == _VETO_STOP_FIRST && _used.length > 0) {
      PolicyManagerMockDigestMethod _method = PolicyManagerMockDigestMethod(_veto.method);
      _veto.stopped = _veto.method;
      _veto.priorAnswer = _method.pauseAnswer();
      _method.setPauseAnswer(_method.ANSWER_TRUE());
      _checkNothingChanged();
    }
    _veto.before = manager.stateOf(_veto.account, _veto.action);
    _veto.honest = _veto.mode < _VETO_STOP_FIRST + 1 && _opening.known && _used.length > 0
      && _veto.before.attempt.state == IPolicyManager.AttemptState.Waiting
      && _veto.before.attempt.attemptId == _opening.attemptId && _veto.before.setupNonce == _opening.setupNonce
      && !_opening.ignoresPause && _reportsStop(_veto.method);
  }

  /*///////////////////////////////////////////////////////////////
                              SEND AND CHECK
  ///////////////////////////////////////////////////////////////*/

  /// @notice Sends the veto and checks what it did, whether it was accepted or refused.
  function _sendVeto(Veto memory _veto) private {
    vm.recordLogs();
    vm.startStateDiffRecording();
    vm.prank(_veto.caller);
    try manager.cancelByVeto(_veto.account, _veto.action, _veto.attemptId, _veto.method) {
      Vm.AccountAccess[] memory _accesses = vm.stopAndReturnStateDiff();
      Vm.Log[] memory _logs = _observe();
      ++ghost_vetoCancels;
      _checkVetoed(_veto, _accesses, _logs);
    } catch (bytes memory _reason) {
      Vm.AccountAccess[] memory _accesses = vm.stopAndReturnStateDiff();
      vm.getRecordedLogs();
      if (_veto.honest) ghost_vetoCancelRefused = true;
      if (!_vetoRefusalExplained(_veto, _reason)) ghost_unexplainedRevert = true;
      _checkPauseReadsOnly(_accesses, _veto.before.attempt.usedMethods);
    }
  }

  /// @notice Checks an accepted veto. The attempt must be the opening the handler saw accepted, still
  ///         waiting under the current setup, named by its own id, from a setup that honours stops,
  ///         and the named method must be one its set used and must answer exactly true. The record
  ///         must turn Cancelled and keep every other field, the setup and counter must stay, one
  ///         AttemptCancelled must name the caller, the method and no places, and no proof may be
  ///         read.
  function _checkVetoed(Veto memory _veto, Vm.AccountAccess[] memory _accesses, Vm.Log[] memory _logs) private {
    AcceptedOpening memory _opening = ghost_acceptedOpening[_veto.entry];
    address[] memory _used = ghost_acceptedUsedMethods[_veto.entry];
    IPolicyManager.Attempt memory _prior = _veto.before.attempt;
    if (_prior.state != IPolicyManager.AttemptState.Waiting) ghost_finishedAttemptMoved = true;
    if (
      !_opening.known || _prior.attemptId != _opening.attemptId || _veto.attemptId != _opening.attemptId
        || _veto.before.setupNonce != _opening.setupNonce || _opening.ignoresPause || !_contains(_used, _veto.method)
        || !_reportsStop(_veto.method)
    ) ghost_vetoCancelWrong = true;

    IPolicyManager.ActionState memory _after = _checkEntries(_veto.entry);
    IPolicyManager.Attempt memory _expected = _prior;
    _expected.state = IPolicyManager.AttemptState.Cancelled;
    if (_hash(_after.attempt) != _hash(_expected)) ghost_acceptedCallWrong = true;
    if (
      _after.setupCommitment != _veto.before.setupCommitment || _after.setupNonce != _veto.before.setupNonce
        || _after.setupCommittedAtBlock != _veto.before.setupCommittedAtBlock
    ) ghost_acceptedCallWrong = true;
    _checkCounterKept(_veto.before, _after);
    bytes memory _data = abi.encode(_veto.attemptId, _veto.caller, _veto.method, _prior.setupNonce, new uint256[](0));
    if (
      _logs.length != 1
        || !_isLog(_logs[0], IPolicyManager.AttemptCancelled.selector, _veto.account, _veto.action, _data)
    ) ghost_wrongEvents = true;
    _checkPauseReadsOnly(_accesses, _used);
  }

  /// @notice Whether `_reason` is one of the veto's six refusals, carrying the values the state before
  ///         the call gives, with its condition true in that state.
  function _vetoRefusalExplained(Veto memory _veto, bytes memory _reason) private view returns (bool _explained) {
    IPolicyManager.Attempt memory _prior = _veto.before.attempt;
    if (_eq(
        _reason,
        abi.encodeWithSelector(IPolicyManager.PolicyManager_NoActiveAttempt.selector, _veto.account, _veto.action)
      )) return _prior.state != IPolicyManager.AttemptState.Waiting;
    if (_eq(
        _reason,
        abi.encodeWithSelector(IPolicyManager.PolicyManager_WrongAttemptId.selector, _veto.attemptId, _prior.attemptId)
      )) return _veto.attemptId != _prior.attemptId;
    if (_eq(
        _reason,
        abi.encodeWithSelector(
          IPolicyManager.PolicyManager_StaleAttempt.selector, _prior.setupNonce, _veto.before.setupNonce
        )
      )) return _prior.setupNonce != _veto.before.setupNonce;
    if (_eq(
        _reason, abi.encodeWithSelector(IPolicyManager.PolicyManager_AttemptIgnoresPause.selector, _veto.attemptId)
      )) return _prior.ignoresPause;
    if (_eq(
        _reason,
        abi.encodeWithSelector(IPolicyManager.PolicyManager_MethodNotUsed.selector, _veto.attemptId, _veto.method)
      )) return !_contains(_prior.usedMethods, _veto.method);
    if (_eq(_reason, abi.encodeWithSelector(IPolicyManager.PolicyManager_MethodNotStopped.selector, _veto.method))) {
      return !_reportsStop(_veto.method);
    }
  }
}
