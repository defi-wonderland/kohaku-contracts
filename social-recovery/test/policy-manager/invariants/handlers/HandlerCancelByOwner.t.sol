// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {Vm} from 'forge-std/Vm.sol';
import {IPolicyManager} from 'interfaces/IPolicyManager.sol';
import {PolicyManagerBaseHandler} from 'test/policy-manager/invariants/handlers/BaseHandler.t.sol';

/// @notice The handler for cancelByOwner, sent from several callers over several actions, with
///         attempts waiting or ended.
abstract contract PolicyManagerHandlerCancelByOwner is PolicyManagerBaseHandler {
  /*///////////////////////////////////////////////////////////////
                                HANDLER
  ///////////////////////////////////////////////////////////////*/

  /// @notice cancelByOwner from a caller picked by `_callerSeed`, for an action picked by `_actionSeed`.
  ///         `_nameSeed` picks the attempt id the caller names: the last attempt's id in three draws of
  ///         four, any other id in the fourth. While that caller's attempt waits and the call names its
  ///         id, the call must succeed, reach no other contract and leave the attempt counter where it
  ///         was. Naming another id must be refused, so a replayed cancel never ends a later attempt.
  function handler_cancelByOwner(uint256 _callerSeed, uint256 _actionSeed, uint256 _nameSeed) external {
    (address _caller, address _pairAction, uint256 _entry) = _pick(_callerSeed, _actionSeed);
    IPolicyManager.ActionState memory _own = manager.stateOf(_caller, _pairAction);
    bool _waiting = _own.attempt.state == IPolicyManager.AttemptState.Waiting;
    uint64 _namedId = _own.attempt.attemptId;
    if (_nameSeed % 4 == 3) {
      unchecked {
        _namedId += uint64(bound(_nameSeed / 4, 1, type(uint64).max));
      }
    }
    bool _namesLive = _namedId == _own.attempt.attemptId;

    vm.recordLogs();
    vm.startStateDiffRecording();
    vm.prank(_caller);
    try manager.cancelByOwner(_pairAction, _namedId) {
      _checkNoOtherContract(vm.stopAndReturnStateDiff());
      Vm.Log[] memory _logs = _observe();
      IPolicyManager.ActionState memory _after = _checkEntries(_entry);
      // The cancel ends a waiting attempt, keeps the rest of its record and leaves the setup.
      IPolicyManager.Attempt memory _cancelled = _own.attempt;
      _cancelled.state = IPolicyManager.AttemptState.Cancelled;
      if (
        !_waiting || !_namesLive || keccak256(abi.encode(_after.attempt)) != keccak256(abi.encode(_cancelled))
          || _after.setupCommitment != _own.setupCommitment || _after.setupNonce != _own.setupNonce
          || _after.setupCommittedAtBlock != _own.setupCommittedAtBlock
      ) ghost_acceptedCallWrong = true;
      _checkCounterKept(_own, _after);
      if (_logs.length != 1 || !_isCancelLog(_logs[0], _caller, _pairAction, _own.attempt, _caller)) {
        ghost_wrongEvents = true;
      }
    } catch (bytes memory _reason) {
      vm.stopAndReturnStateDiff();
      vm.getRecordedLogs();
      if (_waiting && _namesLive) {
        ghost_ownerCancelRefused = true;
        return;
      }
      // Nothing waiting is reported first, then a named id other than the waiting one.
      bytes memory _expected = _waiting
        ? abi.encodeWithSelector(IPolicyManager.PolicyManager_WrongAttemptId.selector, _namedId, _own.attempt.attemptId)
        : abi.encodeWithSelector(IPolicyManager.PolicyManager_NoActiveAttempt.selector, _caller, _pairAction);
      if (!_eq(_reason, _expected)) ghost_unexplainedRevert = true;
    }
  }
}
