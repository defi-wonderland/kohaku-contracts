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
  ///         While that caller's attempt waits the call must succeed, reach no other contract and
  ///         leave the attempt counter where it was.
  function handler_cancelByOwner(uint256 _callerSeed, uint256 _actionSeed) external {
    (address _caller, address _pairAction, uint256 _entry) = _pick(_callerSeed, _actionSeed);
    IPolicyManager.ActionState memory _own = manager.stateOf(_caller, _pairAction);
    bool _waiting = _own.attempt.state == IPolicyManager.AttemptState.Waiting;

    vm.recordLogs();
    vm.startStateDiffRecording();
    vm.prank(_caller);
    try manager.cancelByOwner(_pairAction) {
      _checkNoOtherContract(vm.stopAndReturnStateDiff());
      Vm.Log[] memory _logs = _observe();
      IPolicyManager.ActionState memory _after = _checkEntries(_entry);
      // The cancel ends a waiting attempt, keeps the rest of its record and leaves the setup.
      IPolicyManager.Attempt memory _cancelled = _own.attempt;
      _cancelled.state = IPolicyManager.AttemptState.Cancelled;
      if (
        !_waiting || keccak256(abi.encode(_after.attempt)) != keccak256(abi.encode(_cancelled))
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
      if (_waiting) {
        ghost_ownerCancelRefused = true;
        return;
      }
      if (!_eq(
          _reason, abi.encodeWithSelector(IPolicyManager.PolicyManager_NoActiveAttempt.selector, _caller, _pairAction)
        )) {
        ghost_unexplainedRevert = true;
      }
    }
  }
}
