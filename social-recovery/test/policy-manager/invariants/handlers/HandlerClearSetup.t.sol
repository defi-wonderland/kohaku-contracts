// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {Vm} from 'forge-std/Vm.sol';
import {IPolicyManager} from 'interfaces/IPolicyManager.sol';
import {PolicyManagerBaseHandler} from 'test/policy-manager/invariants/handlers/BaseHandler.t.sol';

/// @notice The handler for clearSetup, sent from several callers over several actions.
abstract contract PolicyManagerHandlerClearSetup is PolicyManagerBaseHandler {
  /*///////////////////////////////////////////////////////////////
                                HANDLER
  ///////////////////////////////////////////////////////////////*/

  /// @notice clearSetup from a caller picked by `_callerSeed`, for an action picked by `_actionSeed`.
  ///         An accepted clear must leave the attempt counter where it was.
  function handler_clearSetup(uint256 _callerSeed, uint256 _actionSeed) external {
    (address _caller, address _pairAction, uint256 _entry) = _pick(_callerSeed, _actionSeed);
    IPolicyManager.ActionState memory _own = manager.stateOf(_caller, _pairAction);

    vm.recordLogs();
    vm.startStateDiffRecording();
    vm.prank(_caller);
    try manager.clearSetup(_pairAction) {
      _checkNoOtherContract(vm.stopAndReturnStateDiff());
      Vm.Log[] memory _logs = _observe();
      IPolicyManager.ActionState memory _after = _checkEntries(_entry);
      // A clear removes an existing setup and writes the next nonce and this block.
      if (
        _own.setupCommitment == bytes32(0) || _after.setupCommitment != bytes32(0)
          || _after.setupNonce != _own.setupNonce + 1 || _after.setupCommittedAtBlock != block.number
      ) ghost_acceptedCallWrong = true;
      _checkCounterKept(_own, _after);
      _rules[_entry].live = false;
      _checkWriteEvents(
        _logs,
        _caller,
        _pairAction,
        _own.attempt,
        _after.attempt,
        IPolicyManager.SetupCleared.selector,
        abi.encode(_after.setupNonce)
      );
    } catch (bytes memory _reason) {
      vm.stopAndReturnStateDiff();
      vm.getRecordedLogs();
      // The only refusal a clear has is that no setup exists.
      bool _explained = _own.setupCommitment == bytes32(0)
        && _eq(_reason, abi.encodeWithSelector(IPolicyManager.PolicyManager_NoSetup.selector, _caller, _pairAction));
      if (!_explained) ghost_unexplainedRevert = true;
    }
  }
}
