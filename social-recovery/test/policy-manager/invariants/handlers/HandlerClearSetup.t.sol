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
  ///         `_nameSeed` picks the setup nonce the caller names: the current one in three draws of
  ///         four, any other nonce in the fourth. An accepted clear must have named the current nonce
  ///         and must leave the attempt counter where it was, so a replayed clear never removes a
  ///         later setup.
  function handler_clearSetup(uint256 _callerSeed, uint256 _actionSeed, uint256 _nameSeed) external {
    (address _caller, address _pairAction, uint256 _entry) = _pick(_callerSeed, _actionSeed);
    IPolicyManager.ActionState memory _own = manager.stateOf(_caller, _pairAction);
    uint64 _namedNonce = _own.setupNonce;
    if (_nameSeed % 4 == 3) {
      unchecked {
        _namedNonce += uint64(bound(_nameSeed / 4, 1, type(uint64).max));
      }
    }

    vm.recordLogs();
    vm.startStateDiffRecording();
    vm.prank(_caller);
    try manager.clearSetup(_pairAction, _namedNonce) {
      _checkNoOtherContract(vm.stopAndReturnStateDiff());
      Vm.Log[] memory _logs = _observe();
      IPolicyManager.ActionState memory _after = _checkEntries(_entry);
      // A clear removes an existing setup and writes the next nonce and this block.
      if (
        _own.setupCommitment == bytes32(0) || _namedNonce != _own.setupNonce || _after.setupCommitment != bytes32(0)
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
      // A clear is refused when no setup exists, and otherwise only when it names another nonce.
      bytes memory _expected = _own.setupCommitment == bytes32(0)
        ? abi.encodeWithSelector(IPolicyManager.PolicyManager_NoSetup.selector, _caller, _pairAction)
        : abi.encodeWithSelector(IPolicyManager.PolicyManager_WrongSetupNonce.selector, _namedNonce, _own.setupNonce);
      bool _explained =
        (_own.setupCommitment == bytes32(0) || _namedNonce != _own.setupNonce) && _eq(_reason, _expected);
      if (!_explained) ghost_unexplainedRevert = true;
    }
  }
}
