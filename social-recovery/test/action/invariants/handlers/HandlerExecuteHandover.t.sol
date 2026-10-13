// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {IPolicyManager} from 'interfaces/IPolicyManager.sol';
import {IAmbireRecoveryAction} from 'contracts/actions/ambire/IAmbireRecoveryAction.sol';
import {ActionBaseHandler} from 'test/action/invariants/handlers/BaseHandler.t.sol';
import {ActionBatch} from 'test/utils/ActionBatch.sol';

/// @notice Anyone calls executeHandover on the account, with the committed payload or another one.
abstract contract ActionHandlerExecuteHandover is ActionBaseHandler {
  /// @notice Calls executeHandover from a sender `_senderSeed` picks. One call in six names a payload
  ///         other than the committed one, with the two keys swapped. When the call succeeds, checks
  ///         what a handover must leave. When it is refused while every condition for the approved
  ///         batch held, sets a flag.
  function handler_executeHandover(uint256 _senderSeed, uint256 _payloadSeed) external {
    address _sender = _senders[_senderSeed % _senders.length];
    bytes memory _payload = _committed.exists ? _committed.payload : ActionBatch.payload(_keys[0], _keys[1]);
    bool _committedPayload = _committed.exists;
    if (_payloadSeed % 6 == 0) {
      _payload = ActionBatch.payload(_committed.removedKey, _committed.newKey);
      _committedPayload = false;
    }
    IPolicyManager.Attempt memory _record = _attempt();
    address _to = _paidTo(_record.order, _sender);
    bool _shouldRun = _committedPayload && _approvedCanRun(_to);
    IAmbireRecoveryAction.Transaction[] memory _batch = _renderApproved(_record, _to);
    Snapshot memory _before = _snapshot();

    vm.prank(_sender);
    try action.executeHandover(account, _payload) {
      ++ghost_ranThroughExecuteHandover;
      if (!_committedPayload) ghost_otherBatchRan = true;
      _checkHandoverRan(_before, _to, _batch);
    } catch (bytes memory _ret) {
      _labelRefusal(_ret);
      if (_shouldRun) {
        ghost_approvedBatchRefused = true;
        ghost_lastUnexpectedRevert = _ret;
      }
    }
  }
}
