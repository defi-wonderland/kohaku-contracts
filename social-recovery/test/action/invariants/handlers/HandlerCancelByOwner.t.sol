// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {IPolicyManager} from 'interfaces/IPolicyManager.sol';
import {ActionBaseHandler} from 'test/action/invariants/handlers/BaseHandler.t.sol';

/// @notice The account cancels its waiting attempt at the manager.
abstract contract ActionHandlerCancelByOwner is ActionBaseHandler {
  /// @notice Cancels the waiting attempt as the account, when one waits. It always cancels an attempt
  ///         that can never run, so the run moves on to a fresh one. Otherwise it cancels in one draw
  ///         of eight as `_seed` picks, so most attempts live long enough to be spent. A cancel never
  ///         spends the attempt.
  function handler_cancelByOwner(uint256 _seed) external {
    Snapshot memory _before = _snapshot();
    if (_before.state != IPolicyManager.AttemptState.Waiting) return;
    if (!_attemptIsStuck() && _seed % 8 != 0) return;
    vm.prank(account);
    manager.cancelByOwner(address(action), _before.attemptId);
    _checkNothingSpent(_before);
  }
}
