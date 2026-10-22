// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {IAmbireAccount} from 'contracts/actions/ambire/IAmbireAccount.sol';
import {ActionBaseHandler} from 'test/action/invariants/handlers/BaseHandler.t.sol';
import {ActionBatch} from 'test/utils/ActionBatch.sol';

/// @notice Anyone sends the account the last batch that ran, a second time.
abstract contract ActionHandlerSendAgain is ActionBaseHandler {
  /// @notice Sends the last batch that ran straight to the account's execute, from a sender
  ///         `_senderSeed` picks. It must never run a second time.
  function handler_sendAgain(uint256 _senderSeed) external {
    if (_lastRun.length == 0) return;
    ++ghost_batchesSentAgain;
    Snapshot memory _before = _snapshot();
    vm.prank(_senders[_senderSeed % _senders.length]);
    try IAmbireAccount(account).execute(_lastRun, ActionBatch.kitSignature(address(action))) {
      ghost_batchRanTwice = true;
    } catch (bytes memory _ret) {
      _labelRefusal(_ret);
    }
    _checkNothingSpent(_before);
  }
}
