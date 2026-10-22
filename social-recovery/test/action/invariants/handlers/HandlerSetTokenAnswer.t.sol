// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {ActionBaseHandler} from 'test/action/invariants/handlers/BaseHandler.t.sol';

/// @notice The order's token switches between a standard transfer and one that answers false.
abstract contract ActionHandlerSetTokenAnswer is ActionBaseHandler {
  /// @notice Makes the token answer false, moving nothing, once in four, as `_seed` picks, and
  ///         transfer normally otherwise.
  function handler_setTokenAnswer(uint256 _seed) external {
    Snapshot memory _before = _snapshot();
    token.setAnswersFalse(_seed % 4 == 0);
    _checkNothingSpent(_before);
  }
}
