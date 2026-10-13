// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {PolicyManagerHarness} from 'test/utils/PolicyManagerHarness.sol';

/// @notice Test harness for the manager's event replay. It is the manager, with the setup and attempt write doors
///         of PolicyManagerHarness, plus one door that runs the manager's own emit of AttemptStarted. The frozen
///         AttemptStarted row fills places whose credentials are bare numbers with no known method, config and salt,
///         so no accepted opening can reach that row's values, and this door emits them through the same statement
///         an accepted opening runs. It adds no behavior to the manager's own functions.
contract ManagerKatEventHarness is PolicyManagerHarness {
  /// @notice Emits AttemptStarted through the manager's internal emit, as an accepted opening does.
  /// @param _request The request the event reports.
  /// @param _usedPlaces The places the event reports as filled.
  /// @param _usedMethods The distinct methods the event reports.
  /// @param _consumableAfter When the event reports the wait ends.
  function harnessEmitAttemptStarted(
    AttemptRequest calldata _request,
    uint256[] calldata _usedPlaces,
    address[] calldata _usedMethods,
    uint48 _consumableAfter
  ) external {
    _emitAttemptStarted(_request, _usedPlaces, _usedMethods, _consumableAfter);
  }
}
