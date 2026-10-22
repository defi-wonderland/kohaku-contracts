// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {PolicyManager} from 'contracts/manager/PolicyManager.sol';

/// @notice Test harness. It is the manager with two extra doors that write a setup or an attempt
///         record straight into the manager's own mappings, so a test can hold a state no sequence
///         of calls reaches: a waiting attempt judged under another nonce or beside no setup, a
///         record naming a method that could never pass a verify, or a setup whose nonce no
///         sequence of writes could reach in a test. It adds no behavior to the manager's own functions.
contract PolicyManagerHarness is PolicyManager {
  /*///////////////////////////////////////////////////////////////
                        EXTERNAL FUNCTIONS
  ///////////////////////////////////////////////////////////////*/

  /// @notice Overwrites the attempt record of (`_account`, `_action`) with `_record`.
  /// @param _account The account the record belongs to.
  /// @param _action The action the record belongs to.
  /// @param _record The record to write.
  function harnessWriteAttempt(address _account, address _action, Attempt calldata _record) external {
    _attempts[_account][_action] = _record;
  }

  /// @notice Overwrites the setup of (`_account`, `_action`) with `_setup`.
  /// @param _account The account the setup belongs to.
  /// @param _action The action the setup governs.
  /// @param _setup The setup to write.
  function harnessWriteSetup(address _account, address _action, Setup calldata _setup) external {
    _setups[_account][_action] = _setup;
  }
}
