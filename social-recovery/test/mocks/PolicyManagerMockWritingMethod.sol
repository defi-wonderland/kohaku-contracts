// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {IPolicyMethod} from 'interfaces/IPolicyMethod.sol';

/// @notice Mock of a hostile method that writes its own storage while it answers. Its verify
///         writes a counter and then returns the magic value, and its pause read writes the same
///         counter and then answers true. Called as a static call, both writes revert, so the
///         method can neither approve a proof nor report a stop, and the counter never moves.
contract PolicyManagerMockWritingMethod {
  /*///////////////////////////////////////////////////////////////
                          STATE VARIABLES
  ///////////////////////////////////////////////////////////////*/

  /// @notice How many answers wrote their counter. It stays zero while every call is static.
  uint256 public writes;

  /*///////////////////////////////////////////////////////////////
                        EXTERNAL FUNCTIONS
  ///////////////////////////////////////////////////////////////*/

  /// @notice Writes the counter, then returns the magic value.
  /// @return _magicValue The verify selector.
  function verify(bytes calldata, bytes32, bytes calldata) external returns (bytes4 _magicValue) {
    ++writes;
    _magicValue = IPolicyMethod.verify.selector;
  }

  /// @notice Writes the counter, then reports a stop.
  /// @return _stopped Always true.
  function paused() external returns (bool _stopped) {
    ++writes;
    _stopped = true;
  }
}
