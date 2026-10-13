// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

/// @notice Mock of a method that reports itself stopped and refuses everything else. The
///         holder's own cancel and a clear must never reach it, so any call to it reverts except
///         the pause read, which answers exactly true.
contract PolicyManagerMockMethod {
  /*///////////////////////////////////////////////////////////////
                              ERRORS
  ///////////////////////////////////////////////////////////////*/

  /// @notice The mock refuses every call it does not declare.
  /// @param _data The calldata of the refused call.
  error PolicyManagerMockMethod_Called(bytes _data);

  /*///////////////////////////////////////////////////////////////
                        EXTERNAL FUNCTIONS
  ///////////////////////////////////////////////////////////////*/

  /// @notice Never approves.
  fallback() external {
    revert PolicyManagerMockMethod_Called(msg.data);
  }

  /// @notice Always stopped.
  function paused() external pure returns (bool _stopped) {
    _stopped = true;
  }
}
