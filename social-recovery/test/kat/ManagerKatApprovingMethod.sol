// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {IPolicyMethod} from 'interfaces/IPolicyMethod.sol';

/// @notice Mock of a method that approves every proof and is never stopped. A replay uses it to open a real
///         attempt, so the manager's own acceptance path runs while the proof itself carries nothing.
contract ManagerKatApprovingMethod {
  /// @notice Answers every verification with the magic value, the selector of verify left-aligned in one word.
  /// @return _magicValue The selector of IPolicyMethod.verify.
  function verify(bytes calldata, bytes32, bytes calldata) external pure returns (bytes4 _magicValue) {
    _magicValue = IPolicyMethod.verify.selector;
  }

  /// @notice Never stopped.
  /// @return _stopped Always false.
  function paused() external pure returns (bool _stopped) {
    _stopped = false;
  }
}
