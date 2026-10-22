// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {IPolicyMethod} from 'interfaces/IPolicyMethod.sol';

/// @notice A third-party method that its pause holder can pause. The tests need it because the
///         wallet and passkey methods cannot be paused. It accepts a proof equal to
///         abi.encode(config, digest), so each approval counts for one credential and one digest.
///         Its verify ignores the pause, because only the manager turns a pause into a refusal.
contract IntegrationPausableMethod {
  /*///////////////////////////////////////////////////////////////
                          STATE VARIABLES
  ///////////////////////////////////////////////////////////////*/

  /// @notice The one address allowed to pause and unpause the method.
  address public immutable PAUSE_HOLDER;
  /// @notice Whether the method is paused.
  bool public paused;

  /*///////////////////////////////////////////////////////////////
                              EVENTS
  ///////////////////////////////////////////////////////////////*/

  /// @notice The method was paused. Both events keep the unindexed layout that a pausable method's
  ///         interface declares.
  // solhint-disable-next-line gas-indexed-events
  event Paused(address account);
  /// @notice The method was unpaused.
  // solhint-disable-next-line gas-indexed-events
  event Unpaused(address account);

  /*///////////////////////////////////////////////////////////////
                              ERRORS
  ///////////////////////////////////////////////////////////////*/

  /// @notice A caller other than the pause holder tried to pause or unpause the method.
  error IntegrationPausableMethod_NotPauseHolder(address _caller);

  /*///////////////////////////////////////////////////////////////
                            CONSTRUCTOR
  ///////////////////////////////////////////////////////////////*/

  constructor(address _pauseHolder) {
    PAUSE_HOLDER = _pauseHolder;
  }

  /*///////////////////////////////////////////////////////////////
                        EXTERNAL FUNCTIONS
  ///////////////////////////////////////////////////////////////*/

  /// @notice Pauses the method.
  function pause() external {
    require(msg.sender == PAUSE_HOLDER, IntegrationPausableMethod_NotPauseHolder(msg.sender));
    paused = true;
    emit Paused(msg.sender);
  }

  /// @notice Unpauses the method.
  function unpause() external {
    require(msg.sender == PAUSE_HOLDER, IntegrationPausableMethod_NotPauseHolder(msg.sender));
    paused = false;
    emit Unpaused(msg.sender);
  }

  /// @notice Answers the magic value for a proof equal to abi.encode(config, digest), and zero otherwise.
  function verify(bytes calldata _config, bytes32 _digest, bytes calldata _proof)
    external
    pure
    returns (bytes4 _magicValue)
  {
    _magicValue =
      keccak256(_proof) == keccak256(abi.encode(_config, _digest)) ? IPolicyMethod.verify.selector : bytes4(0);
  }
}
