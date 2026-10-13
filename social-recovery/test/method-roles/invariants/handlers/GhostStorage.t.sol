// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

/// @notice The role functions a handler can call.
enum MethodRolesCall {
  None,
  SetTrustedKeys,
  TransferAdmin,
  AcceptAdmin,
  RenounceAdmin,
  Pause,
  Unpause,
  TransferOwnership,
  AcceptOwnership,
  RenounceOwnership
}

/// @notice What the method reports about its two roles at one moment, read from the method itself.
///         `keysHash` is keccak256 over the tightly packed trusted key words.
struct MethodRolesSnapshot {
  address admin;
  address pendingAdmin;
  bytes32 keysHash;
  address owner;
  address pendingOwner;
  bool paused;
}

/// @notice Every ghost variable of the roles invariant suite. The handlers predict nothing. They record the
///         last call, who made it, whether it went through, and what the method reported just before and just
///         after it. The invariants then state who may cause each change.
abstract contract PolicyMethodRolesGhostStorage {
  /*///////////////////////////////////////////////////////////////
                            GHOST VARIABLES
  ///////////////////////////////////////////////////////////////*/

  /// @notice The role function the last handler call sent.
  MethodRolesCall public ghost_lastCall;
  /// @notice The address the last handler call was sent from.
  address public ghost_lastCaller;
  /// @notice Whether the last handler call went through.
  bool public ghost_lastSucceeded;

  /// @notice Set once a renounce of the key admin role went through.
  bool public ghost_adminRenounced;
  /// @notice The hash of the trusted keys at the moment the key admin renounced.
  bytes32 public ghost_keysHashAtRenounce;
  /// @notice Set once a renounce of the pause holder role went through while the method was paused.
  bool public ghost_stoppedForGood;
  /// @notice Counts calls the current holder of a role was entitled to make and that reverted.
  uint256 public ghost_holderRefusals;

  /// @notice What the method reported just before the last handler call.
  MethodRolesSnapshot internal _ghostBefore;
  /// @notice What the method reported just after the last handler call.
  MethodRolesSnapshot internal _ghostAfter;

  /*///////////////////////////////////////////////////////////////
                        READS FOR THE INVARIANTS
  ///////////////////////////////////////////////////////////////*/

  /// @notice Returns what the method reported just before the last handler call, as one struct.
  function ghost_before() external view returns (MethodRolesSnapshot memory _snapshot) {
    _snapshot = _ghostBefore;
  }

  /// @notice Returns what the method reported just after the last handler call, as one struct.
  function ghost_after() external view returns (MethodRolesSnapshot memory _snapshot) {
    _snapshot = _ghostAfter;
  }
}
