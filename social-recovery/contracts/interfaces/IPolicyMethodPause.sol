// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

/// @title IPolicyMethodPause
/// @notice The stop surface of a method that carries one. The two identity methods implement it,
///         and the wallet and passkey methods do not. Nobody can stop a method that implements none
///         of it. Ownership of the stop comes from `Ownable2Step`, and this interface does not
///         declare it again.
interface IPolicyMethodPause {
  /// @notice The stop went on. Emitted so that off-chain monitoring, if anyone runs it, can alert
  ///         the holders whose rule names this method, since the manager derives no such
  ///         audience.
  /// @param account The address that turned the stop on.
  // solhint-disable-next-line gas-indexed-events
  event Paused(address account);

  /// @notice The stop came off.
  /// @param account The address that turned the stop off.
  // solhint-disable-next-line gas-indexed-events
  event Unpaused(address account);

  /// @notice Stop this method. Only the pause holder may call it. While the stop is on, the
  ///         method answers the manager's read with true. Unless the holder's setup opted out of
  ///         stops, the manager then refuses the method's proofs at an opening and at a cancel by
  ///         proofs. It also vetoes the spend of any attempt that used the method and lets anyone
  ///         cancel such an attempt. The method itself refuses nothing inside verify.
  function pause() external;

  /// @notice Let this method's proofs count again. Only the pause holder may call it.
  function unpause() external;

  /// @notice Whether this method is stopped. It is the one function of this interface the manager
  ///         calls, and also the one every method may leave out. A method that carries no pause
  ///         implements none of this interface and is adoptable unchanged.
  /// @return _isPaused True while the stop is on.
  function paused() external view returns (bool _isPaused);
}
