// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

/// @title IPolicyAction
/// @author defi-wonderland
/// @notice The view functions every action exposes to clients, whatever its outcome and its account
///         implementation.
/// @dev An action has no storage and no owner, so it carries no pause and nobody can stop it.
interface IPolicyAction {
  /// @notice Whether this action serves the account's current implementation.
  /// @dev The manager calls this in commitSetup and refuses a setup the action does not serve, and a client can call
  ///      it first, so a mismatch shows before anything is sent. It probes the implementation the way the account
  ///      reports it. It treats an unknown answer as unsupported, since some accounts accept any unknown call without
  ///      failing. It answers false for an address whose code is an EIP-7702 delegation designator, a shape the kit
  ///      does not serve.
  /// @param _account The account asked about.
  /// @return _supported True when the account's implementation is one this action serves.
  function supportsAccount(address _account) external view returns (bool _supported);

  /// @notice Whether the given authority currently holds power on the account, in this
  ///         implementation's own terms. Clients read it, at setup and when building a request, to name
  ///         the exact authority an outcome acts on, such as the key a recovery removes.
  /// @param _account The account asked about.
  /// @param _authority The authority, as an address.
  /// @return _holds True when the account currently honors that address as an authority.
  function isAuthority(address _account, address _authority) external view returns (bool _holds);

  /// @notice Whether the account honors this action's authority right now, read from the account
  ///         in that implementation's own way. Clients read it, at setup and when rebuilding a setup, so
  ///         no client hardcodes an implementation's constants to read the authorization back.
  /// @param _account The account asked about.
  /// @return _authorized True when the account honors this action today.
  function isAuthorized(address _account) external view returns (bool _authorized);

  /// @notice Answers ERC-165, so a client can ask a bare address whether it is a policy action.
  ///         The answer is advisory, as the method's probe is. A hostile action answers whatever
  ///         it likes, and the trust an action carries comes from the account's own grant, not
  ///         from a probe.
  /// @param _interfaceId The ERC-165 interface id asked about.
  /// @return _supported True when this action implements that interface.
  function supportsInterface(bytes4 _interfaceId) external view returns (bool _supported);

  /// @notice The action's human-readable name, for display.
  /// @return _actionName The action's human-readable name.
  function name() external view returns (string memory _actionName);

  /// @notice The semantic version of this action.
  /// @return _actionVersion The action's semantic version.
  function version() external view returns (string memory _actionVersion);
}
