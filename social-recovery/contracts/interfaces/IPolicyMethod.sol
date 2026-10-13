// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

/// @title IPolicyMethod
/// @author defi-wonderland
/// @notice One credential verifier. Anyone may deploy it, and any holder may adopt it.
/// @dev A method may carry a pause of its own, which is the only stop in the kit. The manager reads
///      it at an opening, at a cancel by proofs, at the spend and at a cancel by veto. The manager
///      asks for nothing else, so a method that declares no pause is adoptable unchanged.
interface IPolicyMethod {
  /// @notice Verify one credential's proof against the binding digest.
  /// @dev The manager calls it as a static call, after checking that _config hashes to
  ///      the committed credential.
  /// @param _config The credential's written-out configuration, already recommitted.
  /// @param _digest The hash this proof must approve, from hashApproval or hashCancel.
  /// @param _proof The method-specific proof bytes.
  /// @return _magicValue IPolicyMethod.verify.selector when the proof approves exactly this digest
  ///         under this config. The manager reads any other value, an empty return or a revert as
  ///         false. The name and the pattern follow ERC-1271.
  function verify(bytes calldata _config, bytes32 _digest, bytes calldata _proof)
    external
    view
    returns (bytes4 _magicValue);

  /// @notice The method's own declaration of the parties its verdict depends on. It names the key
  ///         admin able to change its keys, the keys it trusts today and whoever can stop it.
  ///         address(0) means nobody, and an empty list means nothing.
  /// @return _admin Who can update this method's trusted keys, or address(0) when nobody can.
  /// @return _pendingAdmin The address one acceptance away from that role, or address(0) when no
  ///         transfer is open.
  /// @return _trustedKeys The outside values this method's verdict depends on today, such as an
  ///         issuer's key hash, in the layout the method documents.
  /// @return _pauseHolder Who can stop this method, or address(0) when it declares no stop or its
  ///         holder renounced the role. It is the method's own claim: the manager never reads it
  ///         and only asks paused().
  /// @return _pendingPauseHolder The address the pause holder offered the role to, which has not
  ///         accepted yet, or address(0) when no transfer is open. A holder reading it at
  ///         adoption sees that the stop is about to change hands.
  function trustedParties()
    external
    view
    returns (
      address _admin,
      address _pendingAdmin,
      bytes32[] memory _trustedKeys,
      address _pauseHolder,
      address _pendingPauseHolder
    );

  /// @notice Answers ERC-165, so a client can ask a bare address whether it is a policy method
  ///         before adopting it. The answer is advisory: a client may warn about a module that fails
  ///         it rather than refuse it.
  /// @param _interfaceId The ERC-165 interface id asked about.
  /// @return _supported True when this module implements that interface.
  function supportsInterface(bytes4 _interfaceId) external view returns (bool _supported);

  /// @notice The module's human-readable name, for display.
  /// @return _moduleName The module's human-readable name.
  function name() external view returns (string memory _moduleName);

  /// @notice The semantic version of this module.
  /// @return _moduleVersion The module's semantic version.
  function version() external view returns (string memory _moduleVersion);
}
