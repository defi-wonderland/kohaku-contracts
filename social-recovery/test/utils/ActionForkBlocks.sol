// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

/// @notice The blocks the action's fork suites pin, one per network. Forking a fixed block keeps the
///         suites independent of later chain state, such as someone funding a test address or
///         deploying a test account at its create2 address first.
abstract contract ActionForkBlocks {
  /// @notice A finalized mainnet block after Ambire's factory 0x26cE6745A633030A6faC5e64e41D21fb6246dc2d
  ///         and implementation 0x0F2AA7bcda3d9D210dF69a394b6965CB2566c828 were deployed, pinned so the
  ///         fork tests do not depend on later chain state.
  uint256 internal constant _MAINNET_BLOCK = 26_097_000;
  /// @notice A finalized Sepolia block after Ambire's factory 0x26cE6745A633030A6faC5e64e41D21fb6246dc2d
  ///         and implementation 0x0F2AA7bcda3d9D210dF69a394b6965CB2566c828 were deployed, pinned so the
  ///         fork tests do not depend on later chain state.
  uint256 internal constant _SEPOLIA_BLOCK = 11_821_000;
}
