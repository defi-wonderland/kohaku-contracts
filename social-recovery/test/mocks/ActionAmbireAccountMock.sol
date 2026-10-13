// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

/// @notice A stand-in for Ambire's account that carries only the privilege mapping, the one read
///         the recovery action's views make. The test writes entries directly, where the real
///         account writes them through setAddrPrivilege inside execute.
contract ActionAmbireAccountMock {
  mapping(address _addr => bytes32 _privilege) internal _privileges;

  /// @notice Ambire's getter, `privileges(address) returns (bytes32)`.
  function privileges(address _addr) external view returns (bytes32 _privilege) {
    _privilege = _privileges[_addr];
  }

  /// @notice Test-only write of one entry.
  function setPrivilege(address _addr, bytes32 _privilege) external {
    _privileges[_addr] = _privilege;
  }
}

/// @notice An account whose fallback accepts any call and returns nothing, the way Ambire's own
///         account answers a call it does not know. A view that decodes the privilege getter's
///         word finds no word here.
contract ActionSilentAccountMock {
  fallback() external payable {}
}
