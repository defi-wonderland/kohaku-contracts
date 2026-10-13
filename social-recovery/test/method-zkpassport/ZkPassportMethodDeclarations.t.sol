// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {IERC165} from '@openzeppelin/contracts/utils/introspection/IERC165.sol';
import {IPolicyMethod} from 'interfaces/IPolicyMethod.sol';
import {IPolicyMethodAdmin} from 'interfaces/IPolicyMethodAdmin.sol';
import {IPolicyMethodPause} from 'interfaces/IPolicyMethodPause.sol';
import {MethodZkPassportFixture} from 'test/utils/MethodZkPassportFixture.sol';

/// @notice Tests what the zkPassport method reports about itself: whom it trusts, its name and release, and the
///         interfaces it supports.
contract ZkPassportMethodDeclarationsTest is MethodZkPassportFixture {
  /// trustedParties reports the key admin, the pause holder and the eight words. Each word sits at its fixed
  /// position. A holder reads this before adopting the method to see which root verifier, verifier helper and version
  /// it trusts.
  function test_WhenTrustedPartiesAreRead() external view {
    (
      address _admin,
      address _pendingAdmin,
      bytes32[] memory _keys,
      address _reportedPauseHolder,
      address _pendingPauseHolder
    ) = _method.trustedParties();
    // it should report the key admin and the pause holder with no transfer open
    assertEq(_admin, _keyAdmin, 'admin');
    assertEq(_pendingAdmin, address(0), 'pendingAdmin');
    assertEq(_reportedPauseHolder, _pauseHolder, 'pauseHolder');
    assertEq(_pendingPauseHolder, address(0), 'pendingPauseHolder');
    // it should report each of the eight words at its position
    assertEq(_keys.length, _KEY_COUNT, 'length');
    assertEq(_keys[_WORD_VERSION], _ZK_VERSION_0_21_0, 'version');
    assertEq(_keys[_WORD_ROOT], bytes32(uint256(uint160(address(_rootMock)))), 'root');
    assertEq(_keys[_WORD_SUB_VERIFIER], bytes32(uint256(uint160(_SUB_VERIFIER))), 'sub-verifier');
    assertEq(_keys[_WORD_VERIFIER_HELPER], bytes32(uint256(uint160(address(_verifierHelperMock)))), 'verifier helper');
    assertEq(_keys[_WORD_REGISTRY], bytes32(uint256(uint160(_REGISTRY))), 'registry');
    assertEq(_keys[_WORD_ROOT_ADMIN], bytes32(uint256(uint160(_ROOT_ADMIN))), 'root admin');
    assertEq(_keys[_WORD_ROOT_GUARDIAN], bytes32(uint256(uint160(_ROOT_GUARDIAN))), 'root guardian');
    assertEq(_keys[_WORD_SUB_VERIFIER_ADMIN], bytes32(uint256(uint160(_SUB_VERIFIER_ADMIN))), 'sub-verifier admin');
  }

  /// The method's name is method-zkpassport. The setup screen and a watcher use it to tell which method a policy
  /// points at.
  function test_WhenTheNameIsRead() external view {
    // it should answer method-zkpassport
    assertEq(_method.name(), 'method-zkpassport');
  }

  /// The method's release is 1.0.0. A watcher uses it to tell which release a policy points at.
  function test_WhenTheVersionIsRead() external view {
    // it should answer 1.0.0
    assertEq(_method.version(), '1.0.0');
  }

  /// supportsInterface answers true for the method, pause, admin and ERC-165 interface ids. The setup screen reads
  /// these to show the method has a stop and a key admin.
  function test_WhenAskedForASupportedInterfaceId() external view {
    // it should answer true for IPolicyMethod, IPolicyMethodPause, IPolicyMethodAdmin and IERC165
    assertTrue(_method.supportsInterface(type(IPolicyMethod).interfaceId), 'IPolicyMethod');
    assertTrue(_method.supportsInterface(type(IPolicyMethodPause).interfaceId), 'IPolicyMethodPause');
    assertTrue(_method.supportsInterface(type(IPolicyMethodAdmin).interfaceId), 'IPolicyMethodAdmin');
    assertTrue(_method.supportsInterface(type(IERC165).interfaceId), 'IERC165');
  }

  /// supportsInterface answers false for 0xffffffff. ERC-165 requires that answer. A caller that probes for ERC-165
  /// support relies on it.
  function test_WhenAskedForTheInvalidInterfaceId() external view {
    // it should answer false
    assertFalse(_method.supportsInterface(0xffffffff));
  }
}
