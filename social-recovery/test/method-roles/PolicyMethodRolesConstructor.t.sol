// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {Ownable} from '@openzeppelin/contracts/access/Ownable.sol';
import {IPolicyMethodAdmin} from 'interfaces/IPolicyMethodAdmin.sol';
import {MethodRolesHarness} from 'test/mocks/MethodRolesHarness.sol';
import {MethodRolesTestBase} from 'test/utils/MethodRolesTestBase.sol';

/// @notice What the roles base checks and records when a method is deployed.
contract PolicyMethodRolesConstructorTest is MethodRolesTestBase {
  /// @notice Deploying with no key admin reverts with the error the key admin surface declares for it, naming
  ///         the zero address. Without a key admin, nobody could ever change the method's keys, so the
  ///         constructor refuses it.
  function test_RevertWhen_TheInitialAdminIsZero() external {
    bytes memory _reason =
      abi.encodeWithSelector(IPolicyMethodAdmin.PolicyMethodRoles_AdminInvalidAdmin.selector, address(0));
    vm.expectRevert(_reason);
    new MethodRolesHarness(_pauseHolder, address(0), _initialKeys, _NAME, _VERSION);
  }

  /// @notice Deploying with no pause holder reverts with OpenZeppelin's own error for a zero
  ///         owner, since the pause holder is the Ownable owner.
  function test_RevertWhen_TheInitialOwnerIsZero() external {
    vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableInvalidOwner.selector, address(0)));
    new MethodRolesHarness(address(0), _keyAdmin, _initialKeys, _NAME, _VERSION);
  }

  /// @notice The constructor runs the method's key validation hook over the initial keys, so a
  ///         key set the method would refuse later cannot be installed at deployment either. The
  ///         harness hook refuses its marker word and names the position it found it at.
  function test_RevertWhen_AnInitialKeyIsTheMarkerTheHookRefuses() external {
    bytes32[] memory _keys = _keyList(keccak256('ok'), _marker);
    vm.expectRevert(_markerRefused(1));
    new MethodRolesHarness(_pauseHolder, _keyAdmin, _keys, _NAME, _VERSION);

    _keys = _keyList(_marker);
    vm.expectRevert(_markerRefused(0));
    new MethodRolesHarness(_pauseHolder, _keyAdmin, _keys, _NAME, _VERSION);
  }

  /// @notice A valid deployment emits AdminTransferred from the zero address to the initial admin, then
  ///         TrustedKeysUpdated from an empty list to the initial keys. The views then report the initial
  ///         pause holder, key admin and keys, with no transfer open and the method running. A watcher reads
  ///         the whole key history from the events, and a holder reads the views before adopting the method.
  function test_WhenEveryArgumentIsValid() external {
    address _expected = vm.computeCreateAddress(address(this), vm.getNonce(address(this)));
    // it should emit AdminTransferred from zero to the initial admin,
    // then TrustedKeysUpdated from no keys to the initial keys.
    vm.expectEmit(_expected);
    emit IPolicyMethodAdmin.AdminTransferred(address(0), _keyAdmin);
    vm.expectEmit(_expected);
    emit IPolicyMethodAdmin.TrustedKeysUpdated(new bytes32[](0), _initialKeys);
    MethodRolesHarness _deployed = _deploy(_pauseHolder, _keyAdmin, _initialKeys);
    assertEq(address(_deployed), _expected, 'deployed address');

    (address _admin, address _pendingAdmin, bytes32[] memory _keys, address _holder, address _pendingHolder) =
      _deployed.trustedParties();
    // it should make the initial owner the pause holder.
    assertEq(_deployed.owner(), _pauseHolder, 'owner');
    assertEq(_holder, _pauseHolder, 'pauseHolder');
    // it should make the initial admin the key admin.
    assertEq(_admin, _keyAdmin, 'admin');
    // it should store the initial keys in order.
    _assertKeys(_keys, _initialKeys);
    // it should leave both pending holders at zero.
    assertEq(_pendingAdmin, address(0), 'pendingAdmin');
    assertEq(_deployed.pendingAdmin(), address(0), 'pendingAdmin()');
    assertEq(_pendingHolder, address(0), 'pendingPauseHolder');
    assertEq(_deployed.pendingOwner(), address(0), 'pendingOwner()');
    // it should leave the method unpaused.
    assertFalse(_deployed.paused(), 'paused');
    // it should set the name and the version.
    assertEq(_deployed.name(), _NAME, 'name');
    assertEq(_deployed.version(), _VERSION, 'version');
  }
}
