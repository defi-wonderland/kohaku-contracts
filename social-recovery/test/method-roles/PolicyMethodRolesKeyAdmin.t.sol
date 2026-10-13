// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {IPolicyMethodAdmin} from 'interfaces/IPolicyMethodAdmin.sol';
import {MethodRolesHarness} from 'test/mocks/MethodRolesHarness.sol';
import {MethodRolesTestBase} from 'test/utils/MethodRolesTestBase.sol';

/// @notice The key admin's four calls, who may send each one, and what each leaves behind.
contract PolicyMethodRolesKeyAdminTest is MethodRolesTestBase {
  /// @notice The key admin replaces the keys. The method stores them in order and emits TrustedKeysUpdated
  ///         with the old and new lists, so a watcher can alert holders to the change. The stop is untouched.
  function test_WhenTheKeyAdminSetsKeysTheHookAccepts() external {
    vm.prank(_pauseHolder);
    _roles.pause();
    bytes32[] memory _fresh = _keyList(keccak256('a'), keccak256('b'), keccak256('c'));

    // it should emit TrustedKeysUpdated with the previous and the current keys.
    vm.expectEmit(address(_roles));
    emit IPolicyMethodAdmin.TrustedKeysUpdated(_initialKeys, _fresh);
    vm.prank(_keyAdmin);
    _roles.setTrustedKeys(_fresh);

    // it should store the new keys in order.
    _assertKeys(_reportedKeys(), _fresh);

    // it should leave the pause holder and the stop unchanged.
    assertEq(_roles.owner(), _pauseHolder, 'owner');
    assertEq(_roles.pendingOwner(), address(0), 'pendingOwner');
    assertTrue(_roles.paused(), 'paused');

    // A second update reports the first update's keys as previous.
    bytes32[] memory _again = _keyList(keccak256('d'));
    vm.expectEmit(address(_roles));
    emit IPolicyMethodAdmin.TrustedKeysUpdated(_fresh, _again);
    vm.prank(_keyAdmin);
    _roles.setTrustedKeys(_again);
    _assertKeys(_reportedKeys(), _again);
  }

  /// @notice When the method's validation hook refuses the new keys, setTrustedKeys reverts with the hook's
  ///         own error and the previous keys stay. Each method relies on this hook to refuse malformed keys.
  function test_RevertWhen_TheKeyAdminSetsKeysContainingTheMarker() external {
    bytes32[] memory _bad = _keyList(keccak256('a'), keccak256('b'), _marker);
    vm.expectRevert(_markerRefused(2));
    vm.prank(_keyAdmin);
    _roles.setTrustedKeys(_bad);
    _assertKeys(_reportedKeys(), _initialKeys);
  }

  /// @notice setTrustedKeys asks the hook before it stores anything. The armed probe reverts unless the old
  ///         keys are still in storage while it runs, and a second call shows the probe does fire on a mismatch.
  function test_WhenTheStoredKeysProbeIsArmed() external {
    _roles.armProbe(keccak256(abi.encodePacked(_initialKeys)));
    bytes32[] memory _fresh = _keyList(keccak256('x'), keccak256('y'));
    vm.prank(_keyAdmin);
    _roles.setTrustedKeys(_fresh);
    _assertKeys(_reportedKeys(), _fresh);

    // Control: the probe does bite when storage differs from the expected snapshot.
    bytes32 _freshHash = keccak256(abi.encodePacked(_fresh));
    _roles.armProbe(keccak256('not the stored keys'));
    vm.expectRevert(
      abi.encodeWithSelector(
        MethodRolesHarness.MethodRolesHarness_HookSawStoredKeys.selector, _freshHash, keccak256('not the stored keys')
      )
    );
    vm.prank(_keyAdmin);
    _roles.setTrustedKeys(_keyList(keccak256('z')));
  }

  /// @notice The pause holder, a nominee, a stranger and the zero address cannot replace the keys. An address
  ///         able to set the keys could forge every proof of the method, so only the key admin may set them.
  function test_RevertWhen_AnyoneOtherThanTheKeyAdminSetsKeys() external {
    bytes32[] memory _fresh = _keyList(keccak256('fresh'));
    address[4] memory _others = [_pauseHolder, _nominee, _stranger, address(0)];
    for (uint256 _i = 0; _i < _others.length; _i++) {
      vm.expectRevert(_adminUnauthorized(_others[_i]));
      vm.prank(_others[_i]);
      _roles.setTrustedKeys(_fresh);
    }
    _assertKeys(_reportedKeys(), _initialKeys);
  }

  /// @notice Offering the key admin role records the nominee as pending and emits AdminTransferOffered. The
  ///         current admin stays in charge until the nominee accepts, and watchers can see the handover while
  ///         the offer is open.
  function test_WhenTheKeyAdminOffersTheRole() external {
    // it should emit AdminTransferOffered with the admin and the _nominee.
    vm.expectEmit(address(_roles));
    emit IPolicyMethodAdmin.AdminTransferOffered(_keyAdmin, _nominee);
    vm.prank(_keyAdmin);
    _roles.transferAdmin(_nominee);

    // it should record the pending admin.
    assertEq(_roles.pendingAdmin(), _nominee, 'pendingAdmin()');
    (address _admin, address _pendingAdmin,,,) = _roles.trustedParties();
    assertEq(_pendingAdmin, _nominee, 'trustedParties pendingAdmin');
    // it should keep the current admin in the role.
    assertEq(_admin, _keyAdmin, 'admin');
    bytes32[] memory _fresh = _keyList(keccak256('still mine'));
    vm.prank(_keyAdmin);
    _roles.setTrustedKeys(_fresh);
    _assertKeys(_reportedKeys(), _fresh);
  }

  /// @notice Nobody but the key admin can offer the role. Otherwise a stranger could name a nominee of their
  ///         own, who would only need to accept before setting keys.
  function test_RevertWhen_AnyoneOtherThanTheKeyAdminOffersTheRole() external {
    address[3] memory _others = [_pauseHolder, _nominee, _stranger];
    for (uint256 _i = 0; _i < _others.length; _i++) {
      vm.expectRevert(_adminUnauthorized(_others[_i]));
      vm.prank(_others[_i]);
      _roles.transferAdmin(_others[_i]);
    }
    assertEq(_roles.pendingAdmin(), address(0), 'pendingAdmin');
    assertEq(_reportedAdmin(), _keyAdmin, 'admin');
  }

  /// @notice A second offer replaces the first. Only the latest nominee can accept, so an admin who named the
  ///         wrong address can correct it.
  function test_WhenASecondOfferReplacesTheFirst() external {
    vm.startPrank(_keyAdmin);
    _roles.transferAdmin(_nominee);
    _roles.transferAdmin(_secondNominee);
    vm.stopPrank();
    assertEq(_roles.pendingAdmin(), _secondNominee, 'pendingAdmin');

    // it should let only the second _nominee accept.
    vm.expectRevert(_adminUnauthorized(_nominee));
    vm.prank(_nominee);
    _roles.acceptAdmin();

    vm.prank(_secondNominee);
    _roles.acceptAdmin();
    assertEq(_reportedAdmin(), _secondNominee, 'admin');
  }

  /// @notice Offering the role to the zero address closes an open offer, the way OpenZeppelin's Ownable2Step
  ///         cancels a handover. The earlier nominee cannot accept afterwards, and neither can the zero address.
  function test_WhenTheKeyAdminOffersTheRoleToTheZeroAddress() external {
    vm.prank(_keyAdmin);
    _roles.transferAdmin(_nominee);

    // it should emit AdminTransferOffered with the admin and the zero address.
    vm.expectEmit(address(_roles));
    emit IPolicyMethodAdmin.AdminTransferOffered(_keyAdmin, address(0));
    vm.prank(_keyAdmin);
    _roles.transferAdmin(address(0));

    // it should close the open offer.
    assertEq(_roles.pendingAdmin(), address(0), 'pendingAdmin()');
    (address _admin, address _pendingAdmin,,,) = _roles.trustedParties();
    assertEq(_pendingAdmin, address(0), 'trustedParties pendingAdmin');
    assertEq(_admin, _keyAdmin, 'admin');

    // it should let neither the earlier nominee nor the zero address accept.
    vm.expectRevert(_adminUnauthorized(_nominee));
    vm.prank(_nominee);
    _roles.acceptAdmin();
    vm.expectRevert(_adminUnauthorized(address(0)));
    vm.prank(address(0));
    _roles.acceptAdmin();
    assertEq(_reportedAdmin(), _keyAdmin, 'admin kept');
  }

  /// @notice The nominee accepts and becomes the key admin, the pending slot clears and AdminTransferred is
  ///         emitted. The previous admin loses every power of the role at once.
  function test_WhenTheNomineeAccepts() external {
    vm.prank(_keyAdmin);
    _roles.transferAdmin(_nominee);

    // it should emit AdminTransferred with the previous admin and the _nominee.
    vm.expectEmit(address(_roles));
    emit IPolicyMethodAdmin.AdminTransferred(_keyAdmin, _nominee);
    vm.prank(_nominee);
    _roles.acceptAdmin();

    // it should make the _nominee the admin.
    (address _admin, address _pendingAdmin,,,) = _roles.trustedParties();
    assertEq(_admin, _nominee, 'admin');
    // it should clear the pending admin.
    assertEq(_pendingAdmin, address(0), 'pendingAdmin');
    assertEq(_roles.pendingAdmin(), address(0), 'pendingAdmin()');

    // it should strip the previous admin of the role.
    bytes32[] memory _fresh = _keyList(keccak256('old admin'));
    vm.expectRevert(_adminUnauthorized(_keyAdmin));
    vm.prank(_keyAdmin);
    _roles.setTrustedKeys(_fresh);
    vm.expectRevert(_adminUnauthorized(_keyAdmin));
    vm.prank(_keyAdmin);
    _roles.transferAdmin(_keyAdmin);
    vm.expectRevert(_adminUnauthorized(_keyAdmin));
    vm.prank(_keyAdmin);
    _roles.renounceAdmin();

    // The new admin holds the role in full.
    vm.prank(_nominee);
    _roles.setTrustedKeys(_fresh);
    _assertKeys(_reportedKeys(), _fresh);

    // A second accept by the same nominee finds no open offer.
    vm.expectRevert(_adminUnauthorized(_nominee));
    vm.prank(_nominee);
    _roles.acceptAdmin();
  }

  /// @notice Only the address offered the role can take it. Other callers are refused while an offer is open,
  ///         and the zero address is refused when none is.
  function test_RevertWhen_AnyoneOtherThanTheNomineeAccepts() external {
    vm.prank(_keyAdmin);
    _roles.transferAdmin(_nominee);
    address[4] memory _others = [_keyAdmin, _pauseHolder, _stranger, _secondNominee];
    for (uint256 _i = 0; _i < _others.length; _i++) {
      vm.expectRevert(_adminUnauthorized(_others[_i]));
      vm.prank(_others[_i]);
      _roles.acceptAdmin();
    }
    assertEq(_reportedAdmin(), _keyAdmin, 'admin');
    assertEq(_roles.pendingAdmin(), _nominee, 'pendingAdmin');

    // With no offer open, nobody accepts, the zero address included.
    vm.prank(_keyAdmin);
    _roles.renounceAdmin();
    vm.expectRevert(_adminUnauthorized(address(0)));
    vm.prank(address(0));
    _roles.acceptAdmin();
  }

  /// @notice A nominee who has not accepted yet cannot set keys, so the role changes hands only through the
  ///         acceptance a watcher can see.
  function test_RevertWhen_TheNomineeSetsKeysBeforeAccepting() external {
    vm.prank(_keyAdmin);
    _roles.transferAdmin(_nominee);
    vm.expectRevert(_adminUnauthorized(_nominee));
    vm.prank(_nominee);
    _roles.setTrustedKeys(_keyList(keccak256('early')));
    _assertKeys(_reportedKeys(), _initialKeys);
  }

  /// @notice Renouncing the key admin role leaves nobody in it and freezes the keys. AdminRenounced is emitted,
  ///         nobody can set keys or reopen the role afterwards, and the pause holder keeps its stop.
  function test_WhenTheKeyAdminRenounces() external {
    // it should emit AdminRenounced with the previous admin.
    vm.expectEmit(address(_roles));
    emit IPolicyMethodAdmin.AdminRenounced(_keyAdmin);
    vm.prank(_keyAdmin);
    _roles.renounceAdmin();

    // it should report no admin.
    (address _admin, address _pendingAdmin, bytes32[] memory _keys,,) = _roles.trustedParties();
    assertEq(_admin, address(0), 'admin');
    assertEq(_pendingAdmin, address(0), 'pendingAdmin');
    // it should keep the keys.
    _assertKeys(_keys, _initialKeys);

    // it should let nobody set keys or offer the role afterwards.
    address[5] memory _everyone = [_keyAdmin, _pauseHolder, _nominee, _stranger, address(0)];
    bytes32[] memory _fresh = _keyList(keccak256('after renounce'));
    for (uint256 _i = 0; _i < _everyone.length; _i++) {
      vm.startPrank(_everyone[_i]);
      vm.expectRevert(_adminUnauthorized(_everyone[_i]));
      _roles.setTrustedKeys(_fresh);
      vm.expectRevert(_adminUnauthorized(_everyone[_i]));
      _roles.transferAdmin(_nominee);
      vm.expectRevert(_adminUnauthorized(_everyone[_i]));
      _roles.acceptAdmin();
      vm.expectRevert(_adminUnauthorized(_everyone[_i]));
      _roles.renounceAdmin();
      vm.stopPrank();
    }
    _assertKeys(_reportedKeys(), _initialKeys);
    assertEq(_reportedAdmin(), address(0), 'admin stays gone');

    // it should leave the pause holder standing.
    assertEq(_roles.owner(), _pauseHolder, 'owner');
    vm.startPrank(_pauseHolder);
    _roles.pause();
    assertTrue(_roles.paused(), 'paused');
    _roles.unpause();
    assertFalse(_roles.paused(), 'unpaused');
    vm.stopPrank();
  }

  /// @notice Renouncing clears an open offer before the admin goes, so no earlier nominee can accept and
  ///         capture the frozen keys afterwards.
  function test_WhenTheKeyAdminRenouncesWithATransferOpen() external {
    vm.startPrank(_keyAdmin);
    _roles.transferAdmin(_nominee);
    _roles.renounceAdmin();
    vm.stopPrank();

    // it should clear the pending admin.
    assertEq(_roles.pendingAdmin(), address(0), 'pendingAdmin()');
    (address _admin, address _pendingAdmin,,,) = _roles.trustedParties();
    assertEq(_pendingAdmin, address(0), 'pendingAdmin');
    assertEq(_admin, address(0), 'admin');

    // it should let no earlier _nominee accept.
    vm.expectRevert(_adminUnauthorized(_nominee));
    vm.prank(_nominee);
    _roles.acceptAdmin();
    assertEq(_reportedAdmin(), address(0), 'admin stays gone');
    vm.expectRevert(_adminUnauthorized(_nominee));
    vm.prank(_nominee);
    _roles.setTrustedKeys(_keyList(keccak256('captured')));
    _assertKeys(_reportedKeys(), _initialKeys);
  }

  /// @notice Nobody but the key admin can renounce the role, so no one else can freeze the keys a method needs
  ///         to follow an issuer's rotation.
  function test_RevertWhen_AnyoneOtherThanTheKeyAdminRenounces() external {
    vm.prank(_keyAdmin);
    _roles.transferAdmin(_nominee);
    address[3] memory _others = [_pauseHolder, _nominee, _stranger];
    for (uint256 _i = 0; _i < _others.length; _i++) {
      vm.expectRevert(_adminUnauthorized(_others[_i]));
      vm.prank(_others[_i]);
      _roles.renounceAdmin();
    }
    assertEq(_reportedAdmin(), _keyAdmin, 'admin');
    assertEq(_roles.pendingAdmin(), _nominee, 'pendingAdmin');
  }

  /// @notice While the method is paused, the key admin can still offer its role, the nominee can still accept
  ///         it and the new admin can still renounce it. The stop stays on throughout. The key admin role is
  ///         separate from the stop, so a paused method can still hand over or freeze its keys.
  function test_WhenTheKeyAdminRoleChangesHandsWhilePaused() external {
    vm.prank(_pauseHolder);
    _roles.pause();

    // it should let the key admin offer the role.
    vm.prank(_keyAdmin);
    _roles.transferAdmin(_nominee);
    assertEq(_roles.pendingAdmin(), _nominee, 'pendingAdmin');

    // it should let the nominee accept the role.
    vm.prank(_nominee);
    _roles.acceptAdmin();
    assertEq(_reportedAdmin(), _nominee, 'admin handed over');
    assertEq(_roles.pendingAdmin(), address(0), 'offer closed');

    // it should let the new admin renounce the role.
    vm.prank(_nominee);
    _roles.renounceAdmin();
    assertEq(_reportedAdmin(), address(0), 'admin renounced');

    // it should leave the method paused.
    assertTrue(_roles.paused(), 'paused');
    assertEq(_roles.owner(), _pauseHolder, 'owner');
  }

  /// @notice The key admin cannot stop, lift, offer, accept or renounce the pause holder role. Holding the keys
  ///         must not grant the power to block or unblock every recovery that relies on the method.
  function test_RevertWhen_TheKeyAdminCallsAPauseHolderFunction() external {
    vm.startPrank(_keyAdmin);
    vm.expectRevert(_unauthorized(_keyAdmin));
    _roles.pause();
    vm.expectRevert(_unauthorized(_keyAdmin));
    _roles.transferOwnership(_keyAdmin);
    vm.expectRevert(_unauthorized(_keyAdmin));
    _roles.renounceOwnership();
    vm.expectRevert(_unauthorized(_keyAdmin));
    _roles.acceptOwnership();
    vm.stopPrank();

    vm.prank(_pauseHolder);
    _roles.pause();
    vm.expectRevert(_unauthorized(_keyAdmin));
    vm.prank(_keyAdmin);
    _roles.unpause();

    assertTrue(_roles.paused(), 'paused');
    assertEq(_roles.owner(), _pauseHolder, 'owner');
    assertEq(_roles.pendingOwner(), address(0), 'pendingOwner');
  }
}
