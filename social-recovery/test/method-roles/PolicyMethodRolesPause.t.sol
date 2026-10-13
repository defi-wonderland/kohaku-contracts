// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {Pausable} from '@openzeppelin/contracts/utils/Pausable.sol';
import {IPolicyMethodPause} from 'interfaces/IPolicyMethodPause.sol';
import {MethodRolesTestBase} from 'test/utils/MethodRolesTestBase.sol';

/// @notice The pause holder's calls, who may send each one, and what each leaves behind.
contract PolicyMethodRolesPauseTest is MethodRolesTestBase {
  /// @notice The pause holder stops a running method, which then reports paused and emits Paused naming
  ///         the holder. The stop is how a suspected bug in an identity method is contained before it is used.
  function test_WhenThePauseHolderPausesAnUnpausedMethod() external {
    // it should emit Paused with the pause holder.
    vm.expectEmit(address(_roles));
    emit IPolicyMethodPause.Paused(_pauseHolder);
    vm.prank(_pauseHolder);
    _roles.pause();
    // it should report paused.
    assertTrue(_roles.paused(), 'paused');
  }

  /// @notice Pausing a method that is already paused reverts with OpenZeppelin's EnforcedPause, since pause
  ///         only calls the library's own pause helper.
  function test_RevertWhen_ThePauseHolderPausesAPausedMethod() external {
    vm.startPrank(_pauseHolder);
    _roles.pause();
    vm.expectRevert(Pausable.EnforcedPause.selector);
    _roles.pause();
    vm.stopPrank();
  }

  /// @notice The pause holder lifts the stop, the method reports running again and emits Unpaused naming
  ///         the holder. A stop that can be lifted can be used before a bug is confirmed.
  function test_WhenThePauseHolderUnpausesAPausedMethod() external {
    vm.prank(_pauseHolder);
    _roles.pause();
    // it should emit Unpaused with the pause holder.
    vm.expectEmit(address(_roles));
    emit IPolicyMethodPause.Unpaused(_pauseHolder);
    vm.prank(_pauseHolder);
    _roles.unpause();
    // it should report not paused.
    assertFalse(_roles.paused(), 'paused');
  }

  /// @notice Unpausing a running method reverts with OpenZeppelin's ExpectedPause, since unpause only calls
  ///         the library's own unpause helper.
  function test_RevertWhen_ThePauseHolderUnpausesAnUnpausedMethod() external {
    vm.expectRevert(Pausable.ExpectedPause.selector);
    vm.prank(_pauseHolder);
    _roles.unpause();
  }

  /// @notice The key admin, a nominee and a stranger cannot stop the method, and each is refused by name.
  ///         Anyone able to stop the method could block every recovery that relies on it.
  function test_RevertWhen_AnyoneElsePauses() external {
    address[3] memory _others = [_keyAdmin, _nominee, _stranger];
    for (uint256 _i = 0; _i < _others.length; _i++) {
      vm.expectRevert(_unauthorized(_others[_i]));
      vm.prank(_others[_i]);
      _roles.pause();
    }
    assertFalse(_roles.paused(), 'paused');
  }

  /// @notice Nobody but the pause holder can lift a stop, not even the key admin. So a method stopped over a
  ///         suspected bug does not accept proofs again until the pause holder lifts the stop.
  function test_RevertWhen_AnyoneElseUnpauses() external {
    vm.prank(_pauseHolder);
    _roles.pause();
    address[3] memory _others = [_keyAdmin, _nominee, _stranger];
    for (uint256 _i = 0; _i < _others.length; _i++) {
      vm.expectRevert(_unauthorized(_others[_i]));
      vm.prank(_others[_i]);
      _roles.unpause();
    }
    assertTrue(_roles.paused(), 'paused');
  }

  /// @notice The pause holder cannot set keys, offer, take or renounce the key admin role. Holding the stop
  ///         must not grant the power to change what the method trusts, since that power forges proofs.
  function test_RevertWhen_ThePauseHolderCallsAKeyAdminFunction() external {
    bytes32[] memory _fresh = _keyList(keccak256('fresh'));

    vm.startPrank(_pauseHolder);
    vm.expectRevert(_adminUnauthorized(_pauseHolder));
    _roles.setTrustedKeys(_fresh);
    vm.expectRevert(_adminUnauthorized(_pauseHolder));
    _roles.transferAdmin(_pauseHolder);
    vm.expectRevert(_adminUnauthorized(_pauseHolder));
    _roles.renounceAdmin();
    vm.expectRevert(_adminUnauthorized(_pauseHolder));
    _roles.acceptAdmin();
    vm.stopPrank();

    // An open offer to someone else does not let the pause holder accept it either.
    vm.prank(_keyAdmin);
    _roles.transferAdmin(_nominee);
    vm.expectRevert(_adminUnauthorized(_pauseHolder));
    vm.prank(_pauseHolder);
    _roles.acceptAdmin();

    (address _admin, address _pendingAdmin, bytes32[] memory _keys, address _holder,) = _roles.trustedParties();
    assertEq(_admin, _keyAdmin, 'admin');
    assertEq(_pendingAdmin, _nominee, 'pendingAdmin');
    assertEq(_holder, _pauseHolder, '_pauseHolder');
    _assertKeys(_keys, _initialKeys);
  }

  /// @notice Renouncing the pause holder role while paused leaves the method paused forever, since nobody can
  ///         lift the stop. A method judged broken ends this way.
  function test_WhenThePauseHolderRenouncesWhilePaused() external {
    vm.startPrank(_pauseHolder);
    _roles.pause();
    _roles.renounceOwnership();
    vm.stopPrank();

    // it should leave the method paused.
    assertTrue(_roles.paused(), 'paused');
    assertEq(_roles.owner(), address(0), 'owner');
    (,,, address _holder, address _pendingHolder) = _roles.trustedParties();
    assertEq(_holder, address(0), '_pauseHolder');
    assertEq(_pendingHolder, address(0), 'pendingPauseHolder');

    // it should let nobody unpause, the former holder included.
    address[4] memory _everyone = [_pauseHolder, _keyAdmin, _nominee, _stranger];
    for (uint256 _i = 0; _i < _everyone.length; _i++) {
      vm.expectRevert(_unauthorized(_everyone[_i]));
      vm.prank(_everyone[_i]);
      _roles.unpause();
    }
    assertTrue(_roles.paused(), 'still paused');
  }

  /// @notice Renouncing the pause holder role while running leaves a method nobody can stop, the former
  ///         holder included.
  function test_WhenThePauseHolderRenouncesWhileUnpaused() external {
    vm.prank(_pauseHolder);
    _roles.renounceOwnership();

    // it should let nobody pause.
    address[4] memory _everyone = [_pauseHolder, _keyAdmin, _nominee, _stranger];
    for (uint256 _i = 0; _i < _everyone.length; _i++) {
      vm.expectRevert(_unauthorized(_everyone[_i]));
      vm.prank(_everyone[_i]);
      _roles.pause();
    }
    assertFalse(_roles.paused(), 'paused');
  }

  /// @notice Renouncing the pause holder role cancels an open handover. So the earlier nominee cannot take
  ///         the role afterwards and lift the stop the holder gave up.
  function test_WhenThePauseHolderRenouncesWithATransferOpen() external {
    vm.startPrank(_pauseHolder);
    _roles.transferOwnership(_nominee);
    _roles.renounceOwnership();
    vm.stopPrank();

    assertEq(_roles.pendingOwner(), address(0), 'pendingOwner');
    // it should let no earlier nominee accept.
    vm.expectRevert(_unauthorized(_nominee));
    vm.prank(_nominee);
    _roles.acceptOwnership();
    assertEq(_roles.owner(), address(0), 'owner');
  }

  /// @notice Renouncing the pause holder role leaves the key admin able to set keys and hand its role on,
  ///         since each role is given up on its own.
  function test_WhenThePauseHolderRenounces() external {
    vm.startPrank(_pauseHolder);
    _roles.pause();
    _roles.renounceOwnership();
    vm.stopPrank();

    // it should leave the key admin standing.
    assertEq(_reportedAdmin(), _keyAdmin, 'admin');
    bytes32[] memory _fresh = _keyList(keccak256('fresh'));
    vm.prank(_keyAdmin);
    _roles.setTrustedKeys(_fresh);
    _assertKeys(_reportedKeys(), _fresh);

    vm.prank(_keyAdmin);
    _roles.transferAdmin(_nominee);
    vm.prank(_nominee);
    _roles.acceptAdmin();
    assertEq(_reportedAdmin(), _nominee, 'admin handed over');
  }

  /// @notice The pause holder role moves only when the nominee accepts. Afterwards only the new holder can
  ///         stop the method, and the key admin and keys are untouched.
  function test_WhenThePauseHolderRoleIsHandedOverInTwoSteps() external {
    vm.prank(_pauseHolder);
    _roles.transferOwnership(_nominee);
    (,,,, address _pendingHolder) = _roles.trustedParties();
    assertEq(_pendingHolder, _nominee, 'pendingPauseHolder');

    // The nominee cannot stop before accepting.
    vm.expectRevert(_unauthorized(_nominee));
    vm.prank(_nominee);
    _roles.pause();

    vm.prank(_nominee);
    _roles.acceptOwnership();

    // it should let only the new holder pause.
    vm.expectRevert(_unauthorized(_pauseHolder));
    vm.prank(_pauseHolder);
    _roles.pause();
    vm.prank(_nominee);
    _roles.pause();
    assertTrue(_roles.paused(), 'paused');

    // it should leave the key admin and the keys unchanged.
    (address _admin, address _pendingAdmin, bytes32[] memory _keys, address _holder, address _pending) =
      _roles.trustedParties();
    assertEq(_admin, _keyAdmin, 'admin');
    assertEq(_pendingAdmin, address(0), 'pendingAdmin');
    _assertKeys(_keys, _initialKeys);
    assertEq(_holder, _nominee, '_pauseHolder');
    assertEq(_pending, address(0), 'pendingPauseHolder');
  }

  /// @notice After a renounce while paused, a call from the zero address cannot unpause, pause, offer the
  ///         role or renounce it. The zero address stands for an empty role, so it must never act as the
  ///         pause holder.
  function test_RevertWhen_TheZeroAddressCallsAfterThePauseHolderRenouncedWhilePaused() external {
    vm.startPrank(_pauseHolder);
    _roles.pause();
    _roles.renounceOwnership();
    vm.stopPrank();

    vm.startPrank(address(0));
    vm.expectRevert(_unauthorized(address(0)));
    _roles.unpause();
    vm.expectRevert(_unauthorized(address(0)));
    _roles.pause();
    vm.expectRevert(_unauthorized(address(0)));
    _roles.transferOwnership(_nominee);
    vm.expectRevert(_unauthorized(address(0)));
    _roles.renounceOwnership();
    vm.stopPrank();

    // it should leave the method paused.
    assertTrue(_roles.paused(), 'paused');
    assertEq(_roles.owner(), address(0), 'owner');
    assertEq(_roles.pendingOwner(), address(0), 'pendingOwner');
  }

  /// @notice With no handover open, the zero address cannot accept the pause holder role. A zero pending
  ///         holder means no offer, never an offer to the zero address.
  function test_RevertWhen_TheZeroAddressAcceptsWithNoTransferOpen() external {
    assertEq(_roles.pendingOwner(), address(0), 'no transfer open');
    vm.expectRevert(_unauthorized(address(0)));
    vm.prank(address(0));
    _roles.acceptOwnership();
    // it should leave the owner unchanged.
    assertEq(_roles.owner(), _pauseHolder, 'owner');
    assertEq(_roles.pendingOwner(), address(0), 'pendingOwner');
  }
}
