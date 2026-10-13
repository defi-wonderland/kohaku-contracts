// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {MethodRolesCall} from 'test/method-roles/invariants/handlers/GhostStorage.t.sol';
import {PolicyMethodRolesInvariantSetup} from 'test/method-roles/invariants/Setup.t.sol';

/// @notice Walks whole sequences of handler calls with chosen arguments, to show each handler reaches
///         the role call it names and that the holder's calls go through instead of reverting.
/// @dev The actors are, in order, the pause holder, the key admin, carol, dave, erin and the zero
///      address, so a target seed of 2 picks carol and 3 picks dave. A holder seed of 0 makes the
///      holder send a renounce.
contract PolicyMethodRolesExecutionPaths is PolicyMethodRolesInvariantSetup {
  /// @notice Carol, as the actors list orders her.
  uint256 internal constant _CAROL = 2;
  /// @notice Dave, as the actors list orders him.
  uint256 internal constant _DAVE = 3;
  /// @notice The holder seed that makes the holder send a renounce.
  uint256 internal constant _HOLDER_RENOUNCES = 0;

  /*///////////////////////////////////////////////////////////////
                            EXECUTION PATHS
  ///////////////////////////////////////////////////////////////*/

  /// @notice The key admin sets keys and offers the role to carol. Carol accepts and sets keys of her own. A
  ///         stranger's renounce is refused, then carol renounces. Each holder call goes through, and the
  ///         renounce freezes the keys carol set.
  function test_keyAdminPath() external {
    _handler.handler_setTrustedKeys(0, true, 7, 2, false);
    _assertLast(MethodRolesCall.SetTrustedKeys, true);
    assertTrue(_handler.ghost_before().keysHash != _handler.ghost_after().keysHash, 'keys did not move');

    _handler.handler_transferAdmin(0, true, _CAROL);
    _assertLast(MethodRolesCall.TransferAdmin, true);
    address _carol = _handler.actors(_CAROL);
    assertEq(_roles.pendingAdmin(), _carol, 'carol not offered');

    _handler.handler_acceptAdmin(0, true);
    _assertLast(MethodRolesCall.AcceptAdmin, true);
    assertEq(_handler.ghost_after().admin, _carol, 'carol not admin');

    _handler.handler_setTrustedKeys(0, true, 9, 3, false);
    _assertLast(MethodRolesCall.SetTrustedKeys, true);
    assertEq(_handler.ghost_lastCaller(), _carol, 'keys not set by carol');

    _handler.handler_renounceAdmin(_DAVE, 1);
    _assertLast(MethodRolesCall.RenounceAdmin, false);

    _handler.handler_renounceAdmin(0, _HOLDER_RENOUNCES);
    _assertLast(MethodRolesCall.RenounceAdmin, true);
    assertTrue(_handler.ghost_adminRenounced(), 'renounce not recorded');
    assertEq(_handler.ghost_keysHashAtRenounce(), _handler.ghost_before().keysHash, 'frozen keys');
    assertEq(_handler.ghost_holderRefusals(), 0, 'a holder was refused');
  }

  /// @notice The pause holder pauses and unpauses, then offers the role to dave. Dave accepts and pauses,
  ///         then renounces while paused. Each holder call goes through, and the method stays paused forever.
  function test_pauseHolderPath() external {
    _handler.handler_pause(0, true);
    _assertLast(MethodRolesCall.Pause, true);
    assertTrue(_roles.paused(), 'not paused');

    _handler.handler_unpause(0, true);
    _assertLast(MethodRolesCall.Unpause, true);
    assertFalse(_roles.paused(), 'still paused');

    _handler.handler_transferOwnership(0, true, _DAVE);
    _assertLast(MethodRolesCall.TransferOwnership, true);
    address _dave = _handler.actors(_DAVE);
    assertEq(_roles.pendingOwner(), _dave, 'dave not offered');

    _handler.handler_acceptOwnership(0, true);
    _assertLast(MethodRolesCall.AcceptOwnership, true);
    assertEq(_roles.owner(), _dave, 'dave not pause holder');

    _handler.handler_pause(0, true);
    _assertLast(MethodRolesCall.Pause, true);

    _handler.handler_renounceOwnership(0, _HOLDER_RENOUNCES);
    _assertLast(MethodRolesCall.RenounceOwnership, true);
    assertTrue(_handler.ghost_stoppedForGood(), 'stop not recorded as for good');
    assertEq(_handler.ghost_holderRefusals(), 0, 'a holder was refused');
  }

  /// @dev Asserts the last handler call sent `_call` and went through exactly when `_succeeded` says.
  function _assertLast(MethodRolesCall _call, bool _succeeded) internal view {
    assertEq(uint256(_handler.ghost_lastCall()), uint256(_call), 'last call');
    assertEq(_handler.ghost_lastSucceeded(), _succeeded, 'last outcome');
  }
}
