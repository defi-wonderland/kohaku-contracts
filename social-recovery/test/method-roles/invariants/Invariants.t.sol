// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {MethodRolesCall, MethodRolesSnapshot} from 'test/method-roles/invariants/handlers/GhostStorage.t.sol';
import {PolicyMethodRolesInvariantSetup} from 'test/method-roles/invariants/Setup.t.sol';

/// @notice Checks who may act on each role of a method after every call of long random call sequences. Here
///         the pause holder and the key admin are different addresses. The unit tests check each function
///         once. These properties check that no order of calls lets a role leak.
contract PolicyMethodRolesInvariants is PolicyMethodRolesInvariantSetup {
  /*///////////////////////////////////////////////////////////////
                              INVARIANTS
  ///////////////////////////////////////////////////////////////*/

  /// @notice This property watches the effect. Whenever the stored keys change, the change came from
  ///         setTrustedKeys called by the key admin. So even a call that is not meant to touch the keys
  ///         cannot change them. A key changed by anyone else would let them forge every proof of the method.
  function invariant_onlyTheKeyAdminMovesTheKeys() external view {
    MethodRolesSnapshot memory _pre = _handler.ghost_before();
    MethodRolesSnapshot memory _post = _handler.ghost_after();
    if (_pre.keysHash == _post.keysHash) return;
    assertEq(uint256(_handler.ghost_lastCall()), uint256(MethodRolesCall.SetTrustedKeys), 'keys moved by another call');
    assertEq(_handler.ghost_lastCaller(), _pre.admin, 'keys moved by a non-admin');
    assertTrue(_pre.admin != address(0), 'keys moved with no admin');
  }

  /// @notice This property watches the action. Whenever setTrustedKeys, transferAdmin or renounceAdmin
  ///         succeeds, the key admin made the call. So a stranger cannot offer or give up the role, even when
  ///         the keys do not change.
  function invariant_onlyTheKeyAdminActsAsKeyAdmin() external view {
    MethodRolesCall _call = _handler.ghost_lastCall();
    bool _keyAdminCall = _call == MethodRolesCall.SetTrustedKeys || _call == MethodRolesCall.TransferAdmin
      || _call == MethodRolesCall.RenounceAdmin;
    if (!_keyAdminCall || !_handler.ghost_lastSucceeded()) return;
    MethodRolesSnapshot memory _pre = _handler.ghost_before();
    assertEq(_handler.ghost_lastCaller(), _pre.admin, 'key admin call from a non-admin');
    assertTrue(_pre.admin != address(0), 'key admin call with no admin');
  }

  /// @notice Only the address offered the key admin role can accept it. After it accepts, it holds the role
  ///         and no offer stays open. So nobody takes the role without an offer.
  function invariant_onlyTheOfferedAddressTakesTheKeyAdminRole() external view {
    if (_handler.ghost_lastCall() != MethodRolesCall.AcceptAdmin || !_handler.ghost_lastSucceeded()) return;
    MethodRolesSnapshot memory _pre = _handler.ghost_before();
    MethodRolesSnapshot memory _post = _handler.ghost_after();
    assertEq(_handler.ghost_lastCaller(), _pre.pendingAdmin, 'accepted by a non-nominee');
    assertTrue(_pre.pendingAdmin != address(0), 'accepted with no offer');
    assertEq(_post.admin, _pre.pendingAdmin, 'nominee not made admin');
    assertEq(_post.pendingAdmin, address(0), 'offer left open');
  }

  /// @notice This property watches the action. Whenever pause, unpause, transferOwnership or
  ///         renounceOwnership succeeds, the pause holder made the call. So a stranger cannot offer or give
  ///         up the role, even when the stop does not change.
  function invariant_onlyThePauseHolderActsAsPauseHolder() external view {
    MethodRolesCall _call = _handler.ghost_lastCall();
    bool _holderCall = _call == MethodRolesCall.Pause || _call == MethodRolesCall.Unpause
      || _call == MethodRolesCall.TransferOwnership || _call == MethodRolesCall.RenounceOwnership;
    if (!_holderCall || !_handler.ghost_lastSucceeded()) return;
    MethodRolesSnapshot memory _pre = _handler.ghost_before();
    assertEq(_handler.ghost_lastCaller(), _pre.owner, 'pause holder call from a non-holder');
    assertTrue(_pre.owner != address(0), 'pause holder call with no holder');
  }

  /// @notice Only the address offered the pause holder role can accept it. After it accepts, it holds the
  ///         role and no offer stays open. So nobody takes the role without an offer.
  function invariant_onlyTheOfferedAddressTakesThePauseHolderRole() external view {
    if (_handler.ghost_lastCall() != MethodRolesCall.AcceptOwnership || !_handler.ghost_lastSucceeded()) return;
    MethodRolesSnapshot memory _pre = _handler.ghost_before();
    MethodRolesSnapshot memory _post = _handler.ghost_after();
    assertEq(_handler.ghost_lastCaller(), _pre.pendingOwner, 'accepted by a non-nominee');
    assertTrue(_pre.pendingOwner != address(0), 'accepted with no offer');
    assertEq(_post.owner, _pre.pendingOwner, 'nominee not made pause holder');
    assertEq(_post.pendingOwner, address(0), 'offer left open');
  }

  /// @notice This property watches the effect. Whenever the stop changes, the change came from pause or
  ///         unpause called by the pause holder. So even a call that is not meant to touch the stop cannot
  ///         change it. A stop changed by anyone else could block or release every recovery through the
  ///         method.
  function invariant_onlyThePauseHolderMovesTheStop() external view {
    MethodRolesSnapshot memory _pre = _handler.ghost_before();
    MethodRolesSnapshot memory _post = _handler.ghost_after();
    if (_pre.paused == _post.paused) return;
    MethodRolesCall _call = _handler.ghost_lastCall();
    assertTrue(_call == MethodRolesCall.Pause || _call == MethodRolesCall.Unpause, 'stop moved by another call');
    assertEq(_handler.ghost_lastCaller(), _pre.owner, 'stop moved by a non-holder');
    assertTrue(_pre.owner != address(0), 'stop moved with no holder');
  }

  /// @notice A key admin call never touches the pause holder's role. Whether it succeeds or fails, the pause
  ///         holder, the address offered that role and the stop stay as they were.
  function invariant_keyAdminCallsLeaveThePauseHolderRoleAlone() external view {
    MethodRolesCall _call = _handler.ghost_lastCall();
    bool _keyAdminCall = _call == MethodRolesCall.SetTrustedKeys || _call == MethodRolesCall.TransferAdmin
      || _call == MethodRolesCall.AcceptAdmin || _call == MethodRolesCall.RenounceAdmin;
    if (!_keyAdminCall) return;
    MethodRolesSnapshot memory _pre = _handler.ghost_before();
    MethodRolesSnapshot memory _post = _handler.ghost_after();
    assertEq(_post.owner, _pre.owner, 'pause holder moved');
    assertEq(_post.pendingOwner, _pre.pendingOwner, 'pending pause holder moved');
    assertEq(_post.paused, _pre.paused, 'stop moved');
  }

  /// @notice A pause holder call never touches the key admin's role. Whether it succeeds or fails, the key
  ///         admin, the address offered that role and the trusted keys stay as they were.
  function invariant_pauseHolderCallsLeaveTheKeyAdminRoleAlone() external view {
    MethodRolesCall _call = _handler.ghost_lastCall();
    bool _holderCall = _call == MethodRolesCall.Pause || _call == MethodRolesCall.Unpause
      || _call == MethodRolesCall.TransferOwnership || _call == MethodRolesCall.AcceptOwnership
      || _call == MethodRolesCall.RenounceOwnership;
    if (!_holderCall) return;
    MethodRolesSnapshot memory _pre = _handler.ghost_before();
    MethodRolesSnapshot memory _post = _handler.ghost_after();
    assertEq(_post.admin, _pre.admin, 'key admin moved');
    assertEq(_post.pendingAdmin, _pre.pendingAdmin, 'pending key admin moved');
    assertEq(_post.keysHash, _pre.keysHash, 'keys moved');
  }

  /// @notice After the key admin renounces, nobody holds or is offered the role again, and the trusted keys
  ///         never change.
  function invariant_renouncedKeyAdminRoleStaysEmpty() external view {
    if (!_handler.ghost_adminRenounced()) return;
    (address _admin, address _pendingAdmin, bytes32[] memory _keys,,) = _roles.trustedParties();
    assertEq(_admin, address(0), 'admin came back');
    assertEq(_pendingAdmin, address(0), 'offer open after renounce');
    assertEq(keccak256(abi.encodePacked(_keys)), _handler.ghost_keysHashAtRenounce(), 'keys moved after renounce');
  }

  /// @notice If the pause holder renounces while the method is paused, the method stays paused forever, and
  ///         nobody holds or is offered the role again.
  function invariant_renouncedWhilePausedStaysStopped() external view {
    if (!_handler.ghost_stoppedForGood()) return;
    assertTrue(_roles.paused(), 'stop lifted after renounce');
    assertEq(_roles.owner(), address(0), 'pause holder came back');
    assertEq(_roles.pendingOwner(), address(0), 'offer open after renounce');
  }

  /// @notice A role holder can always do what the role allows. The key admin can always set valid keys, offer
  ///         the role or renounce it. The address offered a role can always accept it. The pause holder can
  ///         always pause a running method, unpause a paused one, offer the role or renounce it.
  function invariant_holdersAreNeverRefused() external view {
    assertEq(_handler.ghost_holderRefusals(), 0, 'a role holder was refused');
  }
}

/// @notice Runs the same properties with one address holding both roles. This matches a launch where one
///         multisig holds the key admin role and the pause holder role.
contract PolicyMethodRolesSharedHolderInvariantTest is PolicyMethodRolesInvariants {
  /// @dev One address holds both roles from deployment. The list of callers the handlers draw from includes
  ///      it once.
  function _roleHolders() internal override returns (address _owner, address _admin, address[] memory _actors) {
    _owner = makeAddr('safe');
    _admin = _owner;
    _actors = new address[](5);
    _actors[0] = _owner;
    _actors[1] = makeAddr('carol');
    _actors[2] = makeAddr('dave');
    _actors[3] = makeAddr('erin');
    _actors[4] = address(0);
  }
}
