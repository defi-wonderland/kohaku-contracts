// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {PolicyMethodRolesBaseHandler} from 'test/method-roles/invariants/handlers/BaseHandler.t.sol';
import {MethodRolesCall, MethodRolesSnapshot} from 'test/method-roles/invariants/handlers/GhostStorage.t.sol';

/// @notice The handlers for the four key admin calls. Each handler sends setTrustedKeys, transferAdmin,
///         acceptAdmin or renounceAdmin, either from the address the call needs or from a random actor.
abstract contract PolicyMethodRolesHandlerKeyAdmin is PolicyMethodRolesBaseHandler {
  /*///////////////////////////////////////////////////////////////
                                HANDLERS
  ///////////////////////////////////////////////////////////////*/

  /// @notice Calls setTrustedKeys with a list of zero to four words. When `_asHolder` is true the current key
  ///         admin sends it, otherwise `_actorSeed` picks the caller among the actors. When `_withMarker` is
  ///         true the list holds the word the hook refuses at one position, so even the key admin is refused.
  ///         Otherwise `_keysSeed` derives every word.
  function handler_setTrustedKeys(
    uint256 _actorSeed,
    bool _asHolder,
    uint256 _keysSeed,
    uint256 _lengthSeed,
    bool _withMarker
  ) external {
    MethodRolesSnapshot memory _pre = _read();
    address _caller = _asHolder ? _pre.admin : _actor(_actorSeed);
    uint256 _length = bound(_lengthSeed, _withMarker ? 1 : 0, 4);
    bytes32[] memory _keys = new bytes32[](_length);
    for (uint256 _i = 0; _i < _length; _i++) {
      _keys[_i] = keccak256(abi.encode(_keysSeed, _i));
    }
    if (_withMarker) _keys[_keysSeed % _length] = marker;
    vm.prank(_caller);
    bool _ok;
    try roles.setTrustedKeys(_keys) {
      _ok = true;
    } catch {
      _ok = false;
    }
    _record(
      MethodRolesCall.SetTrustedKeys,
      _caller,
      _ok,
      _pre,
      _caller == _pre.admin && _pre.admin != address(0) && !_withMarker
    );
  }

  /// @notice Calls transferAdmin to offer the key admin role to an actor `_targetSeed` picks, the zero
  ///         address included. When `_asHolder` is true the current key admin sends it, otherwise
  ///         `_actorSeed` picks the caller among the actors.
  function handler_transferAdmin(uint256 _actorSeed, bool _asHolder, uint256 _targetSeed) external {
    MethodRolesSnapshot memory _pre = _read();
    address _caller = _asHolder ? _pre.admin : _actor(_actorSeed);
    address _target = _actor(_targetSeed);
    vm.prank(_caller);
    bool _ok;
    try roles.transferAdmin(_target) {
      _ok = true;
    } catch {
      _ok = false;
    }
    _record(MethodRolesCall.TransferAdmin, _caller, _ok, _pre, _caller == _pre.admin && _pre.admin != address(0));
  }

  /// @notice Calls acceptAdmin. When `_asHolder` is true the address currently offered the key admin
  ///         role sends it, otherwise `_actorSeed` picks the caller among the actors.
  function handler_acceptAdmin(uint256 _actorSeed, bool _asHolder) external {
    MethodRolesSnapshot memory _pre = _read();
    address _caller = _asHolder ? _pre.pendingAdmin : _actor(_actorSeed);
    vm.prank(_caller);
    bool _ok;
    try roles.acceptAdmin() {
      _ok = true;
    } catch {
      _ok = false;
    }
    _record(
      MethodRolesCall.AcceptAdmin, _caller, _ok, _pre, _caller == _pre.pendingAdmin && _pre.pendingAdmin != address(0)
    );
  }

  /// @notice Calls renounceAdmin. The current key admin sends it only when `_holderSeed` is a multiple of
  ///         sixteen. Otherwise `_actorSeed` picks an actor other than the key admin. Renouncing ends the
  ///         role for the rest of the sequence. Keeping it rare leaves a key admin in place long enough to
  ///         hand the role over, replace and cancel offers, and set keys after a handover.
  function handler_renounceAdmin(uint256 _actorSeed, uint256 _holderSeed) external {
    MethodRolesSnapshot memory _pre = _read();
    address _caller = _holderSeed % _RARE == 0 ? _pre.admin : _actorOtherThan(_pre.admin, _actorSeed);
    vm.prank(_caller);
    bool _ok;
    try roles.renounceAdmin() {
      _ok = true;
    } catch {
      _ok = false;
    }
    _record(MethodRolesCall.RenounceAdmin, _caller, _ok, _pre, _caller == _pre.admin && _pre.admin != address(0));
    if (_ok) {
      ghost_adminRenounced = true;
      ghost_keysHashAtRenounce = _ghostAfter.keysHash;
    }
  }
}
