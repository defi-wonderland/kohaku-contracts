// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {PolicyMethodRolesBaseHandler} from 'test/method-roles/invariants/handlers/BaseHandler.t.sol';
import {MethodRolesCall, MethodRolesSnapshot} from 'test/method-roles/invariants/handlers/GhostStorage.t.sol';

/// @notice The handlers for the five pause holder calls. Each handler sends pause, unpause,
///         transferOwnership, acceptOwnership or renounceOwnership, either from the address the call needs or
///         from a random actor.
abstract contract PolicyMethodRolesHandlerPauseHolder is PolicyMethodRolesBaseHandler {
  /*///////////////////////////////////////////////////////////////
                                HANDLERS
  ///////////////////////////////////////////////////////////////*/

  /// @notice Calls pause. When `_asHolder` is true the current pause holder sends it, otherwise
  ///         `_actorSeed` picks the caller among the actors.
  function handler_pause(uint256 _actorSeed, bool _asHolder) external {
    MethodRolesSnapshot memory _pre = _read();
    address _caller = _asHolder ? _pre.owner : _actor(_actorSeed);
    vm.prank(_caller);
    bool _ok;
    try roles.pause() {
      _ok = true;
    } catch {
      _ok = false;
    }
    _record(
      MethodRolesCall.Pause, _caller, _ok, _pre, _caller == _pre.owner && _pre.owner != address(0) && !_pre.paused
    );
  }

  /// @notice Calls unpause. When `_asHolder` is true the current pause holder sends it, otherwise
  ///         `_actorSeed` picks the caller among the actors.
  function handler_unpause(uint256 _actorSeed, bool _asHolder) external {
    MethodRolesSnapshot memory _pre = _read();
    address _caller = _asHolder ? _pre.owner : _actor(_actorSeed);
    vm.prank(_caller);
    bool _ok;
    try roles.unpause() {
      _ok = true;
    } catch {
      _ok = false;
    }
    _record(
      MethodRolesCall.Unpause, _caller, _ok, _pre, _caller == _pre.owner && _pre.owner != address(0) && _pre.paused
    );
  }

  /// @notice Calls transferOwnership to offer the pause holder role to an actor `_targetSeed` picks,
  ///         the zero address included. When `_asHolder` is true the current pause holder sends it,
  ///         otherwise `_actorSeed` picks the caller among the actors.
  function handler_transferOwnership(uint256 _actorSeed, bool _asHolder, uint256 _targetSeed) external {
    MethodRolesSnapshot memory _pre = _read();
    address _caller = _asHolder ? _pre.owner : _actor(_actorSeed);
    address _target = _actor(_targetSeed);
    vm.prank(_caller);
    bool _ok;
    try roles.transferOwnership(_target) {
      _ok = true;
    } catch {
      _ok = false;
    }
    _record(MethodRolesCall.TransferOwnership, _caller, _ok, _pre, _caller == _pre.owner && _pre.owner != address(0));
  }

  /// @notice Calls acceptOwnership. When `_asHolder` is true the address currently offered the pause
  ///         holder role sends it, otherwise `_actorSeed` picks the caller among the actors.
  function handler_acceptOwnership(uint256 _actorSeed, bool _asHolder) external {
    MethodRolesSnapshot memory _pre = _read();
    address _caller = _asHolder ? _pre.pendingOwner : _actor(_actorSeed);
    vm.prank(_caller);
    bool _ok;
    try roles.acceptOwnership() {
      _ok = true;
    } catch {
      _ok = false;
    }
    _record(
      MethodRolesCall.AcceptOwnership,
      _caller,
      _ok,
      _pre,
      _caller == _pre.pendingOwner && _pre.pendingOwner != address(0)
    );
  }

  /// @notice Calls renounceOwnership. The current pause holder sends it only when `_holderSeed` is a multiple
  ///         of sixteen. Otherwise `_actorSeed` picks an actor other than the pause holder. Renouncing ends
  ///         the role for the rest of the sequence. Keeping it rare leaves a pause holder in place long
  ///         enough to hand the role over and to pause and unpause in turn.
  function handler_renounceOwnership(uint256 _actorSeed, uint256 _holderSeed) external {
    MethodRolesSnapshot memory _pre = _read();
    address _caller = _holderSeed % _RARE == 0 ? _pre.owner : _actorOtherThan(_pre.owner, _actorSeed);
    vm.prank(_caller);
    bool _ok;
    try roles.renounceOwnership() {
      _ok = true;
    } catch {
      _ok = false;
    }
    _record(MethodRolesCall.RenounceOwnership, _caller, _ok, _pre, _caller == _pre.owner && _pre.owner != address(0));
    if (_ok && _ghostAfter.paused) ghost_stoppedForGood = true;
  }
}
