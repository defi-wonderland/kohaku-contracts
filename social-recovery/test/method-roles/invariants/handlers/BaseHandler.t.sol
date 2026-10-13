// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {CommonBase} from 'forge-std/Base.sol';
import {StdCheats} from 'forge-std/StdCheats.sol';
import {StdUtils} from 'forge-std/StdUtils.sol';
import {MethodRolesHarness} from 'test/mocks/MethodRolesHarness.sol';
import {
  MethodRolesCall,
  MethodRolesSnapshot,
  PolicyMethodRolesGhostStorage
} from 'test/method-roles/invariants/handlers/GhostStorage.t.sol';

/// @notice The state and helpers that every handler of the roles invariant suite shares. It holds the method
///         under test and the callers the handlers pick from. It also reads the method before and after each
///         handler call and records the result.
abstract contract PolicyMethodRolesBaseHandler is PolicyMethodRolesGhostStorage, CommonBase, StdCheats, StdUtils {
  /// @notice One renounce call in this many comes from the holder of the role.
  uint256 internal constant _RARE = 16;

  /// @notice The method under test.
  MethodRolesHarness public roles;
  /// @notice The callers the handlers pick from. They are distinct, and the zero address is one of them.
  address[] public actors;
  /// @notice The one word the harness hook refuses.
  bytes32 public marker;

  /// @dev Stores the method and the callers, and reads the word the method's hook refuses.
  constructor(MethodRolesHarness _roles, address[] memory _actors) {
    roles = _roles;
    actors = _actors;
    marker = _roles.MARKER();
  }

  /*///////////////////////////////////////////////////////////////
                                HELPERS
  ///////////////////////////////////////////////////////////////*/

  /// @dev Picks one of the actors, the zero address among them, from a fuzzed seed.
  function _actor(uint256 _seed) internal view returns (address _picked) {
    _picked = actors[_seed % actors.length];
  }

  /// @dev Picks one of the actors other than `_excluded` from a fuzzed seed. The actors are distinct,
  ///      so when the seed lands on `_excluded` the next actor in the list is a different one.
  function _actorOtherThan(address _excluded, uint256 _seed) internal view returns (address _picked) {
    uint256 _index = _seed % actors.length;
    _picked = actors[_index];
    if (_picked == _excluded) _picked = actors[(_index + 1) % actors.length];
  }

  /// @dev Reads both roles, the keys and the stop from the method.
  function _read() internal view returns (MethodRolesSnapshot memory _snapshot) {
    bytes32[] memory _keys;
    (_snapshot.admin, _snapshot.pendingAdmin, _keys, _snapshot.owner, _snapshot.pendingOwner) = roles.trustedParties();
    _snapshot.keysHash = keccak256(abi.encodePacked(_keys));
    _snapshot.paused = roles.paused();
  }

  /// @dev Stores the call, its caller, its outcome and both readings. `_entitled` is true when the caller
  ///      held the role the call needs and the call's own precondition held. A revert of such a call counts
  ///      as a refusal.
  function _record(MethodRolesCall _call, address _caller, bool _ok, MethodRolesSnapshot memory _pre, bool _entitled)
    internal
  {
    ghost_lastCall = _call;
    ghost_lastCaller = _caller;
    ghost_lastSucceeded = _ok;
    _ghostBefore = _pre;
    _ghostAfter = _read();
    if (_entitled && !_ok) ghost_holderRefusals++;
  }
}
