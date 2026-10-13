// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {StdInvariant} from 'forge-std/StdInvariant.sol';
import {Test} from 'forge-std/Test.sol';
import {MethodRolesHarness} from 'test/mocks/MethodRolesHarness.sol';
import {PolicyMethodRolesHandlersTarget} from 'test/method-roles/invariants/HandlersTarget.t.sol';

/// @notice Deploys the roles invariant suite. It deploys a method harness with two initial keys and the
///         handlers target over a list of callers. The fuzzer sends the nine role calls of that target.
contract PolicyMethodRolesInvariantSetup is StdInvariant, Test {
  MethodRolesHarness internal _roles;
  PolicyMethodRolesHandlersTarget internal _handler;

  /// @dev Deploys the harness with the role holders `_roleHolders` names, deploys the handlers target
  ///      over its callers, and targets the nine handler calls.
  function setUp() public virtual {
    (address _owner, address _admin, address[] memory _actors) = _roleHolders();
    bytes32[] memory _keys = new bytes32[](2);
    _keys[0] = keccak256('initial.key.0');
    _keys[1] = keccak256('initial.key.1');
    _roles = new MethodRolesHarness(_owner, _admin, _keys, 'Harness Method', '1.0.0');
    _handler = new PolicyMethodRolesHandlersTarget(_roles, _actors);

    bytes4[] memory _selectors = new bytes4[](9);
    _selectors[0] = _handler.handler_setTrustedKeys.selector;
    _selectors[1] = _handler.handler_transferAdmin.selector;
    _selectors[2] = _handler.handler_acceptAdmin.selector;
    _selectors[3] = _handler.handler_renounceAdmin.selector;
    _selectors[4] = _handler.handler_pause.selector;
    _selectors[5] = _handler.handler_unpause.selector;
    _selectors[6] = _handler.handler_transferOwnership.selector;
    _selectors[7] = _handler.handler_acceptOwnership.selector;
    _selectors[8] = _handler.handler_renounceOwnership.selector;
    targetSelector(FuzzSelector({addr: address(_handler), selectors: _selectors}));
    targetContract(address(_handler));
  }

  /// @dev The initial pause holder, the initial key admin and the callers the handlers draw from.
  ///      Here the two roles start with different addresses.
  function _roleHolders() internal virtual returns (address _owner, address _admin, address[] memory _actors) {
    _owner = makeAddr('pauseHolder');
    _admin = makeAddr('keyAdmin');
    _actors = new address[](6);
    _actors[0] = _owner;
    _actors[1] = _admin;
    _actors[2] = makeAddr('carol');
    _actors[3] = makeAddr('dave');
    _actors[4] = makeAddr('erin');
    _actors[5] = address(0);
  }
}
