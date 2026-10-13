// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {MethodRolesHarness} from 'test/mocks/MethodRolesHarness.sol';
import {PolicyMethodRolesBaseHandler} from 'test/method-roles/invariants/handlers/BaseHandler.t.sol';
import {PolicyMethodRolesHandlerKeyAdmin} from 'test/method-roles/invariants/handlers/HandlerKeyAdmin.t.sol';
import {PolicyMethodRolesHandlerPauseHolder} from 'test/method-roles/invariants/handlers/HandlerPauseHolder.t.sol';

/// @notice The one contract the roles invariant suite targets. It inherits the key admin and pause
///         holder handlers, so the fuzzer sends every role call from random callers in random orders.
contract PolicyMethodRolesHandlersTarget is PolicyMethodRolesHandlerKeyAdmin, PolicyMethodRolesHandlerPauseHolder {
  /// @dev Hands the method and the callers to the shared handler state.
  constructor(MethodRolesHarness _roles, address[] memory _actors) PolicyMethodRolesBaseHandler(_roles, _actors) {}
}
