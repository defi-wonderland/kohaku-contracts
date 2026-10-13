// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {StdInvariant} from 'forge-std/StdInvariant.sol';
import {Test} from 'forge-std/Test.sol';
import {PolicyManagerMockAction} from 'test/mocks/PolicyManagerMockAction.sol';
import {PolicyManagerHandlersTarget} from 'test/policy-manager/invariants/HandlersTarget.t.sol';
import {PolicyManagerHarness} from 'test/utils/PolicyManagerHarness.sol';

/// @notice Deploys the policy manager's invariant suite: the manager harness, and the handlers
///         target over three callers and two actions, whose handler calls the fuzzer sends.
contract PolicyManagerInvariantSetup is StdInvariant, Test {
  PolicyManagerHarness internal _manager;
  PolicyManagerHandlersTarget internal _handler;

  /// @dev Deploys the manager harness and a handler over three callers and two actions, and targets
  ///      the handler's thirteen calls. Both actions carry the mock action's code, which answers true
  ///      to supportsAccount for every account, so commitSetup accepts them.
  function setUp() public {
    _manager = new PolicyManagerHarness();
    address[] memory _callerList = new address[](3);
    _callerList[0] = makeAddr('alice');
    _callerList[1] = makeAddr('bob');
    _callerList[2] = makeAddr('carol');
    address[] memory _actionList = new address[](2);
    _actionList[0] = makeAddr('recoveryAction');
    _actionList[1] = makeAddr('otherAction');
    address _servingCode = address(new PolicyManagerMockAction());
    vm.etch(_actionList[0], _servingCode.code);
    vm.etch(_actionList[1], _servingCode.code);
    _handler = new PolicyManagerHandlersTarget(_manager, _callerList, _actionList);

    bytes4[] memory _selectors = new bytes4[](13);
    _selectors[0] = _handler.handler_commitSetup.selector;
    _selectors[1] = _handler.handler_clearSetup.selector;
    _selectors[2] = _handler.handler_cancelByOwner.selector;
    _selectors[3] = _handler.handler_startAttempt.selector;
    _selectors[4] = _handler.handler_cancelByProofs.selector;
    _selectors[5] = _handler.handler_replayApproval.selector;
    _selectors[6] = _handler.handler_replayCancel.selector;
    _selectors[7] = _handler.handler_consume.selector;
    _selectors[8] = _handler.handler_cancelByVeto.selector;
    _selectors[9] = _handler.handler_setStopped.selector;
    _selectors[10] = _handler.handler_deployMethod.selector;
    _selectors[11] = _handler.handler_warp.selector;
    _selectors[12] = _handler.handler_roll.selector;
    targetSelector(FuzzSelector({addr: address(_handler), selectors: _selectors}));
    targetContract(address(_handler));
  }
}
