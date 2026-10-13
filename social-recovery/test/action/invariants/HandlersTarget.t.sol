// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {IRecoveryAction} from 'interfaces/IRecoveryAction.sol';
import {ActionPaymentToken} from 'test/mocks/ActionAmbireAccountFixture.sol';
import {ActionBaseHandler} from 'test/action/invariants/handlers/BaseHandler.t.sol';
import {ActionHandlerCancelByOwner} from 'test/action/invariants/handlers/HandlerCancelByOwner.t.sol';
import {ActionHandlerExecuteBatch} from 'test/action/invariants/handlers/HandlerExecuteBatch.t.sol';
import {ActionHandlerExecuteHandover} from 'test/action/invariants/handlers/HandlerExecuteHandover.t.sol';
import {ActionHandlerOpenAttempt} from 'test/action/invariants/handlers/HandlerOpenAttempt.t.sol';
import {ActionHandlerSendAgain} from 'test/action/invariants/handlers/HandlerSendAgain.t.sol';
import {ActionHandlerSetTokenAnswer} from 'test/action/invariants/handlers/HandlerSetTokenAnswer.t.sol';
import {ActionHandlerWritePrivilege} from 'test/action/invariants/handlers/HandlerWritePrivilege.t.sol';
import {PolicyManagerHarness} from 'test/utils/PolicyManagerHarness.sol';

/// @notice The one contract the fuzzer calls in the recovery action's invariant suite. It inherits
///         every handler, so one run mixes all of their calls in a random order.
contract ActionHandlersTarget is
  ActionHandlerOpenAttempt,
  ActionHandlerExecuteHandover,
  ActionHandlerExecuteBatch,
  ActionHandlerSendAgain,
  ActionHandlerWritePrivilege,
  ActionHandlerCancelByOwner,
  ActionHandlerSetTokenAnswer
{
  /// @dev Passes the deployed contracts and the address lists to the shared handler state.
  constructor(
    PolicyManagerHarness _managerUnderTest,
    IRecoveryAction _actionUnderTest,
    address _accountUnderTest,
    ActionPaymentToken _orderToken,
    address[] memory _keyList,
    address[] memory _senderList
  ) ActionBaseHandler(_managerUnderTest, _actionUnderTest, _accountUnderTest, _orderToken, _keyList, _senderList) {}
}
