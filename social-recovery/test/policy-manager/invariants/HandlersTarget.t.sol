// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {PolicyManagerBaseHandler} from 'test/policy-manager/invariants/handlers/BaseHandler.t.sol';
import {PolicyManagerHandlerCancelByOwner} from 'test/policy-manager/invariants/handlers/HandlerCancelByOwner.t.sol';
import {PolicyManagerHandlerCancelByProofs} from 'test/policy-manager/invariants/handlers/HandlerCancelByProofs.t.sol';
import {PolicyManagerHandlerCancelByVeto} from 'test/policy-manager/invariants/handlers/HandlerCancelByVeto.t.sol';
import {PolicyManagerHandlerClearSetup} from 'test/policy-manager/invariants/handlers/HandlerClearSetup.t.sol';
import {PolicyManagerHandlerCommitSetup} from 'test/policy-manager/invariants/handlers/HandlerCommitSetup.t.sol';
import {PolicyManagerHandlerConsume} from 'test/policy-manager/invariants/handlers/HandlerConsume.t.sol';
import {PolicyManagerHandlerStartAttempt} from 'test/policy-manager/invariants/handlers/HandlerStartAttempt.t.sol';
import {PolicyManagerHarness} from 'test/utils/PolicyManagerHarness.sol';

/// @notice The one contract the policy manager's invariant suite targets. It inherits every handler,
///         so the fuzzer sends the account's own calls from several callers over several actions,
///         opens and cancels attempts with proof sets anyone may send, spends them as the account,
///         cancels them on a stopped method's veto, replays old proofs, moves time and
///         methods' stops, and after every call the handlers check what changed.
contract PolicyManagerHandlersTarget is
  PolicyManagerHandlerCommitSetup,
  PolicyManagerHandlerClearSetup,
  PolicyManagerHandlerCancelByOwner,
  PolicyManagerHandlerStartAttempt,
  PolicyManagerHandlerCancelByProofs,
  PolicyManagerHandlerConsume,
  PolicyManagerHandlerCancelByVeto
{
  /// @dev Hands the manager, the callers and the actions to the shared handler state.
  constructor(PolicyManagerHarness _managerUnderTest, address[] memory _callerList, address[] memory _actionList)
    PolicyManagerBaseHandler(_managerUnderTest, _callerList, _actionList)
  {}
}
