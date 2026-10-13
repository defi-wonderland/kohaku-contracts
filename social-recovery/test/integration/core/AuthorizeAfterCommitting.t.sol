// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {IPolicyManager} from 'interfaces/IPolicyManager.sol';
import {IRecoveryAction} from 'interfaces/IRecoveryAction.sol';
import {IntegrationDemoKitTestBase} from 'test/utils/IntegrationDemoKitTestBase.sol';

/// @notice The holder commits the rule first and authorizes the action on the account later. The
///         manager never learns of the authorization. An attempt can wait out its whole delay before
///         the action may act, and then run in the block after the authorization.
contract AuthorizeAfterCommittingTest is IntegrationDemoKitTestBase {
  /// @notice With a setup but no authorization, an attempt's wait runs out while the account refuses
  ///         the action's batch. The attempt keeps waiting. Once the account authorizes the action, the
  ///         handover runs in the next block, with no wait left for the holder to react.
  function test_WhenTheHolderAuthorizesTheActionAfterTheWait() external {
    // it should run the handover in the block after the authorization with no wait left
    uint64 _nonce = _commitNext(_body());
    assertEq(_nonce, 1, 'the commit did not write nonce one');
    assertEq(_state().setupCommitment, _commitmentOf(1, _body()), 'the manager stored no commitment');
    assertFalse(_action.isAuthorized(_account), 'given: the account honors the action');

    vm.recordLogs();
    _open(_openingSet());
    StartedLog memory _started = _startedLog(vm.getRecordedLogs());
    assertEq(_started.setupBody, _body(), 'the opening did not publish the rule');
    assertEq(_started.payload, _payload(), 'the opening did not publish the payload');
    IPolicyManager.Attempt memory _waiting = _state().attempt;

    // The wait runs out, and the account refuses the batch because the kit slot holds nothing.
    vm.warp(_waiting.consumableAfter);
    vm.expectRevert(bytes('EXTERNAL_VALIDATION_NOT_SET'));
    _executeHandover();
    IPolicyManager.ActionState memory _afterRefusal = _state();
    assertEq(uint256(_afterRefusal.attempt.state), uint256(IPolicyManager.AttemptState.Waiting), 'the attempt ended');
    assertEq(_afterRefusal.attempt.attemptId, _waiting.attemptId, 'the waiting attempt changed');

    // The account authorizes the action under the kit slot, and the manager's state does not change.
    uint256 _authorizedAt = block.timestamp;
    _asHolder(_one(_authorizeCall()));
    _assertSameState(_afterRefusal, _state(), 'the authorization reached the manager');
    assertTrue(_action.isAuthorized(_account), 'the kit slot write did not authorize the action');

    // The authorization did not reset the clock. The wait the opening set has already run out.
    assertEq(_state().attempt.consumableAfter, _waiting.consumableAfter, 'the authorization re-timed the attempt');
    assertGe(_authorizedAt, _waiting.consumableAfter, 'the wait had not run out at the authorization');

    // Anyone calls the action again in the next block, with no time passing, and the handover runs.
    vm.roll(block.number + 1);
    _executeHandover();
    assertEq(uint256(_state().attempt.state), uint256(IPolicyManager.AttemptState.Consumed), 'nothing was spent');
    assertEq(_privilege(_newKey), _KEY_VALUE, 'the new key holds no key value');
    assertEq(_privilege(_holderKey), bytes32(0), 'the lost key still holds a privilege');
  }

  /// @notice If the holder never authorizes the action, the attempt waits forever because a spend has
  ///         no deadline. It also keeps the action's one attempt slot, so no other set can open one.
  function test_WhenTheHolderNeverAuthorizesTheAction() external {
    // it should keep the attempt waiting and holding the one slot
    _commitNext(_body());
    _open(_openingSet());
    IPolicyManager.Attempt memory _waiting = _state().attempt;

    vm.warp(uint256(_waiting.consumableAfter) + 3650 days);
    assertEq(uint256(_state().attempt.state), uint256(IPolicyManager.AttemptState.Waiting), 'the attempt retired');
    vm.expectRevert(bytes('EXTERNAL_VALIDATION_NOT_SET'));
    _executeHandover();

    IPolicyManager.AttemptRequest memory _other = _request(_places(_BOB, _CAROL, _PHONE), 2, 1, _window());
    vm.expectRevert(
      abi.encodeWithSelector(
        IPolicyManager.PolicyManager_AttemptAlreadyActive.selector, _account, address(_action), _waiting.attemptId
      )
    );
    _send(_other);
    assertEq(_state().attempt.attemptId, _waiting.attemptId, 'another set displaced the attempt');
  }

  /// @notice The holder's key can cancel an attempt that the action can never spend, because the
  ///         account never authorized it.
  function test_WhenTheHoldersKeyEndsTheUnspendableAttempt() external {
    // it should cancel the attempt with the account as the canceller
    _commitNext(_body());
    _open(_openingSet());
    vm.warp(_state().attempt.consumableAfter);

    vm.expectEmit(true, true, true, true, address(_manager));
    emit IPolicyManager.AttemptCancelled(_account, address(_action), 1, _account, address(0), 1, new uint256[](0));
    _asHolder(_one(_managerCall(abi.encodeCall(IPolicyManager.cancelByOwner, (address(_action))))));
    assertEq(uint256(_state().attempt.state), uint256(IPolicyManager.AttemptState.Cancelled), 'the attempt waits');
  }

  /// @notice Guardians who meet the rule can cancel an attempt that the action can never spend,
  ///         because the account never authorized it.
  function test_WhenASatisfyingSetEndsTheUnspendableAttempt() external {
    // it should cancel the attempt with the places the cancelling set filled
    _commitNext(_body());
    _open(_openingSet());
    vm.warp(_state().attempt.consumableAfter);

    uint256[] memory _cancelling = _places(_ALICE, _CAROL, _PHONE);
    IPolicyManager.CancelRequest memory _cancel = _cancelRequest(_cancelling, 1, 1, _window());
    vm.expectEmit(true, true, true, true, address(_manager));
    emit IPolicyManager.AttemptCancelled(_account, address(_action), 1, _executor, address(0), 1, _cancelling);
    vm.prank(_executor);
    _manager.cancelByProofs(_cancel);
    assertEq(uint256(_state().attempt.state), uint256(IPolicyManager.AttemptState.Cancelled), 'the attempt waits');
  }

  /// @notice Once a method the attempt used is paused, anyone can cancel the attempt by veto, naming
  ///         that method. This ends an attempt the action could never spend.
  function test_WhenAStoppedMethodsVetoEndsTheUnspendableAttempt() external {
    // it should cancel the attempt naming the paused method
    _commitNext(_body());
    _open(_places(_ALICE, _BOB, _THIRD_PARTY));
    vm.warp(_state().attempt.consumableAfter);
    _stopThirdParty();

    vm.expectEmit(true, true, true, true, address(_manager));
    emit IPolicyManager.AttemptCancelled(
      _account, address(_action), 1, _executor, address(_thirdParty), 1, new uint256[](0)
    );
    vm.prank(_executor);
    _manager.cancelByVeto(_account, address(_action), 1, address(_thirdParty));
    assertEq(uint256(_state().attempt.state), uint256(IPolicyManager.AttemptState.Cancelled), 'the attempt waits');
    vm.expectRevert(
      abi.encodeWithSelector(
        IRecoveryAction.RecoveryAction_NotConsumable.selector,
        _account,
        IPolicyManager.AttemptState.Cancelled,
        _state().attempt.consumableAfter,
        keccak256(_payload())
      )
    );
    _executeHandover();
  }
}
