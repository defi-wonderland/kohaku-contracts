// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {IPolicyManager} from 'interfaces/IPolicyManager.sol';
import {IntegrationDemoKitTestBase} from 'test/utils/IntegrationDemoKitTestBase.sol';

/// @notice The guardians opened a recovery that is no longer wanted. Guardians who meet the rule
///         cancel it by signing a cancellation of that exact attempt. The account's key is not needed.
contract CancelByAProofSetTest is IntegrationDemoKitTestBase {
  /// @notice The opening event, as the cancelling guardians read it.
  StartedLog internal _seen;

  function setUp() public override {
    super.setUp();
    _authorizeAndCommit();
    vm.recordLogs();
    _open(_openingSet());
    _seen = _startedLog(vm.getRecordedLogs());
  }

  /// @notice Guardians who meet the rule sign a cancellation of the waiting attempt, and anyone sends
  ///         it. The attempt ends, the event records the caller and the places that signed, and the
  ///         setup keeps its nonce. A later recovery takes the next id and waits the full delay again.
  function test_WhenASatisfyingSetCancelsTheAttempt() external {
    // it should end the attempt, keep the setup and leave the next recovery a fresh id and wait
    assertEq(_seen.setupBody, _body(), 'the opening event did not publish the body');
    assertEq(_seen.usedPlaces, _openingSet(), 'the opening event did not publish the filled places');
    assertEq(_seen.attemptId, 1, 'the opening event did not publish the attempt id');
    IPolicyManager.ActionState memory _before = _state();

    uint256[] memory _cancelling = _places(_ALICE, _CAROL, _PHONE);
    IPolicyManager.CancelRequest memory _cancel =
      _cancelRequest(_cancelling, _seen.attemptId, _before.setupNonce, _window());

    // An approval never counts as a cancel, so Alice's opening signature is refused here.
    IPolicyManager.CancelRequest memory _approvalsAsCancel = _cancelRequest(_cancelling, 1, 1, _window());
    IPolicyManager.AttemptRequest memory _opening = _request(_openingSet(), 1, 1, _window());
    _approvalsAsCancel.proofs[0].proof = _opening.proofs[0].proof;
    vm.expectRevert(
      abi.encodeWithSelector(IPolicyManager.PolicyManager_ProofRejected.selector, _ALICE, address(_ecdsa))
    );
    vm.prank(_executor);
    _manager.cancelByProofs(_approvalsAsCancel);

    address _canceller = makeAddr('canceller');
    vm.expectEmit(true, true, true, true, address(_manager));
    emit IPolicyManager.AttemptCancelled(_account, address(_action), 1, _canceller, address(0), 1, _cancelling);
    vm.prank(_canceller);
    _manager.cancelByProofs(_cancel);

    IPolicyManager.ActionState memory _after = _state();
    assertEq(uint256(_after.attempt.state), uint256(IPolicyManager.AttemptState.Cancelled), 'the attempt runs');
    assertEq(_after.setupCommitment, _before.setupCommitment, 'the cancel touched the setup');
    assertEq(_after.setupNonce, _before.setupNonce, 'the cancel moved the nonce');
    assertEq(_after.nextAttemptId, 2, 'the next recovery does not open under the next id');

    IPolicyManager.AttemptRequest memory _spentId = _request(_openingSet(), 1, 1, _window());
    vm.expectRevert(abi.encodeWithSelector(IPolicyManager.PolicyManager_WrongAttemptId.selector, uint64(1), uint64(2)));
    _send(_spentId);
    vm.warp(block.timestamp + 1 hours);
    _open(_openingSet());
    assertEq(_state().attempt.attemptId, 2, 'the further recovery did not take the next id');
    assertEq(
      _state().attempt.consumableAfter, uint48(block.timestamp) + _WAIT, 'the further recovery skipped part of the wait'
    );
  }

  /// @notice A cancellation that arrives after the spend reverts, because nothing is left to cancel.
  ///         After the wait, guardians who want to cancel must beat the executor.
  function test_RevertWhen_TheCancellationArrivesAfterTheSpend() external {
    // it should revert
    IPolicyManager.CancelRequest memory _cancel = _cancelRequest(_places(_ALICE, _CAROL, _PHONE), 1, 1, _window());
    vm.warp(_state().attempt.consumableAfter);
    _executeHandover();

    vm.expectRevert(
      abi.encodeWithSelector(IPolicyManager.PolicyManager_NoActiveAttempt.selector, _account, address(_action))
    );
    vm.prank(_executor);
    _manager.cancelByProofs(_cancel);
  }

  /// @notice A cancellation that uses a paused method is refused, the same as an opening would be.
  ///         The same cancellation goes through once the pause lifts. This setup lets pauses apply.
  function test_RevertWhen_TheCancellingSetLeansOnAStoppedMethod() external {
    // it should revert
    uint256[] memory _leaning = _places(_ALICE, _CAROL, _THIRD_PARTY);
    IPolicyManager.CancelRequest memory _cancel = _cancelRequest(_leaning, 1, 1, _window());
    _stopThirdParty();
    vm.expectRevert(
      abi.encodeWithSelector(IPolicyManager.PolicyManager_MethodStopped.selector, _THIRD_PARTY, address(_thirdParty))
    );
    vm.prank(_executor);
    _manager.cancelByProofs(_cancel);
    assertEq(uint256(_state().attempt.state), uint256(IPolicyManager.AttemptState.Waiting), 'the attempt ended');

    // it should accept the same cancellation after the lift
    _liftThirdParty();
    vm.prank(_executor);
    _manager.cancelByProofs(_cancel);
    assertEq(uint256(_state().attempt.state), uint256(IPolicyManager.AttemptState.Cancelled), 'the attempt runs');
  }

  /// @notice A cancellation signed for the next attempt id is refused while the current attempt
  ///         waits. A cancel signed for one attempt never ends another.
  function test_RevertWhen_TheCancellationNamesAnotherAttempt() external {
    // it should revert
    IPolicyManager.CancelRequest memory _ahead = _cancelRequest(_places(_ALICE, _CAROL, _PHONE), 2, 1, _window());
    vm.expectRevert(abi.encodeWithSelector(IPolicyManager.PolicyManager_WrongAttemptId.selector, uint64(2), uint64(1)));
    vm.prank(_executor);
    _manager.cancelByProofs(_ahead);
    assertEq(uint256(_state().attempt.state), uint256(IPolicyManager.AttemptState.Waiting), 'the attempt ended');
  }
}
