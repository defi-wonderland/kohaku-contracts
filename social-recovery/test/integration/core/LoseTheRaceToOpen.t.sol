// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {IPolicyManager} from 'interfaces/IPolicyManager.sol';
import {IntegrationDemoKitTestBase} from 'test/utils/IntegrationDemoKitTestBase.sol';

/// @notice A client holds enough approvals to open the next attempt, but other guardians who meet
///         the rule open it first. The client's request is refused at every later try and changes
///         nothing.
contract LoseTheRaceToOpenTest is IntegrationDemoKitTestBase {
  function setUp() public override {
    super.setUp();
    _authorizeAndCommit();
  }

  /// @notice The client's request is refused while the other attempt waits. After the holder edits the
  ///         setup, it is refused on the nonce before any proof is read. If the nonce had not changed, it
  ///         would be refused on its used attempt id. No refusal changes state or starts a clock.
  function test_WhenAnotherSetOpensTheAttemptFirst() external {
    // it should refuse the request at every try and write nothing
    IPolicyManager.AttemptRequest memory _mine = _nextRequest(_openingSet());
    assertEq(_mine.attemptId, 1, 'the client did not predict the next id');
    assertEq(_mine.setupNonce, 1, 'the client did not name the stored nonce');

    // Other guardians who meet the rule open that attempt first.
    _send(_request(_places(_BOB, _CAROL, _THIRD_PARTY), 1, 1, _window()));
    IPolicyManager.ActionState memory _taken = _state();
    assertEq(_taken.attempt.attemptId, 1, 'the other set did not open the predicted id');

    vm.expectRevert(
      abi.encodeWithSelector(
        IPolicyManager.PolicyManager_AttemptAlreadyActive.selector, _account, address(_action), uint64(1)
      )
    );
    _send(_mine);
    _assertSameState(_taken, _state(), 'the refused request wrote state');

    // If the nonce had not changed: the holder's cancel keeps the nonce, and the request fails on its used id.
    uint256 _snapshot = vm.snapshotState();
    _asHolder(_one(_managerCall(abi.encodeCall(IPolicyManager.cancelByOwner, (address(_action))))));
    IPolicyManager.ActionState memory _nonceHeld = _state();
    vm.expectRevert(abi.encodeWithSelector(IPolicyManager.PolicyManager_WrongAttemptId.selector, uint64(1), uint64(2)));
    _send(_mine);
    _assertSameState(_nonceHeld, _state(), 'the request on a spent id wrote state');
    vm.revertToState(_snapshot);

    // The holder edits the setup, which cancels the attempt and moves the nonce.
    _commitNext(_body());
    IPolicyManager.ActionState memory _edited = _state();
    assertEq(_edited.setupNonce, 2, 'the edit did not move the nonce');
    _sendRefusedBeforeAnyMethod(_mine, _wrongNonce(1, 2));
    _assertSameState(_edited, _state(), 'the request on the old nonce wrote state');
    assertEq(uint256(_state().attempt.state), uint256(IPolicyManager.AttemptState.Cancelled), 'a clock runs');
  }

  /// @notice Signed approvals guarantee nothing. Once the nonce changes, the old proofs are refused even
  ///         under the right nonce and id. Only new signatures within a new window open the attempt.
  function test_WhenTheGuardiansMustSignAgain() external {
    // it should refuse every old proof and open only with new approvals
    IPolicyManager.AttemptRequest memory _mine = _nextRequest(_openingSet());
    _send(_request(_places(_BOB, _CAROL, _THIRD_PARTY), 1, 1, _window()));
    _commitNext(_body());

    IPolicyManager.AttemptRequest memory _carried = _request(_openingSet(), 2, 2, _mine.validUntil);
    for (uint256 _i; _i < _carried.proofs.length; ++_i) {
      _carried.proofs[_i].proof = _mine.proofs[_i].proof;
    }
    vm.expectRevert(
      abi.encodeWithSelector(IPolicyManager.PolicyManager_ProofRejected.selector, _ALICE, address(_ecdsa))
    );
    _send(_carried);

    vm.warp(block.timestamp + 1 hours);
    _open(_openingSet());
    assertEq(
      uint256(_state().attempt.state), uint256(IPolicyManager.AttemptState.Waiting), 'the fresh set opened nothing'
    );
    assertEq(_state().attempt.setupNonce, 2, 'the fresh set opened under another setup');
  }
}
