// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {IPolicyManager} from 'interfaces/IPolicyManager.sol';
import {ActionAmbireAccountFixture} from 'test/mocks/ActionAmbireAccountFixture.sol';
import {IntegrationDemoKitTestBase} from 'test/utils/IntegrationDemoKitTestBase.sol';

/// @notice Every proof signs a window, the time until which the request may be sent. When the last
///         approval arrives after the window, the request is refused before any proof is read. The
///         window limits how long signed approvals stay usable.
contract SubmitAfterTheWindowTest is IntegrationDemoKitTestBase {
  function setUp() public override {
    super.setUp();
    _authorizeAndCommit();
  }

  /// @notice A request sent after its window is refused as expired, before any proof is read, and
  ///         changes nothing. A late cancellation is refused the same way. New approvals with a new
  ///         window then open the attempt.
  function test_RevertWhen_TheWindowPassesBeforeTheLastReply() external {
    // it should revert
    uint48 _validUntil = uint48(block.timestamp + 1 hours);
    IPolicyManager.AttemptRequest memory _late = _request(_openingSet(), 1, 1, _validUntil);

    // The proofs sign the window, so the same proofs with a later window are refused.
    IPolicyManager.AttemptRequest memory _stretched = _request(_openingSet(), 1, 1, _validUntil + 1 days);
    for (uint256 _i; _i < _stretched.proofs.length; ++_i) {
      _stretched.proofs[_i].proof = _late.proofs[_i].proof;
    }
    vm.expectRevert(
      abi.encodeWithSelector(IPolicyManager.PolicyManager_ProofRejected.selector, _ALICE, address(_ecdsa))
    );
    _send(_stretched);

    // The slowest guardian replies after the window, and the request is refused before any proof is read.
    vm.warp(uint256(_validUntil) + 1);
    IPolicyManager.ActionState memory _before = _state();
    _sendRefusedBeforeAnyMethod(
      _late,
      abi.encodeWithSelector(IPolicyManager.PolicyManager_RequestExpired.selector, uint48(block.timestamp), _validUntil)
    );

    // it should open nothing and write nothing
    _assertSameState(_before, _state(), 'the expired request wrote state');
    assertEq(uint256(_state().attempt.state), uint256(IPolicyManager.AttemptState.None), 'an attempt opened');

    // A cancellation sent after its own window is refused the same way.
    uint256 _snapshot = vm.snapshotState();
    _open(_openingSet());
    uint48 _cancelUntil = uint48(block.timestamp + 1 hours);
    IPolicyManager.CancelRequest memory _cancel = _cancelRequest(_places(_ALICE, _CAROL, _PHONE), 1, 1, _cancelUntil);
    vm.warp(uint256(_cancelUntil) + 1);
    vm.expectRevert(
      abi.encodeWithSelector(
        IPolicyManager.PolicyManager_RequestExpired.selector, uint48(block.timestamp), _cancelUntil
      )
    );
    vm.prank(_executor);
    _manager.cancelByProofs(_cancel);
    vm.revertToState(_snapshot);

    // The holder's client asks again with a new window, and the same guardians approve.
    _open(_openingSet());
    assertEq(
      uint256(_state().attempt.state), uint256(IPolicyManager.AttemptState.Waiting), 'the fresh set opened nothing'
    );
  }

  /// @notice A holder who lost their key cannot withdraw a signed request. There is no attempt to cancel
  ///         and no key to change the nonce. Anyone with the request can send it until the last second of
  ///         its window.
  function test_WhenTheHolderCannotWithdrawASignedRequest() external {
    // it should stay submittable by anyone until its window ends
    uint48 _validUntil = uint48(block.timestamp + 2 days);
    IPolicyManager.AttemptRequest memory _signed = _request(_openingSet(), 1, 1, _validUntil);

    IPolicyManager.CancelRequest memory _retire = _cancelRequest(_places(_ALICE, _CAROL, _PHONE), 1, 1, _validUntil);
    vm.expectRevert(
      abi.encodeWithSelector(IPolicyManager.PolicyManager_NoActiveAttempt.selector, _account, address(_action))
    );
    vm.prank(_executor);
    _manager.cancelByProofs(_retire);

    // An address that is not a key cannot change the nonce, because the account refuses its batch.
    vm.expectRevert(bytes('INSUFFICIENT_PRIVILEGE'));
    vm.prank(makeAddr('keylessHolder'));
    ActionAmbireAccountFixture(payable(_account)).executeBySender(_one(_commitCall(2, _commitmentOf(2, _body()))));
    assertEq(_state().setupNonce, 1, 'a keyless address moved the nonce');

    vm.warp(_validUntil);
    vm.prank(makeAddr('anyoneWithTheBytes'));
    _manager.startAttempt(_signed);
    assertEq(uint256(_state().attempt.state), uint256(IPolicyManager.AttemptState.Waiting), 'the request lapsed early');
  }
}
