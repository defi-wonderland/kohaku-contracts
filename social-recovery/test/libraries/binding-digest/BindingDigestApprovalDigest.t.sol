// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {IPolicyManager} from 'interfaces/IPolicyManager.sol';
import {BindingDigestMemberChanges} from 'test/utils/BindingDigestMemberChanges.sol';
import {BindingDigestTestBase} from 'test/utils/BindingDigestTestBase.sol';

/// @notice Unit tests for the approval digest, `approvalDigest(_separator, _request, _place)`, the digest a guardian's
///         proof signs to approve a recovery. The test comparing an approval with a cancellation over the same members
///         lives here because the property it guards belongs to the approval: a proof approving a recovery must never
///         count as a proof cancelling it. Tree: BindingDigestApprovalDigest.tree.
contract BindingDigestApprovalDigestTest is BindingDigestTestBase {
  /*///////////////////////////////////////////////////////////////
                             TREE TESTS
  ///////////////////////////////////////////////////////////////*/

  /// An approval digest does not depend on the proofs the request carries. A proof cannot sign itself, so the digest
  /// a guardian signs must be computable before any proof exists.
  function test_WhenComputingAnApprovalDigest() external view {
    // it should ignore the proofs.
    bytes32 _digest = _harness.approvalDigest(_separator, _sampleApproval(), 3);
    IPolicyManager.AttemptRequest memory _noProofs = _sampleApproval();
    _noProofs.proofs = new IPolicyManager.ProofPlace[](0);
    assertEq(_harness.approvalDigest(_separator, _noProofs, 3), _digest, 'no proofs changed the digest');
    IPolicyManager.AttemptRequest memory _otherProofs = _sampleApproval();
    _otherProofs.proofs[0].proof = hex'deadbeef';
    _otherProofs.proofs[0].place = 3;
    assertEq(_harness.approvalDigest(_separator, _otherProofs, 3), _digest, 'other proofs changed the digest');
  }

  /// Changing any one of the twelve approval members changes the digest. Each member stops one replay: a proof for
  /// one account, action, attempt, setup, outcome, price, window or place never counts for another.
  function test_WhenTwoApprovalsDifferInAnyOneMember() external view {
    // it should produce different digests.
    bytes32 _base = _harness.approvalDigest(_separator, _sampleApproval(), 3);
    for (uint256 _which; _which < BindingDigestMemberChanges.APPROVAL_MEMBERS; ++_which) {
      IPolicyManager.AttemptRequest memory _request = _sampleApproval();
      (bytes32 _newSeparator, uint256 _place) =
        BindingDigestMemberChanges.changeApproval(_separator, _request, 3, _which, 1);
      assertTrue(
        _harness.approvalDigest(_newSeparator, _request, _place) != _base,
        string.concat('approval member ignored: ', vm.toString(_which))
      );
    }
  }

  /// An approval and a cancellation over the same account, action, attempt, nonce, body, window and place have
  /// different digests, so a proof approving a recovery never counts as a proof cancelling it. Checked with a full
  /// request, an empty one and all zero values.
  function test_WhenAnApprovalAndACancellationShareEveryMember() external view {
    // it should produce different digests.
    IPolicyManager.AttemptRequest memory _approval = _sampleApproval();
    assertTrue(
      _harness.approvalDigest(_separator, _approval, 3)
        != _harness.cancelDigest(_separator, _cancelSharing(_approval), 3),
      'approval equals cancellation'
    );

    _approval.payload = '';
    _approval.order = IPolicyManager.PaymentOrder({token: address(0), amount: 0, payee: address(0)});
    assertTrue(
      _harness.approvalDigest(_separator, _approval, 3)
        != _harness.cancelDigest(_separator, _cancelSharing(_approval), 3),
      'empty approval equals cancellation'
    );

    IPolicyManager.AttemptRequest memory _zeroApproval;
    IPolicyManager.CancelRequest memory _zeroCancel;
    assertTrue(
      _harness.approvalDigest(bytes32(0), _zeroApproval, 0) != _harness.cancelDigest(bytes32(0), _zeroCancel, 0),
      'zero approval equals zero cancellation'
    );
  }
}
