// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {IPolicyManager} from 'interfaces/IPolicyManager.sol';
import {BindingDigestMemberChanges} from 'test/utils/BindingDigestMemberChanges.sol';
import {BindingDigestTestBase} from 'test/utils/BindingDigestTestBase.sol';

/// @notice Unit tests for the cancellation digest, `cancelDigest(_separator, _request, _place)`, the digest a
///         guardian's proof signs to cancel a pending recovery. Tree: BindingDigestCancelDigest.tree.
contract BindingDigestCancelDigestTest is BindingDigestTestBase {
  /*///////////////////////////////////////////////////////////////
                             TREE TESTS
  ///////////////////////////////////////////////////////////////*/

  /// A cancellation digest does not depend on the proofs the request carries, for the same reason as an approval's:
  /// the proofs are what sign the digest.
  function test_WhenComputingACancellationDigest() external view {
    // it should ignore the proofs.
    bytes32 _digest = _harness.cancelDigest(_separator, _sampleCancel(), 3);
    IPolicyManager.CancelRequest memory _noProofs = _sampleCancel();
    _noProofs.proofs = new IPolicyManager.ProofPlace[](0);
    assertEq(_harness.cancelDigest(_separator, _noProofs, 3), _digest, 'no proofs changed the digest');
  }

  /// Changing any one of the eight cancellation members changes the digest, so a cancel signed for one attempt never
  /// reaches another.
  function test_WhenTwoCancellationsDifferInAnyOneMember() external view {
    // it should produce different digests.
    bytes32 _base = _harness.cancelDigest(_separator, _sampleCancel(), 3);
    for (uint256 _which; _which < BindingDigestMemberChanges.CANCEL_MEMBERS; ++_which) {
      IPolicyManager.CancelRequest memory _request = _sampleCancel();
      (bytes32 _newSeparator, uint256 _place) =
        BindingDigestMemberChanges.changeCancel(_separator, _request, 3, _which, 1);
      assertTrue(
        _harness.cancelDigest(_newSeparator, _request, _place) != _base,
        string.concat('cancel member ignored: ', vm.toString(_which))
      );
    }
  }
}
