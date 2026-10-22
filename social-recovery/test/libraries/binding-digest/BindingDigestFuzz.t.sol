// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {IPolicyManager} from 'interfaces/IPolicyManager.sol';
import {BindingDigestMemberChanges} from 'test/utils/BindingDigestMemberChanges.sol';
import {BindingDigestTestBase} from 'test/utils/BindingDigestTestBase.sol';

/// @notice Property fuzzing of the binding digest library: the domain separator, the approval and cancellation
///         digests, and the setup and credential commitments. Each test checks one property that must hold for any
///         input. A member, the separator and a place are defined in `BindingDigestTestBase`.
contract BindingDigestFuzzTest is BindingDigestTestBase {
  /*///////////////////////////////////////////////////////////////
                             FUZZ TESTS
  ///////////////////////////////////////////////////////////////*/
  // In each, `_which` picks the one member to change and `_seed` builds the change, as BindingDigestMemberChanges
  // describes: a fixed-width member is XORed with `_seed | 1`, which is never zero, and a bytes member gains one
  // trailing byte.

  /// For any two different chain ids and any manager, the separators on the two chains differ. The second chain id
  /// is the first moved forward by `_offset` steps around the range `vm.chainId` accepts, never a full turn, so it
  /// always differs from the first.
  function testFuzz_DomainSeparatorDiffersAcrossChains(uint256 _chainId, uint256 _offset, address _manager) external {
    _chainId = bound(_chainId, 0, _MAX_CHAIN_ID);
    _offset = bound(_offset, 1, _MAX_CHAIN_ID);
    uint256 _otherChainId = (_chainId + _offset) % (_MAX_CHAIN_ID + 1);
    vm.chainId(_chainId);
    bytes32 _first = _harness.domainSeparator(_manager);
    vm.chainId(_otherChainId);
    assertTrue(_harness.domainSeparator(_manager) != _first, 'chain id ignored');
  }

  /// For any chain id and manager, a second manager address gives a different separator, so a redeploy at a new
  /// address invalidates every approval gathered for the old one.
  function testFuzz_DomainSeparatorDiffersAcrossManagers(uint256 _chainId, address _manager, uint160 _seed) external {
    vm.chainId(bound(_chainId, 0, _MAX_CHAIN_ID));
    address _other = address(uint160(_manager) ^ (_seed | 1));
    assertTrue(_harness.domainSeparator(_manager) != _harness.domainSeparator(_other), 'manager ignored');
  }

  /// For any request, the approval digest and the cancellation digest over the members they share differ, so no
  /// approval ever counts as a cancel.
  function testFuzz_ApprovalAndCancellationOverTheSameMembersDiffer(
    bytes32 _separatorIn,
    IPolicyManager.AttemptRequest calldata _approval,
    uint256 _place
  ) external view {
    assertTrue(
      _harness.approvalDigest(_separatorIn, _approval, _place)
        != _harness.cancelDigest(_separatorIn, _cancelSharing(_approval), _place),
      'approval equals cancellation'
    );
  }

  /// For any approval, changing any one member changes the digest, so no member of what a guardian approved can be
  /// swapped after they signed. A failure names the member index `_which` picked.
  function testFuzz_ApprovalsDifferingInOneMemberDiffer(
    bytes32 _separatorIn,
    IPolicyManager.AttemptRequest calldata _original,
    uint256 _place,
    uint256 _which,
    uint256 _seed
  ) external view {
    IPolicyManager.AttemptRequest memory _request = _original;
    _which = bound(_which, 0, BindingDigestMemberChanges.APPROVAL_MEMBERS - 1);
    bytes32 _base = _harness.approvalDigest(_separatorIn, _request, _place);
    (_separatorIn, _place) = BindingDigestMemberChanges.changeApproval(_separatorIn, _request, _place, _which, _seed);
    assertTrue(
      _harness.approvalDigest(_separatorIn, _request, _place) != _base,
      string.concat('approval member ignored: ', vm.toString(_which))
    );
  }

  /// For any cancellation, changing any one member changes the digest, so a cancel reaches only the attempt it was
  /// signed for. A failure names the member index `_which` picked.
  function testFuzz_CancellationsDifferingInOneMemberDiffer(
    bytes32 _separatorIn,
    IPolicyManager.CancelRequest calldata _original,
    uint256 _place,
    uint256 _which,
    uint256 _seed
  ) external view {
    IPolicyManager.CancelRequest memory _request = _original;
    _which = bound(_which, 0, BindingDigestMemberChanges.CANCEL_MEMBERS - 1);
    bytes32 _base = _harness.cancelDigest(_separatorIn, _request, _place);
    (_separatorIn, _place) = BindingDigestMemberChanges.changeCancel(_separatorIn, _request, _place, _which, _seed);
    assertTrue(
      _harness.cancelDigest(_separatorIn, _request, _place) != _base,
      string.concat('cancel member ignored: ', vm.toString(_which))
    );
  }

  /// For any approval, replacing its proofs with any other proofs leaves the digest unchanged, so the view and the
  /// verification path agree whatever proofs a request carries.
  function testFuzz_ProofsNeverEnterTheApprovalDigest(
    bytes32 _separatorIn,
    IPolicyManager.AttemptRequest memory _request,
    IPolicyManager.ProofPlace[] calldata _proofs,
    uint256 _place
  ) external view {
    bytes32 _digest = _harness.approvalDigest(_separatorIn, _request, _place);
    _request.proofs = _proofs;
    assertEq(_harness.approvalDigest(_separatorIn, _request, _place), _digest, 'proofs in approval digest');
  }

  /// For any cancellation, replacing its proofs with any other proofs leaves the digest unchanged, so a cancel can be
  /// signed before its proof set is gathered.
  function testFuzz_ProofsNeverEnterTheCancellationDigest(
    bytes32 _separatorIn,
    IPolicyManager.CancelRequest memory _request,
    IPolicyManager.ProofPlace[] calldata _proofs,
    uint256 _place
  ) external view {
    bytes32 _digest = _harness.cancelDigest(_separatorIn, _request, _place);
    _request.proofs = _proofs;
    assertEq(_harness.cancelDigest(_separatorIn, _request, _place), _digest, 'proofs in cancel digest');
  }

  /// For any account, action, nonce and body, changing any one of them changes the setup commitment, so a revealed
  /// body proves the exact setup it was committed as. A failure names the member index `_which` picked.
  function testFuzz_SetupCommitmentsDifferingInOneMemberDiffer(
    address _account,
    address _action,
    uint64 _nonce,
    bytes calldata _body,
    uint256 _which,
    uint256 _seed
  ) external view {
    _which = bound(_which, 0, BindingDigestMemberChanges.SETUP_MEMBERS - 1);
    bytes32 _base = _harness.setupCommitment(_account, _action, _nonce, _body);
    (address _newAccount, address _newAction, uint64 _newNonce, bytes memory _newBody) =
      BindingDigestMemberChanges.changeSetup(_account, _action, _nonce, _body, _which, _seed);
    assertTrue(
      _harness.setupCommitment(_newAccount, _newAction, _newNonce, _newBody) != _base,
      string.concat('setup member ignored: ', vm.toString(_which))
    );
  }

  /// For any method, config and salt, changing any one of them changes the credential commitment, so only the
  /// committed credential can fill its place. A failure names the member index `_which` picked.
  function testFuzz_CredentialCommitmentsDifferingInOneMemberDiffer(
    address _method,
    bytes calldata _config,
    bytes32 _salt,
    uint256 _which,
    uint256 _seed
  ) external view {
    _which = bound(_which, 0, BindingDigestMemberChanges.CREDENTIAL_MEMBERS - 1);
    bytes32 _base = _harness.credentialCommitment(_method, _config, _salt);
    (address _newMethod, bytes memory _newConfig, bytes32 _newSalt) =
      BindingDigestMemberChanges.changeCredential(_method, _config, _salt, _which, _seed);
    assertTrue(
      _harness.credentialCommitment(_newMethod, _newConfig, _newSalt) != _base,
      string.concat('credential member ignored: ', vm.toString(_which))
    );
  }
}
