// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {Test} from 'forge-std/Test.sol';
import {IPolicyManager} from 'interfaces/IPolicyManager.sol';
import {BindingDigestHarness} from 'test/utils/BindingDigestHarness.sol';

/// @notice Shared setup for the binding digest tests: the harness that exposes the library's functions as external
///         calls, the separator for the test manager, and the sample requests the tests change one member at a time.
///         The exact bytes of every output are checked against the frozen vectors in BindingDigestKat.t.sol. The
///         tests built on this base check properties that hold for every input: which members a hash depends on,
///         which it ignores, and that the approving and the cancelling forms never share a digest.
/// @dev Terms used below. A member is one field a hash covers. The separator is the EIP-712 domain separator, the
///      hash of the manager's name, digest version, chain id and address that every digest is computed under. The
///      library reads the chain id from the chain running the call, so a test moves between chains with
///      `vm.chainId`. A place is the index of one credential in the holder's rule.
abstract contract BindingDigestTestBase is Test {
  address internal constant _MANAGER = address(0x6666666666666666666666666666666666666666);

  /// @dev The largest chain id `vm.chainId` accepts, since it refuses any chain id of 2^64 or more.
  uint256 internal constant _MAX_CHAIN_ID = type(uint64).max;

  BindingDigestHarness internal _harness;
  bytes32 internal _separator;

  /// @dev Deploys the harness and computes the separator for the test manager on the default test chain.
  function setUp() public virtual {
    _harness = new BindingDigestHarness();
    _separator = _harness.domainSeparator(_MANAGER);
  }

  /*///////////////////////////////////////////////////////////////
                              FIXTURES
  ///////////////////////////////////////////////////////////////*/

  /// @dev A request with every member set to a distinct nonzero value and one proof.
  function _sampleApproval() internal pure returns (IPolicyManager.AttemptRequest memory _request) {
    _request.account = address(0x1111111111111111111111111111111111111111);
    _request.action = address(0x2222222222222222222222222222222222222222);
    _request.attemptId = 9;
    _request.setupNonce = 7;
    _request.setupBody = hex'00112233445566778899';
    _request.payload = hex'abcdef';
    _request.order = IPolicyManager.PaymentOrder({
      token: address(0x4444444444444444444444444444444444444444),
      amount: 1_234_567_890_123_456_789,
      payee: address(0x5555555555555555555555555555555555555555)
    });
    _request.validUntil = 1_800_000_000;
    _request.proofs = new IPolicyManager.ProofPlace[](1);
    _request.proofs[0] = IPolicyManager.ProofPlace({
      place: 0,
      method: address(0x3333333333333333333333333333333333333333),
      config: hex'1234',
      salt: bytes32(uint256(0xaa)),
      proof: hex'5678'
    });
  }

  /// @dev The cancellation sharing every member with the sample approval.
  function _sampleCancel() internal pure returns (IPolicyManager.CancelRequest memory _request) {
    _request = _cancelSharing(_sampleApproval());
  }

  /// @dev A cancellation carrying every member it shares with the approval, the proofs included.
  function _cancelSharing(IPolicyManager.AttemptRequest memory _approval)
    internal
    pure
    returns (IPolicyManager.CancelRequest memory _cancel)
  {
    _cancel.account = _approval.account;
    _cancel.action = _approval.action;
    _cancel.attemptId = _approval.attemptId;
    _cancel.setupNonce = _approval.setupNonce;
    _cancel.setupBody = _approval.setupBody;
    _cancel.validUntil = _approval.validUntil;
    _cancel.proofs = _approval.proofs;
  }
}
