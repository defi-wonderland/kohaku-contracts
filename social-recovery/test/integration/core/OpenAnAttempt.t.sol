// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {Vm} from 'forge-std/Vm.sol';
import {IPolicyManager} from 'interfaces/IPolicyManager.sol';
import {IPolicyMethod} from 'interfaces/IPolicyMethod.sol';
import {IPolicyMethodPause} from 'interfaces/IPolicyMethodPause.sol';
import {IntegrationDemoKitTestBase} from 'test/utils/IntegrationDemoKitTestBase.sol';

/// @notice The guardians the rule names approve the new key. Anyone who pays the gas sends their
///         proofs in one request, which opens the attempt and starts the clock.
contract OpenAnAttemptTest is IntegrationDemoKitTestBase {
  function setUp() public override {
    super.setUp();
    _authorizeAndCommit();
  }

  /// @notice Two friends' wallets and the holder's passkey approve one request, and a submitter with
  ///         no authority sends it. The manager reads each method's pause once and checks each proof
  ///         with a read-only call. It stores one attempt, starts the clock and publishes the request.
  function test_WhenTheGuardiansApproveAndAnyoneSubmits() external {
    // it should store one waiting attempt and publish everything the release will perform
    IPolicyManager.ActionState memory _before = _state();
    assertEq(uint256(_before.attempt.state), uint256(IPolicyManager.AttemptState.None), 'given: an attempt exists');
    assertFalse(_action.holdsAnyPrivilege(_account, _submitter), 'given: the submitter holds authority');

    // The client builds one request and each guardian signs the approval digest for their own place.
    IPolicyManager.AttemptRequest memory _req = _request(_openingSet(), 1, _before.setupNonce, _window());

    // The manager reads each method's pause once and checks each proof with a read-only call.
    bytes memory _pausedRead = abi.encodeCall(IPolicyMethodPause.paused, ());
    vm.expectCall(address(_ecdsa), _pausedRead, 1);
    vm.expectCall(address(_passkey), _pausedRead, 1);
    for (uint256 _i; _i < _req.proofs.length; ++_i) {
      IPolicyManager.ProofPlace memory _p = _req.proofs[_i];
      bytes32 _digest = _manager.hashApproval(_req, _p.place);
      vm.expectCall(_p.method, abi.encodeCall(IPolicyMethod.verify, (_p.config, _digest, _p.proof)), 1);
    }
    address[] memory _used = new address[](2);
    _used[0] = address(_ecdsa);
    _used[1] = address(_passkey);
    uint48 _clock = uint48(block.timestamp) + _WAIT;
    vm.expectEmit(true, true, true, true, address(_manager));
    emit IPolicyManager.AttemptStarted(
      _account, address(_action), 1, _before.setupNonce, _body(), _openingSet(), _used, _payload(), _order(), _clock
    );
    vm.startStateDiffRecording();
    _send(_req);
    Vm.AccountAccess[] memory _accesses = vm.stopAndReturnStateDiff();

    IPolicyManager.ActionState memory _after = _state();
    assertEq(uint256(_after.attempt.state), uint256(IPolicyManager.AttemptState.Waiting), 'no attempt waits');
    assertEq(_after.attempt.attemptId, 1, 'the attempt is not the next id');
    assertEq(_after.attempt.setupNonce, _before.setupNonce, 'the attempt names another setup');
    assertEq(_after.attempt.consumableAfter, _clock, 'the clock does not run from acceptance');
    assertEq(_after.attempt.payloadHash, keccak256(_payload()), 'the stored payload hash is not the payload');
    assertEq(abi.encode(_after.attempt.order), abi.encode(_order()), 'the stored order is not the approved one');
    assertEq(_after.attempt.usedMethods, _used, 'the stored methods are not the distinct ones used');
    assertFalse(_after.attempt.ignoresPause, 'the stop choice is not the body one');
    assertEq(_after.nextAttemptId, 2, 'the attempt counter did not move');
    assertEq(_after.setupCommitment, _before.setupCommitment, 'the opening changed the setup');
    assertEq(_after.setupNonce, _before.setupNonce, 'the opening moved the nonce');
    _assertMethodsOnlyReadAndOnlyTheManagerWrites(_accesses);
    assertEq(_privilege(_holderKey), _SIGNER_VALUE, 'the opening touched the account');
  }

  /// @notice One bad proof reverts the whole request, even when the other proofs meet the rule. Here
  ///         Carol's place carries Alice's signature. Nothing is stored, no clock starts and the account
  ///         is untouched.
  function test_RevertWhen_OneProofInTheSetFails() external {
    // it should revert
    IPolicyManager.ActionState memory _before = _state();
    IPolicyManager.AttemptRequest memory _req =
      _request(_places(_ALICE, _BOB, _CAROL), 1, _before.setupNonce, _window());
    _req.proofs = _withPhone(_req);
    (uint8 _v, bytes32 _r, bytes32 _s) = vm.sign(_guardianKeys[_ALICE], _manager.hashApproval(_req, _CAROL));
    _req.proofs[2].proof = abi.encodePacked(_r, _s, _v);

    vm.expectRevert(
      abi.encodeWithSelector(IPolicyManager.PolicyManager_ProofRejected.selector, _CAROL, address(_ecdsa))
    );
    _send(_req);

    // it should write nothing and leave the account untouched
    _assertSameState(_before, _state(), 'the refused request wrote state');
    assertEq(_privilege(_holderKey), _SIGNER_VALUE, 'the refused request touched the account');
  }

  /// @notice A request whose proofs are all valid but too few opens nothing. One friend and the phone
  ///         do not meet the clause that needs two friends, so the manager stores nothing.
  function test_RevertWhen_TheSetFallsShortOfAClause() external {
    // it should revert
    IPolicyManager.ActionState memory _before = _state();
    IPolicyManager.AttemptRequest memory _req = _request(_places(_ALICE, _PHONE), 1, _before.setupNonce, _window());

    vm.expectRevert(abi.encodeWithSelector(IPolicyManager.PolicyManager_RuleUnsatisfied.selector, uint256(0)));
    _send(_req);

    // it should write nothing and leave the account untouched
    _assertSameState(_before, _state(), 'the short request wrote state');
    assertEq(_privilege(_holderKey), _SIGNER_VALUE, 'the short request touched the account');
  }

  /// @notice A request that carries a different rule from the committed one, here a shorter wait, is
  ///         refused before any method is called. Only the rule the holder committed can open an
  ///         attempt.
  function test_RevertWhen_TheRequestCarriesAnotherRule() external {
    // it should revert
    bytes memory _otherRule = _rule(1 days, false);
    IPolicyManager.AttemptRequest memory _req = _requestOver(_otherRule, _openingSet(), 1, 1, _window());
    IPolicyManager.ActionState memory _before = _state();
    _sendRefusedBeforeAnyMethod(
      _req,
      abi.encodeWithSelector(
        IPolicyManager.PolicyManager_SetupCommitmentMismatch.selector,
        _commitmentOf(1, _otherRule),
        _commitmentOf(1, _body())
      )
    );
    _assertSameState(_before, _state(), 'the refused request wrote state');
  }

  /// @notice A place with a different salt gives a different credential hash,
  ///         keccak256(abi.encode(method, config, salt)), and is refused before any method is called.
  ///         Only the method and config the holder committed can check a proof.
  function test_RevertWhen_APlaceCarriesAnotherCredential() external {
    // it should revert
    IPolicyManager.AttemptRequest memory _req = _nextRequest(_openingSet());
    _req.proofs[0].salt = keccak256('another salt');
    bytes32 _recomputed = keccak256(abi.encode(_req.proofs[0].method, _req.proofs[0].config, _req.proofs[0].salt));
    _sendRefusedBeforeAnyMethod(
      _req, abi.encodeWithSelector(IPolicyManager.PolicyManager_CredentialMismatch.selector, _ALICE, _recomputed)
    );
  }

  /// @notice Appends the phone's place, signed over its approval digest, to a request's proofs.
  function _withPhone(IPolicyManager.AttemptRequest memory _req)
    internal
    view
    returns (IPolicyManager.ProofPlace[] memory _proofs)
  {
    uint256 _n = _req.proofs.length;
    _proofs = new IPolicyManager.ProofPlace[](_n + 1);
    for (uint256 _i; _i < _n; ++_i) {
      _proofs[_i] = _req.proofs[_i];
    }
    uint256[] memory _phone = new uint256[](1);
    _phone[0] = _PHONE;
    _proofs[_n] = _unsignedPlaces(_phone)[0];
    _proofs[_n].proof = _prove(_PHONE, _manager.hashApproval(_req, _PHONE));
  }
}
