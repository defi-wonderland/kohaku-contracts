// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {Vm} from 'forge-std/Vm.sol';
import {IPolicyManager} from 'interfaces/IPolicyManager.sol';
import {IPolicyMethodAdmin} from 'interfaces/IPolicyMethodAdmin.sol';
import {IPolicyMethodPause} from 'interfaces/IPolicyMethodPause.sol';
import {
  MethodZkPassportRootVerifierMock,
  MethodZkPassportVerifierHelperMock
} from 'test/mocks/MethodZkPassportMocks.sol';
import {IntegrationIdentityKitTestBase} from 'test/utils/IntegrationIdentityKitTestBase.sol';

/// @notice A holder's rule counts an identity credential, and the Safe stops the method that judges it while an
///         attempt that credential opened waits. A stop is the Safe pausing a method through the method's own pause
///         call. The holder's setup honours stops, so anyone can end that attempt by veto. Once the Safe unpauses the
///         method, every rule naming it counts it again with no write from any holder's key.
contract StopAnIdentityMethodDuringAWaitTest is IntegrationIdentityKitTestBase {
  /// @notice The holder's rule, under which every stop reaches the holder's attempts.
  bytes internal _idBody;

  function setUp() public override {
    super.setUp();
    _idBody = _idRule(false);
    _authorizeAndCommitBody(_idBody);
  }

  /*///////////////////////////////////////////////////////////////
                          THE WALK, PER METHOD
  ///////////////////////////////////////////////////////////////*/

  /// @notice A stop on the zkPassport method during the wait lets anyone end the attempt it opened by veto. After
  ///         the Safe unpauses the method, the same rule counts it again for a fresh attempt that waits the whole
  ///         wait. `_seed` builds the address of whoever sends the veto.
  function test_WhenTheZkPassportMethodIsStoppedDuringTheWait(uint256 _seed) external {
    // it should let anyone end the attempt by veto and count the method again after the Safe unpauses it
    _walkTheStop(_ZKPASSPORT, _seed);
  }

  /// @notice A stop on the Aadhaar method during the wait lets anyone end the attempt it opened by veto. After the
  ///         Safe unpauses the method, the same rule counts it again with no write from the holder. `_seed` builds the
  ///         address of whoever sends the veto.
  function test_WhenTheAadhaarMethodIsStoppedDuringTheWait(uint256 _seed) external {
    // it should let anyone end the attempt by veto and count the method again after the Safe unpauses it
    _walkTheStop(_AADHAAR, _seed);
  }

  /*///////////////////////////////////////////////////////////////
                          WHAT A STOP DOES NOT DO
  ///////////////////////////////////////////////////////////////*/

  /// @notice A stop ends no attempt by itself and moves no clock. If nobody sends the veto cancel, the spend is
  ///         refused while the method is stopped and runs in the first block after the Safe unpauses it. `_stopAt`
  ///         picks the moment of the stop inside the wait, and `_unpauseAfter` how long after the wait, up to thirty
  ///         days, the Safe unpauses the method.
  function test_WhenNobodySendsTheVetoCancel(uint256 _stopAt, uint256 _unpauseAfter) external {
    // it should keep the attempt waiting and let it be spent in the first block after the Safe unpauses the method
    _send(_idRequest(_idBody, _friendsAnd(_ZKPASSPORT)));
    IPolicyManager.Attempt memory _accepted = _state().attempt;

    vm.warp(bound(_stopAt, block.timestamp, uint256(_accepted.consumableAfter) - 1));
    _stopMethod(address(_zkPassport));
    vm.warp(uint256(_accepted.consumableAfter) + bound(_unpauseAfter, 0, 30 days));

    vm.expectRevert(
      abi.encodeWithSelector(IPolicyManager.PolicyManager_MethodVetoedSpend.selector, address(_zkPassport))
    );
    _executeHandover();
    assertEq(uint256(_state().attempt.state), uint256(IPolicyManager.AttemptState.Waiting), 'the stop ended it');
    _assertNoKeyMoved();

    _unpauseMethod(address(_zkPassport));
    vm.roll(block.number + 1);
    vm.warp(block.timestamp + 12);
    assertEq(_state().attempt.consumableAfter, _accepted.consumableAfter, 'the stop moved the clock');
    _executeHandover();
    _assertHandedOver();
  }

  /// @notice Unlike a stop, the key admin can make a forged proof count. Once the Safe, as key admin, sets an
  ///         Aadhaar issuer key it controls, a proof under that key counts for the guardian's place and the recovery
  ///         runs, where the same proof was refused before. `_seed` builds the key the admin controls.
  function test_WhenTheAadhaarKeyAdminSetsAKeyItControls(uint256 _seed) external {
    // it should accept the proofs that key forges
    bytes32 _forgerKey = keccak256(abi.encode('forgerKey', _seed));
    IPolicyManager.ActionState memory _committed = _state();
    IPolicyManager.AttemptRequest memory _req = _idRequest(_idBody, _friendsAnd(_AADHAAR));
    _req.proofs[2].proof = _aadhaarProve(_forgerKey, _manager.hashApproval(_req, _AADHAAR));

    vm.expectRevert(_proofRejected(_AADHAAR, address(_aadhaar)));
    _send(_req);

    vm.expectEmit(true, true, true, true, address(_aadhaar));
    emit IPolicyMethodAdmin.TrustedKeysUpdated(_oneWord(_AADHAAR_KEY), _oneWord(_forgerKey));
    vm.prank(_identitySafe);
    _aadhaar.setTrustedKeys(_oneWord(_forgerKey));

    _send(_req);
    _assertForgedAttemptSpent(address(_aadhaar), _committed);
  }

  /// @notice Once the Safe, as key admin, sets a root verifier and verifier helper it controls in the zkPassport
  ///         trusted keys, a proof the guardian never made counts for the guardian's place and the recovery runs.
  ///         The same proof was refused before the change, and no contract check stands between the new verifiers
  ///         and the holder's account.
  function test_WhenTheZkPassportKeyAdminRoutesProofsToAVerifierItControls() external {
    // it should accept the proofs that verifier forges
    MethodZkPassportRootVerifierMock _forgerRoot = new MethodZkPassportRootVerifierMock();
    MethodZkPassportVerifierHelperMock _forgerVerifierHelper = new MethodZkPassportVerifierHelperMock();
    IPolicyManager.ActionState memory _committed = _state();
    IPolicyManager.AttemptRequest memory _req = _idRequest(_idBody, _friendsAnd(_ZKPASSPORT));
    _req.proofs[2].proof =
      _zkProveThrough(_forgerRoot, _forgerVerifierHelper, _manager.hashApproval(_req, _ZKPASSPORT), 'forger');

    vm.expectRevert(_proofRejected(_ZKPASSPORT, address(_zkPassport)));
    _send(_req);

    bytes32[] memory _forgerWords = _zkWords(address(_forgerRoot), address(_forgerVerifierHelper));
    vm.expectEmit(true, true, true, true, address(_zkPassport));
    emit IPolicyMethodAdmin.TrustedKeysUpdated(_zkWords(address(_zkRoot), address(_zkVerifierHelper)), _forgerWords);
    vm.prank(_identitySafe);
    _zkPassport.setTrustedKeys(_forgerWords);

    _send(_req);
    _assertForgedAttemptSpent(address(_zkPassport), _committed);
  }

  /*///////////////////////////////////////////////////////////////
                              HELPERS
  ///////////////////////////////////////////////////////////////*/

  /// @notice Walks the stop over the identity credential at `_place`, every step in order, asserting each outcome.
  function _walkTheStop(uint256 _place, uint256 _seed) internal {
    address _method = _identityMethodAt(_place);
    IPolicyManager.ActionState memory _committed = _state();
    assertFalse(_answersStopped(_method), 'the method starts stopped');

    IPolicyManager.Attempt memory _first = _openWithTheCredential(_place);
    _stopAndVeto(_place, _fresh('anyone', _seed));

    // While the stop is on, the method's proofs count for nothing and the ended attempt cannot be spent.
    IPolicyManager.AttemptRequest memory _during = _idRequest(_idBody, _friendsAnd(_place));
    vm.expectRevert(abi.encodeWithSelector(IPolicyManager.PolicyManager_MethodStopped.selector, _place, _method));
    _send(_during);
    vm.warp(_first.consumableAfter);
    vm.expectRevert(_notConsumable(IPolicyManager.AttemptState.Cancelled, _first));
    _executeHandover();
    _assertNoKeyMoved();

    // The Safe unpauses the method. No holder wrote anything.
    vm.expectEmit(true, true, true, true, _method);
    emit IPolicyMethodPause.Unpaused(_identitySafe);
    _unpauseMethod(_method);
    assertFalse(_answersStopped(_method), 'the method still answers true');
    _assertSetupUnchanged(_committed);

    _recoverAgain(_place);
  }

  /// @notice The guardian's device proves the place's digest, the submitter opens the attempt, and the manager
  ///         reads the identity method's stop once, before its proof. The attempt records the method among the
  ///         distinct methods its set used, in storage and in the opening event.
  function _openWithTheCredential(uint256 _place) internal returns (IPolicyManager.Attempt memory _first) {
    address _method = _identityMethodAt(_place);
    IPolicyManager.AttemptRequest memory _req = _idRequest(_idBody, _friendsAnd(_place));
    _expectTheOutsideCheck(_place, _manager.hashApproval(_req, _place), _req.proofs[2].proof);
    vm.recordLogs();
    vm.startStateDiffRecording();
    _send(_req);
    Vm.AccountAccess[] memory _accesses = vm.stopAndReturnStateDiff();
    StartedLog memory _started = _startedLog(vm.getRecordedLogs());

    uint256[] memory _calls = _callsTo(_accesses, _method);
    assertEq(_calls.length, 2, 'the method was called other than twice');
    assertEq(_calls[0], 1, 'the first call to the method was not its stop read');
    assertEq(_calls[1], 2, 'the second call to the method was not its verify');

    _first = _state().attempt;
    assertEq(uint256(_first.state), uint256(IPolicyManager.AttemptState.Waiting), 'no attempt opened');
    assertEq(_first.attemptId, 1, 'the attempt is not the first');
    assertFalse(_first.ignoresPause, 'the attempt ignores stops');
    assertEq(_first.consumableAfter, block.timestamp + _WAIT, 'the wait is not the committed one');
    assertEq(_first.usedMethods.length, 2, 'the set used other than two methods');
    assertEq(_first.usedMethods[0], address(_ecdsa), 'the wallet method is not recorded first');
    assertEq(_first.usedMethods[1], _method, 'the identity method is not recorded');
    assertEq(abi.encode(_started.usedMethods), abi.encode(_first.usedMethods), 'the event names other methods');
    assertEq(abi.encode(_started.usedPlaces), abi.encode(_friendsAnd(_place)), 'the event names other places');
  }

  /// @notice During the wait the Safe stops the method at `_place`, which reports it and answers the stop read with
  ///         true. A cancel by proofs leaning on the stopped method is refused. The veto needs the live attempt, a
  ///         method that attempt used and an exact true from that method.
  ///         Then `_anyone`'s veto cancel ends the attempt, and its event names the method that vetoed it.
  function _stopAndVeto(uint256 _place, address _anyone) internal {
    address _method = _identityMethodAt(_place);
    vm.warp(block.timestamp + 1 days);
    vm.expectEmit(true, true, true, true, _method);
    emit IPolicyMethodPause.Paused(_identitySafe);
    _stopMethod(_method);
    assertTrue(_answersStopped(_method), 'the method does not answer true');

    // A cancelling set that leans on the stopped method counts for nothing either.
    IPolicyManager.CancelRequest memory _leaning = _idCancelRequest(_idBody, _places(_ALICE, _CAROL, _place));
    vm.expectRevert(abi.encodeWithSelector(IPolicyManager.PolicyManager_MethodStopped.selector, _place, _method));
    vm.prank(_anyone);
    _manager.cancelByProofs(_leaning);

    address _unused = _place == _ZKPASSPORT ? address(_aadhaar) : address(_zkPassport);
    _vetoRefused(
      _anyone, 2, _method, abi.encodeWithSelector(IPolicyManager.PolicyManager_WrongAttemptId.selector, 2, 1)
    );
    _vetoRefused(
      _anyone, 1, _unused, abi.encodeWithSelector(IPolicyManager.PolicyManager_MethodNotUsed.selector, 1, _unused)
    );
    _vetoRefused(
      _anyone,
      1,
      address(_ecdsa),
      abi.encodeWithSelector(IPolicyManager.PolicyManager_MethodNotStopped.selector, address(_ecdsa))
    );

    vm.recordLogs();
    vm.expectEmit(true, true, true, true, address(_manager));
    emit IPolicyManager.AttemptCancelled(_account, address(_action), 1, _anyone, _method, 1, new uint256[](0));
    vm.prank(_anyone);
    _manager.cancelByVeto(_account, address(_action), 1, _method);
    assertEq(_countLogs(vm.getRecordedLogs(), IPolicyManager.AttemptCancelled.selector), 1, 'not one cancel event');
    assertEq(uint256(_state().attempt.state), uint256(IPolicyManager.AttemptState.Cancelled), 'it did not end');
  }

  /// @notice After the Safe unpauses it, the same rule counts the method at `_place` again. A fresh set of proofs
  ///         opens the next attempt id, which waits the whole wait before its spend goes through.
  function _recoverAgain(uint256 _place) internal {
    IPolicyManager.AttemptRequest memory _again = _idRequest(_idBody, _friendsAnd(_place));
    assertEq(_again.attemptId, 2, 'the fresh set is not for the next attempt id');
    _send(_again);
    IPolicyManager.Attempt memory _second = _state().attempt;
    assertEq(_second.attemptId, 2, 'the fresh attempt is not the second');
    assertEq(_second.consumableAfter, block.timestamp + _WAIT, 'the fresh attempt skipped part of the wait');
    assertEq(_second.usedMethods[1], _identityMethodAt(_place), 'the unpaused method was not counted');

    vm.warp(uint256(_second.consumableAfter) - 1);
    vm.expectRevert(_notConsumable(IPolicyManager.AttemptState.Waiting, _second));
    _executeHandover();
    vm.warp(_second.consumableAfter);
    _executeHandover();
    _assertHandedOver();
  }

  /// @notice Expects the identity method to hand its outside verifier exactly the guardian's proof for `_digest`.
  ///         For zkPassport that is the root verifier's call with the accepted 0.21.0 version and the holder's
  ///         service configuration, then the verifier helper's read of the committed inputs. For Aadhaar it is the
  ///         Groth16 verifier's call with the proof's words, its signal input carrying the digest.
  function _expectTheOutsideCheck(uint256 _place, bytes32 _digest, bytes memory _proof) internal {
    if (_place == _ZKPASSPORT) {
      vm.expectCall(
        address(_zkRoot), abi.encodeCall(MethodZkPassportRootVerifierMock.verify, (_zkParams(_digest, 'guardian'))), 1
      );
      vm.expectCall(
        address(_zkVerifierHelper),
        abi.encodeCall(MethodZkPassportVerifierHelperMock.getBoundData, (_zkCommittedInputs(_digest))),
        1
      );
      return;
    }
    (,,, uint256[9] memory _inputs) = abi.decode(_proof, (uint256[2], uint256[2][2], uint256[2], uint256[9]));
    assertEq(_inputs[8], _aadhaarSignal(_digest), 'the proof does not carry the digest as its signal');
    vm.expectCall(address(_aadhaarVerifier), abi.encodePacked(_aadhaarVerifier.VERIFY_PROOF_SELECTOR(), _proof), 1);
  }

  /// @notice Sends a veto cancel from `_anyone` naming `_attemptId` and `_method`, and expects `_err`.
  function _vetoRefused(address _anyone, uint64 _attemptId, address _method, bytes memory _err) internal {
    vm.expectRevert(_err);
    vm.prank(_anyone);
    _manager.cancelByVeto(_account, address(_action), _attemptId, _method);
  }

  /// @notice Asserts an attempt that a forged proof under `_method` opened is waiting with that method among its
  ///         used methods, that the holder wrote nothing, and that the spend runs once the wait is over.
  function _assertForgedAttemptSpent(address _method, IPolicyManager.ActionState memory _committed) internal {
    IPolicyManager.Attempt memory _forged = _state().attempt;
    assertEq(uint256(_forged.state), uint256(IPolicyManager.AttemptState.Waiting), 'the forged set opened nothing');
    assertEq(_forged.usedMethods[1], _method, 'the forged proof did not count');
    assertFalse(_answersStopped(_method), 'the method was stopped');
    _assertSetupUnchanged(_committed);
    vm.warp(_forged.consumableAfter);
    _executeHandover();
    _assertHandedOver();
  }
}
