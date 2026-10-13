// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {Vm} from 'forge-std/Vm.sol';
import {IPolicyManager} from 'interfaces/IPolicyManager.sol';
import {IPolicyMethodPause} from 'interfaces/IPolicyMethodPause.sol';
import {MethodAadhaarVerifierMock} from 'test/mocks/MethodAadhaarVerifierMock.sol';
import {ActionAmbireProxy, ActionAmbireProxyDeployer} from 'test/utils/ActionAmbireProxy.sol';
import {IntegrationIdentityKitTestBase} from 'test/utils/IntegrationIdentityKitTestBase.sol';

/// @notice A holder whose rule names an identity method beside their friends commits a setup that ignores stops. A
///         stop is the Safe pausing a method through the method's own pause call. Here the identity method is stopped
///         before any request, and the holder's attempt is opened, kept and spent as if no stop existed. The manager
///         reads no stop at the opening, the veto, the cancel by proofs or the spend, the four moments it otherwise
///         would.
contract KeepRecoveriesThroughAStopTest is IntegrationIdentityKitTestBase {
  /// @notice The holder's rule, which ignores every stop.
  bytes internal _ignoring;

  function setUp() public override {
    super.setUp();
    _ignoring = _idRule(true);
  }

  /*///////////////////////////////////////////////////////////////
                          THE WALK, PER METHOD
  ///////////////////////////////////////////////////////////////*/

  /// @notice A holder who ignores stops recovers through a stopped zkPassport method as if no stop existed, and no
  ///         step reads the stop. The proof is counted for its place, the veto is refused, both cancels still work
  ///         and the spend runs after the wait. `_seed` builds the addresses of whoever sends the veto and the cancel.
  function test_WhenTheZkPassportMethodIsStoppedBeforeTheRequest(uint256 _seed) external {
    // it should judge, keep and spend the attempt as if no stop existed
    _walkThroughTheStop(_ZKPASSPORT, _seed);
  }

  /// @notice A holder who ignores stops recovers through a stopped Aadhaar method as if no stop existed, and no step
  ///         reads the stop. The steps are the zkPassport walk's, with the Aadhaar credential instead. `_seed` builds
  ///         the addresses of whoever sends the veto and the cancel.
  function test_WhenTheAadhaarMethodIsStoppedBeforeTheRequest(uint256 _seed) external {
    // it should judge, keep and spend the attempt as if no stop existed
    _walkThroughTheStop(_AADHAAR, _seed);
  }

  /*///////////////////////////////////////////////////////////////
                        WHAT THE CHOICE COSTS
  ///////////////////////////////////////////////////////////////*/

  /// @notice Ignoring stops has a cost: a forged proof, one no guardian made, still opens a recovery that no veto
  ///         can end. The stopped Aadhaar method here has the bug that accepts such a proof, and the spend runs after
  ///         the wait. `_seed` builds the address of whoever tries the veto.
  function test_WhenAForgedProofFromTheStoppedMethodIsCounted(uint256 _seed) external {
    // it should open the attempt and spend it the same way
    _openForged();
    _assertVetoRefused(_fresh('anyone', _seed));

    vm.warp(_state().attempt.consumableAfter);
    vm.startStateDiffRecording();
    _executeHandover();
    assertEq(_pauseReads(vm.stopAndReturnStateDiff()), 0, 'the spend read a stop');
    _assertHandedOver();
  }

  /// @notice The holder's own key still cancels an attempt a forged proof opened, where the veto cannot. That cancel
  ///         calls neither the stopped method nor the wallet method. `_seed` builds the address of whoever tries the
  ///         veto.
  function test_WhenTheHoldersKeyAnswersAForgedAttempt(uint256 _seed) external {
    // it should cancel it while the veto cannot
    _openForged();
    _assertVetoRefused(_fresh('anyone', _seed));

    vm.startStateDiffRecording();
    _asHolder(_one(_cancelByOwnerCall()));
    Vm.AccountAccess[] memory _accesses = vm.stopAndReturnStateDiff();
    assertFalse(_reached(_accesses, address(_aadhaar)), 'the holder cancel reached the stopped method');
    assertFalse(_reached(_accesses, address(_ecdsa)), 'the holder cancel reached the wallet method');
    _assertCancelledBeforeTheSpend();
  }

  /// @notice Two friends and the holder's phone, a set that meets the rule without the stopped method, still cancel
  ///         an attempt a forged proof opened, where the veto cannot. `_seed` builds the addresses of whoever tries the
  ///         veto and whoever sends the cancel.
  function test_WhenASatisfyingSetAnswersAForgedAttempt(uint256 _seed) external {
    // it should cancel it while the veto cannot
    _openForged();
    _assertVetoRefused(_fresh('anyone', _seed));

    IPolicyManager.CancelRequest memory _cancel = _idCancelRequest(_ignoring, _places(_ALICE, _CAROL, _PHONE));
    vm.prank(_fresh('canceller', _seed));
    _manager.cancelByProofs(_cancel);
    _assertCancelledBeforeTheSpend();
  }

  /// @notice The holder's choice to ignore stops changes only through a fresh setup their key commits. That write
  ///         cancels the attempt opened under the old choice, and the new choice refuses the next request through the
  ///         stopped method. A commit from another Ambire account the action serves writes that account's own setup
  ///         and leaves the holder's alone. `_seed` builds the key of that other account and whoever tries the veto.
  function test_WhenTheHolderChangesTheChoice(uint256 _seed) external {
    // it should take a fresh setup under the holder's key and never read the accepted attempt again
    _authorizeAndCommitBody(_ignoring);
    _stopMethod(address(_aadhaar));
    _send(_idRequest(_ignoring, _friendsAnd(_AADHAAR)));
    IPolicyManager.ActionState memory _judged = _state();
    bytes memory _honouring = _idRule(false);

    address _other = new ActionAmbireProxyDeployer()
      .deploy(ActionAmbireProxy.creationCode(_implementation, _fresh('otherCommitter', _seed), _SIGNER_VALUE), 0);
    vm.prank(_other);
    _manager.commitSetup(address(_action), keccak256(abi.encode(_other, address(_action), 1, _honouring)), 1, '', '');
    _assertSameState(_judged, _state(), 'another commit touched the holder');

    vm.recordLogs();
    _asHolder(_one(_commitCall(2, _commitmentOf(2, _honouring))));
    _assertTheWriteCancelledFirst(vm.getRecordedLogs());

    IPolicyManager.Attempt memory _old = _state().attempt;
    assertEq(uint256(_old.state), uint256(IPolicyManager.AttemptState.Cancelled), 'the old attempt still waits');
    assertTrue(_old.ignoresPause, 'the old attempt was re-read under the new choice');
    assertEq(_state().setupCommitment, _commitmentOf(2, _honouring), 'the new choice was not committed');

    vm.expectRevert(
      abi.encodeWithSelector(IPolicyManager.PolicyManager_NoActiveAttempt.selector, _account, address(_action))
    );
    vm.prank(_fresh('anyone', _seed));
    _manager.cancelByVeto(_account, address(_action), 1, address(_aadhaar));
    vm.warp(_old.consumableAfter);
    vm.expectRevert(_notConsumable(IPolicyManager.AttemptState.Cancelled, _old));
    _executeHandover();

    IPolicyManager.AttemptRequest memory _next = _idRequest(_honouring, _friendsAnd(_AADHAAR));
    vm.expectRevert(
      abi.encodeWithSelector(IPolicyManager.PolicyManager_MethodStopped.selector, _AADHAAR, address(_aadhaar))
    );
    _send(_next);
    _assertNoKeyMoved();
  }

  /*///////////////////////////////////////////////////////////////
                              HELPERS
  ///////////////////////////////////////////////////////////////*/

  /// @notice Walks the holder's choice through a stop of the identity method at `_place`, every step in order. The
  ///         two cancels are shown from one saved state and rolled back, so the spend at the end runs on the same
  ///         attempt they could have ended.
  function _walkThroughTheStop(uint256 _place, uint256 _seed) internal {
    address _method = _identityMethodAt(_place);
    IPolicyManager.Attempt memory _accepted = _openThroughTheStop(_place);

    // Anyone's veto cancel is refused.
    _assertVetoRefused(_fresh('anyone', _seed));

    uint256 _saved = vm.snapshotState();
    _cancelByProofsThroughTheStop(_place, _fresh('canceller', _seed));
    vm.revertToState(_saved);
    _cancelByTheHoldersKey(_method);
    vm.revertToState(_saved);

    // The wait ends, and the spend makes no stop read and goes through.
    vm.warp(_accepted.consumableAfter);
    vm.expectEmit(true, true, true, true, address(_manager));
    emit IPolicyManager.AttemptConsumed(_account, address(_action), 1);
    vm.startStateDiffRecording();
    _executeHandover();
    assertEq(_pauseReads(vm.stopAndReturnStateDiff()), 0, 'the spend read a stop');
    _assertHandedOver();
    assertTrue(_answersStopped(_method), 'the stop came off');
  }

  /// @notice The first steps of the walk: the holder commits the ignoring rule, the Safe stops the method at
  ///         `_place` before any request, and the submitter opens an attempt whose set includes that method's
  ///         proof. The manager makes no stop read, verifies the proof like any other and copies the choice onto
  ///         the attempt.
  function _openThroughTheStop(uint256 _place) internal returns (IPolicyManager.Attempt memory _accepted) {
    address _method = _identityMethodAt(_place);
    _authorizeAndCommitBody(_ignoring);
    assertEq(_state().setupCommitment, _commitmentOf(1, _ignoring), 'the choice was not committed');

    vm.expectEmit(true, true, true, true, _method);
    emit IPolicyMethodPause.Paused(_identitySafe);
    _stopMethod(_method);
    assertTrue(_answersStopped(_method), 'the method does not answer true');

    IPolicyManager.AttemptRequest memory _req = _idRequest(_ignoring, _friendsAnd(_place));
    uint256 _openedAt = block.timestamp;
    vm.startStateDiffRecording();
    _send(_req);
    Vm.AccountAccess[] memory _accesses = vm.stopAndReturnStateDiff();
    assertEq(_pauseReads(_accesses), 0, 'the opening read a stop');
    uint256[] memory _calls = _callsTo(_accesses, _method);
    assertEq(_calls.length, 1, 'the stopped method was called other than once');
    assertEq(_calls[0], 2, 'the call to the stopped method was not its verify');

    _accepted = _state().attempt;
    assertEq(uint256(_accepted.state), uint256(IPolicyManager.AttemptState.Waiting), 'no attempt opened');
    assertTrue(_accepted.ignoresPause, 'the attempt does not carry the choice');
    assertEq(_accepted.usedMethods[1], _method, 'the stopped method was not counted');
    _assertTheWholeWaitRuns(_openedAt);
  }

  /// @notice A satisfying set that includes the stopped method at `_place` cancels the attempt by proofs, sent by
  ///         `_canceller`. The manager verifies the stopped method's cancel proof and makes no stop read.
  function _cancelByProofsThroughTheStop(uint256 _place, address _canceller) internal {
    uint256[] memory _cancelling = _places(_ALICE, _CAROL, _place);
    IPolicyManager.CancelRequest memory _cancel = _idCancelRequest(_ignoring, _cancelling);
    vm.expectEmit(true, true, true, true, address(_manager));
    emit IPolicyManager.AttemptCancelled(_account, address(_action), 1, _canceller, address(0), 1, _cancelling);
    vm.startStateDiffRecording();
    vm.prank(_canceller);
    _manager.cancelByProofs(_cancel);
    Vm.AccountAccess[] memory _accesses = vm.stopAndReturnStateDiff();
    assertEq(_pauseReads(_accesses), 0, 'the cancel by proofs read a stop');
    uint256[] memory _calls = _callsTo(_accesses, _identityMethodAt(_place));
    assertEq(_calls.length, 1, 'the stopped method was called other than once by the cancel');
    assertEq(_calls[0], 2, 'the cancel did not verify the stopped method');
    _assertCancelledBeforeTheSpend();
  }

  /// @notice The holder's own key cancels the attempt as always, and the call reaches neither `_method` nor the
  ///         wallet method.
  function _cancelByTheHoldersKey(address _method) internal {
    vm.expectEmit(true, true, true, true, address(_manager));
    emit IPolicyManager.AttemptCancelled(_account, address(_action), 1, _account, address(0), 1, new uint256[](0));
    vm.startStateDiffRecording();
    _asHolder(_one(_cancelByOwnerCall()));
    Vm.AccountAccess[] memory _accesses = vm.stopAndReturnStateDiff();
    assertFalse(_reached(_accesses, _method), 'the holder cancel reached the stopped method');
    assertFalse(_reached(_accesses, address(_ecdsa)), 'the holder cancel reached the wallet method');
    _assertCancelledBeforeTheSpend();
  }

  /// @notice Asserts the holder's setup write in `_logs` cancelled the waiting attempt first, with exactly one cancel
  ///         event before the commit event. That event names the holder's account and action, attempt one under
  ///         setup one, no canceller, no stopped method and no places.
  function _assertTheWriteCancelledFirst(Vm.Log[] memory _logs) internal view {
    uint256 _cancelAt = _indexOfLog(_logs, IPolicyManager.AttemptCancelled.selector);
    assertEq(_logs[_cancelAt].topics[1], _word(_account), 'the cancel names another account');
    assertEq(_logs[_cancelAt].topics[2], _word(address(_action)), 'the cancel names another action');
    uint256 _commitAt = _indexOfLog(_logs, IPolicyManager.SetupCommitted.selector);
    assertLt(_cancelAt, _commitAt, 'the cancel event does not come before the commit event');
    assertEq(_countLogs(_logs, IPolicyManager.AttemptCancelled.selector), 1, 'the write emitted other than one cancel');
    (uint64 _attemptId, address _canceller, address _stoppedMethod, uint64 _setupNonce, uint256[] memory _usedPlaces) =
      abi.decode(_logs[_cancelAt].data, (uint64, address, address, uint64, uint256[]));
    assertEq(_usedPlaces.length, 0, 'a setup write named cancelling places');
    assertEq(_attemptId, 1, 'the write cancelled another attempt');
    assertEq(_canceller, address(0), 'a setup write named a canceller');
    assertEq(_stoppedMethod, address(0), 'a setup write named a stopped method');
    assertEq(_setupNonce, 1, 'the cancel names another setup');
  }

  /// @notice Commits the ignoring rule, stops the Aadhaar method and opens an attempt whose Aadhaar proof no
  ///         guardian made. The bug the stop answers is modelled by a Groth16 verifier that accepts any points, so
  ///         the forger needs only the public inputs. The opening reads no stop.
  function _openForged() internal {
    _authorizeAndCommitBody(_ignoring);
    _stopMethod(address(_aadhaar));
    IPolicyManager.AttemptRequest memory _req = _idRequest(_ignoring, _friendsAnd(_AADHAAR));
    uint256[2] memory _a;
    uint256[2][2] memory _b;
    uint256[2] memory _c;
    _req.proofs[2].proof = abi.encode(_a, _b, _c, _aadhaarInputs(_AADHAAR_KEY, _manager.hashApproval(_req, _AADHAAR)));
    _aadhaarVerifier.setMode(MethodAadhaarVerifierMock.Mode.AlwaysTrue);

    uint256 _openedAt = block.timestamp;
    vm.startStateDiffRecording();
    _send(_req);
    assertEq(_pauseReads(vm.stopAndReturnStateDiff()), 0, 'the forged opening read a stop');
    IPolicyManager.Attempt memory _forged = _state().attempt;
    assertEq(uint256(_forged.state), uint256(IPolicyManager.AttemptState.Waiting), 'the forged set opened nothing');
    assertEq(_forged.usedMethods[1], address(_aadhaar), 'the forged proof did not count');
    _assertTheWholeWaitRuns(_openedAt);
  }

  /// @notice Asserts the attempt opened at `_openedAt` waits the whole committed wait, as it would with no stop. Its
  ///         deadline is the opening time plus the committed wait, and one second before that deadline the handover
  ///         is refused with the attempt still waiting and no key moved. The clock is left at that second.
  function _assertTheWholeWaitRuns(uint256 _openedAt) internal {
    IPolicyManager.Attempt memory _waiting = _state().attempt;
    assertEq(_waiting.consumableAfter, _openedAt + _WAIT, 'the attempt does not wait the committed wait');
    vm.warp(_openedAt + _WAIT - 1);
    vm.expectRevert(_notConsumable(IPolicyManager.AttemptState.Waiting, _waiting));
    _executeHandover();
    _assertNoKeyMoved();
  }

  /// @notice Asserts that `_anyone`'s veto cancel naming the stopped identity method the attempt used is refused
  ///         because the attempt ignores stops, before any stop read, and that the attempt still waits.
  function _assertVetoRefused(address _anyone) internal {
    address _method = _state().attempt.usedMethods[1];
    vm.startStateDiffRecording();
    vm.expectRevert(abi.encodeWithSelector(IPolicyManager.PolicyManager_AttemptIgnoresPause.selector, 1));
    vm.prank(_anyone);
    _manager.cancelByVeto(_account, address(_action), 1, _method);
    assertEq(_pauseReads(vm.stopAndReturnStateDiff()), 0, 'the veto read a stop');
    assertEq(uint256(_state().attempt.state), uint256(IPolicyManager.AttemptState.Waiting), 'the veto ended it');
  }

  /// @notice Asserts the attempt was cancelled and that its spend is refused once the wait is over, with no key
  ///         moved.
  function _assertCancelledBeforeTheSpend() internal {
    IPolicyManager.Attempt memory _ended = _state().attempt;
    assertEq(uint256(_ended.state), uint256(IPolicyManager.AttemptState.Cancelled), 'the attempt still waits');
    vm.warp(_ended.consumableAfter);
    vm.expectRevert(_notConsumable(IPolicyManager.AttemptState.Cancelled, _ended));
    _executeHandover();
    _assertNoKeyMoved();
  }
}
