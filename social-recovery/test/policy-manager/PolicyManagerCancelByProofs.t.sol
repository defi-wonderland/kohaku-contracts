// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {Vm} from 'forge-std/Vm.sol';
import {BindingDigest} from 'libraries/BindingDigest.sol';
import {IPolicyManager} from 'interfaces/IPolicyManager.sol';
import {IPolicyMethod} from 'interfaces/IPolicyMethod.sol';
import {PolicyManagerMockWritingMethod} from 'test/mocks/PolicyManagerMockWritingMethod.sol';
import {PolicyManagerAcceptanceTestBase} from 'test/utils/PolicyManagerAcceptanceTestBase.sol';

/// @notice cancelByProofs, the permissionless cancel of a waiting attempt by a proof set that
///         satisfies the committed rule. It runs the opening's checks with five differences: it
///         needs a waiting attempt where an opening refuses one, it names the live attempt rather
///         than the next, its proofs sign the cancellation digest rather than the approval digest,
///         it refuses an attempt judged under another setup nonce, and it does not check that a
///         setup exists. Everything else an opening checks, it checks the same way.
/// @dev The default rule is the base contract's: clause 0 needs place 0, clause 1 needs 2 of places
///      1, 2 and 3; method A judges places 0 and 1 and method B places 2 and 3. A poisoned
///      cancellation carries one proof at place 99, past the end of the rule, so reading any place
///      would revert with PolicyManager_PlaceOutOfRange.
contract PolicyManagerCancelByProofsTest is PolicyManagerAcceptanceTestBase {
  /// @notice The gas a call gets in the test of a huge answer. A manager that copies a huge answer
  ///         before reading its size runs out of it, and one that reads the size first does not.
  uint256 internal constant _HUGE_ANSWER_GAS = 2_000_000;
  /// @notice The size of a huge answer. Copying it into memory costs several million gas.
  uint256 internal constant _HUGE_ANSWER_SIZE = 2_000_000;

  /*///////////////////////////////////////////////////////////////
                             THE PRE-CHECKS
  ///////////////////////////////////////////////////////////////*/

  /// @notice With no setup and no attempt ever recorded a cancellation is refused as
  ///         PolicyManager_NoActiveAttempt, never as PolicyManager_NoSetup, before any place is read:
  ///         the cancel path checks for a waiting attempt and not for a setup.
  function test_WhenNoAttemptWasEverRecorded() external {
    _useDefaultRule(1 days, false);
    IPolicyManager.CancelRequest memory _req = _poisoned(_cancelRequest(_places(0, 1, 2)));

    _expectNoMethodCalled();
    vm.expectRevert(abi.encodeWithSelector(IPolicyManager.PolicyManager_NoActiveAttempt.selector, _account, _action));
    _manager.cancelByProofs(_req);
  }

  /// @notice A committed setup with no attempt opened under it has nothing to cancel: the
  ///         cancellation is refused as PolicyManager_NoActiveAttempt before any place is read.
  function test_WhenASetupExistsButNoAttemptWasEverOpened() external {
    _useDefaultRule(1 days, false);
    _commitRule();
    IPolicyManager.CancelRequest memory _req = _poisoned(_cancelRequest(_places(0, 1, 2)));

    _expectNoMethodCalled();
    vm.expectRevert(abi.encodeWithSelector(IPolicyManager.PolicyManager_NoActiveAttempt.selector, _account, _action));
    _manager.cancelByProofs(_req);
  }

  /// @notice An attempt the holder already cancelled cannot be cancelled again, so no cancel event
  ///         reports a transition that did not happen, and its record stays as it was.
  function test_WhenTheAttemptWasAlreadyCancelled() external {
    _openDefault();
    vm.prank(_account);
    _manager.cancelByOwner(_action);
    IPolicyManager.Attempt memory _ended = _state(_account, _action).attempt;
    IPolicyManager.CancelRequest memory _req = _poisoned(_cancelRequest(_places(0, 1, 2)));

    _expectNoMethodCalled();
    vm.expectRevert(abi.encodeWithSelector(IPolicyManager.PolicyManager_NoActiveAttempt.selector, _account, _action));
    _manager.cancelByProofs(_req);

    assertEq(abi.encode(_state(_account, _action).attempt), abi.encode(_ended), 'record untouched');
  }

  /// @notice A consumed attempt cannot be cancelled: once the account spent it, nothing waits.
  function test_WhenTheAttemptWasConsumed() external {
    IPolicyManager.AttemptRequest memory _opening = _openDefault();
    vm.warp(block.timestamp + 1 days);
    vm.prank(_account);
    _manager.consume(_action, 1, keccak256(_opening.payload));
    IPolicyManager.CancelRequest memory _req = _poisoned(_cancelRequest(_places(0, 1, 2)));

    _expectNoMethodCalled();
    vm.expectRevert(abi.encodeWithSelector(IPolicyManager.PolicyManager_NoActiveAttempt.selector, _account, _action));
    _manager.cancelByProofs(_req);
  }

  /// @notice A cancellation naming any attempt id but the live one is refused as
  ///         PolicyManager_WrongAttemptId with both ids, before any place is read, so a cancel aimed at
  ///         one attempt never reaches another. `_offsetSeed` builds any id but the live one.
  function test_WhenTheAttemptIdIsNotTheLiveOne(uint64 _offsetSeed) external {
    _openDefault();
    IPolicyManager.CancelRequest memory _req = _poisoned(_cancelRequest(_places(0, 1, 2)));
    _req.attemptId = _otherThan(1, _offsetSeed);

    _expectNoMethodCalled();
    vm.expectRevert(
      abi.encodeWithSelector(IPolicyManager.PolicyManager_WrongAttemptId.selector, _req.attemptId, uint64(1))
    );
    _manager.cancelByProofs(_req);
  }

  /// @notice A cancellation naming the next id, the one an opening would name, is refused, since a
  ///         cancel names the live attempt rather than the next one.
  function test_WhenTheAttemptIdIsTheNextOne() external {
    _openDefault();
    IPolicyManager.CancelRequest memory _req = _poisoned(_cancelRequest(_places(0, 1, 2)));
    _req.attemptId = _state(_account, _action).nextAttemptId;

    _expectNoMethodCalled();
    vm.expectRevert(abi.encodeWithSelector(IPolicyManager.PolicyManager_WrongAttemptId.selector, uint64(2), uint64(1)));
    _manager.cancelByProofs(_req);
  }

  /// @notice A cancellation naming any setup nonce but the stored one is refused as
  ///         PolicyManager_WrongSetupNonce with both nonces, before any place is read. `_offsetSeed`
  ///         builds any nonce but the stored one.
  function test_WhenTheRequestNamesANonceOtherThanTheStoredOne(uint64 _offsetSeed) external {
    _openDefault();
    IPolicyManager.CancelRequest memory _req = _poisoned(_cancelRequest(_places(0, 1, 2)));
    _req.setupNonce = _otherThan(1, _offsetSeed);

    _expectNoMethodCalled();
    vm.expectRevert(
      abi.encodeWithSelector(IPolicyManager.PolicyManager_WrongSetupNonce.selector, _req.setupNonce, uint64(1))
    );
    _manager.cancelByProofs(_req);
  }

  /// @notice A cancellation whose validUntil is before the block's timestamp is refused as
  ///         PolicyManager_RequestExpired with both times, before any place is read, so a stale cancel
  ///         cancels nothing. `_delaySeed` moves time forward and `_untilSeed` picks a passed deadline.
  function test_WhenTheWindowHasPassed(uint256 _delaySeed, uint256 _untilSeed) external {
    _openDefault();
    vm.warp(block.timestamp + bound(_delaySeed, 1, 365 days));
    IPolicyManager.CancelRequest memory _req = _poisoned(_cancelRequest(_places(0, 1, 2)));
    _req.validUntil = uint48(bound(_untilSeed, 0, block.timestamp - 1));

    _expectNoMethodCalled();
    vm.expectRevert(
      abi.encodeWithSelector(
        IPolicyManager.PolicyManager_RequestExpired.selector, uint48(block.timestamp), _req.validUntil
      )
    );
    _manager.cancelByProofs(_req);
  }

  /// @notice A cancellation whose validUntil is the block's own timestamp still cancels.
  function test_WhenTheWindowEndsInThisBlock() external {
    _openDefault();
    IPolicyManager.CancelRequest memory _req = _cancelRequest(_places(0, 1, 2));
    _req.validUntil = uint48(block.timestamp);
    _approveCancel(_req);

    _manager.cancelByProofs(_req);

    assertEq(uint8(_state(_account, _action).attempt.state), uint8(IPolicyManager.AttemptState.Cancelled), 'state');
  }

  /// @notice An attempt whose own setup nonce is not the stored one is refused as
  ///         PolicyManager_StaleAttempt with both nonces, before any place is read. Every setup write
  ///         cancels the waiting attempt, so no sequence of calls leaves such a record, and the
  ///         harness writes it: the check is a second guard.
  function test_WhenTheAttemptWasJudgedUnderAnotherNonce() external {
    _useDefaultRule(1 days, false);
    uint64 _nonce = _commitRule();
    _plant(_account, _action, _attempt(1, _nonce + 3, IPolicyManager.AttemptState.Waiting, false, _methods()));
    IPolicyManager.CancelRequest memory _req = _poisoned(_cancelRequest(_places(0, 1, 2)));

    _expectNoMethodCalled();
    vm.expectRevert(abi.encodeWithSelector(IPolicyManager.PolicyManager_StaleAttempt.selector, _nonce + 3, _nonce));
    _manager.cancelByProofs(_req);
  }

  /// @notice With the setup cleared and a waiting record left under the stored nonce, the cancellation
  ///         fails on the commitment, recomputed against the zero commitment, and never as
  ///         PolicyManager_NoSetup: the cancel path runs no setup existence check. No sequence of
  ///         calls leaves such a record, so the harness writes it.
  function test_WhenTheSetupIsGoneButARecordStillWaits() external {
    _useDefaultRule(1 days, false);
    _commitRule();
    _clear(_account, _action);
    uint64 _nonce = _state(_account, _action).setupNonce;
    _plant(_account, _action, _attempt(1, _nonce, IPolicyManager.AttemptState.Waiting, false, _methods()));
    IPolicyManager.CancelRequest memory _req = _poisoned(_cancelRequest(_places(0, 1, 2)));

    _expectNoMethodCalled();
    vm.expectRevert(
      abi.encodeWithSelector(
        IPolicyManager.PolicyManager_SetupCommitmentMismatch.selector,
        BindingDigest.setupCommitment(_account, _action, _nonce, _setupBody),
        bytes32(0)
      )
    );
    _manager.cancelByProofs(_req);
  }

  /// @notice With no attempt waiting and the id, the nonce and the window all wrong, the missing
  ///         attempt decides: the waiting-attempt check runs first.
  function test_WhenNoAttemptWaitsAndEveryOtherCheckFails() external {
    _openDefault();
    vm.prank(_account);
    _manager.cancelByOwner(_action);
    vm.warp(block.timestamp + 2 days);
    IPolicyManager.CancelRequest memory _req = _poisoned(_cancelRequest(_places(0, 1, 2)));
    _req.attemptId = 9;
    _req.setupNonce = 9;
    _req.validUntil = uint48(block.timestamp - 1);

    _expectNoMethodCalled();
    vm.expectRevert(abi.encodeWithSelector(IPolicyManager.PolicyManager_NoActiveAttempt.selector, _account, _action));
    _manager.cancelByProofs(_req);
  }

  /// @notice With the nonce, the id and the window all wrong, the nonce decides: a cancellation runs
  ///         the opening's checks in the opening's order, the request's nonce before its id.
  function test_WhenTheNonceTheIdAndTheWindowAllFail() external {
    _openDefault();
    vm.warp(block.timestamp + 2 days);
    IPolicyManager.CancelRequest memory _req = _poisoned(_cancelRequest(_places(0, 1, 2)));
    _req.setupNonce = 9;
    _req.attemptId = 9;
    _req.validUntil = uint48(block.timestamp - 1);

    bytes memory _wrongNonce =
      abi.encodeWithSelector(IPolicyManager.PolicyManager_WrongSetupNonce.selector, uint64(9), uint64(1));

    _expectNoMethodCalled();
    vm.expectRevert(_wrongNonce);
    _manager.cancelByProofs(_req);
  }

  /// @notice With the nonce and the window both wrong, the nonce decides: the request's nonce is
  ///         checked before the window, as at an opening.
  function test_WhenTheNonceAndTheWindowBothFail() external {
    _openDefault();
    vm.warp(block.timestamp + 2 days);
    IPolicyManager.CancelRequest memory _req = _poisoned(_cancelRequest(_places(0, 1, 2)));
    _req.setupNonce = 9;
    _req.validUntil = uint48(block.timestamp - 1);

    bytes memory _wrongNonce =
      abi.encodeWithSelector(IPolicyManager.PolicyManager_WrongSetupNonce.selector, uint64(9), uint64(1));

    _expectNoMethodCalled();
    vm.expectRevert(_wrongNonce);
    _manager.cancelByProofs(_req);
  }

  /// @notice With the id and the window both wrong, the id decides: the attempt id is checked before
  ///         the window.
  function test_WhenTheIdAndTheWindowBothFail() external {
    _openDefault();
    vm.warp(block.timestamp + 2 days);
    IPolicyManager.CancelRequest memory _req = _poisoned(_cancelRequest(_places(0, 1, 2)));
    _req.attemptId = 9;
    _req.validUntil = uint48(block.timestamp - 1);

    _expectNoMethodCalled();
    vm.expectRevert(abi.encodeWithSelector(IPolicyManager.PolicyManager_WrongAttemptId.selector, uint64(9), uint64(1)));
    _manager.cancelByProofs(_req);
  }

  /// @notice With the window passed and a body that does not match the commitment, the window decides:
  ///         the pre-checks run before the commitment is recomputed.
  function test_WhenTheWindowHasPassedAndTheBodyDoesNotMatch() external {
    _openDefault();
    vm.warp(block.timestamp + 2 days);
    IPolicyManager.CancelRequest memory _req = _poisoned(_cancelRequest(_places(0, 1, 2)));
    _req.setupBody = bytes.concat(_req.setupBody, hex'01');
    _req.validUntil = uint48(block.timestamp - 1);

    vm.expectRevert(
      abi.encodeWithSelector(
        IPolicyManager.PolicyManager_RequestExpired.selector, uint48(block.timestamp), _req.validUntil
      )
    );
    _manager.cancelByProofs(_req);
  }

  /// @notice With a stale attempt and a body that does not match the commitment, the stale attempt
  ///         decides: the nonce check on the attempt runs before the commitment is recomputed. The
  ///         stale record is written through the harness.
  function test_WhenTheAttemptIsStaleAndTheBodyDoesNotMatch() external {
    _useDefaultRule(1 days, false);
    uint64 _nonce = _commitRule();
    _plant(_account, _action, _attempt(1, _nonce + 1, IPolicyManager.AttemptState.Waiting, false, _methods()));
    IPolicyManager.CancelRequest memory _req = _poisoned(_cancelRequest(_places(0, 1, 2)));
    _req.setupBody = bytes.concat(_req.setupBody, hex'01');

    vm.expectRevert(abi.encodeWithSelector(IPolicyManager.PolicyManager_StaleAttempt.selector, _nonce + 1, _nonce));
    _manager.cancelByProofs(_req);
  }

  /// @notice A body that does not hash to the stored commitment is refused as
  ///         PolicyManager_SetupCommitmentMismatch with both commitments, before any place is read.
  ///         `_extra` is appended to the committed body, so the body always differs.
  function test_WhenTheBodyDoesNotHashToTheCommitment(bytes calldata _extra) external {
    _openDefault();
    IPolicyManager.CancelRequest memory _req = _poisoned(_cancelRequest(_places(0, 1, 2)));
    _req.setupBody = bytes.concat(_req.setupBody, hex'01', _extra);

    _expectNoMethodCalled();
    vm.expectRevert(
      abi.encodeWithSelector(
        IPolicyManager.PolicyManager_SetupCommitmentMismatch.selector,
        BindingDigest.setupCommitment(_account, _action, 1, _req.setupBody),
        _state(_account, _action).setupCommitment
      )
    );
    _manager.cancelByProofs(_req);
  }

  /*///////////////////////////////////////////////////////////////
                           WHAT THE PROOFS SIGN
  ///////////////////////////////////////////////////////////////*/

  /// @notice Proofs that approve the opening digest of the same attempt do not cancel it: the manager
  ///         hands each method the cancellation digest, so an approval never counts as a cancel.
  function test_WhenTheProofsSignTheApprovalDigest() external {
    IPolicyManager.AttemptRequest memory _opening = _openDefault();
    vm.clearMockedCalls();
    IPolicyManager.CancelRequest memory _req = _cancelRequest(_places(0, 1, 2));
    _req.validUntil = _opening.validUntil;
    _approve(_opening);

    vm.expectRevert(abi.encodeWithSelector(IPolicyManager.PolicyManager_ProofRejected.selector, 0, _methodA));
    _manager.cancelByProofs(_req);
  }

  /// @notice Proofs that approve the cancellation of attempt 1 do not cancel attempt 2, so a cancel
  ///         signed for one attempt counts for no other.
  function test_WhenTheProofsWereSignedForAnotherAttempt() external {
    _openDefault();
    IPolicyManager.CancelRequest memory _forFirst = _cancelRequest(_places(0, 1, 2));
    vm.prank(_account);
    _manager.cancelByOwner(_action);
    _open(_places(0, 1, 2));
    vm.clearMockedCalls();
    _approveCancel(_forFirst);
    IPolicyManager.CancelRequest memory _req = _cancelRequest(_places(0, 1, 2));
    _req.validUntil = _forFirst.validUntil;

    vm.expectRevert(abi.encodeWithSelector(IPolicyManager.PolicyManager_ProofRejected.selector, 0, _methodA));
    _manager.cancelByProofs(_req);
  }

  /// @notice Each method is asked once, by a static call, with the cancellation digest of this exact
  ///         attempt and place, its own config and its own proof.
  function test_WhenEachMethodIsAsked() external {
    _openDefault();
    IPolicyManager.CancelRequest memory _req = _cancelRequest(_places(0, 2, 3));
    _approveCancel(_req);
    _expectEachProofVerifiedOnce(_req);

    vm.startStateDiffRecording();
    _manager.cancelByProofs(_req);
    _assertOnlyStaticCalls(vm.stopAndReturnStateDiff());
  }

  /*///////////////////////////////////////////////////////////////
                              EACH PLACE
  ///////////////////////////////////////////////////////////////*/

  /// @notice A proof repeating the place before it is refused as
  ///         PolicyManager_PlacesNotStrictlyIncreasing, as at an opening.
  function test_WhenAPlaceRepeatsThePreviousOne() external {
    _openDefault();
    IPolicyManager.CancelRequest memory _req = _cancelRequest(_places(0, 2, 2));
    _approveCancel(_req);

    vm.expectRevert(abi.encodeWithSelector(IPolicyManager.PolicyManager_PlacesNotStrictlyIncreasing.selector, 2));
    _manager.cancelByProofs(_req);
  }

  /// @notice A proof at a place past the end of the rule is refused as PolicyManager_PlaceOutOfRange,
  ///         as at an opening. `_placeSeed` picks a place from 4 upward.
  function test_WhenAPlaceIsPastTheEndOfTheRule(uint256 _placeSeed) external {
    _openDefault();
    uint256 _place = bound(_placeSeed, 4, type(uint256).max);
    IPolicyManager.CancelRequest memory _req = _cancelRequest(_places(0, 1, 2));
    _approveCancel(_req);
    _req.proofs[2] = _proofsAt(_places(_place))[0];

    vm.expectRevert(abi.encodeWithSelector(IPolicyManager.PolicyManager_PlaceOutOfRange.selector, _place, 4));
    _manager.cancelByProofs(_req);
  }

  /// @notice A proof naming method A at a place committed to method B is refused as
  ///         PolicyManager_CredentialMismatch, and A never judges that place, as at an opening.
  function test_WhenTheProofNamesAnotherMethodOfTheRule() external {
    _openDefault();
    IPolicyManager.CancelRequest memory _req = _cancelRequest(_places(0, 1, 2));
    _approveCancel(_req);
    _req.proofs[2].method = _methodA;
    vm.mockCall(_methodA, abi.encodePacked(IPolicyMethod.verify.selector), abi.encode(_MAGIC));
    bytes32 _recomputed = BindingDigest.credentialCommitment(_methodA, _req.proofs[2].config, _req.proofs[2].salt);

    vm.expectCall(_methodA, _verifyCall(_req.proofs[2], _manager.hashCancel(_req, 2)), 0);
    vm.expectRevert(abi.encodeWithSelector(IPolicyManager.PolicyManager_CredentialMismatch.selector, 2, _recomputed));
    _manager.cancelByProofs(_req);
  }

  /// @notice A proof naming a method the rule never names is refused as
  ///         PolicyManager_CredentialMismatch and that method is never called, so a method the holder
  ///         never named cannot cancel their attempt. `_config` and `_salt` are the outsider's own.
  function test_WhenAProofNamesAMethodTheRuleNeverNames(bytes calldata _config, bytes32 _salt) external {
    _openDefault();
    address _outsider = _silentMethod('outsider');
    vm.mockCall(_outsider, abi.encodePacked(IPolicyMethod.verify.selector), abi.encode(_MAGIC));
    IPolicyManager.CancelRequest memory _req = _cancelRequest(_places(0, 1, 2));
    _approveCancel(_req);
    _req.proofs[0] =
      IPolicyManager.ProofPlace({place: 0, method: _outsider, config: _config, salt: _salt, proof: 'anything'});

    vm.expectCall(_outsider, '', 0);
    vm.expectRevert(
      abi.encodeWithSelector(
        IPolicyManager.PolicyManager_CredentialMismatch.selector,
        0,
        BindingDigest.credentialCommitment(_outsider, _config, _salt)
      )
    );
    _manager.cancelByProofs(_req);
  }

  /// @notice A proof carrying a config other than the committed one is refused as
  ///         PolicyManager_CredentialMismatch before its method is called. `_suffix` builds a config
  ///         that always differs.
  function test_WhenTheProofCarriesAnotherConfig(bytes calldata _suffix) external {
    _openDefault();
    IPolicyManager.CancelRequest memory _req = _cancelRequest(_places(0, 1, 2));
    _approveCancel(_req);
    _req.proofs[2].config = bytes.concat('forged ', _suffix);

    vm.expectCall(_methodB, '', 0);
    vm.expectRevert(
      abi.encodeWithSelector(
        IPolicyManager.PolicyManager_CredentialMismatch.selector,
        2,
        BindingDigest.credentialCommitment(_methodB, _req.proofs[2].config, _req.proofs[2].salt)
      )
    );
    _manager.cancelByProofs(_req);
  }

  /*///////////////////////////////////////////////////////////////
                              THE STOP
  ///////////////////////////////////////////////////////////////*/

  /// @notice A method answering the pause read with exactly true has its cancel proof refused as
  ///         PolicyManager_MethodStopped before its verify is called, as at an opening.
  function test_WhenAMethodReportsItselfStopped() external {
    _openDefault();
    IPolicyManager.CancelRequest memory _req = _cancelRequest(_places(0, 1, 2));
    _approveCancel(_req);
    _stop(_methodB);

    vm.expectCall(_methodB, abi.encodePacked(IPolicyMethod.verify.selector), 0);
    vm.expectRevert(abi.encodeWithSelector(IPolicyManager.PolicyManager_MethodStopped.selector, 2, _methodB));
    _manager.cancelByProofs(_req);
  }

  /// @notice When the committed body says the holder ignores stops, a stopped method's cancel proofs
  ///         still count and the pause is never read.
  function test_WhenTheBodyIgnoresStops() external {
    _useDefaultRule(1 days, true);
    _commitRule();
    _open(_places(0, 1, 2));
    IPolicyManager.CancelRequest memory _req = _cancelRequest(_places(0, 1, 2));
    _approveCancel(_req);
    _stop(_methodA);
    _stop(_methodB);

    vm.expectCall(_methodA, _pausedCall(), 0);
    vm.expectCall(_methodB, _pausedCall(), 0);
    _manager.cancelByProofs(_req);

    assertEq(uint8(_state(_account, _action).attempt.state), uint8(IPolicyManager.AttemptState.Cancelled), 'state');
  }

  /// @notice The pause choice is read from the revealed body, not from the attempt record: with a body
  ///         that ignores stops beside a record that does not, a stopped method's proofs count and no
  ///         pause is read. The record written through the harness disagrees with its body, which no
  ///         sequence of calls produces.
  function test_WhenTheBodyIgnoresStopsButTheRecordDoesNot() external {
    _useDefaultRule(1 days, true);
    _commitRule();
    _plantWaiting(_account, _action, 1, false);
    IPolicyManager.CancelRequest memory _req = _cancelRequest(_places(0, 1, 2));
    _approveCancel(_req);
    _stop(_methodA);
    _stop(_methodB);

    vm.expectCall(_methodA, _pausedCall(), 0);
    vm.expectCall(_methodB, _pausedCall(), 0);
    _manager.cancelByProofs(_req);

    assertEq(uint8(_state(_account, _action).attempt.state), uint8(IPolicyManager.AttemptState.Cancelled), 'state');
  }

  /// @notice With a body that does not ignore stops beside a record that does, a stopped method's
  ///         cancel proof is refused as PolicyManager_MethodStopped: the revealed body decides. The
  ///         disagreeing record is written through the harness.
  function test_WhenTheRecordIgnoresStopsButTheBodyDoesNot() external {
    _useDefaultRule(1 days, false);
    _commitRule();
    _plantWaiting(_account, _action, 1, true);
    IPolicyManager.CancelRequest memory _req = _cancelRequest(_places(0, 1, 2));
    _approveCancel(_req);
    _stop(_methodA);

    vm.expectRevert(abi.encodeWithSelector(IPolicyManager.PolicyManager_MethodStopped.selector, 0, _methodA));
    _manager.cancelByProofs(_req);
  }

  /// @notice A pause read that reverts is not a stop, so the cancel proceeds. `_revertData` is the
  ///         revert's data.
  function test_WhenThePauseReadReverts(bytes calldata _revertData) external {
    _openDefault();
    IPolicyManager.CancelRequest memory _req = _cancelRequest(_places(0, 1, 2));
    _approveCancel(_req);
    vm.mockCallRevert(_methodB, _pausedCall(), _revertData);

    _manager.cancelByProofs(_req);

    assertEq(uint8(_state(_account, _action).attempt.state), uint8(IPolicyManager.AttemptState.Cancelled), 'state');
  }

  /*///////////////////////////////////////////////////////////////
                              THE VERDICT
  ///////////////////////////////////////////////////////////////*/

  /// @notice A method that reverts has its cancel proof refused as PolicyManager_ProofRejected, as at
  ///         an opening. `_revertData` is the revert's data.
  function test_WhenTheMethodReverts(bytes calldata _revertData) external {
    _openDefault();
    IPolicyManager.CancelRequest memory _req = _cancelRequest(_places(0, 1, 2));
    _approveCancel(_req);
    vm.mockCallRevert(_methodB, _verifyCall(_req.proofs[2], _manager.hashCancel(_req, 2)), _revertData);

    vm.expectRevert(abi.encodeWithSelector(IPolicyManager.PolicyManager_ProofRejected.selector, 2, _methodB));
    _manager.cancelByProofs(_req);
  }

  /// @notice A method that returns nothing has its cancel proof refused.
  function test_WhenTheMethodReturnsNothing() external {
    _openDefault();
    IPolicyManager.CancelRequest memory _req = _cancelRequest(_places(0, 1, 2));
    _approveCancel(_req);
    vm.mockCall(_methodB, _verifyCall(_req.proofs[2], _manager.hashCancel(_req, 2)), '');

    vm.expectRevert(abi.encodeWithSelector(IPolicyManager.PolicyManager_ProofRejected.selector, 2, _methodB));
    _manager.cancelByProofs(_req);
  }

  /// @notice A method returning the magic word followed by more bytes has its cancel proof refused.
  ///         `_extra` is the trailing bytes, at least one.
  function test_WhenTheMethodReturnsMoreThanAWord(bytes calldata _extra) external {
    _openDefault();
    IPolicyManager.CancelRequest memory _req = _cancelRequest(_places(0, 1, 2));
    _approveCancel(_req);
    vm.mockCall(
      _methodB,
      _verifyCall(_req.proofs[2], _manager.hashCancel(_req, 2)),
      bytes.concat(abi.encode(_MAGIC), hex'00', _extra)
    );

    vm.expectRevert(abi.encodeWithSelector(IPolicyManager.PolicyManager_ProofRejected.selector, 2, _methodB));
    _manager.cancelByProofs(_req);
  }

  /// @notice A method returning one word other than the magic value has its cancel proof refused.
  ///         `_mask` is XORed into the magic word and is never zero.
  function test_WhenTheMethodReturnsAnotherWord(uint256 _mask) external {
    _openDefault();
    IPolicyManager.CancelRequest memory _req = _cancelRequest(_places(0, 1, 2));
    _approveCancel(_req);
    bytes32 _word = bytes32(_MAGIC) ^ bytes32(bound(_mask, 1, type(uint256).max));
    vm.mockCall(_methodB, _verifyCall(_req.proofs[2], _manager.hashCancel(_req, 2)), abi.encode(_word));

    vm.expectRevert(abi.encodeWithSelector(IPolicyManager.PolicyManager_ProofRejected.selector, 2, _methodB));
    _manager.cancelByProofs(_req);
  }

  /// @notice A method that writes its own storage while verifying cannot approve a cancel, since the
  ///         call is static, and its storage stays untouched.
  function test_WhenTheMethodWritesStateWhileVerifying() external {
    PolicyManagerMockWritingMethod _writer = new PolicyManagerMockWritingMethod();
    _useDefaultRule(1 days, true);
    _credentials[3].method = address(_writer);
    _reshapeDefault(1 days, true);
    _commitRule();
    _open(_places(0, 1, 2));
    IPolicyManager.CancelRequest memory _req = _cancelRequest(_places(0, 1, 3));
    _approveCancel(_cancelRequest(_places(0, 1)));

    vm.expectRevert(abi.encodeWithSelector(IPolicyManager.PolicyManager_ProofRejected.selector, 3, address(_writer)));
    _manager.cancelByProofs(_req);

    assertEq(_writer.writes(), 0, 'the method wrote nothing');
  }

  /// @notice A method answering the magic word followed by two megabytes has its cancel proof refused,
  ///         and the refusal arrives on a gas budget that copying the answer would exhaust, so the size
  ///         is read before any copy.
  function test_WhenTheMethodReturnsAHugeAnswer() external {
    _openDefault();
    IPolicyManager.CancelRequest memory _req = _cancelRequest(_places(0, 1, 2));
    _approveCancel(_req);
    vm.mockCall(
      _methodB,
      _verifyCall(_req.proofs[2], _manager.hashCancel(_req, 2)),
      bytes.concat(abi.encode(_MAGIC), new bytes(_HUGE_ANSWER_SIZE))
    );

    vm.expectRevert(abi.encodeWithSelector(IPolicyManager.PolicyManager_ProofRejected.selector, 2, _methodB));
    _manager.cancelByProofs{gas: _HUGE_ANSWER_GAS}(_req);
  }

  /*///////////////////////////////////////////////////////////////
                               THE RULE
  ///////////////////////////////////////////////////////////////*/

  /// @notice A set too weak to open an attempt cancels none: every proof verified but the second
  ///         clause misses its threshold, and the cancellation is refused naming clause 1.
  function test_WhenTheSetIsTooWeakToOpen() external {
    _openDefault();
    IPolicyManager.CancelRequest memory _req = _cancelRequest(_places(0, 3));
    _approveCancel(_req);

    vm.expectRevert(abi.encodeWithSelector(IPolicyManager.PolicyManager_RuleUnsatisfied.selector, 1));
    _manager.cancelByProofs(_req);
  }

  /// @notice A cancellation with no proofs is refused naming clause 0 and calls no method, so the
  ///         sender alone never cancels.
  function test_WhenTheRequestCarriesNoProofs() external {
    _openDefault();
    IPolicyManager.CancelRequest memory _req = _cancelRequest(new uint256[](0));

    _expectNoMethodCalled();
    vm.expectRevert(abi.encodeWithSelector(IPolicyManager.PolicyManager_RuleUnsatisfied.selector, 0));
    _manager.cancelByProofs(_req);
  }

  /*///////////////////////////////////////////////////////////////
                             CANCELLATION
  ///////////////////////////////////////////////////////////////*/

  /// @notice A set satisfying the rule cancels the waiting attempt even when it names other people
  ///         than the set that opened it, sent by anyone: the record turns Cancelled and keeps every
  ///         other field, one AttemptCancelled names the sender, no vetoing method, the attempt's
  ///         setup nonce and the places filled, and the setup and the attempt counter stay.
  ///         `_submitter` is any sender.
  function test_WhenASatisfyingSetCancels(address _submitter) external {
    _openDefault();
    IPolicyManager.ActionState memory _before = _state(_account, _action);
    IPolicyManager.CancelRequest memory _req = _cancelRequest(_places(0, 2, 3));
    _approveCancel(_req);

    vm.recordLogs();
    vm.prank(_submitter);
    _manager.cancelByProofs(_req);
    Vm.Log[] memory _logs = vm.getRecordedLogs();

    IPolicyManager.ActionState memory _after = _state(_account, _action);
    // it should set the attempt to Cancelled and keep the rest of its record
    _assertRecordKept(_after.attempt, _before.attempt, IPolicyManager.AttemptState.Cancelled);
    // it should emit AttemptCancelled alone
    assertEq(_logs.length, 1, 'one event');
    _assertCancelledByProofsLog(_logs[0], 1, _submitter, _before.attempt.setupNonce, _places(0, 2, 3));
    // it should leave the setup and the attempt counter unchanged
    _assertSetupKept(_before, _after);
    assertEq(_after.nextAttemptId, _before.nextAttemptId, 'attempt counter');
  }

  /// @notice Once cancelled, the attempt cannot be cancelled again by the same proofs, since nothing
  ///         waits any more.
  function test_WhenTheSameCancellationIsSentTwice() external {
    _openDefault();
    IPolicyManager.CancelRequest memory _req = _cancelRequest(_places(0, 1, 2));
    _approveCancel(_req);
    _manager.cancelByProofs(_req);

    vm.expectRevert(abi.encodeWithSelector(IPolicyManager.PolicyManager_NoActiveAttempt.selector, _account, _action));
    _manager.cancelByProofs(_req);
  }

  /// @notice After a cancel by proofs the next opening names the next id and runs: the cancel moved
  ///         neither the nonce nor the counter.
  function test_WhenAnAttemptOpensAfterTheCancel() external {
    _openDefault();
    IPolicyManager.CancelRequest memory _req = _cancelRequest(_places(0, 1, 2));
    _approveCancel(_req);
    _manager.cancelByProofs(_req);

    _open(_places(0, 1, 3));

    IPolicyManager.ActionState memory _after = _state(_account, _action);
    assertEq(_after.attempt.attemptId, 2, 'attempt id');
    assertEq(uint8(_after.attempt.state), uint8(IPolicyManager.AttemptState.Waiting), 'waiting');
  }

  /*///////////////////////////////////////////////////////////////
                                HELPERS
  ///////////////////////////////////////////////////////////////*/

  /// @notice Commits the default rule with a one-day wait and opens attempt 1 with places 0, 1 and 2.
  function _openDefault() private returns (IPolicyManager.AttemptRequest memory _opening) {
    _useDefaultRule(1 days, false);
    _commitRule();
    _opening = _open(_places(0, 1, 2));
  }

  /// @notice Replaces the cancellation's proofs with one proof at place 99, past the end of the rule.
  function _poisoned(IPolicyManager.CancelRequest memory _req)
    private
    view
    returns (IPolicyManager.CancelRequest memory _poisonedReq)
  {
    _req.proofs = _proofsAt(_places(99));
    _poisonedReq = _req;
  }
}
