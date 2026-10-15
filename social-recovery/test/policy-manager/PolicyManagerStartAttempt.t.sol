// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {SafeCast} from '@openzeppelin/contracts/utils/math/SafeCast.sol';
import {stdError} from 'forge-std/StdError.sol';
import {Vm} from 'forge-std/Vm.sol';
import {BindingDigest} from 'libraries/BindingDigest.sol';
import {IPolicyManager} from 'interfaces/IPolicyManager.sol';
import {IPolicyMethod} from 'interfaces/IPolicyMethod.sol';
import {PolicyManagerMockDigestMethod} from 'test/mocks/PolicyManagerMockDigestMethod.sol';
import {PolicyManagerMockWritingMethod} from 'test/mocks/PolicyManagerMockWritingMethod.sol';
import {PolicyManagerAcceptanceTestBase} from 'test/utils/PolicyManagerAcceptanceTestBase.sol';

/// @notice startAttempt, the permissionless call that opens a recovery attempt with a complete
///         proof set. It must refuse every request the committed rule does not authorize, check
///         the cheap facts before it reads any proof, treat every method as hostile, and write the
///         attempt record the spend later relies on.
/// @dev The default rule is the base contract's: clause 0 needs place 0, clause 1 needs 2 of places
///      1, 2 and 3; method A judges places 0 and 1 and method B places 2 and 3. A poisoned request
///      carries one proof at place 99, past the end of the rule, so reading any place would revert
///      with PolicyManager_PlaceOutOfRange: a test that sees another error knows no place was read.
contract PolicyManagerStartAttemptTest is PolicyManagerAcceptanceTestBase {
  /// @notice The gas a call gets in the tests of huge answers. A manager that copies a huge answer
  ///         before reading its size runs out of it, and one that reads the size first does not.
  uint256 internal constant _HUGE_ANSWER_GAS = 2_000_000;
  /// @notice The size of a huge answer. Copying it into memory costs several million gas.
  uint256 internal constant _HUGE_ANSWER_SIZE = 2_000_000;

  /*///////////////////////////////////////////////////////////////
                         THE FIVE PRE-CHECKS
  ///////////////////////////////////////////////////////////////*/

  /// @notice With no setup ever committed a request is refused as PolicyManager_NoSetup before any
  ///         place is read or any method is called, so a request against nothing costs no method
  ///         call and names the pair it looked for.
  function test_WhenNoSetupExists() external {
    _useDefaultRule(1 days, false);
    IPolicyManager.AttemptRequest memory _req = _poisoned(_request(_places(0, 1, 2)));

    _expectNoMethodCalled();
    vm.expectRevert(abi.encodeWithSelector(IPolicyManager.PolicyManager_NoSetup.selector, _account, _action));
    _manager.startAttempt(_req);
  }

  /// @notice After the account cleared its setup, a request naming the stored nonce is refused as
  ///         PolicyManager_NoSetup before any place is read, so a cleared setup opens nothing.
  function test_WhenTheSetupWasCleared() external {
    _useDefaultRule(1 days, false);
    _commitRule();
    _clear(_account, _action);
    IPolicyManager.AttemptRequest memory _req = _poisoned(_request(_places(0, 1, 2)));

    _expectNoMethodCalled();
    vm.expectRevert(abi.encodeWithSelector(IPolicyManager.PolicyManager_NoSetup.selector, _account, _action));
    _manager.startAttempt(_req);
  }

  /// @notice While an attempt waits a second request is refused as PolicyManager_AttemptAlreadyActive
  ///         naming the waiting attempt, before any place is read, so no request displaces the attempt
  ///         that holds the action's one slot.
  function test_WhenAnAttemptIsAlreadyWaiting() external {
    _useDefaultRule(1 days, false);
    _commitRule();
    _open(_places(0, 1, 2));
    IPolicyManager.AttemptRequest memory _req = _poisoned(_request(_places(0, 1, 2)));

    _expectNoMethodCalled();
    vm.expectRevert(
      abi.encodeWithSelector(IPolicyManager.PolicyManager_AttemptAlreadyActive.selector, _account, _action, uint64(1))
    );
    _manager.startAttempt(_req);
  }

  /// @notice A request naming any setup nonce but the stored one is refused as
  ///         PolicyManager_WrongSetupNonce with both nonces, before any place is read, so proofs signed
  ///         under another setup version fail by name rather than as a rejected proof. `_offsetSeed`
  ///         builds any nonce but the stored one.
  function test_WhenTheRequestNamesANonceOtherThanTheStoredOne(uint64 _offsetSeed) external {
    _useDefaultRule(1 days, false);
    uint64 _nonce = _commitRule();
    IPolicyManager.AttemptRequest memory _req = _poisoned(_request(_places(0, 1, 2)));
    _req.setupNonce = _otherThan(_nonce, _offsetSeed);

    _expectNoMethodCalled();
    vm.expectRevert(
      abi.encodeWithSelector(IPolicyManager.PolicyManager_WrongSetupNonce.selector, _req.setupNonce, _nonce)
    );
    _manager.startAttempt(_req);
  }

  /// @notice A request prepared under a setup the account has since rewritten with the identical rule
  ///         is refused as PolicyManager_WrongSetupNonce, so an approval banked under an old setup
  ///         never comes back, even when the rule itself did not change.
  function test_WhenTheRequestWasSignedUnderARetiredSetup() external {
    _useDefaultRule(1 days, false);
    uint64 _retired = _commitRule();
    IPolicyManager.AttemptRequest memory _banked = _request(_places(0, 1, 2));
    _approve(_banked);
    uint64 _current = _commitRule();

    vm.expectRevert(abi.encodeWithSelector(IPolicyManager.PolicyManager_WrongSetupNonce.selector, _retired, _current));
    _manager.startAttempt(_banked);
  }

  /// @notice A request naming any attempt id but the stored counter plus one is refused as
  ///         PolicyManager_WrongAttemptId with both ids, before any place is read, so nobody can
  ///         save a proof set for a later attempt. `_offsetSeed` builds any id but the next one.
  function test_WhenTheAttemptIdIsNotTheNextOne(uint64 _offsetSeed) external {
    _useDefaultRule(1 days, false);
    _commitRule();
    IPolicyManager.AttemptRequest memory _req = _poisoned(_request(_places(0, 1, 2)));
    _req.attemptId = _otherThan(1, _offsetSeed);

    _expectNoMethodCalled();
    vm.expectRevert(
      abi.encodeWithSelector(IPolicyManager.PolicyManager_WrongAttemptId.selector, _req.attemptId, uint64(1))
    );
    _manager.startAttempt(_req);
  }

  /// @notice Once attempt 1 has ended, a request for id 1 is refused as PolicyManager_WrongAttemptId
  ///         naming id 2, so an attempt id is never handed out twice and a proof set that opened one
  ///         attempt cannot open another.
  function test_WhenTheAttemptIdWasAlreadyUsed() external {
    _useDefaultRule(1 days, false);
    _commitRule();
    IPolicyManager.AttemptRequest memory _first = _open(_places(0, 1, 2));
    vm.prank(_account);
    _manager.cancelByOwner(_action, 1);

    vm.expectRevert(abi.encodeWithSelector(IPolicyManager.PolicyManager_WrongAttemptId.selector, uint64(1), uint64(2)));
    _manager.startAttempt(_first);
  }

  /// @notice A request whose validUntil is before the block's timestamp is refused as
  ///         PolicyManager_RequestExpired with both times, before any place is read, so a stale
  ///         request fails on its window rather than on a proof. `_nowSeed` picks the block time and
  ///         `_untilSeed` a deadline before it.
  function test_WhenTheWindowHasPassed(uint256 _nowSeed, uint256 _untilSeed) external {
    _useDefaultRule(1 days, false);
    _commitRule();
    uint48 _now = uint48(bound(_nowSeed, 1, type(uint48).max));
    vm.warp(_now);
    IPolicyManager.AttemptRequest memory _req = _poisoned(_request(_places(0, 1, 2)));
    _req.validUntil = uint48(bound(_untilSeed, 0, _now - 1));

    bytes memory _expired =
      abi.encodeWithSelector(IPolicyManager.PolicyManager_RequestExpired.selector, _now, _req.validUntil);

    _expectNoMethodCalled();
    vm.expectRevert(_expired);
    _manager.startAttempt(_req);
  }

  /// @notice A request whose validUntil is the block's own timestamp is still inside its window and
  ///         opens the attempt, so the deadline is the last second a request counts.
  function test_WhenTheWindowEndsInThisBlock() external {
    _useDefaultRule(1 days, false);
    _commitRule();
    vm.warp(1_700_000_000);
    IPolicyManager.AttemptRequest memory _req = _request(_places(0, 1, 2));
    _req.validUntil = uint48(block.timestamp);
    _approve(_req);

    _manager.startAttempt(_req);

    assertEq(uint8(_state(_account, _action).attempt.state), uint8(IPolicyManager.AttemptState.Waiting), 'waiting');
  }

  /// @notice With all five pre-checks failing, the first one decides: no setup. The waiting record
  ///         beside an absent setup is written through the harness, since no sequence of calls
  ///         leaves one. The check order is part of what a client can rely on to read a refusal.
  function test_WhenAllFivePrechecksFail() external {
    _useDefaultRule(1 days, false);
    _plantWaiting(_account, _action, 1, false);
    vm.warp(1_700_000_000);
    IPolicyManager.AttemptRequest memory _req = _poisoned(_request(_places(0, 1, 2)));
    _req.setupNonce = 5;
    _req.attemptId = 9;
    _req.validUntil = uint48(block.timestamp - 1);

    _expectNoMethodCalled();
    vm.expectRevert(abi.encodeWithSelector(IPolicyManager.PolicyManager_NoSetup.selector, _account, _action));
    _manager.startAttempt(_req);
  }

  /// @notice With a setup present and the last four pre-checks failing, the waiting attempt decides:
  ///         PolicyManager_AttemptAlreadyActive, the second check in order.
  function test_WhenTheLastFourPrechecksFail() external {
    _useDefaultRule(1 days, false);
    _commitRule();
    _open(_places(0, 1, 2));
    vm.warp(block.timestamp + 2 days);
    IPolicyManager.AttemptRequest memory _req = _poisoned(_request(_places(0, 1, 2)));
    _req.setupNonce = 5;
    _req.attemptId = 9;
    _req.validUntil = uint48(block.timestamp - 1);

    _expectNoMethodCalled();
    vm.expectRevert(
      abi.encodeWithSelector(IPolicyManager.PolicyManager_AttemptAlreadyActive.selector, _account, _action, uint64(1))
    );
    _manager.startAttempt(_req);
  }

  /// @notice With the nonce, the id and the window all wrong, the nonce decides:
  ///         PolicyManager_WrongSetupNonce, the third check in order.
  function test_WhenTheLastThreePrechecksFail() external {
    _useDefaultRule(1 days, false);
    uint64 _nonce = _commitRule();
    vm.warp(1_700_000_000);
    IPolicyManager.AttemptRequest memory _req = _poisoned(_request(_places(0, 1, 2)));
    _req.setupNonce = _nonce + 4;
    _req.attemptId = 9;
    _req.validUntil = uint48(block.timestamp - 1);

    _expectNoMethodCalled();
    vm.expectRevert(abi.encodeWithSelector(IPolicyManager.PolicyManager_WrongSetupNonce.selector, _nonce + 4, _nonce));
    _manager.startAttempt(_req);
  }

  /// @notice With the id and the window both wrong, the id decides: PolicyManager_WrongAttemptId, the
  ///         fourth check in order.
  function test_WhenTheLastTwoPrechecksFail() external {
    _useDefaultRule(1 days, false);
    _commitRule();
    vm.warp(1_700_000_000);
    IPolicyManager.AttemptRequest memory _req = _poisoned(_request(_places(0, 1, 2)));
    _req.attemptId = 9;
    _req.validUntil = uint48(block.timestamp - 1);

    _expectNoMethodCalled();
    vm.expectRevert(abi.encodeWithSelector(IPolicyManager.PolicyManager_WrongAttemptId.selector, uint64(9), uint64(1)));
    _manager.startAttempt(_req);
  }

  /// @notice With the window passed and a body that does not match the commitment, the window decides:
  ///         the five pre-checks all run before the commitment is recomputed.
  function test_WhenTheWindowHasPassedAndTheBodyDoesNotMatch() external {
    _useDefaultRule(1 days, false);
    _commitRule();
    vm.warp(1_700_000_000);
    IPolicyManager.AttemptRequest memory _req = _poisoned(_request(_places(0, 1, 2)));
    _req.setupBody = bytes.concat(_req.setupBody, hex'01');
    _req.validUntil = uint48(block.timestamp - 1);

    vm.expectRevert(
      abi.encodeWithSelector(
        IPolicyManager.PolicyManager_RequestExpired.selector, uint48(block.timestamp), _req.validUntil
      )
    );
    _manager.startAttempt(_req);
  }

  /*///////////////////////////////////////////////////////////////
                          THE SETUP COMMITMENT
  ///////////////////////////////////////////////////////////////*/

  /// @notice A body that does not hash, with the account, the action and the stored nonce, to the
  ///         stored commitment is refused as PolicyManager_SetupCommitmentMismatch with both
  ///         commitments, before any place is read, so no field of an unproven body ever counts.
  ///         `_extra` is appended to the committed body, so the request's body always differs.
  function test_WhenTheBodyDoesNotHashToTheCommitment(bytes calldata _extra) external {
    _useDefaultRule(1 days, false);
    uint64 _nonce = _commitRule();
    IPolicyManager.AttemptRequest memory _req = _poisoned(_request(_places(0, 1, 2)));
    _req.setupBody = bytes.concat(_req.setupBody, hex'01', _extra);
    bytes32 _recomputed = BindingDigest.setupCommitment(_account, _action, _nonce, _req.setupBody);

    _expectNoMethodCalled();
    vm.expectRevert(
      abi.encodeWithSelector(
        IPolicyManager.PolicyManager_SetupCommitmentMismatch.selector,
        _recomputed,
        _state(_account, _action).setupCommitment
      )
    );
    _manager.startAttempt(_req);
  }

  /// @notice A body the account committed under another action does not open an attempt under this
  ///         one, since the commitment hashes the action: the request is refused as
  ///         PolicyManager_SetupCommitmentMismatch.
  function test_WhenTheBodyWasCommittedUnderAnotherAction() external {
    _useDefaultRule(1 days, false);
    bytes memory _otherBody = _setupBody;
    vm.prank(_account);
    _manager.commitSetup(_otherAction, BindingDigest.setupCommitment(_account, _otherAction, 1, _otherBody), 1, '', '');
    _useDefaultRule(2 days, false);
    _commitRule();
    IPolicyManager.AttemptRequest memory _req = _request(_places(0, 1, 2));
    _req.setupBody = _otherBody;
    _approve(_req);

    vm.expectRevert(
      abi.encodeWithSelector(
        IPolicyManager.PolicyManager_SetupCommitmentMismatch.selector,
        BindingDigest.setupCommitment(_account, _action, 1, _otherBody),
        _state(_account, _action).setupCommitment
      )
    );
    _manager.startAttempt(_req);
  }

  /*///////////////////////////////////////////////////////////////
                              EACH PLACE
  ///////////////////////////////////////////////////////////////*/

  /// @notice A proof repeating the place before it is refused as
  ///         PolicyManager_PlacesNotStrictlyIncreasing naming that place, so no credential fills its
  ///         place twice.
  function test_WhenAPlaceRepeatsThePreviousOne() external {
    _useDefaultRule(1 days, false);
    _commitRule();
    IPolicyManager.AttemptRequest memory _req = _request(_places(0, 1, 1));
    _approve(_req);

    vm.expectRevert(abi.encodeWithSelector(IPolicyManager.PolicyManager_PlacesNotStrictlyIncreasing.selector, 1));
    _manager.startAttempt(_req);
  }

  /// @notice A proof below the place before it is refused as PolicyManager_PlacesNotStrictlyIncreasing
  ///         naming that place, even when its credential is also wrong: the order check at a place runs
  ///         before its credential is recomputed.
  function test_WhenAPlaceIsBelowThePreviousOne() external {
    _useDefaultRule(1 days, false);
    _commitRule();
    IPolicyManager.AttemptRequest memory _req = _request(_places(0, 2, 1));
    _req.proofs[2].config = 'not the committed config';
    _approve(_req);

    vm.expectRevert(abi.encodeWithSelector(IPolicyManager.PolicyManager_PlacesNotStrictlyIncreasing.selector, 1));
    _manager.startAttempt(_req);
  }

  /// @notice A proof at a place past the end of the rule is refused as PolicyManager_PlaceOutOfRange
  ///         with the place and the rule's four places, and its method is never asked. `_placeSeed`
  ///         picks a place from 4 upward.
  function test_WhenAPlaceIsPastTheEndOfTheRule(uint256 _placeSeed) external {
    _useDefaultRule(1 days, false);
    _commitRule();
    uint256 _place = bound(_placeSeed, 4, type(uint256).max);
    IPolicyManager.AttemptRequest memory _req = _request(_places(0, 1, 2));
    _approve(_req);
    _req.proofs[2] = _proofsAt(_places(_place))[0];

    vm.expectCall(_methodB, '', 0);
    vm.expectRevert(abi.encodeWithSelector(IPolicyManager.PolicyManager_PlaceOutOfRange.selector, _place, 4));
    _manager.startAttempt(_req);
  }

  /// @notice A proof naming method A at a place the holder committed to method B is refused as
  ///         PolicyManager_CredentialMismatch with the recomputed hash, and A is never asked about
  ///         that place even though A would approve anything: the module that runs is the module the
  ///         holder committed.
  function test_WhenTheProofNamesAnotherMethodOfTheRule() external {
    _useDefaultRule(1 days, false);
    _commitRule();
    IPolicyManager.AttemptRequest memory _req = _request(_places(0, 1, 2));
    _approve(_req);
    _req.proofs[2].method = _methodA;
    vm.mockCall(_methodA, abi.encodePacked(IPolicyMethod.verify.selector), abi.encode(_MAGIC));
    bytes32 _recomputed = BindingDigest.credentialCommitment(_methodA, _req.proofs[2].config, _req.proofs[2].salt);

    vm.expectCall(_methodA, _verifyCall(_req.proofs[2], _manager.hashApproval(_req, 2)), 0);
    vm.expectCall(_methodB, '', 0);
    vm.expectRevert(abi.encodeWithSelector(IPolicyManager.PolicyManager_CredentialMismatch.selector, 2, _recomputed));
    _manager.startAttempt(_req);
  }

  /// @notice A proof naming a method the rule never names is refused as
  ///         PolicyManager_CredentialMismatch, and that method is never called, even though it approves
  ///         anything and stands at a place the rule has: a method the holder never named cannot
  ///         contribute. `_configSeed` and `_salt` are the outsider's own config and salt.
  function test_WhenAProofNamesAMethodTheRuleNeverNames(bytes calldata _configSeed, bytes32 _salt) external {
    _useDefaultRule(1 days, false);
    _commitRule();
    address _outsider = _silentMethod('outsider');
    vm.mockCall(_outsider, abi.encodePacked(IPolicyMethod.verify.selector), abi.encode(_MAGIC));
    IPolicyManager.AttemptRequest memory _req = _request(_places(0, 1, 2));
    _approve(_req);
    _req.proofs[1] =
      IPolicyManager.ProofPlace({place: 1, method: _outsider, config: _configSeed, salt: _salt, proof: 'anything'});
    bytes32 _recomputed = BindingDigest.credentialCommitment(_outsider, _configSeed, _salt);

    vm.expectCall(_outsider, '', 0);
    vm.expectRevert(abi.encodeWithSelector(IPolicyManager.PolicyManager_CredentialMismatch.selector, 1, _recomputed));
    _manager.startAttempt(_req);
  }

  /// @notice A proof carrying a config other than the committed one is refused as
  ///         PolicyManager_CredentialMismatch, and its method never judges that config: the config the
  ///         method reads is the one the holder wrote. `_suffix` builds a config that always differs.
  function test_WhenTheProofCarriesAnotherConfig(bytes calldata _suffix) external {
    _useDefaultRule(1 days, false);
    _commitRule();
    IPolicyManager.AttemptRequest memory _req = _request(_places(0, 1, 2));
    _approve(_req);
    _req.proofs[2].config = bytes.concat('forged ', _suffix);
    bytes32 _recomputed = BindingDigest.credentialCommitment(_methodB, _req.proofs[2].config, _req.proofs[2].salt);

    vm.expectCall(_methodB, '', 0);
    vm.expectRevert(abi.encodeWithSelector(IPolicyManager.PolicyManager_CredentialMismatch.selector, 2, _recomputed));
    _manager.startAttempt(_req);
  }

  /// @notice A proof carrying a salt other than the committed one is refused as
  ///         PolicyManager_CredentialMismatch before its method is called. `_mask` is XORed into the
  ///         committed salt and is never zero, so the salt always differs.
  function test_WhenTheProofCarriesAnotherSalt(uint256 _mask) external {
    _useDefaultRule(1 days, false);
    _commitRule();
    IPolicyManager.AttemptRequest memory _req = _request(_places(0, 1, 2));
    _approve(_req);
    _req.proofs[2].salt = _req.proofs[2].salt ^ bytes32(bound(_mask, 1, type(uint256).max));
    bytes32 _recomputed = BindingDigest.credentialCommitment(_methodB, _req.proofs[2].config, _req.proofs[2].salt);

    vm.expectCall(_methodB, '', 0);
    vm.expectRevert(abi.encodeWithSelector(IPolicyManager.PolicyManager_CredentialMismatch.selector, 2, _recomputed));
    _manager.startAttempt(_req);
  }

  /*///////////////////////////////////////////////////////////////
                              THE STOP
  ///////////////////////////////////////////////////////////////*/

  /// @notice A method that answers the pause read with exactly true has its proof refused as
  ///         PolicyManager_MethodStopped naming the place and the method, before its verify is called,
  ///         so a stopped method's credential stops counting.
  function test_WhenAMethodReportsItselfStopped() external {
    _useDefaultRule(1 days, false);
    _commitRule();
    IPolicyManager.AttemptRequest memory _req = _request(_places(0, 1, 2));
    _approve(_req);
    _stop(_methodB);

    vm.expectCall(_methodB, abi.encodePacked(IPolicyMethod.verify.selector), 0);
    vm.expectRevert(abi.encodeWithSelector(IPolicyManager.PolicyManager_MethodStopped.selector, 2, _methodB));
    _manager.startAttempt(_req);
  }

  /// @notice A stopped method at the first place is refused there, and no verify of any method runs.
  function test_WhenTheStoppedMethodFillsTheFirstPlace() external {
    _useDefaultRule(1 days, false);
    _commitRule();
    IPolicyManager.AttemptRequest memory _req = _request(_places(0, 1, 2));
    _approve(_req);
    _stop(_methodA);

    vm.expectCall(_methodA, abi.encodePacked(IPolicyMethod.verify.selector), 0);
    vm.expectCall(_methodB, abi.encodePacked(IPolicyMethod.verify.selector), 0);
    vm.expectRevert(abi.encodeWithSelector(IPolicyManager.PolicyManager_MethodStopped.selector, 0, _methodA));
    _manager.startAttempt(_req);
  }

  /// @notice A wrong credential at a stopped method's place fails as PolicyManager_CredentialMismatch:
  ///         the credential is recomputed before the pause is read, so no stop is read from an address
  ///         the holder did not commit.
  function test_WhenTheCredentialIsWrongAtAStoppedMethodsPlace() external {
    _useDefaultRule(1 days, false);
    _commitRule();
    IPolicyManager.AttemptRequest memory _req = _request(_places(0, 1, 2));
    _approve(_req);
    _stop(_methodB);
    _req.proofs[2].config = 'forged';
    bytes32 _recomputed = BindingDigest.credentialCommitment(_methodB, 'forged', _req.proofs[2].salt);

    vm.expectCall(_methodB, '', 0);
    vm.expectRevert(abi.encodeWithSelector(IPolicyManager.PolicyManager_CredentialMismatch.selector, 2, _recomputed));
    _manager.startAttempt(_req);
  }

  /// @notice When the committed body says the holder ignores stops, stopped methods still count, the
  ///         pause is never read, and the attempt records the choice, so a stop never reaches a holder
  ///         who opted out.
  function test_WhenTheBodyIgnoresStops() external {
    _useDefaultRule(1 days, true);
    _commitRule();
    IPolicyManager.AttemptRequest memory _req = _request(_places(0, 1, 2));
    _approve(_req);
    _stop(_methodA);
    _stop(_methodB);

    vm.expectCall(_methodA, _pausedCall(), 0);
    vm.expectCall(_methodB, _pausedCall(), 0);
    _manager.startAttempt(_req);

    IPolicyManager.Attempt memory _record = _state(_account, _action).attempt;
    assertEq(uint8(_record.state), uint8(IPolicyManager.AttemptState.Waiting), 'waiting');
    assertTrue(_record.ignoresPause, 'the attempt carries the choice');
  }

  /// @notice The pause is read once per distinct method, however many places the method fills, and
  ///         each proof is verified once, a proof beyond what the rule needs included: the set of all
  ///         four places carries one more than the rule needs and still opens the attempt.
  function test_WhenOneMethodFillsSeveralPlaces() external {
    _useDefaultRule(1 days, false);
    _commitRule();
    IPolicyManager.AttemptRequest memory _req = _request(_places(0, 1, 2, 3));
    _approve(_req);

    vm.expectCall(_methodA, _pausedCall(), 1);
    vm.expectCall(_methodB, _pausedCall(), 1);
    _expectEachProofVerifiedOnce(_req);
    _manager.startAttempt(_req);

    assertEq(uint8(_state(_account, _action).attempt.state), uint8(IPolicyManager.AttemptState.Waiting), 'waiting');
  }

  /// @notice A rule may name one guardian at two places, the same credential under two salts. When the guardian proves
  ///         once for each place, over each place's own digest, both places count and the attempt opens.
  function test_WhenOneGuardianSitsAtTwoPlaces() external {
    _useDefaultRule(1 days, false);
    _credentials[3] = Credential(_methodB, 'config-2', keccak256('salt-3'));
    _reshapeDefault(1 days, false);
    _commitRule();
    IPolicyManager.AttemptRequest memory _req = _request(_places(0, 2, 3));
    _approve(_req);

    _manager.startAttempt(_req);

    assertEq(uint8(_state(_account, _action).attempt.state), uint8(IPolicyManager.AttemptState.Waiting), 'waiting');
  }

  /// @notice The proof made for place 2 is reused at place 3, where the same guardian sits. The digest names the
  ///         place, so the proof does not count there and the request fails: one signature never fills two places.
  function test_WhenOneProofIsReusedAtASecondPlaceOfTheSameGuardian() external {
    _useDefaultRule(1 days, false);
    _credentials[3] = Credential(_methodB, 'config-2', keccak256('salt-3'));
    _reshapeDefault(1 days, false);
    _commitRule();
    IPolicyManager.AttemptRequest memory _req = _request(_places(0, 2, 3));
    _approve(_req);
    _req.proofs[2].proof = _req.proofs[1].proof;

    vm.expectRevert(abi.encodeWithSelector(IPolicyManager.PolicyManager_ProofRejected.selector, 3, _methodB));
    _manager.startAttempt(_req);
  }

  /// @notice A pause read that reverts, even with the encoding of true as its data, is not a stop,
  ///         so the request opens. `_revertData` is the revert's data.
  function test_WhenThePauseReadReverts(bytes calldata _revertData) external {
    _useDefaultRule(1 days, false);
    _commitRule();
    IPolicyManager.AttemptRequest memory _req = _request(_places(0, 1, 2));
    _approve(_req);
    vm.mockCallRevert(_methodB, _pausedCall(), _revertData);

    _manager.startAttempt(_req);

    assertEq(uint8(_state(_account, _action).attempt.state), uint8(IPolicyManager.AttemptState.Waiting), 'waiting');
  }

  /// @notice A pause read that reverts with exactly the encoding of true is not a stop either, so a
  ///         revert never passes for an answer.
  function test_WhenThePauseReadRevertsWithTrue() external {
    _useDefaultRule(1 days, false);
    _commitRule();
    IPolicyManager.AttemptRequest memory _req = _request(_places(0, 1, 2));
    _approve(_req);
    vm.mockCallRevert(_methodB, _pausedCall(), abi.encode(true));

    _manager.startAttempt(_req);

    assertEq(uint8(_state(_account, _action).attempt.state), uint8(IPolicyManager.AttemptState.Waiting), 'waiting');
  }

  /// @notice A pause read returning one word other than the encoding of true is not a stop. `_seed`
  ///         builds the word: zero when it is 1, itself otherwise, so the word is never 1.
  function test_WhenThePauseReadReturnsAWordOtherThanTrue(uint256 _seed) external {
    _useDefaultRule(1 days, false);
    _commitRule();
    IPolicyManager.AttemptRequest memory _req = _request(_places(0, 1, 2));
    _approve(_req);
    vm.mockCall(_methodB, _pausedCall(), abi.encode(_seed == 1 ? 0 : _seed));

    _manager.startAttempt(_req);

    assertEq(uint8(_state(_account, _action).attempt.state), uint8(IPolicyManager.AttemptState.Waiting), 'waiting');
  }

  /// @notice A pause read returning the encoding of true followed by more bytes is not a stop, since
  ///         only exactly one word counts. `_extra` is the trailing bytes, at least one.
  function test_WhenThePauseReadReturnsTrueAndMore(bytes calldata _extra) external {
    _useDefaultRule(1 days, false);
    _commitRule();
    IPolicyManager.AttemptRequest memory _req = _request(_places(0, 1, 2));
    _approve(_req);
    vm.mockCall(_methodB, _pausedCall(), bytes.concat(abi.encode(true), hex'01', _extra));

    _manager.startAttempt(_req);

    assertEq(uint8(_state(_account, _action).attempt.state), uint8(IPolicyManager.AttemptState.Waiting), 'waiting');
  }

  /// @notice A pause read returning fewer than 32 bytes is not a stop. `_lengthSeed` picks 1 to 31
  ///         bytes, the last of them 0x01.
  function test_WhenThePauseReadReturnsLessThanAWord(uint256 _lengthSeed) external {
    _useDefaultRule(1 days, false);
    _commitRule();
    IPolicyManager.AttemptRequest memory _req = _request(_places(0, 1, 2));
    _approve(_req);
    bytes memory _short = new bytes(bound(_lengthSeed, 1, 31));
    _short[_short.length - 1] = 0x01;
    vm.mockCall(_methodB, _pausedCall(), _short);

    _manager.startAttempt(_req);

    assertEq(uint8(_state(_account, _action).attempt.state), uint8(IPolicyManager.AttemptState.Waiting), 'waiting');
  }

  /// @notice A method whose pause read writes its own storage cannot report a stop, since the read
  ///         is a static call and the write reverts it, and its storage stays untouched.
  function test_WhenThePauseReadWritesState() external {
    PolicyManagerMockWritingMethod _writer = new PolicyManagerMockWritingMethod();
    _useDefaultRule(1 days, false);
    _credentials[2].method = address(_writer);
    _credentials[3].method = address(_writer);
    _reshapeDefault(1 days, false);
    _commitRule();
    IPolicyManager.AttemptRequest memory _req = _request(_places(0, 1, 2));
    _approve(_request(_places(0, 1)));

    vm.expectRevert(abi.encodeWithSelector(IPolicyManager.PolicyManager_ProofRejected.selector, 2, address(_writer)));
    _manager.startAttempt(_req);

    assertEq(_writer.writes(), 0, 'the method wrote nothing');
  }

  /// @notice A pause answer of true followed by two megabytes is not a stop, and the manager reads
  ///         its size before copying it: the request opens on a gas budget that copying the answer
  ///         would exhaust.
  function test_WhenThePauseReadReturnsAHugeAnswer() external {
    _useDefaultRule(1 days, false);
    _commitRule();
    IPolicyManager.AttemptRequest memory _req = _request(_places(0, 1, 2));
    _approve(_req);
    vm.mockCall(_methodB, _pausedCall(), bytes.concat(abi.encode(true), new bytes(_HUGE_ANSWER_SIZE)));

    _manager.startAttempt{gas: _HUGE_ANSWER_GAS}(_req);

    assertEq(uint8(_state(_account, _action).attempt.state), uint8(IPolicyManager.AttemptState.Waiting), 'waiting');
  }

  /*///////////////////////////////////////////////////////////////
                              THE VERDICT
  ///////////////////////////////////////////////////////////////*/

  /// @notice A method that reverts has its proof refused as PolicyManager_ProofRejected naming the
  ///         place and the method. `_revertData` is the revert's data.
  function test_WhenTheMethodReverts(bytes calldata _revertData) external {
    _useDefaultRule(1 days, false);
    _commitRule();
    IPolicyManager.AttemptRequest memory _req = _request(_places(0, 1, 2));
    _approve(_req);
    vm.mockCallRevert(_methodB, _verifyCall(_req.proofs[2], _manager.hashApproval(_req, 2)), _revertData);

    vm.expectRevert(abi.encodeWithSelector(IPolicyManager.PolicyManager_ProofRejected.selector, 2, _methodB));
    _manager.startAttempt(_req);
  }

  /// @notice A method that reverts with the magic value as its data is still a rejection, so a revert
  ///         never reads as an approval.
  function test_WhenTheMethodRevertsWithTheMagicValue() external {
    _useDefaultRule(1 days, false);
    _commitRule();
    IPolicyManager.AttemptRequest memory _req = _request(_places(0, 1, 2));
    _approve(_req);
    vm.mockCallRevert(_methodB, _verifyCall(_req.proofs[2], _manager.hashApproval(_req, 2)), abi.encode(_MAGIC));

    vm.expectRevert(abi.encodeWithSelector(IPolicyManager.PolicyManager_ProofRejected.selector, 2, _methodB));
    _manager.startAttempt(_req);
  }

  /// @notice A method that returns nothing has its proof refused as PolicyManager_ProofRejected, so a
  ///         successful call is not an approval.
  function test_WhenTheMethodReturnsNothing() external {
    _useDefaultRule(1 days, false);
    _commitRule();
    IPolicyManager.AttemptRequest memory _req = _request(_places(0, 1, 2));
    _approve(_req);
    vm.mockCall(_methodB, _verifyCall(_req.proofs[2], _manager.hashApproval(_req, 2)), '');

    vm.expectRevert(abi.encodeWithSelector(IPolicyManager.PolicyManager_ProofRejected.selector, 2, _methodB));
    _manager.startAttempt(_req);
  }

  /// @notice A committed method address with no code answers nothing, and its proof is refused as
  ///         PolicyManager_ProofRejected, so an empty address never approves.
  function test_WhenTheMethodHasNoCode() external {
    address _empty = makeAddr('no code here');
    _useDefaultRule(1 days, false);
    _credentials[2].method = _empty;
    _reshapeDefault(1 days, false);
    _commitRule();
    IPolicyManager.AttemptRequest memory _req = _request(_places(0, 1, 2));
    _approve(_request(_places(0, 1)));

    vm.expectRevert(abi.encodeWithSelector(IPolicyManager.PolicyManager_ProofRejected.selector, 2, _empty));
    _manager.startAttempt(_req);
  }

  /// @notice A method returning fewer than 32 bytes, the leading bytes of the magic word, is refused,
  ///         so the manager never reads a partial word as the magic value. `_lengthSeed` picks 1 to 31
  ///         bytes.
  function test_WhenTheMethodReturnsLessThanAWord(uint256 _lengthSeed) external {
    _useDefaultRule(1 days, false);
    _commitRule();
    IPolicyManager.AttemptRequest memory _req = _request(_places(0, 1, 2));
    _approve(_req);
    bytes memory _word = abi.encode(_MAGIC);
    bytes memory _short = new bytes(bound(_lengthSeed, 1, 31));
    for (uint256 _i; _i < _short.length; ++_i) {
      _short[_i] = _word[_i];
    }
    vm.mockCall(_methodB, _verifyCall(_req.proofs[2], _manager.hashApproval(_req, 2)), _short);

    vm.expectRevert(abi.encodeWithSelector(IPolicyManager.PolicyManager_ProofRejected.selector, 2, _methodB));
    _manager.startAttempt(_req);
  }

  /// @notice A method returning the magic word followed by more bytes is refused, so trailing bytes a
  ///         decoder would ignore never pass. `_extra` is the trailing bytes, at least one.
  function test_WhenTheMethodReturnsMoreThanAWord(bytes calldata _extra) external {
    _useDefaultRule(1 days, false);
    _commitRule();
    IPolicyManager.AttemptRequest memory _req = _request(_places(0, 1, 2));
    _approve(_req);
    vm.mockCall(
      _methodB,
      _verifyCall(_req.proofs[2], _manager.hashApproval(_req, 2)),
      bytes.concat(abi.encode(_MAGIC), hex'00', _extra)
    );

    vm.expectRevert(abi.encodeWithSelector(IPolicyManager.PolicyManager_ProofRejected.selector, 2, _methodB));
    _manager.startAttempt(_req);
  }

  /// @notice A method returning one word other than the magic value left-aligned is refused, the
  ///         selector followed by nonzero bytes and the selector right-aligned among them, so the whole
  ///         word is compared. `_mask` is XORed into the magic word and is never zero.
  function test_WhenTheMethodReturnsAnotherWord(uint256 _mask) external {
    _useDefaultRule(1 days, false);
    _commitRule();
    IPolicyManager.AttemptRequest memory _req = _request(_places(0, 1, 2));
    _approve(_req);
    bytes32 _word = bytes32(_MAGIC) ^ bytes32(bound(_mask, 1, type(uint256).max));
    vm.mockCall(_methodB, _verifyCall(_req.proofs[2], _manager.hashApproval(_req, 2)), abi.encode(_word));

    vm.expectRevert(abi.encodeWithSelector(IPolicyManager.PolicyManager_ProofRejected.selector, 2, _methodB));
    _manager.startAttempt(_req);
  }

  /// @notice A method returning the magic selector in the top four bytes with the lowest byte set is
  ///         refused, so the manager compares the whole word and not only its leading four bytes.
  function test_WhenTheMethodReturnsTheSelectorWithALowByteSet() external {
    _useDefaultRule(1 days, false);
    _commitRule();
    IPolicyManager.AttemptRequest memory _req = _request(_places(0, 1, 2));
    _approve(_req);
    bytes32 _word = bytes32(_MAGIC) | bytes32(uint256(1));
    vm.mockCall(_methodB, _verifyCall(_req.proofs[2], _manager.hashApproval(_req, 2)), abi.encode(_word));

    vm.expectRevert(abi.encodeWithSelector(IPolicyManager.PolicyManager_ProofRejected.selector, 2, _methodB));
    _manager.startAttempt(_req);
  }

  /// @notice A committed method that is the identity precompile echoes the whole call, which starts
  ///         with the verify selector, and is refused because its answer is longer than one word.
  function test_WhenTheMethodIsAPrecompileThatEchoes() external {
    _useDefaultRule(1 days, false);
    _credentials[2].method = address(4);
    _reshapeDefault(1 days, false);
    _commitRule();
    IPolicyManager.AttemptRequest memory _req = _request(_places(0, 1, 2));
    _approve(_request(_places(0, 1)));

    vm.expectRevert(abi.encodeWithSelector(IPolicyManager.PolicyManager_ProofRejected.selector, 2, address(4)));
    _manager.startAttempt(_req);
  }

  /// @notice A method that writes its own storage while verifying is refused, since the manager calls
  ///         it as a static call and the write reverts it, and its storage stays untouched: a method
  ///         can change no state while it judges.
  function test_WhenTheMethodWritesStateWhileVerifying() external {
    PolicyManagerMockWritingMethod _writer = new PolicyManagerMockWritingMethod();
    _useDefaultRule(1 days, true);
    _credentials[2].method = address(_writer);
    _reshapeDefault(1 days, true);
    _commitRule();
    IPolicyManager.AttemptRequest memory _req = _request(_places(0, 1, 2));
    _approve(_request(_places(0, 1)));

    vm.expectRevert(abi.encodeWithSelector(IPolicyManager.PolicyManager_ProofRejected.selector, 2, address(_writer)));
    _manager.startAttempt(_req);

    assertEq(_writer.writes(), 0, 'the method wrote nothing');
  }

  /// @notice A method answering the magic word followed by two megabytes is refused, and the manager
  ///         reads the answer's size before copying it: the refusal arrives on a gas budget that
  ///         copying the answer would exhaust.
  function test_WhenTheMethodReturnsAHugeAnswer() external {
    _useDefaultRule(1 days, false);
    _commitRule();
    IPolicyManager.AttemptRequest memory _req = _request(_places(0, 1, 2));
    _approve(_req);
    vm.mockCall(
      _methodB,
      _verifyCall(_req.proofs[2], _manager.hashApproval(_req, 2)),
      bytes.concat(abi.encode(_MAGIC), new bytes(_HUGE_ANSWER_SIZE))
    );

    vm.expectRevert(abi.encodeWithSelector(IPolicyManager.PolicyManager_ProofRejected.selector, 2, _methodB));
    _manager.startAttempt{gas: _HUGE_ANSWER_GAS}(_req);
  }

  /// @notice A method that binds its verdict to the digest approves only a proof that seals the digest it is
  ///         handed. A seal here is PolicyManagerMockDigestMethod's keccak256 of the config and the digest, and a
  ///         proof sealed for a digest is that hash. Such a method rejects a proof sealed for the digest of another
  ///         payload, since the manager hands it this request's digest, so a proof approves one exact outcome.
  function test_WhenTheProofApprovesAnotherPayload() external {
    PolicyManagerMockDigestMethod _binding = new PolicyManagerMockDigestMethod();
    _useDefaultRule(1 days, false);
    _credentials[2].method = address(_binding);
    _reshapeDefault(1 days, false);
    _commitRule();
    IPolicyManager.AttemptRequest memory _req = _request(_places(0, 1, 2));
    _approve(_request(_places(0, 1)));
    IPolicyManager.AttemptRequest memory _other = _request(_places(0, 1, 2));
    _other.payload = 'another new key';
    bytes32 _otherDigest = _manager.hashApproval(_other, 2);
    _req.proofs[2].proof = _binding.seal(_req.proofs[2].config, _otherDigest);
    assertEq(_binding.verify(_req.proofs[2].config, _otherDigest, _req.proofs[2].proof), _MAGIC, 'seals the other');

    vm.expectRevert(abi.encodeWithSelector(IPolicyManager.PolicyManager_ProofRejected.selector, 2, address(_binding)));
    _manager.startAttempt(_req);
  }

  /// @notice A proof sealed for the request with a higher payment amount is refused as PolicyManager_ProofRejected,
  ///         so nobody can raise the price a guardian approved after the guardian signed.
  function test_WhenTheProofApprovesAnotherOrderAmount() external {
    PolicyManagerMockDigestMethod _binding = new PolicyManagerMockDigestMethod();
    _useDefaultRule(1 days, false);
    _credentials[2].method = address(_binding);
    _reshapeDefault(1 days, false);
    _commitRule();
    IPolicyManager.AttemptRequest memory _req = _request(_places(0, 1, 2));
    _approve(_request(_places(0, 1)));
    IPolicyManager.AttemptRequest memory _other = _request(_places(0, 1, 2));
    _other.order.amount = _req.order.amount + 1;
    _req.proofs[2].proof = _binding.seal(_req.proofs[2].config, _manager.hashApproval(_other, 2));

    vm.expectRevert(abi.encodeWithSelector(IPolicyManager.PolicyManager_ProofRejected.selector, 2, address(_binding)));
    _manager.startAttempt(_req);
  }

  /// @notice A proof sealed for the request that pays another payee is refused as PolicyManager_ProofRejected, so
  ///         nobody can redirect the payment a guardian approved after the guardian signed.
  function test_WhenTheProofApprovesAnotherOrderPayee() external {
    PolicyManagerMockDigestMethod _binding = new PolicyManagerMockDigestMethod();
    _useDefaultRule(1 days, false);
    _credentials[2].method = address(_binding);
    _reshapeDefault(1 days, false);
    _commitRule();
    IPolicyManager.AttemptRequest memory _req = _request(_places(0, 1, 2));
    _approve(_request(_places(0, 1)));
    IPolicyManager.AttemptRequest memory _other = _request(_places(0, 1, 2));
    _other.order.payee = makeAddr('another payee');
    _req.proofs[2].proof = _binding.seal(_req.proofs[2].config, _manager.hashApproval(_other, 2));

    vm.expectRevert(abi.encodeWithSelector(IPolicyManager.PolicyManager_ProofRejected.selector, 2, address(_binding)));
    _manager.startAttempt(_req);
  }

  /// @notice A proof sealed for the cancellation of this same attempt id is refused as PolicyManager_ProofRejected:
  ///         the two digests differ by their type, so a guardian's cancel never counts as an approval.
  function test_WhenTheProofSignsTheCancellationDigest() external {
    PolicyManagerMockDigestMethod _binding = new PolicyManagerMockDigestMethod();
    _useDefaultRule(1 days, false);
    _credentials[2].method = address(_binding);
    _reshapeDefault(1 days, false);
    _commitRule();
    IPolicyManager.AttemptRequest memory _req = _request(_places(0, 1, 2));
    _approve(_request(_places(0, 1)));
    IPolicyManager.CancelRequest memory _cancel = _cancelRequest(_places(0, 1, 2));
    _cancel.attemptId = _req.attemptId;
    _cancel.validUntil = _req.validUntil;
    _req.proofs[2].proof = _binding.seal(_req.proofs[2].config, _manager.hashCancel(_cancel, 2));

    vm.expectRevert(abi.encodeWithSelector(IPolicyManager.PolicyManager_ProofRejected.selector, 2, address(_binding)));
    _manager.startAttempt(_req);
  }

  /// @notice A rejected proof in a set that is also too short fails as PolicyManager_ProofRejected, not
  ///         as an unmet rule: every proof is judged before the rule is counted.
  function test_WhenARejectedProofSitsInAShortSet() external {
    _useDefaultRule(1 days, false);
    _commitRule();
    IPolicyManager.AttemptRequest memory _req = _request(_places(2));

    vm.expectRevert(abi.encodeWithSelector(IPolicyManager.PolicyManager_ProofRejected.selector, 2, _methodB));
    _manager.startAttempt(_req);
  }

  /*///////////////////////////////////////////////////////////////
                               THE RULE
  ///////////////////////////////////////////////////////////////*/

  /// @notice A set whose every proof verified but that misses the second clause's threshold is refused
  ///         as PolicyManager_RuleUnsatisfied naming clause 1, so an incomplete set opens nothing.
  function test_WhenAClauseMissesItsThreshold() external {
    _useDefaultRule(1 days, false);
    _commitRule();
    IPolicyManager.AttemptRequest memory _req = _request(_places(0, 1));
    _approve(_req);

    vm.expectRevert(abi.encodeWithSelector(IPolicyManager.PolicyManager_RuleUnsatisfied.selector, 1));
    _manager.startAttempt(_req);
  }

  /// @notice A set that fills the second clause but not the first is refused naming clause 0.
  function test_WhenTheFirstClauseIsNotFilled() external {
    _useDefaultRule(1 days, false);
    _commitRule();
    IPolicyManager.AttemptRequest memory _req = _request(_places(1, 2, 3));
    _approve(_req);

    vm.expectRevert(abi.encodeWithSelector(IPolicyManager.PolicyManager_RuleUnsatisfied.selector, 0));
    _manager.startAttempt(_req);
  }

  /// @notice A request with no proofs is refused as PolicyManager_RuleUnsatisfied and calls no method,
  ///         so the submitter is never counted as a filled place.
  function test_WhenTheRequestCarriesNoProofs() external {
    _useDefaultRule(1 days, false);
    _commitRule();
    IPolicyManager.AttemptRequest memory _req = _request(new uint256[](0));

    _expectNoMethodCalled();
    vm.expectRevert(abi.encodeWithSelector(IPolicyManager.PolicyManager_RuleUnsatisfied.selector, 0));
    _manager.startAttempt(_req);
  }

  /// @notice A committed rule whose every threshold is zero opens nothing, even with a valid proof,
  ///         and is refused naming clause 0, since anyone could meet it with no proof at all.
  function test_WhenEveryThresholdIsZero() external {
    _useDefaultRule(1 days, false);
    uint8[] memory _thresholds = new uint8[](2);
    uint256[] memory _sizes = new uint256[](2);
    _sizes[0] = 1;
    _sizes[1] = 3;
    _useRule(1 days, false, _thresholds, _sizes);
    _commitRule();
    IPolicyManager.AttemptRequest memory _req = _request(_places(0));
    _approve(_req);

    vm.expectRevert(abi.encodeWithSelector(IPolicyManager.PolicyManager_RuleUnsatisfied.selector, 0));
    _manager.startAttempt(_req);
  }

  /// @notice A committed body with no clauses opens nothing, and a request against it is refused
  ///         naming clause 0.
  function test_WhenTheBodyHasNoClauses() external {
    _useRule(1 days, false, new uint8[](0), new uint256[](0));
    _commitRule();
    IPolicyManager.AttemptRequest memory _req = _request(new uint256[](0));

    vm.expectRevert(abi.encodeWithSelector(IPolicyManager.PolicyManager_RuleUnsatisfied.selector, 0));
    _manager.startAttempt(_req);
  }

  /*///////////////////////////////////////////////////////////////
                              ACCEPTANCE
  ///////////////////////////////////////////////////////////////*/

  /// @notice A complete set opens the attempt: the record holds the id, the setup nonce, the end of
  ///         the wait, the Waiting state, the body's pause choice, the payload hash, the order and the
  ///         distinct methods in proof order; the counter moves to this id; the setup stays; one
  ///         AttemptStarted carries the body and the payload in the clear; each method is asked once
  ///         with this request's own digest, config and proof, by a static call; and no storage word
  ///         holds the rule. Anyone may send it. The setup is committed twice, so its nonce 2 differs
  ///         from the attempt id 1, and the set fills places 0, 2 and 3, so the places the event
  ///         lists are not simply their positions. `_waitSeed`, `_payload`, `_paymentOrder` and
  ///         `_submitter` are any wait that fits, outcome, payment and sender. The payload gets a fixed
  ///         prefix and the amount stays below 2^128, so neither the payload hash nor the amount can
  ///         equal a salt or a credential hash of the rule.
  function test_WhenACompleteSetIsAccepted(
    uint256 _waitSeed,
    bool _ignoresPause,
    bytes calldata _payload,
    IPolicyManager.PaymentOrder memory _paymentOrder,
    address _submitter
  ) external {
    _paymentOrder.amount = bound(_paymentOrder.amount, 0, type(uint128).max);
    vm.warp(1_700_000_000);
    uint48 _wait = uint48(bound(_waitSeed, 0, type(uint48).max - block.timestamp));
    _useDefaultRule(_wait, _ignoresPause);
    _commitRule();
    uint64 _nonce = _commitRule();
    IPolicyManager.ActionState memory _before = _state(_account, _action);
    IPolicyManager.AttemptRequest memory _req = _request(_places(0, 2, 3));
    _req.payload = bytes.concat('payload: ', _payload);
    _req.order = _paymentOrder;
    _approve(_req);
    _expectEachProofVerifiedOnce(_req);

    vm.recordLogs();
    vm.startStateDiffRecording();
    vm.prank(_submitter);
    _manager.startAttempt(_req);
    Vm.AccountAccess[] memory _accesses = vm.stopAndReturnStateDiff();
    Vm.Log[] memory _logs = vm.getRecordedLogs();

    uint48 _consumableAfter = uint48(block.timestamp) + _wait;
    IPolicyManager.ActionState memory _after = _state(_account, _action);
    // it should write the attempt record
    IPolicyManager.Attempt memory _expected = IPolicyManager.Attempt({
      attemptId: 1,
      setupNonce: _nonce,
      consumableAfter: _consumableAfter,
      state: IPolicyManager.AttemptState.Waiting,
      ignoresPause: _ignoresPause,
      payloadHash: keccak256(_req.payload),
      order: _paymentOrder,
      usedMethods: _methodList(_methodA, _methodB)
    });
    assertEq(abi.encode(_after.attempt), abi.encode(_expected), 'attempt record');
    // it should move the attempt counter to this id and leave the setup
    assertEq(_after.nextAttemptId, 2, 'next attempt id');
    _assertSetupKept(_before, _after);
    // it should emit AttemptStarted alone
    assertEq(_logs.length, 1, 'one event');
    _assertStartedLog(_logs[0], _req, _places(0, 2, 3), _methodList(_methodA, _methodB), _consumableAfter);
    // it should call methods only through static calls and store no part of the rule
    _assertOnlyStaticCalls(_accesses);
    _assertStoresNoRuleSecret(_accesses);
  }

  /// @notice The used methods are listed once each, in the order the proofs first name them: with B at
  ///         place 0, A at place 1 and B again at place 2, the record lists B then A.
  function test_WhenMethodsRepeatAcrossThePlaces() external {
    _credentials.push(Credential(_methodB, 'b-0', keccak256('b-0')));
    _credentials.push(Credential(_methodA, 'a-1', keccak256('a-1')));
    _credentials.push(Credential(_methodB, 'b-2', keccak256('b-2')));
    uint8[] memory _thresholds = new uint8[](1);
    _thresholds[0] = 3;
    uint256[] memory _sizes = new uint256[](1);
    _sizes[0] = 3;
    _useRule(1 days, false, _thresholds, _sizes);
    _commitRule();

    IPolicyManager.AttemptRequest memory _req = _open(_places(0, 1, 2));

    assertEq(abi.encode(_state(_account, _action).attempt.usedMethods), abi.encode(_methodList(_methodB, _methodA)));
    assertEq(_req.proofs.length, 3, 'three proofs');
  }

  /// @notice With a wait of zero the attempt can be spent from its own block: consumableAfter is the
  ///         block's timestamp, since the kit sets no minimum wait.
  function test_WhenTheWaitIsZero() external {
    vm.warp(1_700_000_000);
    _useDefaultRule(0, false);
    _commitRule();

    _open(_places(0, 1, 2));

    assertEq(_state(_account, _action).attempt.consumableAfter, uint48(block.timestamp), 'consumableAfter');
  }

  /// @notice A wait that ends exactly at the largest uint48 second is accepted and stored as that
  ///         second, so the checked sum refuses only a value past the width. `_nowSeed` picks the block
  ///         time.
  function test_WhenTheWaitEndsAtTheLastUint48Second(uint256 _nowSeed) external {
    uint48 _now = uint48(bound(_nowSeed, 1, type(uint48).max));
    _useDefaultRule(type(uint48).max - _now, false);
    _commitRule();
    vm.warp(_now);

    _open(_places(0, 1, 2));

    assertEq(_state(_account, _action).attempt.consumableAfter, type(uint48).max, 'consumableAfter');
  }

  /// @notice A wait that carries the end of the wait past the uint48 width reverts with the arithmetic
  ///         overflow panic rather than wrapping into a shorter wait, and nothing changes. `_nowSeed`
  ///         picks the block time and `_waitSeed` a wait whose sum with it overflows.
  function test_WhenTheWaitCarriesTheEndPastTheUint48Width(uint256 _nowSeed, uint256 _waitSeed) external {
    uint48 _now = uint48(bound(_nowSeed, 1, type(uint48).max));
    uint48 _wait = uint48(bound(_waitSeed, uint256(type(uint48).max) - _now + 1, type(uint48).max));
    _useDefaultRule(_wait, false);
    _commitRule();
    vm.warp(_now);
    IPolicyManager.AttemptRequest memory _req = _request(_places(0, 1, 2));
    _req.validUntil = type(uint48).max;
    _approve(_req);
    IPolicyManager.ActionState memory _before = _state(_account, _action);

    vm.expectRevert(stdError.arithmeticError);
    _manager.startAttempt(_req);

    assertEq(abi.encode(_state(_account, _action)), abi.encode(_before), 'a refused request changes nothing');
  }

  /// @notice At a block timestamp past the uint48 width the request reverts through the checked cast,
  ///         SafeCastOverflowedUintDowncast with the width and the timestamp, rather than reading a
  ///         wrapped time. `_nowSeed` picks a timestamp from 2^48 upward.
  function test_WhenTheBlockTimestampIsPastTheUint48Width(uint256 _nowSeed) external {
    _useDefaultRule(1 days, false);
    _commitRule();
    IPolicyManager.AttemptRequest memory _req = _request(_places(0, 1, 2));
    _req.validUntil = type(uint48).max;
    _approve(_req);
    uint256 _now = bound(_nowSeed, uint256(type(uint48).max) + 1, type(uint256).max);
    vm.warp(_now);

    vm.expectRevert(abi.encodeWithSelector(SafeCast.SafeCastOverflowedUintDowncast.selector, uint8(48), _now));
    _manager.startAttempt(_req);
  }

  /// @notice Once accepted, an attempt does not depend on its request's window any more: after the
  ///         window passes the record is unchanged and still Waiting, so acceptance never regresses.
  function test_WhenTheWindowPassesAfterAcceptance() external {
    _useDefaultRule(1 days, false);
    _commitRule();
    IPolicyManager.AttemptRequest memory _req = _open(_places(0, 1, 2));
    IPolicyManager.Attempt memory _accepted = _state(_account, _action).attempt;

    vm.warp(uint256(_req.validUntil) + 30 days);

    assertEq(abi.encode(_state(_account, _action).attempt), abi.encode(_accepted), 'record unchanged');
  }

  /// @notice After the first attempt ended, a request for the next id opens attempt 2 and moves the
  ///         counter to 2, so ids run in sequence and each attempt runs its own wait.
  function test_WhenAnEarlierAttemptEnded() external {
    _useDefaultRule(1 days, false);
    _commitRule();
    _open(_places(0, 1, 2));
    vm.prank(_account);
    _manager.cancelByOwner(_action, 1);

    _open(_places(0, 2, 3));

    IPolicyManager.ActionState memory _after = _state(_account, _action);
    assertEq(_after.attempt.attemptId, 2, 'attempt id');
    assertEq(uint8(_after.attempt.state), uint8(IPolicyManager.AttemptState.Waiting), 'waiting');
    assertEq(_after.nextAttemptId, 3, 'next attempt id');
  }

  /*///////////////////////////////////////////////////////////////
                                UTILITIES
  ///////////////////////////////////////////////////////////////*/

  /// @notice Replaces the request's proofs with one proof at place 99, past the end of the rule.
  function _poisoned(IPolicyManager.AttemptRequest memory _req)
    private
    view
    returns (IPolicyManager.AttemptRequest memory _poisonedReq)
  {
    _req.proofs = _proofsAt(_places(99));
    _poisonedReq = _req;
  }
}
