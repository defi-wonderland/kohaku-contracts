// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {Vm} from 'forge-std/Vm.sol';
import {IPolicyManager} from 'interfaces/IPolicyManager.sol';
import {IPolicyMethod} from 'interfaces/IPolicyMethod.sol';
import {PolicyManagerMockWritingMethod} from 'test/mocks/PolicyManagerMockWritingMethod.sol';
import {PolicyManagerAcceptanceTestBase} from 'test/utils/PolicyManagerAcceptanceTestBase.sol';

/// @notice cancelByVeto, the third cancel path: anyone ends a waiting attempt once a method that
///         attempt used reports itself stopped. It reads no proof. It refuses when nothing waits,
///         when the id is not the live one, when the setup nonce moved, when the attempt's setup
///         committed to ignore stops, when the attempt did not use the named method, and when that
///         method does not answer the pause read with exactly true. It moves neither the setup nonce
///         nor the attempt counter.
/// @dev The default rule is the base contract's: clause 0 needs place 0, clause 1 needs 2 of places
///      1, 2 and 3; method A judges places 0 and 1 and method B places 2 and 3. The default attempt
///      opens with places 0, 1 and 2, so it uses method A then method B, and waits one day. Both
///      methods are addresses whose code stops at once, so an unmocked pause read returns nothing.
contract PolicyManagerCancelByVetoTest is PolicyManagerAcceptanceTestBase {
  /// @notice The wait of the default rule.
  uint48 internal constant _WAIT = 1 days;
  /// @notice The gas a call gets in the test of a huge answer. A manager that copies a huge answer
  ///         before reading its size runs out of it, and one that reads the size first does not.
  uint256 internal constant _HUGE_ANSWER_GAS = 2_000_000;
  /// @notice The size of a huge answer. Copying it into memory costs several million gas.
  uint256 internal constant _HUGE_ANSWER_SIZE = 2_000_000;

  /*///////////////////////////////////////////////////////////////
                           NOTHING TO CANCEL
  ///////////////////////////////////////////////////////////////*/

  /// @notice With no attempt ever recorded the veto is refused as PolicyManager_NoActiveAttempt and
  ///         no method is asked, so no cancel event reports a transition that did not happen.
  function test_WhenNoAttemptWasEverRecorded() external {
    _useDefaultRule(_WAIT, false);
    _stop(_methodB);

    _expectNoMethodCalled();
    vm.expectRevert(abi.encodeWithSelector(IPolicyManager.PolicyManager_NoActiveAttempt.selector, _account, _action));
    _manager.cancelByVeto(_account, _action, 1, _methodB);
  }

  /// @notice An attempt the holder already cancelled is not cancelled again, and no method is asked.
  function test_WhenTheAttemptWasCancelled() external {
    _openDefault();
    vm.prank(_account);
    _manager.cancelByOwner(_action, 1);
    _stop(_methodB);

    _expectNoMethodCalled();
    vm.expectRevert(abi.encodeWithSelector(IPolicyManager.PolicyManager_NoActiveAttempt.selector, _account, _action));
    _manager.cancelByVeto(_account, _action, 1, _methodB);
  }

  /// @notice A spent attempt is history: a later stop cannot cancel it, and no method is asked.
  function test_WhenTheAttemptWasConsumed() external {
    IPolicyManager.AttemptRequest memory _opening = _openDefault();
    vm.warp(block.timestamp + _WAIT);
    vm.prank(_account);
    _manager.consume(_action, 1, keccak256(_opening.payload));
    _stop(_methodB);

    _expectNoMethodCalled();
    vm.expectRevert(abi.encodeWithSelector(IPolicyManager.PolicyManager_NoActiveAttempt.selector, _account, _action));
    _manager.cancelByVeto(_account, _action, 1, _methodB);
  }

  /*///////////////////////////////////////////////////////////////
                              THE CHECKS
  ///////////////////////////////////////////////////////////////*/

  /// @notice A veto naming any attempt id but the live one is refused as PolicyManager_WrongAttemptId
  ///         with both ids before any method is asked, so a cancel aimed at one attempt never reaches
  ///         its successor. `_offsetSeed` builds any id but the live one.
  function test_WhenTheAttemptIdIsNotTheLiveOne(uint64 _offsetSeed) external {
    _openDefault();
    _stop(_methodB);
    uint64 _supplied = _otherThan(1, _offsetSeed);

    _expectNoMethodCalled();
    vm.expectRevert(abi.encodeWithSelector(IPolicyManager.PolicyManager_WrongAttemptId.selector, _supplied, uint64(1)));
    _manager.cancelByVeto(_account, _action, _supplied, _methodB);
  }

  /// @notice An attempt whose own setup nonce is not the stored one is refused as
  ///         PolicyManager_StaleAttempt with both nonces, before any method is asked. Every setup
  ///         write cancels the waiting attempt, so no sequence of calls leaves such a record and the
  ///         harness writes it. The record's first method reports a stop.
  function test_WhenTheAttemptWasJudgedUnderAnotherNonce() external {
    _useDefaultRule(_WAIT, false);
    uint64 _nonce = _commitRule();
    _plant(_account, _action, _attempt(1, _nonce + 3, IPolicyManager.AttemptState.Waiting, false, _methods()));

    vm.expectCall(_stoppedMethod, _pausedCall(), 0);
    vm.expectRevert(abi.encodeWithSelector(IPolicyManager.PolicyManager_StaleAttempt.selector, _nonce + 3, _nonce));
    _manager.cancelByVeto(_account, _action, 1, _stoppedMethod);
  }

  /// @notice A holder who committed to ignore stops keeps an accepted attempt through a stop: the
  ///         veto is refused as PolicyManager_AttemptIgnoresPause carrying the id, and no method is
  ///         asked.
  function test_WhenTheAttemptIgnoresStops() external {
    _useDefaultRule(_WAIT, true);
    _commitRule();
    _open(_places(0, 1, 2));
    _stop(_methodB);

    _expectNoMethodCalled();
    vm.expectRevert(abi.encodeWithSelector(IPolicyManager.PolicyManager_AttemptIgnoresPause.selector, uint64(1)));
    _manager.cancelByVeto(_account, _action, 1, _methodB);
  }

  /// @notice A stopped method the attempt never used cannot cancel it: the veto is refused as
  ///         PolicyManager_MethodNotUsed with the id and the method, and that method is never
  ///         called, so no caller makes the manager read an address the holder never committed.
  ///         `_methodSeed` builds the address, which reports a stop.
  function test_WhenTheMethodIsNotOneTheAttemptUsed(uint256 _methodSeed) external {
    _openDefault();
    address _outsider = _addressFrom('outsider', _methodSeed);
    _stop(_outsider);

    vm.expectCall(_outsider, '', 0);
    vm.expectRevert(abi.encodeWithSelector(IPolicyManager.PolicyManager_MethodNotUsed.selector, uint64(1), _outsider));
    _manager.cancelByVeto(_account, _action, 1, _outsider);
  }

  /// @notice A stopped method the rule names but the accepted set did not use cannot cancel the
  ///         attempt either: the authorization comes from the attempt's own list of used methods.
  ///         Method C judges place 3, which the default attempt leaves empty.
  function test_WhenTheMethodIsInTheRuleButTheAttemptDidNotUseIt() external {
    address _methodC = _silentMethod('methodC');
    _useDefaultRule(_WAIT, false);
    _credentials[3].method = _methodC;
    _reshapeDefault(_WAIT, false);
    _commitRule();
    _open(_places(0, 1, 2));
    _stop(_methodC);

    vm.expectCall(_methodC, '', 0);
    vm.expectRevert(abi.encodeWithSelector(IPolicyManager.PolicyManager_MethodNotUsed.selector, uint64(1), _methodC));
    _manager.cancelByVeto(_account, _action, 1, _methodC);
  }

  /// @notice The zero address is never a used method, so naming it is refused as
  ///         PolicyManager_MethodNotUsed.
  function test_WhenTheMethodIsTheZeroAddress() external {
    _openDefault();

    vm.expectRevert(abi.encodeWithSelector(IPolicyManager.PolicyManager_MethodNotUsed.selector, uint64(1), address(0)));
    _manager.cancelByVeto(_account, _action, 1, address(0));
  }

  /// @notice A used method whose pause read succeeds with nothing returned, the answer of a method
  ///         that declares no pause, has not stopped: the veto is refused as
  ///         PolicyManager_MethodNotStopped naming it.
  function test_WhenThePauseReadReturnsNothing() external {
    _openDefault();
    vm.mockCall(_methodB, _pausedCall(), '');

    _expectNotStopped(_methodB);
  }

  /// @notice A used method answering one word holding false has not stopped.
  function test_WhenThePauseReadReturnsFalse() external {
    _openDefault();
    vm.mockCall(_methodB, _pausedCall(), abi.encode(false));

    _expectNotStopped(_methodB);
  }

  /// @notice A pause read that reverts is not a stop, so it authorizes no cancel. `_revertData` is
  ///         the revert's data.
  function test_WhenThePauseReadReverts(bytes calldata _revertData) external {
    _openDefault();
    vm.mockCallRevert(_methodB, _pausedCall(), _revertData);

    _expectNotStopped(_methodB);
  }

  /// @notice A pause read that reverts carrying exactly the encoding of true is not a stop either.
  function test_WhenThePauseReadRevertsWithTrue() external {
    _openDefault();
    vm.mockCallRevert(_methodB, _pausedCall(), abi.encode(true));

    _expectNotStopped(_methodB);
  }

  /// @notice A pause read returning fewer than 32 bytes is not a stop. `_lengthSeed` picks 1 to 31
  ///         bytes, the last of them 0x01.
  function test_WhenThePauseReadReturnsLessThanAWord(uint256 _lengthSeed) external {
    _openDefault();
    bytes memory _short = new bytes(bound(_lengthSeed, 1, 31));
    _short[_short.length - 1] = 0x01;
    vm.mockCall(_methodB, _pausedCall(), _short);

    _expectNotStopped(_methodB);
  }

  /// @notice A pause read returning one word other than the encoding of true is not a stop. `_seed`
  ///         builds the word: zero when it is 1, itself otherwise, so the word is never 1.
  function test_WhenThePauseReadReturnsAWordOtherThanTrue(uint256 _seed) external {
    _openDefault();
    vm.mockCall(_methodB, _pausedCall(), abi.encode(_seed == 1 ? 0 : _seed));

    _expectNotStopped(_methodB);
  }

  /// @notice A pause read returning the encoding of true followed by more bytes is not a stop, since
  ///         only exactly one word counts. `_extra` is the trailing bytes after a first 0x01.
  function test_WhenThePauseReadReturnsTrueAndMore(bytes calldata _extra) external {
    _openDefault();
    vm.mockCall(_methodB, _pausedCall(), bytes.concat(abi.encode(true), hex'01', _extra));

    _expectNotStopped(_methodB);
  }

  /// @notice A pause answer of true followed by two megabytes is not a stop, and the manager reads its
  ///         size before copying it: the refusal arrives on a gas budget that copying the answer would
  ///         exhaust.
  function test_WhenThePauseReadReturnsAHugeAnswer() external {
    _openDefault();
    vm.mockCall(_methodB, _pausedCall(), bytes.concat(abi.encode(true), new bytes(_HUGE_ANSWER_SIZE)));

    vm.expectRevert(abi.encodeWithSelector(IPolicyManager.PolicyManager_MethodNotStopped.selector, _methodB));
    _manager.cancelByVeto{gas: _HUGE_ANSWER_GAS}(_account, _action, 1, _methodB);
  }

  /// @notice A used method whose pause read writes its own storage cannot report a stop, since the
  ///         read is a static call and the write reverts it, and its storage stays untouched. Such a
  ///         method never passes a verify, so the harness writes the record naming it.
  function test_WhenThePauseReadWritesState() external {
    PolicyManagerMockWritingMethod _writer = new PolicyManagerMockWritingMethod();
    _plantWaiting(_methodList(address(_writer)), false);

    vm.expectRevert(abi.encodeWithSelector(IPolicyManager.PolicyManager_MethodNotStopped.selector, address(_writer)));
    _manager.cancelByVeto(_account, _action, 1, address(_writer));

    assertEq(_writer.writes(), 0, 'the method wrote nothing');
  }

  /// @notice A used method at an address with no code answers the pause read with nothing, which is
  ///         not a stop. The harness writes the record naming it.
  function test_WhenTheUsedMethodHasNoCode() external {
    address _codeless = address(0xDEAD0001);
    _plantWaiting(_methodList(_codeless), false);

    vm.expectRevert(abi.encodeWithSelector(IPolicyManager.PolicyManager_MethodNotStopped.selector, _codeless));
    _manager.cancelByVeto(_account, _action, 1, _codeless);
  }

  /*///////////////////////////////////////////////////////////////
                       THE ORDER OF THE CHECKS
  ///////////////////////////////////////////////////////////////*/

  /// @notice With no attempt waiting and the id, the nonce, the pause choice and the method all
  ///         wrong, the missing attempt decides: the state is checked first.
  function test_WhenNoAttemptWaitsAndEveryOtherCheckFails() external {
    _useDefaultRule(_WAIT, false);
    uint64 _nonce = _commitRule();
    _plant(_account, _action, _attempt(1, _nonce + 3, IPolicyManager.AttemptState.Cancelled, true, _methods()));

    vm.expectRevert(abi.encodeWithSelector(IPolicyManager.PolicyManager_NoActiveAttempt.selector, _account, _action));
    _manager.cancelByVeto(_account, _action, 9, _methodA);
  }

  /// @notice With the id, the nonce, the pause choice and the method all wrong, the id decides.
  function test_WhenTheIdTheNonceThePauseChoiceAndTheMethodAllFail() external {
    _useDefaultRule(_WAIT, false);
    uint64 _nonce = _commitRule();
    _plant(_account, _action, _attempt(1, _nonce + 3, IPolicyManager.AttemptState.Waiting, true, _methods()));

    vm.expectRevert(abi.encodeWithSelector(IPolicyManager.PolicyManager_WrongAttemptId.selector, uint64(9), uint64(1)));
    _manager.cancelByVeto(_account, _action, 9, _methodA);
  }

  /// @notice With the nonce, the pause choice and the method all wrong, the nonce decides.
  function test_WhenTheNonceThePauseChoiceAndTheMethodAllFail() external {
    _useDefaultRule(_WAIT, false);
    uint64 _nonce = _commitRule();
    _plant(_account, _action, _attempt(1, _nonce + 3, IPolicyManager.AttemptState.Waiting, true, _methods()));

    vm.expectRevert(abi.encodeWithSelector(IPolicyManager.PolicyManager_StaleAttempt.selector, _nonce + 3, _nonce));
    _manager.cancelByVeto(_account, _action, 1, _methodA);
  }

  /// @notice With the pause choice and the method both wrong, the pause choice decides: an attempt
  ///         whose setup ignores stops is refused before the method is looked up.
  function test_WhenThePauseChoiceAndTheMethodBothFail() external {
    _useDefaultRule(_WAIT, true);
    _commitRule();
    _open(_places(0, 1, 2));
    address _outsider = _silentMethod('outsider');

    vm.expectRevert(abi.encodeWithSelector(IPolicyManager.PolicyManager_AttemptIgnoresPause.selector, uint64(1)));
    _manager.cancelByVeto(_account, _action, 1, _outsider);
  }

  /// @notice A method the attempt did not use and that does not report a stop is refused as not used:
  ///         membership is checked before the pause is read.
  function test_WhenTheMethodIsUnusedAndNotStopped() external {
    _openDefault();
    address _outsider = _silentMethod('outsider');

    vm.expectCall(_outsider, '', 0);
    vm.expectRevert(abi.encodeWithSelector(IPolicyManager.PolicyManager_MethodNotUsed.selector, uint64(1), _outsider));
    _manager.cancelByVeto(_account, _action, 1, _outsider);
  }

  /*///////////////////////////////////////////////////////////////
                            THE CANCELLATION
  ///////////////////////////////////////////////////////////////*/

  /// @notice Once a used method answers the pause read with exactly true, anyone ends the attempt
  ///         with no proof: the record turns Cancelled and keeps every other field, one
  ///         AttemptCancelled names the caller as canceller, the stopped method, the attempt's setup
  ///         nonce and no places, no method is asked to verify anything, every outside call is
  ///         static, only the named method's pause is read, once, and the setup and the attempt
  ///         counter stay. The setup is committed twice before the opening, so the attempt is id 1
  ///         under nonce 2 and the event is seen to carry the attempt's nonce and not its id.
  ///         `_callerSeed` builds any caller.
  function test_WhenAUsedMethodReportsAStop(uint256 _callerSeed) external {
    _useDefaultRule(_WAIT, false);
    _commitRule();
    _commitRule();
    _open(_places(0, 1, 2));
    _stop(_methodB);
    address _caller = _addressFrom('caller', _callerSeed);
    IPolicyManager.ActionState memory _before = _state(_account, _action);

    vm.expectCall(_methodB, _pausedCall(), 1);
    vm.expectCall(_methodA, _pausedCall(), 0);
    vm.expectCall(_methodA, abi.encodePacked(IPolicyMethod.verify.selector), 0);
    vm.expectCall(_methodB, abi.encodePacked(IPolicyMethod.verify.selector), 0);
    vm.expectCall(_account, '', 0);
    vm.recordLogs();
    vm.startStateDiffRecording();
    vm.prank(_caller);
    _manager.cancelByVeto(_account, _action, 1, _methodB);
    Vm.AccountAccess[] memory _accesses = vm.stopAndReturnStateDiff();
    Vm.Log[] memory _logs = vm.getRecordedLogs();

    IPolicyManager.ActionState memory _after = _state(_account, _action);
    // it should set the attempt to Cancelled and keep the rest of its record
    _assertRecordKept(_after.attempt, _before.attempt, IPolicyManager.AttemptState.Cancelled);
    // it should emit AttemptCancelled alone, naming the caller and the method, with no places
    assertEq(_logs.length, 1, 'one event');
    _assertVetoLog(_logs[0], _caller, _methodB, uint64(2));
    // it should read no proof and make only static calls
    _assertOnlyStaticCalls(_accesses);
    // it should leave the setup and the attempt counter unchanged
    _assertSetupKept(_before, _after);
    assertEq(_after.nextAttemptId, _before.nextAttemptId, 'attempt counter');
  }

  /// @notice A stop on one used method authorizes only a veto naming that method: naming another
  ///         used method that has not stopped is refused as PolicyManager_MethodNotStopped naming it,
  ///         and the attempt keeps waiting. Method A is stopped and method B is named.
  function test_WhenAnotherUsedMethodReportsAStop() external {
    _openDefault();
    _stop(_methodA);

    _expectNotStopped(_methodB);
  }

  /// @notice The veto needs no wait: it cancels whether or not the wait is over, so a stop that
  ///         spanned the whole wait is cleared rather than released.
  function test_WhenTheWaitIsOver() external {
    _openDefault();
    vm.warp(block.timestamp + _WAIT + 1);
    _stop(_methodB);

    _manager.cancelByVeto(_account, _action, 1, _methodB);

    assertEq(uint8(_state(_account, _action).attempt.state), uint8(IPolicyManager.AttemptState.Cancelled), 'state');
  }

  /// @notice Once cancelled, the attempt cannot be cancelled again by the same veto.
  function test_WhenTheSameVetoIsSentTwice() external {
    _openDefault();
    _stop(_methodB);
    _manager.cancelByVeto(_account, _action, 1, _methodB);

    vm.expectRevert(abi.encodeWithSelector(IPolicyManager.PolicyManager_NoActiveAttempt.selector, _account, _action));
    _manager.cancelByVeto(_account, _action, 1, _methodB);
  }

  /// @notice An attempt ended by a veto is never released, even once the stop lifts and the wait is
  ///         over.
  function test_WhenTheAccountSpendsAfterTheVeto() external {
    IPolicyManager.AttemptRequest memory _opening = _openDefault();
    _stop(_methodB);
    _manager.cancelByVeto(_account, _action, 1, _methodB);
    vm.clearMockedCalls();
    vm.warp(block.timestamp + _WAIT);

    vm.expectRevert(abi.encodeWithSelector(IPolicyManager.PolicyManager_NoActiveAttempt.selector, _account, _action));
    vm.prank(_account);
    _manager.consume(_action, 1, keccak256(_opening.payload));
  }

  /// @notice After a veto the next opening names the next id under the same setup nonce and runs:
  ///         the veto moved neither the nonce nor the counter.
  function test_WhenAnAttemptOpensAfterTheVeto() external {
    _openDefault();
    uint64 _nonce = _state(_account, _action).setupNonce;
    _stop(_methodB);
    _manager.cancelByVeto(_account, _action, 1, _methodB);
    vm.clearMockedCalls();

    _open(_places(0, 1, 3));

    IPolicyManager.ActionState memory _after = _state(_account, _action);
    assertEq(_after.attempt.attemptId, 2, 'attempt id');
    assertEq(_after.attempt.setupNonce, _nonce, 'same setup nonce');
    assertEq(_after.setupNonce, _nonce, 'nonce unchanged');
    assertEq(uint8(_after.attempt.state), uint8(IPolicyManager.AttemptState.Waiting), 'waiting');
  }

  /*///////////////////////////////////////////////////////////////
                                HELPERS
  ///////////////////////////////////////////////////////////////*/

  /// @notice Commits the default rule with a one-day wait that honours stops, and opens attempt 1
  ///         with places 0, 1 and 2.
  function _openDefault() private returns (IPolicyManager.AttemptRequest memory _opening) {
    _useDefaultRule(_WAIT, false);
    _commitRule();
    _opening = _open(_places(0, 1, 2));
  }

  /// @notice Expects a veto naming `_method` on attempt 1 to be refused as
  ///         PolicyManager_MethodNotStopped, and the attempt to keep waiting.
  function _expectNotStopped(address _method) private {
    vm.expectRevert(abi.encodeWithSelector(IPolicyManager.PolicyManager_MethodNotStopped.selector, _method));
    _manager.cancelByVeto(_account, _action, 1, _method);
    assertEq(uint8(_state(_account, _action).attempt.state), uint8(IPolicyManager.AttemptState.Waiting), 'waiting');
  }

  /// @notice Commits the default rule and writes, through the harness, a waiting attempt 1 under the
  ///         stored nonce that used `_usedMethods`.
  function _plantWaiting(address[] memory _usedMethods, bool _ignoresPause) private {
    _useDefaultRule(_WAIT, false);
    uint64 _nonce = _commitRule();
    _plant(_account, _action, _attempt(1, _nonce, IPolicyManager.AttemptState.Waiting, _ignoresPause, _usedMethods));
  }

  /// @notice Asserts `_log` is AttemptCancelled for attempt 1 of the default pair, cancelled by
  ///         `_canceller` on the veto of `_method`, judged under `_setupNonce`, with no places.
  function _assertVetoLog(Vm.Log memory _log, address _canceller, address _method, uint64 _setupNonce) private view {
    assertEq(_log.emitter, address(_manager), 'AttemptCancelled emitter');
    assertEq(_log.topics.length, 3, 'AttemptCancelled topics');
    assertEq(_log.topics[0], IPolicyManager.AttemptCancelled.selector, 'AttemptCancelled topic0');
    assertEq(_log.topics[1], bytes32(uint256(uint160(_account))), 'AttemptCancelled account');
    assertEq(_log.topics[2], bytes32(uint256(uint160(_action))), 'AttemptCancelled action');
    assertEq(
      _log.data, abi.encode(uint64(1), _canceller, _method, _setupNonce, new uint256[](0)), 'AttemptCancelled data'
    );
  }
}
