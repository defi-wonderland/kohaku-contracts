// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {stdError} from 'forge-std/StdError.sol';
import {Vm, VmSafe} from 'forge-std/Vm.sol';
import {SafeCast} from '@openzeppelin/contracts/utils/math/SafeCast.sol';
import {IPolicyAction} from 'interfaces/IPolicyAction.sol';
import {IPolicyManager} from 'interfaces/IPolicyManager.sol';
import {PolicyManagerMockAction} from 'test/mocks/PolicyManagerMockAction.sol';
import {PolicyManagerTestBase} from 'test/utils/PolicyManagerTestBase.sol';

/// @notice commitSetup, the call through which an account creates or replaces its own setup for one
///         action. A setup is the commitment to the rule that decides a recovery, so only the
///         account may write it, and each write retires every proof gathered under the one before.
contract PolicyManagerCommitSetupTest is PolicyManagerTestBase {
  /*///////////////////////////////////////////////////////////////
                             TREE TESTS
  ///////////////////////////////////////////////////////////////*/

  /// @notice A write must name the stored nonce plus one, so a stale or skipped write fails loudly and
  ///         changes nothing. That includes a write prepared against the same stored nonce as another
  ///         write that has since landed: it names a nonce the other write moved past and cannot
  ///         silently overwrite it. `_priorWrites` makes 0 to 3 valid writes first, and `_offsetSeed`
  ///         builds any nonce except the expected one.
  function test_WhenTheNonceIsNotTheCurrentOnePlusOne(uint8 _priorWrites, uint64 _offsetSeed) external {
    uint256 _writes = bound(_priorWrites, 0, 3);
    for (uint256 _i; _i < _writes; ++_i) {
      _commit(_account, _action);
    }
    IPolicyManager.ActionState memory _before = _state(_account, _action);
    uint64 _expected = _before.setupNonce + 1;

    // The equality case (the current nonce itself), one too far, and zero.
    _expectWrongNonce(_before.setupNonce, _expected);
    _expectWrongNonce(_expected + 1, _expected);
    _expectWrongNonce(0, _expected);

    _expectWrongNonce(_otherThan(_expected, _offsetSeed), _expected);

    assertEq(abi.encode(_state(_account, _action)), abi.encode(_before), 'a refused write changes nothing');

    // Two writes prepared against the same stored nonce: the first lands, and the second then names
    // the nonce the first moved past.
    bytes32 _first = _commitmentFor(_account, _action, _expected);
    bytes32 _second = keccak256('a second write prepared against the same stored nonce');
    vm.prank(_account);
    _manager.commitSetup(_action, _first, _expected, '', '');
    IPolicyManager.ActionState memory _afterFirst = _state(_account, _action);

    vm.expectRevert(_wrongNonce(_expected, _expected + 1));
    vm.prank(_account);
    _manager.commitSetup(_action, _second, _expected, '', '');

    assertEq(abi.encode(_state(_account, _action)), abi.encode(_afterFirst), 'the first write stands');
    assertEq(_state(_account, _action).setupCommitment, _first, 'commitment');
  }

  /// @notice A zero commitment is refused because zero is the value that means no setup. The write
  ///         names the right nonce so only the commitment is wrong. `_priorWrites` makes 0 to 3 writes.
  function test_WhenTheCommitmentIsZero(uint8 _priorWrites) external {
    uint256 _writes = bound(_priorWrites, 0, 3);
    for (uint256 _i; _i < _writes; ++_i) {
      _commit(_account, _action);
    }
    IPolicyManager.ActionState memory _before = _state(_account, _action);

    vm.expectRevert(abi.encodeWithSelector(IPolicyManager.PolicyManager_InvalidCommitment.selector, bytes32(0)));
    vm.prank(_account);
    _manager.commitSetup(_action, bytes32(0), _before.setupNonce + 1, 'pub', 'priv');

    assertEq(abi.encode(_state(_account, _action)), abi.encode(_before), 'a refused write changes nothing');
  }

  /// @notice The commitment of an empty rule body under the nonce the write would hold is refused,
  ///         since no real body produces it and it would store a setup nothing can ever satisfy.
  ///         `_accountSeed` builds the writing account, `_actionSeed` builds a fresh action that
  ///         serves every account and `_priorWrites` makes 0 to 3 writes first.
  function test_WhenTheCommitmentIsTheCommitmentOfAnEmptyBodyAtTheNonceTheWriteWillHold(
    uint256 _accountSeed,
    uint256 _actionSeed,
    uint8 _priorWrites
  ) external {
    address _writer = _addressFrom('account', _accountSeed);
    address _anyAction = _servingActionFrom(_actionSeed);
    uint256 _writes = bound(_priorWrites, 0, 3);
    for (uint256 _i; _i < _writes; ++_i) {
      _commit(_writer, _anyAction);
    }
    IPolicyManager.ActionState memory _before = _state(_writer, _anyAction);
    uint64 _next = _before.setupNonce + 1;
    bytes32 _dead = _emptyBodyCommitment(_writer, _anyAction, _next);

    vm.expectRevert(abi.encodeWithSelector(IPolicyManager.PolicyManager_InvalidCommitment.selector, _dead));
    vm.prank(_writer);
    _manager.commitSetup(_anyAction, _dead, _next, '', '');

    assertEq(abi.encode(_state(_writer, _anyAction)), abi.encode(_before), 'a refused write changes nothing');
  }

  /// @notice With both a wrong nonce and an invalid commitment the write is refused with either of
  ///         the two errors, since neither check is fixed to run first, and it changes nothing. What
  ///         matters is that such a write never lands. `_offsetSeed` builds any wrong nonce.
  function test_WhenTheNonceIsWrongAndTheCommitmentIsInvalid(uint8 _priorWrites, uint64 _offsetSeed) external {
    uint256 _writes = bound(_priorWrites, 0, 3);
    for (uint256 _i; _i < _writes; ++_i) {
      _commit(_account, _action);
    }
    IPolicyManager.ActionState memory _before = _state(_account, _action);
    uint64 _expected = _before.setupNonce + 1;
    uint64 _nonce = _otherThan(_expected, _offsetSeed);
    bytes32 _dead = _emptyBodyCommitment(_account, _action, _expected);

    _expectEitherRefusal(bytes32(0), _nonce, _expected);
    _expectEitherRefusal(_dead, _nonce, _expected);
    // The equality case of a stale write: the current nonce itself.
    _expectEitherRefusal(bytes32(0), _before.setupNonce, _expected);

    assertEq(abi.encode(_state(_account, _action)), abi.encode(_before), 'a refused write changes nothing');
  }

  /// @notice The first write stores its commitment under nonce one, records its block so a client
  ///         can find the write event, leaves the attempt counter alone and emits one event carrying
  ///         both metadata fields as given.
  function test_WhenNoSetupExists(uint48 _blockNumber, bytes calldata _publicMetadata, bytes calldata _privateMetadata)
    external
  {
    vm.roll(_blockNumber);
    bytes32 _commitment = _commitmentFor(_account, _action, 1);

    vm.recordLogs();
    vm.prank(_account);
    _manager.commitSetup(_action, _commitment, 1, _publicMetadata, _privateMetadata);
    Vm.Log[] memory _logs = vm.getRecordedLogs();

    IPolicyManager.ActionState memory _actionState = _state(_account, _action);
    // it should store the commitment under nonce one
    assertEq(_actionState.setupCommitment, _commitment, 'commitment');
    assertEq(_actionState.setupNonce, 1, 'nonce');
    // it should write the current block as setupCommittedAtBlock
    assertEq(_actionState.setupCommittedAtBlock, _blockNumber, 'setupCommittedAtBlock');
    // it should leave the next attempt id at one
    assertEq(_actionState.nextAttemptId, 1, 'nextAttemptId');
    assertEq(uint8(_actionState.attempt.state), uint8(IPolicyManager.AttemptState.None), 'no attempt');
    // it should emit SetupCommitted alone with both metadata fields
    assertEq(_logs.length, 1, 'one event per write');
    _assertCommittedLog(_logs[0], _account, _action, 1, _commitment, _publicMetadata, _privateMetadata);
  }

  /// @notice Each replacing write moves the nonce by exactly one and records its own block, so every
  ///         proof signed under the previous setup stops matching. `_writeCount` makes 1 to 6 writes
  ///         and `_blockStep` moves the chain forward between them.
  function test_WhenASetupExists(uint8 _writeCount, uint32 _blockStep) external {
    uint256 _count = bound(_writeCount, 1, 6);
    _commit(_account, _action);
    for (uint256 _i; _i < _count; ++_i) {
      IPolicyManager.ActionState memory _before = _state(_account, _action);
      vm.roll(block.number + bound(_blockStep, 1, type(uint32).max));
      uint64 _next = _before.setupNonce + 1;
      bytes32 _commitment = _commitmentFor(_account, _action, _next);

      vm.recordLogs();
      vm.prank(_account);
      _manager.commitSetup(_action, _commitment, _next, 'public', 'private');
      Vm.Log[] memory _logs = vm.getRecordedLogs();

      IPolicyManager.ActionState memory _actionState = _state(_account, _action);
      // it should replace the commitment and move the nonce by exactly one
      assertEq(_actionState.setupCommitment, _commitment, 'commitment');
      assertEq(_actionState.setupNonce, _before.setupNonce + 1, 'nonce moves by exactly one');
      // it should write the block of the new write
      assertEq(_actionState.setupCommittedAtBlock, block.number, 'setupCommittedAtBlock');
      assertEq(_actionState.nextAttemptId, _before.nextAttemptId, 'attempt counter');
      // it should emit SetupCommitted alone
      assertEq(_logs.length, 1, 'one event per write');
      _assertCommittedLog(_logs[0], _account, _action, _next, _commitment, 'public', 'private');
    }
  }

  /// @notice After a clear the next write continues from the clear's nonce, so a proof signed before
  ///         the clear can never match a later setup.
  function test_WhenTheSetupWasCleared() external {
    _commit(_account, _action);
    _clear(_account, _action);
    assertEq(_state(_account, _action).setupNonce, 2, 'the clear moved the nonce');

    // A write naming the first nonce again, or the clear's own nonce, is refused.
    bytes32 _again = _commitmentFor(_account, _action, 1);
    vm.expectRevert(_wrongNonce(uint64(1), uint64(3)));
    vm.prank(_account);
    _manager.commitSetup(_action, _again, 1, '', '');
    vm.expectRevert(_wrongNonce(uint64(2), uint64(3)));
    vm.prank(_account);
    _manager.commitSetup(_action, _again, 2, '', '');

    // it should continue the nonce from the clear rather than rewind it
    (uint64 _nonce, bytes32 _commitment) = _commit(_account, _action);
    assertEq(_nonce, 3, 'nonce');
    assertEq(_state(_account, _action).setupNonce, 3, 'stored nonce');
    assertEq(_state(_account, _action).setupCommitment, _commitment, 'commitment');
  }

  /// @notice Two writes in one block each move the nonce and each emit their own event, so a client
  ///         reading that block takes the last write event as the current setup.
  function test_WhenTwoWritesLandInOneBlock() external {
    vm.roll(4242);
    bytes32 _first = _commitmentFor(_account, _action, 1);
    bytes32 _second = _commitmentFor(_account, _action, 2);

    vm.recordLogs();
    vm.startPrank(_account);
    _manager.commitSetup(_action, _first, 1, 'a', 'b');
    _manager.commitSetup(_action, _second, 2, 'c', 'd');
    vm.stopPrank();
    Vm.Log[] memory _logs = vm.getRecordedLogs();

    IPolicyManager.ActionState memory _actionState = _state(_account, _action);
    assertEq(_actionState.setupNonce, 2, 'nonce');
    assertEq(_actionState.setupCommitment, _second, 'the last write wins');
    assertEq(_actionState.setupCommittedAtBlock, 4242, 'setupCommittedAtBlock');
    assertEq(_logs.length, 2, 'one event per write');
    _assertCommittedLog(_logs[0], _account, _action, 1, _first, 'a', 'b');
    _assertCommittedLog(_logs[1], _account, _action, 2, _second, 'c', 'd');
  }

  /// @notice A write succeeds for an action at any address once that action answers true to
  ///         supportsAccount for the caller, since the manager keeps no list of actions. The write
  ///         lands under the caller and that action, with one event. `_actionSeed` builds a fresh
  ///         address carrying the mock action's code, which serves every account.
  function test_WhenTheActionIsAnyAddressThatServesTheAccount(uint256 _actionSeed) external {
    address _anyAction = _servingActionFrom(_actionSeed);
    bytes32 _commitment = _commitmentFor(_account, _anyAction, 1);

    vm.recordLogs();
    vm.prank(_account);
    _manager.commitSetup(_anyAction, _commitment, 1, 'public', 'private');
    Vm.Log[] memory _logs = vm.getRecordedLogs();

    IPolicyManager.ActionState memory _actionState = _state(_account, _anyAction);
    // it should store the commitment under that action
    assertEq(_actionState.setupCommitment, _commitment, 'commitment');
    assertEq(_actionState.setupNonce, 1, 'nonce');
    assertEq(_actionState.setupCommittedAtBlock, block.number, 'setupCommittedAtBlock');
    // it should emit SetupCommitted alone for that action
    assertEq(_logs.length, 1, 'one event per write');
    _assertCommittedLog(_logs[0], _account, _anyAction, 1, _commitment, 'public', 'private');
  }

  /// @notice The manager asks the named action whether it serves the caller, so a wallet that skips
  ///         the setup screen still cannot commit a setup its action will never execute. The question
  ///         names the caller and goes out as a static call, the one call a write makes, and an answer
  ///         of exactly true lets the write land. `_callerSeed` builds the writing account.
  function test_WhenTheActionServesTheAccount(uint256 _callerSeed) external {
    address _caller = _addressFrom('account', _callerSeed);
    bytes32 _commitment = _commitmentFor(_caller, _action, 1);

    vm.expectCall(_action, abi.encodeCall(IPolicyAction.supportsAccount, (_caller)), 1);
    vm.recordLogs();
    vm.startStateDiffRecording();
    vm.prank(_caller);
    _manager.commitSetup(_action, _commitment, 1, 'public', 'private');
    Vm.AccountAccess[] memory _accesses = vm.stopAndReturnStateDiff();
    Vm.Log[] memory _logs = vm.getRecordedLogs();

    // it should ask the action supportsAccount for the caller, by a static call and nothing else
    _assertReachedOnlyTheServingProbe(_accesses, _caller, _action);
    // it should store the commitment
    IPolicyManager.ActionState memory _actionState = _state(_caller, _action);
    assertEq(_actionState.setupCommitment, _commitment, 'commitment');
    assertEq(_actionState.setupNonce, 1, 'nonce');
    assertEq(_actionState.setupCommittedAtBlock, block.number, 'setupCommittedAtBlock');
    // it should emit SetupCommitted alone
    assertEq(_logs.length, 1, 'one event per write');
    _assertCommittedLog(_logs[0], _caller, _action, 1, _commitment, 'public', 'private');
  }

  /// @notice The manager asks before it writes anything: the action reads the manager while it
  ///         answers and serves only while the account's setup and waiting attempt are still the ones
  ///         stored before the call. The write lands, so the question saw the state untouched, and
  ///         the attempt is cancelled and the setup replaced only afterwards.
  function test_WhenTheActionReadsTheManagerWhileAnswering() external {
    _commit(_account, _action);
    IPolicyManager.Attempt memory _planted = _plantWaiting(_account, _action, 1, false);
    IPolicyManager.ActionState memory _before = _state(_account, _action);
    PolicyManagerMockAction(_action).setServesWhileUnwritten(_manager, keccak256(abi.encode(_before)));
    bytes32 _commitment = _commitmentFor(_account, _action, 2);

    vm.prank(_account);
    _manager.commitSetup(_action, _commitment, 2, '', '');

    // it should ask before the attempt is cancelled and before the setup is written
    IPolicyManager.ActionState memory _actionState = _state(_account, _action);
    assertEq(_actionState.setupCommitment, _commitment, 'commitment');
    assertEq(_actionState.setupNonce, 2, 'nonce');
    _assertRecordKept(_actionState.attempt, _planted, IPolicyManager.AttemptState.Cancelled);
  }

  /// @notice An action address with no code cannot serve anyone, so a write naming it is refused
  ///         and the setup and waiting attempt already stored under it stay as they were. The setup is
  ///         planted through the harness, since no write could have named this action.
  ///         `_actionSeed` builds a fresh address with no code.
  function test_WhenTheActionHasNoCode(uint256 _actionSeed) external {
    address _codeless = _addressFrom('action', _actionSeed);
    _manager.harnessWriteSetup(
      _account,
      _codeless,
      IPolicyManager.Setup({
        commitment: keccak256('a setup planted under a codeless action'),
        nonce: 4,
        attemptCounter: 1,
        setupCommittedAtBlock: 7
      })
    );
    _plantWaiting(_account, _codeless, 1, false);

    _assertRefusedAsNotServing(_codeless);
  }

  /// @notice An action whose supportsAccount reverts gives no answer, and no answer is not a yes, so
  ///         the write is refused and changes nothing.
  function test_WhenTheActionsSupportsAccountReverts() external {
    _prepareWaiting();
    PolicyManagerMockAction(_action).setAnswer(PolicyManagerMockAction.Answer.Reverts);

    _assertRefusedAsNotServing(_action);
  }

  /// @notice An action that answers false does not serve the account, so the write is refused and
  ///         changes nothing.
  function test_WhenTheActionAnswersFalse() external {
    _prepareWaiting();
    PolicyManagerMockAction(_action).setAnswer(PolicyManagerMockAction.Answer.AnswersFalse);

    _assertRefusedAsNotServing(_action);
  }

  /// @notice An action that returns no bytes at all, as an account fallback that accepts any call
  ///         does, has not answered true, so the write is refused and changes nothing.
  function test_WhenTheActionReturnsNoData() external {
    _prepareWaiting();
    PolicyManagerMockAction(_action).setRawAnswer('');

    _assertRefusedAsNotServing(_action);
  }

  /// @notice An answer shorter than one word is not the word true, even when its last byte is 1, so
  ///         the write is refused and changes nothing. `_lengthSeed` picks a length of 1 to 31 bytes,
  ///         all zero but the last, which is 1.
  function test_WhenTheActionReturnsLessThanOneWord(uint256 _lengthSeed) external {
    _prepareWaiting();
    bytes memory _short = new bytes(bound(_lengthSeed, 1, 31));
    _short[_short.length - 1] = 0x01;
    PolicyManagerMockAction(_action).setRawAnswer(_short);

    _assertRefusedAsNotServing(_action);
  }

  /// @notice An answer longer than one word is refused even when its first word is true, since only
  ///         exactly one word equal to true counts as a yes. `_extraSeed` picks 1 to 64 zero bytes
  ///         appended after the word true.
  function test_WhenTheActionReturnsMoreThanOneWord(uint256 _extraSeed) external {
    _prepareWaiting();
    PolicyManagerMockAction(_action).setRawAnswer(bytes.concat(abi.encode(true), new bytes(bound(_extraSeed, 1, 64))));

    _assertRefusedAsNotServing(_action);
  }

  /// @notice One word that is neither false nor true is not a yes, so the write is refused and
  ///         changes nothing. Only the word 1 serves. `_word` is any word from 2 upward.
  function test_WhenTheActionReturnsAWordOtherThanOne(uint256 _word) external {
    _prepareWaiting();
    PolicyManagerMockAction(_action).setRawAnswer(abi.encode(bound(_word, 2, type(uint256).max)));

    _assertRefusedAsNotServing(_action);
  }

  /// @notice Two words whose first is the word true are still not exactly one word, so the write is
  ///         refused and changes nothing. A probe that read only the first word would wrongly take this
  ///         answer as a yes.
  function test_WhenTheActionReturnsTwoWordsWhoseFirstIsOne() external {
    _prepareWaiting();
    PolicyManagerMockAction(_action).setRawAnswer(abi.encode(uint256(1), uint256(0)));

    _assertRefusedAsNotServing(_action);
  }

  /// @notice One word whose only nonzero byte is 0x01 anywhere but the last byte is not the word
  ///         true, so the write is refused and changes nothing. The test tries each of the 31 wrong
  ///         positions, the first and the sixteenth among them.
  function test_WhenTheActionReturnsOneWordWithItsOnlySetByteOtherThanTheLast() external {
    _prepareWaiting();
    for (uint256 _position; _position < 31; ++_position) {
      bytes memory _word = new bytes(32);
      _word[_position] = 0x01;
      PolicyManagerMockAction(_action).setRawAnswer(_word);

      _assertRefusedAsNotServing(_action);
    }
  }

  /// @notice The word 0x101 has a low byte of 1 but is not the word 1, so the write is refused and
  ///         changes nothing. A probe that kept only the low byte of the answer would wrongly take it as
  ///         a yes.
  function test_WhenTheActionReturnsAWordWhoseLowByteIsOneButIsNotOne() external {
    _prepareWaiting();
    PolicyManagerMockAction(_action).setRawAnswer(abi.encode(uint256(0x101)));

    _assertRefusedAsNotServing(_action);
  }

  /// @notice The question is a static call, so an action that tries to write its own storage while
  ///         answering fails the call instead of answering true, the write is refused and the
  ///         action's storage stays as it was.
  function test_WhenTheActionWritesStateWhileAnswering() external {
    _prepareWaiting();
    PolicyManagerMockAction(_action).setAnswer(PolicyManagerMockAction.Answer.WritesState);

    _assertRefusedAsNotServing(_action);
    assertEq(PolicyManagerMockAction(_action).writes(), 0, 'the action wrote nothing');
  }

  /// @notice A stored nonce at the largest uint64 has no next value, so a write reverts with the
  ///         arithmetic overflow panic rather than wrap to zero and reopen every old nonce, and the
  ///         waiting attempt it would have cancelled stays waiting. No real sequence of writes gets
  ///         there, so the harness writes the setup directly. `_nonce` is any nonce the write names.
  function test_WhenTheStoredNonceIsTheLargestUint64(uint64 _nonce) external {
    _manager.harnessWriteSetup(
      _account,
      _action,
      IPolicyManager.Setup({
        commitment: keccak256('a setup at the last nonce'),
        nonce: type(uint64).max,
        attemptCounter: 0,
        setupCommittedAtBlock: 7
      })
    );
    _plantWaiting(_account, _action, 1, false);
    IPolicyManager.ActionState memory _before = _state(_account, _action);

    vm.expectRevert(stdError.arithmeticError);
    vm.prank(_account);
    _manager.commitSetup(_action, keccak256('any commitment'), _nonce, '', '');

    assertEq(abi.encode(_state(_account, _action)), abi.encode(_before), 'a refused write changes nothing');
  }

  /// @notice A write in the last block whose number fits the uint48 setupCommittedAtBlock lands and
  ///         stores that block exactly, so the checked cast refuses only a value past the width.
  function test_WhenTheBlockNumberIsTheLargestUint48() external {
    vm.roll(type(uint48).max);
    bytes32 _commitment = _commitmentFor(_account, _action, 1);

    vm.prank(_account);
    _manager.commitSetup(_action, _commitment, 1, '', '');

    IPolicyManager.ActionState memory _actionState = _state(_account, _action);
    // it should store the commitment under nonce one
    assertEq(_actionState.setupCommitment, _commitment, 'commitment');
    assertEq(_actionState.setupNonce, 1, 'nonce');
    // it should store the largest uint48 as setupCommittedAtBlock
    assertEq(_actionState.setupCommittedAtBlock, type(uint48).max, 'setupCommittedAtBlock');
  }

  /// @notice A write in a block whose number no longer fits the uint48 setupCommittedAtBlock reverts
  ///         rather than wrapping, because a truncated block would point a client rebuilding the setup
  ///         at the wrong block. The setup and the waiting attempt it would have cancelled stay as they
  ///         were. `_offsetSeed` picks a block from 2^48 upward.
  function test_WhenTheBlockNumberIsPastTheWidthOfTheBlockField(uint256 _offsetSeed) external {
    _commit(_account, _action);
    _plantWaiting(_account, _action, 1, false);
    IPolicyManager.ActionState memory _before = _state(_account, _action);
    uint256 _blockNumber = bound(_offsetSeed, uint256(type(uint48).max) + 1, type(uint256).max);
    vm.roll(_blockNumber);

    // it should revert with SafeCastOverflowedUintDowncast carrying the width and the block number
    vm.expectRevert(abi.encodeWithSelector(SafeCast.SafeCastOverflowedUintDowncast.selector, uint8(48), _blockNumber));
    vm.prank(_account);
    _manager.commitSetup(_action, keccak256('a write past the width'), _before.setupNonce + 1, '', '');

    // it should change nothing
    assertEq(abi.encode(_state(_account, _action)), abi.encode(_before), 'a refused write changes nothing');
  }

  /// @notice A write while a recovery attempt waits cancels that attempt first, with its own event
  ///         and a zero canceller, so no attempt outlives the setup it was judged under. It reaches no
  ///         method and no pause read, so a stopped or broken method cannot block the holder's write:
  ///         the one call it makes asks the action whether it serves the account.
  ///         `_attemptId` and `_ignoresPause` vary the planted attempt, `_blockStep` moves the chain.
  function test_WhenAnAttemptIsWaiting(uint64 _attemptId, bool _ignoresPause, uint32 _blockStep) external {
    _commit(_account, _action);
    IPolicyManager.ActionState memory _before = _state(_account, _action);
    IPolicyManager.Attempt memory _planted = _plantWaiting(_account, _action, _attemptId, _ignoresPause);
    vm.roll(block.number + bound(_blockStep, 1, type(uint32).max));
    bytes32 _commitment = _commitmentFor(_account, _action, 2);

    vm.recordLogs();
    vm.startStateDiffRecording();
    vm.prank(_account);
    _manager.commitSetup(_action, _commitment, 2, 'public', 'private');
    Vm.AccountAccess[] memory _accesses = vm.stopAndReturnStateDiff();
    Vm.Log[] memory _logs = vm.getRecordedLogs();

    IPolicyManager.ActionState memory _actionState = _state(_account, _action);
    // it should set the attempt to Cancelled and keep the rest of its record
    _assertRecordKept(_actionState.attempt, _planted, IPolicyManager.AttemptState.Cancelled);
    // it should emit AttemptCancelled with a zero canceller before SetupCommitted
    assertEq(_logs.length, 2, 'the cancel event and the write event, nothing else');
    _assertCancelledLog(_logs[0], _account, _action, _attemptId, address(0), _before.setupNonce);
    _assertCommittedLog(_logs[1], _account, _action, 2, _commitment, 'public', 'private');
    // it should leave the attempt counter where it was
    assertEq(_actionState.nextAttemptId, _before.nextAttemptId, 'attempt counter');
    assertEq(_actionState.setupNonce, _before.setupNonce + 1, 'nonce moves by exactly one');
    assertEq(_actionState.setupCommitment, _commitment, 'commitment');
    assertEq(_actionState.setupCommittedAtBlock, block.number, 'setupCommittedAtBlock');
    // it should reach no method and no pause read, only the action's own supportsAccount
    _assertReachedOnlyTheServingProbe(_accesses, _account, _action);
  }

  /// @notice A write after the attempt already ended emits only its own event and leaves the ended
  ///         record as it was. `_consumed` picks a consumed or a cancelled record.
  function test_WhenTheLastAttemptIsNoLongerWaiting(bool _consumed, uint64 _attemptId) external {
    (uint64 _nonce,) = _commit(_account, _action);
    IPolicyManager.Attempt memory _planted = _attempt(
      _attemptId,
      _nonce,
      _consumed ? IPolicyManager.AttemptState.Consumed : IPolicyManager.AttemptState.Cancelled,
      false,
      _methods()
    );
    _plant(_account, _action, _planted);
    bytes32 _commitment = _commitmentFor(_account, _action, 2);

    vm.recordLogs();
    vm.prank(_account);
    _manager.commitSetup(_action, _commitment, 2, '', '');
    Vm.Log[] memory _logs = vm.getRecordedLogs();

    assertEq(_logs.length, 1, 'no cancel event without a waiting attempt');
    _assertCommittedLog(_logs[0], _account, _action, 2, _commitment, '', '');
    assertEq(abi.encode(_state(_account, _action).attempt), abi.encode(_planted), 'record untouched');
  }

  /// @notice A write for one action leaves an attempt waiting under another action untouched, since
  ///         each action has its own setup and its own attempt.
  function test_WhenAnAttemptWaitsUnderAnotherAction() external {
    _commit(_account, _action);
    _commit(_account, _otherAction);
    IPolicyManager.Attempt memory _other = _plantWaiting(_account, _otherAction, 7, false);
    IPolicyManager.ActionState memory _otherBefore = _state(_account, _otherAction);

    vm.recordLogs();
    _commit(_account, _action);
    Vm.Log[] memory _logs = vm.getRecordedLogs();

    assertEq(_logs.length, 1, 'no cancel event for another action');
    assertEq(
      uint8(_state(_account, _otherAction).attempt.state), uint8(IPolicyManager.AttemptState.Waiting), 'still waiting'
    );
    assertEq(abi.encode(_state(_account, _otherAction).attempt), abi.encode(_other), 'record untouched');
    assertEq(abi.encode(_state(_account, _otherAction)), abi.encode(_otherBefore), 'other setup untouched');
  }

  /// @notice No argument names an account, so another address can only write its own entry. Its
  ///         replay of the account's next write is refused, and the account's setup and waiting
  ///         attempt stay as they were. `_callerSeed` builds that other address.
  function test_WhenAnAddressOtherThanTheAccountCalls(uint256 _callerSeed) external {
    address _caller = _addressFrom('caller', _callerSeed);
    _commit(_account, _action);
    _plantWaiting(_account, _action, 1, false);
    IPolicyManager.ActionState memory _accountBefore = _state(_account, _action);

    // Replaying the account's next write from another address names no account: it is refused
    // against the caller's own nonce.
    bytes32 _accountsNext = _commitmentFor(_account, _action, 2);
    vm.expectRevert(_wrongNonce(uint64(2), uint64(1)));
    vm.prank(_caller);
    _manager.commitSetup(_action, _accountsNext, 2, '', '');

    // A valid write from the caller lands in the caller's own entry.
    bytes32 _own = _commitmentFor(_caller, _action, 1);
    vm.recordLogs();
    vm.prank(_caller);
    _manager.commitSetup(_action, _own, 1, '', '');
    Vm.Log[] memory _logs = vm.getRecordedLogs();

    // it should write only that address's own setup
    assertEq(_state(_caller, _action).setupCommitment, _own, 'caller commitment');
    assertEq(_state(_caller, _action).setupNonce, 1, 'caller nonce');
    assertEq(_logs.length, 1, 'one event');
    _assertCommittedLog(_logs[0], _caller, _action, 1, _own, '', '');
    // it should leave the account's setup and waiting attempt untouched
    assertEq(abi.encode(_state(_account, _action)), abi.encode(_accountBefore), 'account untouched');
  }

  /*///////////////////////////////////////////////////////////////
                              HELPERS
  ///////////////////////////////////////////////////////////////*/

  /// @notice The revert data of PolicyManager_WrongSetupNonce(_supplied, _expected).
  function _wrongNonce(uint64 _supplied, uint64 _expected) private pure returns (bytes memory _revertData) {
    _revertData = abi.encodeWithSelector(IPolicyManager.PolicyManager_WrongSetupNonce.selector, _supplied, _expected);
  }

  /// @notice The revert data of PolicyManager_InvalidCommitment(_commitment).
  function _invalidCommitment(bytes32 _commitment) private pure returns (bytes memory _revertData) {
    _revertData = abi.encodeWithSelector(IPolicyManager.PolicyManager_InvalidCommitment.selector, _commitment);
  }

  /// @notice Calls commitSetup with `_commitment` and `_nonce`, both wrong, and asserts it reverts
  ///         with either PolicyManager_WrongSetupNonce(_nonce, _expected) or
  ///         PolicyManager_InvalidCommitment(_commitment).
  function _expectEitherRefusal(bytes32 _commitment, uint64 _nonce, uint64 _expected) private {
    vm.prank(_account);
    (bool _success, bytes memory _revertData) =
      address(_manager).call(abi.encodeCall(IPolicyManager.commitSetup, (_action, _commitment, _nonce, '', '')));
    assertFalse(_success, 'the write is refused');
    assertTrue(
      keccak256(_revertData) == keccak256(_wrongNonce(_nonce, _expected))
        || keccak256(_revertData) == keccak256(_invalidCommitment(_commitment)),
      'refused with one of the two errors'
    );
  }

  /// @notice Commits a setup for `_action` and plants a waiting attempt under it, so a refused write
  ///         has a setup and an attempt it must leave alone.
  function _prepareWaiting() private {
    _commit(_account, _action);
    _plantWaiting(_account, _action, 1, false);
  }

  /// @notice Sends the account's next valid write for `_refusedAction`, a block later, and asserts it
  ///         reverts as PolicyManager_ActionDoesNotServeAccount(account, action), emits nothing, and
  ///         leaves the commitment, the nonce, setupCommittedAtBlock and the waiting attempt as they
  ///         were.
  function _assertRefusedAsNotServing(address _refusedAction) private {
    IPolicyManager.ActionState memory _before = _state(_account, _refusedAction);
    uint64 _next = _before.setupNonce + 1;
    vm.roll(block.number + 1);

    vm.recordLogs();
    vm.expectRevert(
      abi.encodeWithSelector(IPolicyManager.PolicyManager_ActionDoesNotServeAccount.selector, _account, _refusedAction)
    );
    vm.prank(_account);
    _manager.commitSetup(_refusedAction, _commitmentFor(_account, _refusedAction, _next), _next, 'public', 'private');

    assertEq(vm.getRecordedLogs().length, 0, 'a refused write emits nothing');
    assertEq(abi.encode(_state(_account, _refusedAction)), abi.encode(_before), 'a refused write changes nothing');
    assertEq(
      uint8(_state(_account, _refusedAction).attempt.state),
      uint8(IPolicyManager.AttemptState.Waiting),
      'the attempt still waits'
    );
  }

  /// @notice Asserts that the only contract other than itself the manager reached was `_probed`, by
  ///         a static call carrying exactly supportsAccount(_caller), and that it reached it once.
  function _assertReachedOnlyTheServingProbe(Vm.AccountAccess[] memory _accesses, address _caller, address _probed)
    private
    view
  {
    bytes memory _probe = abi.encodeCall(IPolicyAction.supportsAccount, (_caller));
    uint256 _probes;
    for (uint256 _i; _i < _accesses.length; ++_i) {
      Vm.AccountAccess memory _access = _accesses[_i];
      if (_access.accessor != address(_manager)) continue;
      if (_access.kind == VmSafe.AccountAccessKind.Resume) continue;
      if (_access.account == address(_manager)) continue;
      assertEq(_access.account, _probed, 'the manager reached a contract other than the action');
      assertEq(uint8(_access.kind), uint8(VmSafe.AccountAccessKind.StaticCall), 'the question is a static call');
      assertEq(_access.data, _probe, 'the question names the caller');
      ++_probes;
    }
    assertEq(_probes, 1, 'the action is asked once');
  }

  /// @notice Expects commitSetup with `_nonce` to revert as PolicyManager_WrongSetupNonce(_nonce, _expected).
  function _expectWrongNonce(uint64 _nonce, uint64 _expected) private {
    bytes32 _commitment = _commitmentFor(_account, _action, _nonce);
    vm.expectRevert(_wrongNonce(_nonce, _expected));
    vm.prank(_account);
    _manager.commitSetup(_action, _commitment, _nonce, '', '');
  }
}
