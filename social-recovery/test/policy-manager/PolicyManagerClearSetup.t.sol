// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {stdError} from 'forge-std/StdError.sol';
import {Vm} from 'forge-std/Vm.sol';
import {SafeCast} from '@openzeppelin/contracts/utils/math/SafeCast.sol';
import {IPolicyManager} from 'interfaces/IPolicyManager.sol';
import {PolicyManagerTestBase} from 'test/utils/PolicyManagerTestBase.sol';

/// @notice clearSetup, the call through which an account removes its own setup for one action. A
///         clear is how a holder leaves the kit, so it must end any waiting recovery attempt and must
///         not depend on any method answering.
contract PolicyManagerClearSetupTest is PolicyManagerTestBase {
  /*///////////////////////////////////////////////////////////////
                             TREE TESTS
  ///////////////////////////////////////////////////////////////*/

  /// @notice Clearing an action that never had a setup reverts, since it would record a removal that
  ///         did not happen. `_anyAction` is any action address.
  function test_WhenNoSetupWasEverCommitted(address _anyAction) external {
    vm.expectRevert(abi.encodeWithSelector(IPolicyManager.PolicyManager_NoSetup.selector, _account, _anyAction));
    vm.prank(_account);
    _manager.clearSetup(_anyAction);

    assertEq(_state(_account, _anyAction).setupNonce, 0, 'nonce untouched');
  }

  /// @notice Clearing twice reverts on the second call and leaves the state of the first clear.
  function test_WhenTheSetupWasAlreadyCleared() external {
    _commit(_account, _action);
    _clear(_account, _action);
    IPolicyManager.ActionState memory _before = _state(_account, _action);

    vm.expectRevert(abi.encodeWithSelector(IPolicyManager.PolicyManager_NoSetup.selector, _account, _action));
    vm.prank(_account);
    _manager.clearSetup(_action);

    assertEq(abi.encode(_state(_account, _action)), abi.encode(_before), 'a refused clear changes nothing');
  }

  /// @notice A clear zeroes the commitment, moves the nonce by exactly one, records its block, emits
  ///         one event and calls no other contract. `_priorWrites` makes 1 to 4 writes first.
  function test_WhenASetupExists(uint8 _priorWrites, uint32 _blockStep) external {
    for (uint256 _i; _i < bound(_priorWrites, 1, 4); ++_i) {
      _commit(_account, _action);
    }
    IPolicyManager.ActionState memory _before = _state(_account, _action);
    vm.roll(block.number + bound(_blockStep, 1, type(uint32).max));

    vm.recordLogs();
    vm.startStateDiffRecording();
    vm.prank(_account);
    _manager.clearSetup(_action);
    Vm.AccountAccess[] memory _accesses = vm.stopAndReturnStateDiff();
    Vm.Log[] memory _logs = vm.getRecordedLogs();

    IPolicyManager.ActionState memory _actionState = _state(_account, _action);
    // it should zero the commitment and move the nonce by exactly one
    assertEq(_actionState.setupCommitment, bytes32(0), 'commitment zeroed');
    assertEq(_actionState.setupNonce, _before.setupNonce + 1, 'nonce moves by exactly one');
    // it should write the current block as setupCommittedAtBlock
    assertEq(_actionState.setupCommittedAtBlock, block.number, 'setupCommittedAtBlock');
    // it should leave the next attempt id where it was
    assertEq(_actionState.nextAttemptId, _before.nextAttemptId, 'attempt counter');
    // it should emit SetupCleared alone with the new nonce
    assertEq(_logs.length, 1, 'one event per write');
    _assertClearedLog(_logs[0], _account, _action, _before.setupNonce + 1);
    // it should reach no other contract
    _assertReachedNoOtherContract(_accesses);
  }

  /// @notice A clear while an attempt waits cancels it first with a zero canceller, and reaches no
  ///         method or pause read, so a stopped or broken method cannot keep the holder from leaving.
  function test_WhenAnAttemptIsWaiting(uint64 _attemptId, bool _ignoresPause, uint32 _blockStep) external {
    _commit(_account, _action);
    IPolicyManager.ActionState memory _before = _state(_account, _action);
    IPolicyManager.Attempt memory _planted = _plantWaiting(_account, _action, _attemptId, _ignoresPause);
    vm.roll(block.number + bound(_blockStep, 1, type(uint32).max));

    vm.recordLogs();
    vm.startStateDiffRecording();
    vm.prank(_account);
    _manager.clearSetup(_action);
    Vm.AccountAccess[] memory _accesses = vm.stopAndReturnStateDiff();
    Vm.Log[] memory _logs = vm.getRecordedLogs();

    IPolicyManager.ActionState memory _actionState = _state(_account, _action);
    // it should set the attempt to Cancelled and keep the rest of its record
    _assertRecordKept(_actionState.attempt, _planted, IPolicyManager.AttemptState.Cancelled);
    // it should emit AttemptCancelled with a zero canceller before SetupCleared
    assertEq(_logs.length, 2, 'the cancel event and the clear event, nothing else');
    _assertCancelledLog(_logs[0], _account, _action, _attemptId, address(0), _before.setupNonce);
    _assertClearedLog(_logs[1], _account, _action, _before.setupNonce + 1);
    // it should leave the attempt counter where it was
    assertEq(_actionState.nextAttemptId, _before.nextAttemptId, 'attempt counter');
    assertEq(_actionState.setupNonce, _before.setupNonce + 1, 'nonce moves by exactly one');
    assertEq(_actionState.setupCommitment, bytes32(0), 'commitment zeroed');
    assertEq(_actionState.setupCommittedAtBlock, block.number, 'setupCommittedAtBlock');
    // it should reach no method and no pause read
    _assertReachedNoOtherContract(_accesses);
  }

  /// @notice An action that stopped serving the account after the commit, as an upgraded account
  ///         sees it, cannot keep a setup in place: the clear asks the action nothing, so it still
  ///         zeroes the commitment, cancels the waiting attempt and reaches no other contract.
  ///         `_answerSeed` picks how the action stopped serving: it answers false, it reverts, or its
  ///         code is gone.
  function test_WhenTheActionStoppedServingTheAccount(uint256 _answerSeed) external {
    _commit(_account, _action);
    IPolicyManager.Attempt memory _planted = _plantWaiting(_account, _action, 1, false);
    IPolicyManager.ActionState memory _before = _state(_account, _action);
    _stopServing(_action, _answerSeed);

    vm.startStateDiffRecording();
    vm.prank(_account);
    _manager.clearSetup(_action);
    Vm.AccountAccess[] memory _accesses = vm.stopAndReturnStateDiff();

    IPolicyManager.ActionState memory _actionState = _state(_account, _action);
    // it should zero the commitment and move the nonce by exactly one
    assertEq(_actionState.setupCommitment, bytes32(0), 'commitment');
    assertEq(_actionState.setupNonce, _before.setupNonce + 1, 'nonce');
    // it should cancel the waiting attempt
    _assertRecordKept(_actionState.attempt, _planted, IPolicyManager.AttemptState.Cancelled);
    // it should not ask the action
    _assertReachedNoOtherContract(_accesses);
  }

  /// @notice A stored nonce at the largest uint64 has no next value, so a clear reverts with the
  ///         arithmetic overflow panic rather than wrap to zero and reopen every old nonce, and the
  ///         setup and the waiting attempt stay as they were. No real sequence of writes gets there,
  ///         so the harness writes the setup directly.
  function test_WhenTheStoredNonceIsTheLargestUint64() external {
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
    _manager.clearSetup(_action);

    assertEq(abi.encode(_state(_account, _action)), abi.encode(_before), 'a refused clear changes nothing');
  }

  /// @notice A clear in the last block whose number fits the uint48 setupCommittedAtBlock lands and
  ///         stores that block exactly, so the checked cast refuses only a value past the width.
  function test_WhenTheBlockNumberIsTheLargestUint48() external {
    (uint64 _nonce,) = _commit(_account, _action);
    vm.roll(type(uint48).max);

    _clear(_account, _action);

    IPolicyManager.ActionState memory _actionState = _state(_account, _action);
    // it should zero the commitment and move the nonce by exactly one
    assertEq(_actionState.setupCommitment, bytes32(0), 'commitment zeroed');
    assertEq(_actionState.setupNonce, _nonce + 1, 'nonce');
    // it should store the largest uint48 as setupCommittedAtBlock
    assertEq(_actionState.setupCommittedAtBlock, type(uint48).max, 'setupCommittedAtBlock');
  }

  /// @notice A clear in a block whose number no longer fits the uint48 setupCommittedAtBlock reverts
  ///         rather than wrapping, because a truncated block would point a client rebuilding the setup
  ///         at the wrong block. The setup and the waiting attempt stay as they were. `_offsetSeed`
  ///         picks a block from 2^48 upward.
  function test_WhenTheBlockNumberIsPastTheWidthOfTheBlockField(uint256 _offsetSeed) external {
    _commit(_account, _action);
    _plantWaiting(_account, _action, 1, false);
    IPolicyManager.ActionState memory _before = _state(_account, _action);
    uint256 _blockNumber = bound(_offsetSeed, uint256(type(uint48).max) + 1, type(uint256).max);
    vm.roll(_blockNumber);

    // it should revert with SafeCastOverflowedUintDowncast carrying the width and the block number
    vm.expectRevert(abi.encodeWithSelector(SafeCast.SafeCastOverflowedUintDowncast.selector, uint8(48), _blockNumber));
    vm.prank(_account);
    _manager.clearSetup(_action);

    // it should change nothing
    assertEq(abi.encode(_state(_account, _action)), abi.encode(_before), 'a refused clear changes nothing');
  }

  /// @notice A clear after the attempt already ended emits only its own event and leaves the ended
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

    vm.recordLogs();
    _clear(_account, _action);
    Vm.Log[] memory _logs = vm.getRecordedLogs();

    assertEq(_logs.length, 1, 'no cancel event without a waiting attempt');
    _assertClearedLog(_logs[0], _account, _action, _nonce + 1);
    assertEq(abi.encode(_state(_account, _action).attempt), abi.encode(_planted), 'record untouched');
  }

  /// @notice Another address clearing the same action only reaches its own empty entry and reverts,
  ///         so nobody but the account can remove the account's setup. `_callerSeed` builds it.
  function test_WhenAnAddressOtherThanTheAccountCalls(uint256 _callerSeed) external {
    address _caller = _addressFrom('caller', _callerSeed);
    _commit(_account, _action);
    _plantWaiting(_account, _action, 1, false);
    IPolicyManager.ActionState memory _before = _state(_account, _action);

    // it should revert with PolicyManager_NoSetup carrying that address and the action
    vm.expectRevert(abi.encodeWithSelector(IPolicyManager.PolicyManager_NoSetup.selector, _caller, _action));
    vm.prank(_caller);
    _manager.clearSetup(_action);

    // it should leave the account's setup and waiting attempt untouched
    assertEq(abi.encode(_state(_account, _action)), abi.encode(_before), 'account untouched');
  }
}
