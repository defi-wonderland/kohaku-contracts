// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {Vm} from 'forge-std/Vm.sol';
import {IPolicyManager} from 'interfaces/IPolicyManager.sol';
import {IRecoveryAction} from 'interfaces/IRecoveryAction.sol';
import {IAmbireAccount} from 'contracts/actions/ambire/IAmbireAccount.sol';
import {IAmbireRecoveryAction} from 'contracts/actions/ambire/IAmbireRecoveryAction.sol';
import {ActionBatch} from 'test/utils/ActionBatch.sol';
import {IntegrationDemoKitTestBase} from 'test/utils/IntegrationDemoKitTestBase.sol';

/// @notice The holder sets up recovery while they still hold their key. The wallet's setup screen
///         first checks the account and the methods. Then one batch from the account authorizes the
///         action and commits the setup at the manager.
contract SetUpRecoveryInOneBatchTest is IntegrationDemoKitTestBase {
  /// @notice A holder with one key and no setup checks the account and the methods. The manager
  ///         refuses a wrong nonce and an empty commitment. The holder then sets up in one batch, and
  ///         the account authorizes the action and holds one setup at nonce one with no attempt.
  function test_WhenTheHolderSetsUpInOneBatch() external {
    // it should hold one setup at nonce one that the account authorizes, with no attempt
    address _kitSlot = ActionBatch.kitSlot(address(_action));
    bytes32 _binding = ActionBatch.binding(address(_action));
    assertEq(_state().setupCommitment, bytes32(0), 'given: a setup exists');
    assertEq(_privilege(_kitSlot), bytes32(0), 'given: the kit slot is written');
    assertEq(_privilege(_holderKey), _SIGNER_VALUE, 'given: the holder key is not the one key');

    _assertTheScreenChecks();

    // The holder's client hashes the account, the action, the nonce of this setup and the rule.
    bytes memory _setupBody = _body();
    bytes32 _commitment = _commitmentOf(1, _setupBody);

    // The manager accepts only the current nonce plus one. The whole batch reverts.
    vm.expectRevert(_wrongNonce(2, 1));
    _asHolder(_two(_authorizeCall(), _commitCall(2, _commitmentOf(2, _setupBody))));
    // The manager refuses the commitment of zero-length bytes.
    bytes32 _emptyCommitment = _commitmentOf(1, '');
    vm.expectRevert(abi.encodeWithSelector(IPolicyManager.PolicyManager_InvalidCommitment.selector, _emptyCommitment));
    _asHolder(_two(_authorizeCall(), _commitCall(1, _emptyCommitment)));

    // The account runs one batch: it authorizes the action under the kit slot, then commits the setup.
    vm.recordLogs();
    vm.expectEmit(true, true, true, true, _account);
    emit IAmbireAccount.LogPrivilegeChanged(_kitSlot, _binding);
    vm.expectEmit(true, true, true, true, address(_manager));
    emit IPolicyManager.SetupCommitted(_account, address(_action), 1, _commitment, _PUBLIC_METADATA, _PRIVATE_METADATA);
    _authorizeAndCommit();
    Vm.Log[] memory _logs = vm.getRecordedLogs();

    // The client hashes the commitment again from its own record and reads the authorization back.
    IPolicyManager.ActionState memory _afterSetup = _state();
    assertEq(_afterSetup.setupCommitment, _commitmentOf(1, _setupBody), 'the stored commitment is not the derived one');
    assertTrue(_action.isAuthorized(_account), 'the account does not honor the action');
    assertFalse(_action.isAuthority(_account, _kitSlot), 'the kit slot reads as a key');
    assertTrue(_action.holdsAnyPrivilege(_account, _kitSlot), 'the kit slot reads as holding nothing');

    assertEq(_afterSetup.setupNonce, 1, 'the setup is not at nonce one');
    assertEq(_afterSetup.nextAttemptId, 1, 'an attempt id was allocated');
    assertEq(_afterSetup.setupCommittedAtBlock, uint48(block.number), 'the setup block is not this block');
    assertEq(uint256(_afterSetup.attempt.state), uint256(IPolicyManager.AttemptState.None), 'an attempt exists');
    assertEq(_privilege(_kitSlot), _binding, 'the kit slot does not hold the binding');
    assertEq(_privilege(_holderKey), _SIGNER_VALUE, 'the setup moved the holder key');
    assertEq(_countLogs(_logs, IPolicyManager.SetupCommitted.selector), 1, 'not exactly one commitment event');
  }

  /// @notice When the commit in the setup batch fails, the authorization reverts with it. The account
  ///         runs a batch all or nothing, so no account is left half set up.
  function test_RevertWhen_TheCommitInsideTheSetupBatchFails() external {
    // it should revert
    vm.expectRevert(_wrongNonce(2, 1));
    _asHolder(_two(_authorizeCall(), _commitCall(2, _commitmentOf(2, _body()))));

    // it should leave neither the binding nor the setup
    assertFalse(_action.isAuthorized(_account), 'the binding survived the failed batch');
    assertEq(_privilege(ActionBatch.kitSlot(address(_action))), bytes32(0), 'the kit slot was written');
    assertEq(_state().setupCommitment, bytes32(0), 'a setup was stored');
    assertEq(_state().setupNonce, 0, 'the nonce moved');
  }

  /// @notice A wallet can send the authorization and the commit as two transactions. Between them,
  ///         the account authorizes the action and the manager holds no setup.
  function test_WhenTheTwoWritesGoAsTwoTransactions() external {
    // it should reach the authorization alone between them
    _asHolder(_one(_authorizeCall()));
    assertTrue(_action.isAuthorized(_account), 'the first transaction did not authorize the action');
    assertEq(_state().setupCommitment, bytes32(0), 'a setup exists after the first transaction');

    _asHolder(_one(_commitCall(1, _commitmentOf(1, _body()))));
    assertTrue(_action.isAuthorized(_account), 'the second transaction removed the authorization');
    assertEq(_state().setupCommitment, _commitmentOf(1, _body()), 'the second transaction stored no setup');
  }

  /// @notice A setup committed without the account authorizing the action still lets an attempt
  ///         open. The attempt publishes the rule and the payload and starts the clock. The manager
  ///         never asks the account whether it authorizes the action.
  function test_WhenASetupHasNoAuthorization() external {
    // it should still open an attempt that publishes the rule and runs its clock
    _commitNext(_body());
    assertFalse(_action.isAuthorized(_account), 'given: the account honors the action');

    vm.recordLogs();
    _open(_openingSet());
    StartedLog memory _started = _startedLog(vm.getRecordedLogs());

    assertEq(uint256(_state().attempt.state), uint256(IPolicyManager.AttemptState.Waiting), 'no attempt waits');
    assertEq(_started.setupBody, _body(), 'the opening event does not publish the rule');
    assertEq(_started.payload, _payload(), 'the opening event does not publish the payload');
    assertEq(_started.consumableAfter, uint48(block.timestamp) + _WAIT, 'the clock does not run from acceptance');
    assertEq(_state().attempt.consumableAfter, uint48(block.timestamp) + _WAIT, 'the stored clock is not the wait');
  }

  /// @notice An authorization with no setup does nothing. The action has no attempt to spend, and the
  ///         account refuses any batch sent through the kit slot. A later commit completes the setup,
  ///         and a recovery then runs.
  function test_WhenAnAuthorizationHasNoSetup() external {
    // it should do nothing until a later commit completes the setup
    _asHolder(_one(_authorizeCall()));
    IPolicyManager.Attempt memory _none = _state().attempt;

    vm.expectRevert(
      abi.encodeWithSelector(
        IRecoveryAction.RecoveryAction_NotConsumable.selector,
        _account,
        IPolicyManager.AttemptState.None,
        uint48(0),
        bytes32(0)
      )
    );
    _executeHandover();

    IAmbireRecoveryAction.Transaction[] memory _calls = _approvedBatch(_none, _payee);
    vm.expectRevert(
      abi.encodeWithSelector(
        IRecoveryAction.RecoveryAction_NotConsumable.selector,
        _account,
        IPolicyManager.AttemptState.None,
        uint48(0),
        bytes32(0)
      )
    );
    vm.prank(_executor);
    IAmbireAccount(_account).execute(_calls, ActionBatch.kitSignature(address(_action)));
    assertEq(_privilege(_holderKey), _SIGNER_VALUE, 'the refused batch moved the holder key');

    _commitNext(_body());
    _open(_openingSet());
    vm.warp(_state().attempt.consumableAfter);
    _executeHandover();
    assertEq(_privilege(_newKey), _KEY_VALUE, 'the later commit did not complete the setup');
    assertEq(_privilege(_holderKey), bytes32(0), 'the later commit did not complete the setup');
  }

  /// @notice The setup screen's checks before the setup. The action serves this account and no other
  ///         address, the holder's key is a key and the new key is not, and no method in the rule is paused.
  function _assertTheScreenChecks() internal view {
    // The setup screen asks the action whether it serves this account's implementation.
    assertTrue(_action.supportsAccount(_account), 'the action does not serve the account');
    assertFalse(_action.supportsAccount(address(_manager)), 'the action serves an address that is no account');
    // It asks whether each candidate address holds a key on the account today.
    assertTrue(_action.isAuthority(_account, _holderKey), 'the holder key reads as no key');
    assertFalse(_action.isAuthority(_account, _newKey), 'the future key reads as a key');
    // It asks each method in the rule whether it is paused.
    assertFalse(_answersStopped(address(_ecdsa)), 'the wallet method reads as stopped');
    assertFalse(_answersStopped(address(_passkey)), 'the passkey method reads as stopped');
    assertFalse(_answersStopped(address(_thirdParty)), 'the third-party method reads as stopped');
  }
}
