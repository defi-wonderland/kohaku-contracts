// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {SetupBody} from 'libraries/SetupBody.sol';
import {IPolicyManager} from 'interfaces/IPolicyManager.sol';
import {IRecoveryAction} from 'interfaces/IRecoveryAction.sol';
import {AmbireRecoveryAction} from 'contracts/actions/ambire/AmbireRecoveryAction.sol';
import {IAmbireAccount} from 'contracts/actions/ambire/IAmbireAccount.sol';
import {IAmbireRecoveryAction} from 'contracts/actions/ambire/IAmbireRecoveryAction.sol';
import {PolicyManager} from 'contracts/manager/PolicyManager.sol';
import {ActionBatch} from 'test/utils/ActionBatch.sol';
import {IntegrationDemoKitTestBase} from 'test/utils/IntegrationDemoKitTestBase.sol';

/// @notice A holder who still has their key moves recovery to a new manager and a new action in one batch. A holder can
///         also run two actions on one account. Each action has its own setup and attempt. Each approval counts for one
///         manager and one action only.
contract MigrateTheKitTest is IntegrationDemoKitTestBase {
  /// @notice The account's call to itself that writes `_value` under `_forAction`'s kit slot.
  function _slotCall(address _forAction, bytes32 _value)
    internal
    view
    returns (IAmbireRecoveryAction.Transaction memory _call)
  {
    _call = IAmbireRecoveryAction.Transaction({
      to: _account,
      value: 0,
      data: abi.encodeCall(IAmbireAccount.setAddrPrivilege, (ActionBatch.kitSlot(_forAction), _value))
    });
  }

  /// @notice The holder moves to a new manager and action in one batch while an attempt waits under the old ones. The
  ///         move cancels that attempt. The new manager refuses the old approvals. New approvals then recover the
  ///         account through the new manager and action.
  function test_WhenTheHolderMigratesInOneBatch() external {
    // it should end everything on the old pair and recover on the new one
    PolicyManager _newManager = new PolicyManager();
    AmbireRecoveryAction _newAction = new AmbireRecoveryAction(IPolicyManager(address(_newManager)), _implementation);
    _authorizeAndCommit();
    IPolicyManager.AttemptRequest memory _old = _open(_openingSet());
    IPolicyManager.Attempt memory _oldAttempt = _state().attempt;

    bytes32 _newCommitment = keccak256(abi.encode(_account, address(_newAction), uint64(1), _body()));
    vm.expectEmit(true, true, true, true, address(_manager));
    emit IPolicyManager.AttemptCancelled(_account, address(_action), 1, address(0), address(0), 1, new uint256[](0));
    vm.expectEmit(true, true, true, true, address(_manager));
    emit IPolicyManager.SetupCleared(_account, address(_action), 2);
    vm.expectEmit(true, true, true, true, address(_newManager));
    emit IPolicyManager.SetupCommitted(
      _account, address(_newAction), 1, _newCommitment, _PUBLIC_METADATA, _PRIVATE_METADATA
    );
    _asHolder(_moveBatch(_newManager, address(_newAction), _newCommitment));

    IPolicyManager.ActionState memory _oldState = _state();
    assertEq(uint256(_oldState.attempt.state), uint256(IPolicyManager.AttemptState.Cancelled), 'the old attempt waits');
    assertEq(_oldState.setupCommitment, bytes32(0), 'the old setup survived');
    assertEq(_oldState.setupNonce, 2, 'the clear did not move the old nonce');
    assertFalse(_action.isAuthorized(_account), 'the old action still holds the account');
    assertTrue(_newAction.isAuthorized(_account), 'the new action does not hold the account');
    assertEq(_newManager.stateOf(_account, address(_newAction)).setupNonce, 1, 'the new setup is not at nonce one');
    vm.warp(_oldAttempt.consumableAfter);
    vm.expectRevert(_notConsumable(IPolicyManager.AttemptState.Cancelled, _oldAttempt));
    _executeHandover();

    // From here the base contract's functions use the new manager and action.
    _manager = _newManager;
    _action = _newAction;
    _old.action = address(_newAction);
    _old.validUntil = _window();
    vm.expectRevert(_proofRejected(_ALICE, address(_ecdsa)));
    _send(_old);

    _open(_openingSet());
    vm.warp(_state().attempt.consumableAfter);
    _executeHandover();
    assertEq(_privilege(_newKey), _KEY_VALUE, 'the new pair did not install the new key');
    assertEq(_privilege(_holderKey), bytes32(0), 'the new pair did not remove the lost key');
  }

  /// @notice Two actions on one account keep separate setups and attempts. A new setup for the first
  ///         action cancels only its attempt. The second action's attempt keeps waiting under its own
  ///         nonce.
  function test_WhenTheHolderEditsOneOfTwoActions() external {
    // it should cancel only the edited action's attempt
    AmbireRecoveryAction _second = _setUpASecondAction();
    _open(_openingSet());
    _openUnder(_second, ActionBatch.payload(makeAddr('newerKey'), _newKey));

    vm.expectEmit(true, true, true, true, address(_manager));
    emit IPolicyManager.AttemptCancelled(_account, address(_action), 1, address(0), address(0), 1, new uint256[](0));
    _commitNext(_body());

    IPolicyManager.ActionState memory _secondState = _manager.stateOf(_account, address(_second));
    assertEq(uint256(_state().attempt.state), uint256(IPolicyManager.AttemptState.Cancelled), 'the edit missed');
    assertEq(
      uint256(_secondState.attempt.state), uint256(IPolicyManager.AttemptState.Waiting), 'the edit reached the other'
    );
    assertEq(_secondState.setupNonce, 1, 'the edit moved the other action nonce');
  }

  /// @notice Two actions each have a waiting attempt. The second removes the key the first adds. If the second runs
  ///         first, it fails because that key is not on the account yet. Its attempt keeps waiting. In order, both
  ///         handovers go through.
  function test_WhenBothActionsHandOverInTurn() external {
    // it should refuse the second first and run both in order
    AmbireRecoveryAction _second = _setUpASecondAction();
    address _newerKey = makeAddr('newerKey');
    bytes memory _secondPayload = ActionBatch.payload(_newerKey, _newKey);
    _open(_openingSet());
    _openUnder(_second, _secondPayload);
    vm.warp(_manager.stateOf(_account, address(_second)).attempt.consumableAfter);

    vm.expectRevert(abi.encodeWithSelector(IRecoveryAction.RecoveryAction_NotAKey.selector, _newKey));
    vm.prank(_executor);
    _second.executeHandover(_account, _secondPayload);
    assertEq(
      uint256(_manager.stateOf(_account, address(_second)).attempt.state),
      uint256(IPolicyManager.AttemptState.Waiting),
      'the refused handover ended the second attempt'
    );

    _executeHandover();
    vm.prank(_executor);
    _second.executeHandover(_account, _secondPayload);
    assertEq(_privilege(_newerKey), _KEY_VALUE, 'the second action did not install its key');
    assertEq(_privilege(_newKey), bytes32(0), 'the second action did not remove the first key');
    assertEq(_privilege(_holderKey), bytes32(0), 'the lost key came back');
    assertTrue(_action.isAuthorized(_account) && _second.isAuthorized(_account), 'a kit slot was lost');
  }

  /// @notice Alice alone cannot open the default action's rule, which needs two wallet guardians and a second factor.
  ///         Her one signature does open the second action's one-guardian rule. After the wait, that handover installs
  ///         the new key and removes the holder's key. So the weakest rule on an account decides who can recover it.
  function test_WhenTheSecondActionHasAWeakerRule() external {
    // it should let the weaker rule hand the account over
    AmbireRecoveryAction _second = _setUpASecondActionWith(_aliceAlone());
    uint256[] memory _alice = new uint256[](1);
    _alice[0] = _ALICE;
    IPolicyManager.AttemptRequest memory _strictReq = _request(_alice, 1, 1, _window());
    vm.expectRevert(abi.encodeWithSelector(IPolicyManager.PolicyManager_RuleUnsatisfied.selector, 0));
    _send(_strictReq);

    AmbireRecoveryAction _default = _action;
    _action = _second;
    _send(_requestOver(_aliceAlone(), _alice, 1, 1, _window()));
    _action = _default;
    vm.warp(_manager.stateOf(_account, address(_second)).attempt.consumableAfter);
    vm.prank(_executor);
    _second.executeHandover(_account, _payload());

    assertEq(_privilege(_newKey), _KEY_VALUE, 'the weaker rule did not install the new key');
    assertEq(_privilege(_holderKey), bytes32(0), 'the weaker rule did not remove the holder key');
    IPolicyManager.ActionState memory _strict = _state();
    assertEq(uint256(_strict.attempt.state), uint256(IPolicyManager.AttemptState.None), 'the strict rule opened');
    assertEq(_strict.nextAttemptId, 1, 'the strict rule allocated an attempt');
  }

  /// @notice A rule of one clause that Alice alone satisfies, under her committed credential.
  function _aliceAlone() internal view returns (bytes memory _setupBody) {
    IPolicyManager.Clause[] memory _clauses = new IPolicyManager.Clause[](1);
    _clauses[0].threshold = 1;
    _clauses[0].credentials = new bytes32[](1);
    _clauses[0].credentials[0] = _credentialHash(_ALICE);
    _setupBody = SetupBody.encode(_WAIT, false, _clauses);
  }

  /// @notice The holder's batch that moves to a new manager and action. It clears the old kit slot,
  ///         clears the old setup, writes the new kit slot and commits the new setup.
  function _moveBatch(PolicyManager _newManager, address _newAction, bytes32 _newCommitment)
    internal
    view
    returns (IAmbireRecoveryAction.Transaction[] memory _move)
  {
    _move = new IAmbireRecoveryAction.Transaction[](4);
    _move[0] = _slotCall(address(_action), bytes32(0));
    _move[1] = _managerCall(abi.encodeCall(IPolicyManager.clearSetup, (address(_action))));
    _move[2] = _slotCall(_newAction, ActionBatch.binding(_newAction));
    _move[3] = IAmbireRecoveryAction.Transaction({
      to: address(_newManager),
      value: 0,
      data: abi.encodeCall(
        IPolicyManager.commitSetup, (_newAction, _newCommitment, 1, _PUBLIC_METADATA, _PRIVATE_METADATA)
      )
    });
  }

  /// @notice Sets up the default action and a second action on the same manager. Each has its own kit
  ///         slot and the same rule committed under its own address.
  function _setUpASecondAction() internal returns (AmbireRecoveryAction _second) {
    _second = _setUpASecondActionWith(_body());
  }

  /// @notice Sets up the default action under the default rule and a second action on the same manager
  ///         under `_secondBody`, each with its own kit slot.
  function _setUpASecondActionWith(bytes memory _secondBody) internal returns (AmbireRecoveryAction _second) {
    _second = new AmbireRecoveryAction(IPolicyManager(address(_manager)), _implementation);
    _authorizeAndCommit();
    bytes32 _commitment = keccak256(abi.encode(_account, address(_second), uint64(1), _secondBody));
    _asHolder(
      _two(
        _slotCall(address(_second), ActionBatch.binding(address(_second))),
        _managerCall(
          abi.encodeCall(
            IPolicyManager.commitSetup, (address(_second), _commitment, 1, _PUBLIC_METADATA, _PRIVATE_METADATA)
          )
        )
      )
    );
  }

  /// @notice Opens the next attempt under `_other` with the default guardians. The attempt commits to the handover
  ///         `_committed`.
  function _openUnder(AmbireRecoveryAction _other, bytes memory _committed) internal {
    AmbireRecoveryAction _default = _action;
    _action = _other;
    _openWith(_openingSet(), _committed, _order());
    _action = _default;
  }
}
