// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {Vm} from 'forge-std/Vm.sol';
import {IPolicyManager} from 'interfaces/IPolicyManager.sol';
import {IPolicyMethodPause} from 'interfaces/IPolicyMethodPause.sol';
import {IRecoveryAction} from 'interfaces/IRecoveryAction.sol';
import {IAmbireAccount} from 'contracts/actions/ambire/IAmbireAccount.sol';
import {IAmbireRecoveryAction} from 'contracts/actions/ambire/IAmbireRecoveryAction.sol';
import {
  ActionAmbireAccountFixture,
  ActionCallbackPayee,
  ActionPaymentToken,
  ActionRefusingPayee
} from 'test/mocks/ActionAmbireAccountFixture.sol';
import {ActionBatch} from 'test/utils/ActionBatch.sol';
import {IntegrationDemoKitTestBase} from 'test/utils/IntegrationDemoKitTestBase.sol';

/// @notice The wait is over and anyone runs the handover. The action builds a batch, and the account
///         asks the action to check it before running it. The batch spends the approval, installs the
///         new key, removes the lost key and pays the payee, all or nothing.
contract HandOverTheAccountTest is IntegrationDemoKitTestBase {
  /// @notice The payload the opening event published, as a watcher read it.
  bytes internal _published;

  function setUp() public override {
    super.setUp();
    _authorizeAndCommit();
    vm.recordLogs();
    _open(_openingSet());
    _published = _startedLog(vm.getRecordedLogs()).payload;
    vm.warp(_state().attempt.consumableAfter);
  }

  /// @notice After the wait, anyone can run the recovery. The new key becomes a key of the account, the
  ///         lost key stops being one, the approval is spent once and the payee is paid.
  function test_WhenAnyoneExecutesTheHandoverAfterTheWait() external {
    // it should install the new key, remove the lost one, release the approval once and pay the order
    IPolicyManager.Attempt memory _attempt = _state().attempt;
    IAmbireRecoveryAction.Transaction[] memory _calls = _approvedBatch(_attempt, _payee);
    assertEq(_calls.length, 4, 'the order carries an amount, so the batch has four calls');
    uint256 _nonceBefore = ActionAmbireAccountFixture(payable(_account)).nonce();
    uint256 _payeeBefore = _token.balanceOf(_payee);

    // One second before the wait ends, the action refuses the attempt.
    vm.warp(_attempt.consumableAfter - 1);
    vm.expectRevert(
      abi.encodeWithSelector(
        IRecoveryAction.RecoveryAction_NotConsumable.selector,
        _account,
        IPolicyManager.AttemptState.Waiting,
        _attempt.consumableAfter,
        _attempt.payloadHash
      )
    );
    _executeHandover();
    vm.warp(_attempt.consumableAfter);

    _expectTheHandoverCalls(_attempt, _calls);
    vm.recordLogs();
    vm.prank(_executor);
    _action.executeHandover(_account, _published);
    Vm.Log[] memory _logs = vm.getRecordedLogs();

    assertEq(_privilege(_newKey), _KEY_VALUE, 'the new key holds no key value');
    assertTrue(_action.isAuthority(_account, _newKey), 'the new key reads as no key');
    assertEq(_privilege(_holderKey), bytes32(0), 'the lost key still holds a privilege');
    assertFalse(_action.isAuthority(_account, _holderKey), 'the lost key reads as a key');
    assertEq(uint256(_state().attempt.state), uint256(IPolicyManager.AttemptState.Consumed), 'nothing was spent');
    assertEq(_countLogs(_logs, IPolicyManager.AttemptConsumed.selector), 1, 'not released exactly once');
    assertEq(_token.balanceOf(_payee), _payeeBefore + _PAYMENT, 'the payee was not paid');
    assertTrue(_action.isAuthorized(_account), 'the kit slot did not survive the batch');
    assertEq(
      ActionAmbireAccountFixture(payable(_account)).nonce(), _nonceBefore + 1, 'the account did not bump its nonce'
    );
  }

  /// @notice When one call in the batch reverts, the whole batch reverts, the spend included. Here the
  ///         account lacks the tokens to pay, so the attempt keeps waiting and no key changes. The same
  ///         handover runs once the account has the tokens again.
  function test_RevertWhen_ACallInTheBatchReverts() external {
    // it should revert
    uint256 _balance = _token.balanceOf(_account);
    vm.prank(_account);
    assertTrue(_token.transfer(makeAddr('elsewhere'), _balance), 'the account could not be emptied');
    vm.expectRevert(
      abi.encodeWithSelector(ActionPaymentToken.ActionPaymentToken_Insufficient.selector, _account, 0, _PAYMENT)
    );
    _executeHandover();

    // it should leave the attempt waiting and executable once the cause is gone
    assertEq(uint256(_state().attempt.state), uint256(IPolicyManager.AttemptState.Waiting), 'the attempt ended');
    assertEq(_privilege(_holderKey), _SIGNER_VALUE, 'the failed batch moved the lost key');
    assertEq(_privilege(_newKey), bytes32(0), 'the failed batch installed the new key');
    _token.mint(_account, _PAYMENT);
    _executeHandover();
    assertEq(uint256(_state().attempt.state), uint256(IPolicyManager.AttemptState.Consumed), 'the retry spent nothing');
    assertEq(_privilege(_newKey), _KEY_VALUE, 'the retry did not install the new key');
  }

  /// @notice Sending the same batch again after the handover is refused, so nothing is spent twice. The
  ///         account's check finds the attempt already spent before the batch reaches the manager.
  function test_RevertWhen_TheSameBatchIsSentAgain() external {
    // it should revert
    IPolicyManager.Attempt memory _attempt = _state().attempt;
    IAmbireRecoveryAction.Transaction[] memory _calls = _approvedBatch(_attempt, _payee);
    _executeHandover();
    uint256 _payeeAfterFirst = _token.balanceOf(_payee);

    vm.expectRevert(
      abi.encodeWithSelector(
        IRecoveryAction.RecoveryAction_NotConsumable.selector,
        _account,
        IPolicyManager.AttemptState.Consumed,
        _attempt.consumableAfter,
        _attempt.payloadHash
      )
    );
    vm.prank(_executor);
    IAmbireAccount(_account).execute(_calls, ActionBatch.kitSignature(address(_action)));

    // it should spend nothing a second time
    assertEq(_token.balanceOf(_payee), _payeeAfterFirst, 'the payee was paid twice');
    assertEq(_privilege(_newKey), _KEY_VALUE, 'the repeat moved the new key');
  }

  /// @notice A payee that sends the same batch back to the account while being paid finds the approval
  ///         already spent, because the spend runs first. That nested run reverts, and the handover
  ///         completes once.
  function test_WhenThePayeeReentersWithTheSameBatch() external {
    // it should refuse the nested run and complete the outer one once
    ActionCallbackPayee _reentrant = new ActionCallbackPayee();
    IPolicyManager.PaymentOrder memory _native =
      IPolicyManager.PaymentOrder({token: address(0), amount: 1 ether, payee: address(_reentrant)});
    IPolicyManager.Attempt memory _attempt = _reopenWithOrder(_native);
    IAmbireRecoveryAction.Transaction[] memory _calls = _approvedBatch(_attempt, address(_reentrant));
    _reentrant.load(_account, _calls, ActionBatch.kitSignature(address(_action)));

    vm.recordLogs();
    _executeHandover();
    Vm.Log[] memory _logs = vm.getRecordedLogs();

    assertEq(_reentrant.attempts(), 1, 'the payee did not re-enter');
    assertEq(_reentrant.successes(), 0, 'the nested run succeeded');
    assertEq(
      _reentrant.lastRevert(),
      abi.encodeWithSelector(
        IRecoveryAction.RecoveryAction_NotConsumable.selector,
        _account,
        IPolicyManager.AttemptState.Consumed,
        _attempt.consumableAfter,
        _attempt.payloadHash
      ),
      'the nested run failed for another reason'
    );
    assertEq(_countLogs(_logs, IPolicyManager.AttemptConsumed.selector), 1, 'not released exactly once');
    assertEq(address(_reentrant).balance, 1 ether, 'the payee was not paid exactly once');
    assertEq(_privilege(_newKey), _KEY_VALUE, 'the outer handover did not run');
  }

  /// @notice A token transfer that returns false pays nobody, but the handover still completes. The
  ///         batch only checks that the payment call did not revert.
  function test_WhenThePaymentPaysNobody() external {
    // it should complete the handover with the payee unpaid
    _token.setAnswersFalse(true);
    uint256 _payeeBefore = _token.balanceOf(_payee);
    _executeHandover();
    assertEq(uint256(_state().attempt.state), uint256(IPolicyManager.AttemptState.Consumed), 'nothing was spent');
    assertEq(_privilege(_newKey), _KEY_VALUE, 'the new key holds no key value');
    assertEq(_privilege(_holderKey), bytes32(0), 'the lost key still holds a privilege');
    assertEq(_token.balanceOf(_payee), _payeeBefore, 'the payee received something');
  }

  /// @notice A batch sent straight to the account with a fifth call after the approved four is refused
  ///         at the extra call. Nobody can add a call to the handover the guardians approved.
  function test_RevertWhen_ABatchCarriesAnExtraCall() external {
    // it should revert
    IAmbireRecoveryAction.Transaction[] memory _approved = _approvedBatch(_state().attempt, _payee);
    IAmbireRecoveryAction.Transaction[] memory _five = new IAmbireRecoveryAction.Transaction[](5);
    for (uint256 _i; _i < 4; ++_i) {
      _five[_i] = _approved[_i];
    }
    _five[4] = IAmbireRecoveryAction.Transaction({
      to: address(_token), value: 0, data: abi.encodeCall(ActionPaymentToken.transfer, (_executor, 1))
    });
    bytes memory _signature = ActionBatch.kitSignature(address(_action));
    vm.expectRevert(abi.encodeWithSelector(IRecoveryAction.RecoveryAction_BatchNotApproved.selector, uint256(4)));
    vm.prank(_executor);
    IAmbireAccount(_account).execute(_five, _signature);
    assertEq(uint256(_state().attempt.state), uint256(IPolicyManager.AttemptState.Waiting), 'the attempt ended');
  }

  /// @notice A handover that would remove the kit slot is refused. The kit slot is the account entry
  ///         that authorizes the action, not a key, so a recovery can never remove it.
  function test_RevertWhen_TheHandoverRemovesTheKitSlot() external {
    // it should revert
    address _kitSlot = ActionBatch.kitSlot(address(_action));
    bytes memory _removesSlot = ActionBatch.payload(_newKey, _kitSlot);
    _reopenWithPayload(_removesSlot);
    vm.expectRevert(abi.encodeWithSelector(IRecoveryAction.RecoveryAction_NotAKey.selector, _kitSlot));
    vm.prank(_executor);
    _action.executeHandover(_account, _removesSlot);
    assertEq(_privilege(_kitSlot), ActionBatch.binding(address(_action)), 'the kit slot moved');
  }

  /// @notice A handover that names the zero address as the new key is refused. It would remove the lost
  ///         key and leave the account with no key. The attempt keeps waiting until someone cancels it.
  function test_RevertWhen_TheHandoverInstallsTheZeroAddress() external {
    // it should revert
    bytes memory _toNobody = ActionBatch.payload(address(0), _holderKey);
    _reopenWithPayload(_toNobody);
    vm.expectRevert(abi.encodeWithSelector(IRecoveryAction.RecoveryAction_MalformedHandover.selector, _toNobody));
    vm.prank(_executor);
    _action.executeHandover(_account, _toNobody);
    assertEq(uint256(_state().attempt.state), uint256(IPolicyManager.AttemptState.Waiting), 'the attempt ended');
    assertEq(_privilege(_holderKey), _SIGNER_VALUE, 'the refused handover moved the lost key');
  }

  /// @notice A handover whose new key and lost key are the same address is refused. Adding and then
  ///         removing that key in one batch would leave the account without it.
  function test_RevertWhen_TheHandoverNamesOneAddressOnBothSides() external {
    // it should revert
    bytes memory _sameKey = ActionBatch.payload(_holderKey, _holderKey);
    _reopenWithPayload(_sameKey);
    vm.expectRevert(abi.encodeWithSelector(IRecoveryAction.RecoveryAction_MalformedHandover.selector, _sameKey));
    vm.prank(_executor);
    _action.executeHandover(_account, _sameKey);
    assertEq(_privilege(_holderKey), _SIGNER_VALUE, 'the refused handover moved the lost key');
  }

  /// @notice If the account gives the new key a privilege during the wait, the handover is refused. A
  ///         handover never overwrites a privilege the account already set. The attempt keeps waiting
  ///         and no key changes.
  function test_RevertWhen_TheNewKeyGainedAPrivilegeDuringTheWait() external {
    // it should revert
    _asHolder(
      _one(
        IAmbireRecoveryAction.Transaction({
          to: _account, value: 0, data: abi.encodeCall(IAmbireAccount.setAddrPrivilege, (_newKey, _SIGNER_VALUE))
        })
      )
    );
    vm.expectRevert(abi.encodeWithSelector(IRecoveryAction.RecoveryAction_AlreadyPrivileged.selector, _newKey));
    _executeHandover();
    assertEq(uint256(_state().attempt.state), uint256(IPolicyManager.AttemptState.Waiting), 'the attempt ended');
    assertEq(_privilege(_newKey), _SIGNER_VALUE, 'the refused handover rewrote the new key');
    assertEq(_privilege(_holderKey), _SIGNER_VALUE, 'the refused handover moved the lost key');
  }

  /// @notice A payment order with no amount gives a batch of three calls: the spend, adding the new key
  ///         and removing the lost key. The batch has no payment call, and the payee gets nothing.
  function test_WhenTheOrderHasNoAmount() external {
    // it should run the three calls and pay nothing
    IPolicyManager.Attempt memory _attempt =
      _reopenWithOrder(IPolicyManager.PaymentOrder({token: address(_token), amount: 0, payee: _payee}));
    IAmbireRecoveryAction.Transaction[] memory _three = _approvedBatch(_attempt, _payee);
    assertEq(_three.length, 3, 'the rendered batch is not three calls');
    vm.expectCall(
      _account, abi.encodeCall(IAmbireAccount.execute, (_three, ActionBatch.kitSignature(address(_action)))), 1
    );
    vm.expectCall(address(_token), abi.encodeWithSelector(ActionPaymentToken.transfer.selector), 0);
    uint256 _payeeBefore = _token.balanceOf(_payee);
    _executeHandover();
    assertEq(uint256(_state().attempt.state), uint256(IPolicyManager.AttemptState.Consumed), 'nothing was spent');
    assertEq(_privilege(_newKey), _KEY_VALUE, 'the new key holds no key value');
    assertEq(_token.balanceOf(_payee), _payeeBefore, 'the payee was paid');
  }

  /// @notice A payee that refuses ether reverts the whole batch with its own error, the spend included.
  ///         The attempt keeps waiting, no key changes and the account keeps its funds.
  function test_RevertWhen_TheNamedNativePayeeReverts() external {
    // it should revert
    address _refusing = address(new ActionRefusingPayee());
    _reopenWithOrder(IPolicyManager.PaymentOrder({token: address(0), amount: 1 ether, payee: _refusing}));
    uint256 _accountBefore = _account.balance;
    vm.expectRevert(ActionRefusingPayee.ActionRefusingPayee_Refused.selector);
    _executeHandover();
    assertEq(uint256(_state().attempt.state), uint256(IPolicyManager.AttemptState.Waiting), 'the attempt ended');
    assertEq(_privilege(_newKey), bytes32(0), 'the failed batch installed the new key');
    assertEq(_privilege(_holderKey), _SIGNER_VALUE, 'the failed batch moved the lost key');
    assertEq(_account.balance, _accountBefore, 'the failed batch moved funds');
  }

  /// @notice After the handover, the new key calls the manager's spend directly from the account. The
  ///         manager refuses it because nothing is left to spend. One approval is never spent twice.
  function test_RevertWhen_TheNewKeySendsTheSpendAgain() external {
    // it should revert
    IPolicyManager.Attempt memory _attempt = _state().attempt;
    _executeHandover();
    bytes memory _consume =
      abi.encodeCall(IPolicyManager.consume, (address(_action), _attempt.attemptId, _attempt.payloadHash));
    vm.expectRevert(
      abi.encodeWithSelector(IPolicyManager.PolicyManager_NoActiveAttempt.selector, _account, address(_action))
    );
    vm.prank(_newKey);
    ActionAmbireAccountFixture(payable(_account)).executeBySender(_one(_managerCall(_consume)));
  }

  /// @notice Cancels the attempt opened in setUp with the holder's key, opens a new one committed to
  ///         `_committed`, and waits out its delay.
  function _reopenWithPayload(bytes memory _committed) internal {
    _asHolder(_one(_managerCall(abi.encodeCall(IPolicyManager.cancelByOwner, (address(_action))))));
    IPolicyManager.AttemptRequest memory _req = _nextRequest(_openingSet());
    _req.payload = _committed;
    for (uint256 _i; _i < _req.proofs.length; ++_i) {
      _req.proofs[_i].proof = _prove(_req.proofs[_i].place, _manager.hashApproval(_req, _req.proofs[_i].place));
    }
    _send(_req);
    vm.warp(_state().attempt.consumableAfter);
  }

  /// @notice Cancels the attempt opened in setUp with the holder's key, opens a new one that pays
  ///         `_paymentOrder`, and waits out its delay.
  function _reopenWithOrder(IPolicyManager.PaymentOrder memory _paymentOrder)
    internal
    returns (IPolicyManager.Attempt memory _attempt)
  {
    _asHolder(_one(_managerCall(abi.encodeCall(IPolicyManager.cancelByOwner, (address(_action))))));
    IPolicyManager.ActionState memory _now = _state();
    IPolicyManager.AttemptRequest memory _req = _request(_openingSet(), _now.nextAttemptId, _now.setupNonce, _window());
    _req.order = _paymentOrder;
    for (uint256 _i; _i < _req.proofs.length; ++_i) {
      _req.proofs[_i].proof = _prove(_req.proofs[_i].place, _manager.hashApproval(_req, _req.proofs[_i].place));
    }
    _send(_req);
    _attempt = _state().attempt;
    vm.warp(_attempt.consumableAfter);
  }

  /// @notice Expects every call and event of one handover. The action reads the manager and calls the
  ///         account, the account asks the action to check the batch, the spend reads one pause per
  ///         method used, the token pays, and the manager and the account emit their events.
  function _expectTheHandoverCalls(
    IPolicyManager.Attempt memory _attempt,
    IAmbireRecoveryAction.Transaction[] memory _calls
  ) internal {
    // The action reads the manager's state, then sends the batch to the account with the kit signature.
    vm.expectCall(address(_manager), abi.encodeCall(IPolicyManager.stateOf, (_account, address(_action))));
    vm.expectCall(
      _account, abi.encodeCall(IAmbireAccount.execute, (_calls, ActionBatch.kitSignature(address(_action)))), 1
    );
    // The account asks the action to check the batch, and the action reads the account's attempt.
    vm.expectCall(address(_action), abi.encodeCall(IAmbireRecoveryAction.validateSig, ('', '', _calls)), 1);
    // The spend runs first, and the manager asks each method the attempt used whether it is paused.
    vm.expectCall(
      address(_manager),
      abi.encodeCall(IPolicyManager.consume, (address(_action), _attempt.attemptId, keccak256(_published))),
      1
    );
    vm.expectCall(address(_ecdsa), abi.encodeCall(IPolicyMethodPause.paused, ()), 1);
    vm.expectCall(address(_passkey), abi.encodeCall(IPolicyMethodPause.paused, ()), 1);
    vm.expectCall(address(_token), abi.encodeCall(ActionPaymentToken.transfer, (_payee, _PAYMENT)), 1);

    vm.expectEmit(true, true, true, true, address(_manager));
    emit IPolicyManager.AttemptConsumed(_account, address(_action), _attempt.attemptId);
    vm.expectEmit(true, true, true, true, _account);
    emit IAmbireAccount.LogPrivilegeChanged(_newKey, _KEY_VALUE);
    vm.expectEmit(true, true, true, true, _account);
    emit IAmbireAccount.LogPrivilegeChanged(_holderKey, bytes32(0));
  }
}
