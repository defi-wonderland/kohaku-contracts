// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {IPolicyManager} from 'interfaces/IPolicyManager.sol';
import {IAmbireAccount} from 'contracts/actions/ambire/IAmbireAccount.sol';
import {IAmbireRecoveryAction} from 'contracts/actions/ambire/IAmbireRecoveryAction.sol';
import {ActionPaymentToken, ActionRefusingPayee} from 'test/mocks/ActionAmbireAccountFixture.sol';
import {ActionBatch} from 'test/utils/ActionBatch.sol';
import {IntegrationDemoKitTestBase} from 'test/utils/IntegrationDemoKitTestBase.sol';

/// @notice The payment is the last call of the handover batch. If it reverts, the spend reverts too
///         and the attempt keeps waiting. The waiting attempt holds the action's one attempt slot until
///         someone cancels it or the payment works. An order with no payee pays whoever runs it.
contract PaymentOrdersAndTheOneSlotTest is IntegrationDemoKitTestBase {
  /// @notice The amount of the native orders, in wei.
  uint256 internal constant _NATIVE = 1 ether;
  /// @notice A payee that refuses ether.
  address internal _refusing;

  function setUp() public override {
    super.setUp();
    _authorizeAndCommit();
    _refusing = address(new ActionRefusingPayee());
  }

  /// @notice A payee that refuses ether reverts the whole handover. The attempt keeps waiting, no key
  ///         changes and nothing is paid. Other guardians cannot open a new attempt while it waits.
  function test_RevertWhen_ANamedPayeeRefusesTheNativeAsset() external {
    // it should revert
    _openPaying(_native(_refusing));
    vm.expectRevert(ActionRefusingPayee.ActionRefusingPayee_Refused.selector);
    _executeHandover();

    // it should hold the one attempt slot against another set
    assertEq(uint256(_state().attempt.state), uint256(IPolicyManager.AttemptState.Waiting), 'the attempt ended');
    assertEq(_privilege(_holderKey), _SIGNER_VALUE, 'the failed batch moved the lost key');
    assertEq(_account.balance, 10 ether, 'the failed batch paid something');
    IPolicyManager.AttemptRequest memory _other = _request(_places(_BOB, _CAROL, _PHONE), 2, 1, _window());
    vm.expectRevert(
      abi.encodeWithSelector(IPolicyManager.PolicyManager_AttemptAlreadyActive.selector, _account, address(_action), 1)
    );
    _send(_other);
  }

  /// @notice The holder's key cancels the attempt the refusing payee blocks, which frees the slot. A new
  ///         attempt that pays a working payee opens and runs after its own wait.
  function test_WhenTheHolderCancelsTheBlockedAttempt() external {
    // it should free the slot for a new attempt that runs
    _openPaying(_native(_refusing));
    _asHolder(_one(_cancelByOwnerCall()));

    _openPaying(_native(_payee));
    assertEq(_state().attempt.attemptId, 2, 'the fresh attempt took another id');
    _executeHandover();
    assertEq(_payee.balance, _NATIVE, 'the accepting payee was not paid');
    assertEq(_privilege(_newKey), _KEY_VALUE, 'the new key holds no key value');
  }

  /// @notice When the payee starts accepting ether, the same handover runs. The attempt kept waiting,
  ///         so it needs no cancel and no new approval.
  function test_WhenTheRefusingPayeeLaterAccepts() external {
    // it should run the same handover and pay the payee
    _openPaying(_native(_refusing));
    vm.expectRevert(ActionRefusingPayee.ActionRefusingPayee_Refused.selector);
    _executeHandover();

    vm.etch(_refusing, '');
    _executeHandover();
    assertEq(uint256(_state().attempt.state), uint256(IPolicyManager.AttemptState.Consumed), 'nothing was spent');
    assertEq(_refusing.balance, _NATIVE, 'the payee was not paid');
  }

  /// @notice An order with no payee pays whoever calls the action. A holder with no funds can still
  ///         get the last step run. `_seed` builds the caller's address.
  function test_WhenAnOpenTokenOrderPaysWhoeverExecutes(uint256 _seed) external {
    // it should pay the token amount to the caller
    address _caller = _fresh('openTokenExecutor', _seed);
    _openPaying(IPolicyManager.PaymentOrder({token: address(_token), amount: _PAYMENT, payee: address(0)}));
    vm.prank(_caller);
    _action.executeHandover(_account, _payload());
    assertEq(_token.balanceOf(_caller), _PAYMENT, 'the caller was not paid');
    assertEq(_privilege(_newKey), _KEY_VALUE, 'the new key holds no key value');
  }

  /// @notice An ether order with no payee pays the caller in ether. `_seed` builds the caller's
  ///         address.
  function test_WhenAnOpenNativeOrderPaysWhoeverExecutes(uint256 _seed) external {
    // it should pay the native amount to the caller
    address _caller = _fresh('openNativeExecutor', _seed);
    _openPaying(_native(address(0)));
    vm.prank(_caller);
    _action.executeHandover(_account, _payload());
    assertEq(_caller.balance, _NATIVE, 'the caller was not paid');
    assertEq(_privilege(_newKey), _KEY_VALUE, 'the new key holds no key value');
  }

  /// @notice An order with no payee and no amount gives a batch of three calls. The caller is paid
  ///         nothing and the handover still runs. `_seed` builds the caller's address.
  function test_WhenAnOpenOrderHasNoAmount(uint256 _seed) external {
    // it should run three calls and pay nobody
    address _caller = _fresh('unpaidExecutor', _seed);
    _openPaying(IPolicyManager.PaymentOrder({token: address(_token), amount: 0, payee: address(0)}));
    IAmbireRecoveryAction.Transaction[] memory _three = _approvedBatch(_state().attempt, _caller);
    assertEq(_three.length, 3, 'the rendered batch is not three calls');
    vm.expectCall(
      _account, abi.encodeCall(IAmbireAccount.execute, (_three, ActionBatch.kitSignature(address(_action)))), 1
    );
    vm.expectCall(address(_token), abi.encodeWithSelector(ActionPaymentToken.transfer.selector), 0);
    vm.prank(_caller);
    _action.executeHandover(_account, _payload());
    assertEq(_token.balanceOf(_caller), 0, 'the caller was paid');
    assertEq(_privilege(_newKey), _KEY_VALUE, 'the new key holds no key value');
  }

  /// @notice An account without enough ether cannot pay, so the handover reverts and the attempt keeps
  ///         waiting. Once someone funds the account, the same handover runs.
  function test_RevertWhen_TheAccountIsShortOfTheNativeAsset() external {
    // it should revert
    _openPaying(_native(_payee));
    vm.deal(_account, _NATIVE - 1);
    vm.expectRevert(bytes(''));
    _executeHandover();
    assertEq(uint256(_state().attempt.state), uint256(IPolicyManager.AttemptState.Waiting), 'the attempt ended');

    // it should run the same handover once the account is funded
    vm.deal(_account, _NATIVE);
    _executeHandover();
    assertEq(_payee.balance, _NATIVE, 'the payee was not paid');
    assertEq(_account.balance, 0, 'the account paid another amount');
  }

  /// @notice An order that pays one ether to `_to`.
  function _native(address _to) internal pure returns (IPolicyManager.PaymentOrder memory _paymentOrder) {
    _paymentOrder = IPolicyManager.PaymentOrder({token: address(0), amount: _NATIVE, payee: _to});
  }

  /// @notice Opens the next attempt with the default set and payload, paying `_paymentOrder`, and waits it out.
  function _openPaying(IPolicyManager.PaymentOrder memory _paymentOrder) internal {
    _openWith(_openingSet(), _payload(), _paymentOrder);
    vm.warp(_state().attempt.consumableAfter);
  }
}
