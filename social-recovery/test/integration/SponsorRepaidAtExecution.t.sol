// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {IERC20} from '@openzeppelin/contracts/token/ERC20/IERC20.sol';
import {IERC20Errors} from '@openzeppelin/contracts/interfaces/draft-IERC6093.sol';

import {IPolicyManager} from 'interfaces/IPolicyManager.sol';
import {IRecoveryAction} from 'interfaces/IRecoveryAction.sol';

import {IAmbireAccount} from 'contracts/actions/ambire/IAmbireAccount.sol';
import {IAmbireRecoveryAction} from 'contracts/actions/ambire/IAmbireRecoveryAction.sol';

import {IntegrationBase} from 'test/integration/base/IntegrationBase.sol';
import {FalseReturningToken, RefusingPayee} from 'test/integration/base/LocalWorld.sol';

/// @notice A payee contract that, on receiving the native payment, sends the same batch to the account again with the
///         kit's signature and catches the failure, recording whether the nested run failed.
/// @dev What it replaces: a sponsor's contract wallet written to try a second spend from inside the first. Why no real
///      contract is used: the re-entry is the point, and no real sponsor wallet does this. Which test covers the real
///      callback: test/action/AmbireRecoveryActionValidateSig.t.sol covers the action's refusal of a spent attempt at
///      the unit level, and this story shows it inside a running handover.
contract ReenteringPayee {
  /// @notice The account it re-enters, the batch it sends again and the signature it sends it with.
  address internal _account;
  IAmbireRecoveryAction.Transaction[] internal _calls;
  bytes internal _signature;
  /// @notice How many payments arrived, whether the nested run of the batch failed, and the revert data it failed with.
  uint256 public payments;
  bool public nestedRunFailed;
  bytes public nestedRevertData;

  /// @notice Remembers the batch to send again when paid.
  function aim(address _target, IAmbireRecoveryAction.Transaction[] calldata _batch, bytes calldata _kitSignature)
    external
  {
    _account = _target;
    delete _calls;
    for (uint256 _i; _i < _batch.length; ++_i) {
      _calls.push(_batch[_i]);
    }
    _signature = _kitSignature;
  }

  /// @notice On the first payment, sends the same batch to the account again and catches the failure with its reason.
  // The re-entry from inside the payment is what this payee exists for.
  // solhint-disable-next-line no-complex-fallback
  receive() external payable {
    ++payments;
    if (payments > 1) return;
    try IAmbireAccount(_account).execute(_calls, _signature) {
      nestedRunFailed = false;
    } catch (bytes memory _reason) {
      nestedRunFailed = true;
      nestedRevertData = _reason;
    }
  }
}

/// @notice A sponsor pays the gas for a friend with no funded key, and the friend's account repays the sponsor when the
///         recovery completes, whoever sends the last transaction. The story is told once; each kind below says what
///         the account pays in, to whom, and how the opening reaches the chain.
abstract contract SponsorRepaidAtExecution is IntegrationBase {
  /// @notice The holder's account, holding 100 USDC and 1 ETH.
  address internal _account;
  /// @notice The holder's rule, Maya's rule, as the backup holds it.
  Rule internal _holderRule;
  /// @notice The sponsor who pays for the opening and expects to be repaid.
  address internal _sponsor;

  function setUp() public virtual override {
    super.setUp();
    _sponsor = _funded('sponsor');
    _account = _openAccount(_originalKey.addr);
    _usdc.mint(_account, 100e6);
    Rule memory _r = _mayaRule(_account);
    _keep(_holderRule, _r);
    _setUpRecovery(_account, _originalKey, _r);
  }

  /*///////////////////////////////////////////////////////////////
                         WHAT EACH KIND SAYS
  ///////////////////////////////////////////////////////////////*/

  /// @notice The order the holder and the sponsor agreed on.
  function _agreedOrder() internal view virtual returns (IPolicyManager.PaymentOrder memory _order);

  /// @notice What an address holds in the asset of the agreed order.
  function _heldBy(address _holder) internal view virtual returns (uint256 _balance);

  /// @notice Who the account pays when `_caller` sends executeHandover.
  function _whoIsPaid(address _caller) internal view virtual returns (address _paid);

  /// @notice Before losing the key, the holder moved every unit of the order's asset out of the account.
  function _holderMovesEverythingOut() internal virtual;

  /// @notice A friend sends the account the agreed amount in the order's asset.
  function _friendFundsTheAccount(uint256 _amount) internal virtual;

  /// @notice Expects the next call to fail because the account cannot pay.
  function _expectTheAccountCannotPay() internal virtual;

  /// @notice The signed request reaches the chain on the sponsor's behalf.
  function _openingIsSent(IPolicyManager.AttemptRequest memory _req) internal virtual {
    // The relayer sends startAttempt on the sponsor's behalf.
    _submits(_relayer, _req);
  }

  /*///////////////////////////////////////////////////////////////
                              THE WALK
  ///////////////////////////////////////////////////////////////*/

  /// @notice The sponsor pays for the opening, a bot that copied the pending execute transaction gets it mined first,
  ///         and the account still repays the agreed party once. With a named payee the sponsor is paid though the bot
  ///         sent the transaction; with an open payee whoever called executeHandover is paid.
  function test_WhenABotExecutesAndTheSponsorIsPaid() external {
    Rule memory _r = _holderRule;
    IPolicyManager.PaymentOrder memory _order = _agreedOrder();
    address _paid = _whoIsPaid(_executor);
    uint256 _paidBefore = _heldBy(_paid);
    uint256 _accountBefore = _heldBy(_account);
    uint256 _relayerBefore = _heldBy(_relayer);

    // The holder builds the request with the order, and Ben, Carla and the passkey sign approvals that include it.
    bytes memory _payload = _handover(_newKey.addr, _originalKey.addr);
    IPolicyManager.AttemptRequest memory _req =
      _request(_account, _r, _payload, _order, uint48(block.timestamp + 24 hours));
    _approversApprove(_req, _r);

    // The opening reaches the chain on the sponsor's behalf.
    _openingIsSent(_req);

    // Five days pass.
    skip(5 days);

    // A bot that copied the sponsor's pending execute transaction sends executeHandover first.
    _executes(_executor, _account, _payload);

    // The sponsor's own copy then finds nothing left to run.
    vm.prank(_sponsor);
    vm.expectPartialRevert(IRecoveryAction.RecoveryAction_NotConsumable.selector);
    _action.executeHandover(_account, _payload);

    // The agreed party received the amount once, and the relayer got nothing.
    assertEq(_heldBy(_paid) - _paidBefore, _order.amount, 'the agreed party was paid the amount once');
    assertEq(_accountBefore - _heldBy(_account), _order.amount, 'the account paid the amount once');
    if (_paid != _relayer) assertEq(_heldBy(_relayer), _relayerBefore, 'the relayer got nothing');
    // The handover is done.
    _assertKeyControls(_account, _newKey, 'the new key');
    _assertKeyLocked(_account, _originalKey);
  }

  /*///////////////////////////////////////////////////////////////
                              EVEN IF
  ///////////////////////////////////////////////////////////////*/

  /// @notice The account lacks the amount when the wait ends: the whole handover reverts and the attempt keeps waiting.
  ///         Once someone funds the account, the same call hands it over and pays. The payment is never skipped.
  function test_WhenTheAccountIsShortOfTheToken() external {
    // Before losing the key, the holder moved everything the order pays in out of the account.
    _holderMovesEverythingOut();

    // The approvers open the attempt with the agreed order, and the wait passes.
    bytes memory _payload = _approversOpenTheAttempt(_agreedOrder());
    skip(5 days);

    // The bot executes, and the account cannot pay.
    vm.prank(_executor);
    _expectTheAccountCannotPay();
    _action.executeHandover(_account, _payload);
    assertEq(_privilegeOf(_account, _newKey.addr), bytes32(0), 'the new key is not installed');
    assertEq(uint8(_attempt(_account).state), uint8(IPolicyManager.AttemptState.Waiting), 'the attempt waits');

    // A friend funds the account with the agreed amount.
    address _paid = _whoIsPaid(_executor);
    uint256 _paidBefore = _heldBy(_paid);
    _friendFundsTheAccount(_agreedOrder().amount);

    // The bot sends the same call, and it hands the account over and pays.
    _executes(_executor, _account, _payload);
    assertEq(_heldBy(_paid) - _paidBefore, _agreedOrder().amount, 'the agreed party was paid');
    assertEq(_privilegeOf(_account, _newKey.addr), bytes32(uint256(1)), 'the new key holds privilege 1');
    _assertKeyLocked(_account, _originalKey);
  }

  /*///////////////////////////////////////////////////////////////
                              UTILITIES
  ///////////////////////////////////////////////////////////////*/

  /// @notice Ben, Carla and Maya's passkey sign the approval, each for their place.
  function _approversApprove(IPolicyManager.AttemptRequest memory _req, Rule memory _r) internal view {
    _signApproval(_req, _r, 1);
    _signApproval(_req, _r, 2);
    _signApproval(_req, _r, 4);
  }

  /// @notice The approvers sign the handover from the lost key to the new key with an order, the sponsor submits it,
  ///         and the payload comes back.
  function _approversOpenTheAttempt(IPolicyManager.PaymentOrder memory _order)
    internal
    returns (bytes memory _payload)
  {
    Rule memory _r = _holderRule;
    _payload = _handover(_newKey.addr, _originalKey.addr);
    IPolicyManager.AttemptRequest memory _req =
      _request(_account, _r, _payload, _order, uint48(block.timestamp + 24 hours));
    _approversApprove(_req, _r);
    _submits(_sponsor, _req);
  }

  /// @notice Ben, Carla and Maya's passkey sign a cancel of the waiting attempt, and a friend submits it.
  function _approversCancel() internal {
    Rule memory _r = _holderRule;
    IPolicyManager.CancelRequest memory _cancel =
      _cancelRequest(_account, _r, _attempt(_account).attemptId, uint48(block.timestamp + 24 hours));
    _signCancel(_cancel, _r, 1);
    _signCancel(_cancel, _r, 2);
    _signCancel(_cancel, _r, 4);
    _submitsCancel(_friend, _cancel);
  }

  /// @notice The first three calls of the batch the action builds for the handover to the new key: the consume, the
  ///         grant and the revoke.
  function _handoverCalls(bytes memory _payload)
    internal
    view
    returns (
      IAmbireRecoveryAction.Transaction memory _consume,
      IAmbireRecoveryAction.Transaction memory _grant,
      IAmbireRecoveryAction.Transaction memory _revoke
    )
  {
    _consume = _call(
      address(_manager),
      abi.encodeCall(IPolicyManager.consume, (address(_action), _attempt(_account).attemptId, keccak256(_payload)))
    );
    _grant = _setPrivilegeCall(_account, _newKey.addr, bytes32(uint256(1)));
    _revoke = _setPrivilegeCall(_account, _originalKey.addr, bytes32(0));
  }
}

/// @notice The account pays the sponsor 10 USDC, a named payee with an ERC-20 token. This kind also carries the cases
///         that try to change a token payment, and the trade-offs a token payment brings.
contract SponsorRepaidAtExecutionInUsdc is SponsorRepaidAtExecution {
  function _agreedOrder() internal view virtual override returns (IPolicyManager.PaymentOrder memory _order) {
    _order = IPolicyManager.PaymentOrder(address(_usdc), 10e6, _sponsor);
  }

  function _heldBy(address _holder) internal view override returns (uint256 _balance) {
    _balance = _usdc.balanceOf(_holder);
  }

  function _whoIsPaid(address) internal view virtual override returns (address _paid) {
    _paid = _sponsor;
  }

  function _holderMovesEverythingOut() internal override {
    // The holder's key sends all the account's USDC to the holder's exchange address.
    _keySignsAndRelayerSends(
      _account,
      _originalKey,
      _batch(_call(address(_usdc), abi.encodeCall(IERC20.transfer, (makeAddr('exchange'), _usdc.balanceOf(_account)))))
    );
  }

  function _friendFundsTheAccount(uint256 _amount) internal override {
    // The friend buys USDC on an exchange and withdraws it to the account.
    _usdc.mint(_account, _amount);
  }

  function _expectTheAccountCannotPay() internal override {
    vm.expectPartialRevert(IERC20Errors.ERC20InsufficientBalance.selector);
  }
}

/// @notice The named USDC payee again, with the opening sent as an ERC-4337 operation from the new key's empty smart
///         account, which the sponsor's paymaster pays for. This kind also carries the batches that try to divert or
///         drop the payment, and the trade-offs a token payment brings.
contract SponsorRepaidAtExecutionThroughThePaymaster is SponsorRepaidAtExecutionInUsdc {
  function _openingIsSent(IPolicyManager.AttemptRequest memory _req) internal override {
    // The new key's new smart account, holding no ETH, sends the request as an operation the sponsor's paymaster pays.
    address _newKeyAccount = _openAccountWithEntryPoint(_newKey.addr);
    vm.deal(_newKeyAccount, 0);
    _keySendsSponsoredOperation(
      _newKeyAccount, _newKey, _batch(_call(address(_manager), abi.encodeCall(IPolicyManager.startAttempt, (_req))))
    );
  }

  /*///////////////////////////////////////////////////////////////
                              EVEN IF
  ///////////////////////////////////////////////////////////////*/

  /// @notice Nobody can redirect the payment by sending the batch straight to the account: with the approved handover
  ///         but another payee, or another amount, the account's callback refuses it and the attempt keeps waiting.
  function test_RevertWhen_ABatchSentToTheAccountDivertsThePayment() external {
    // The approvers open the attempt with the agreed order, and the wait passes.
    bytes memory _payload = _approversOpenTheAttempt(_agreedOrder());
    skip(5 days);
    (
      IAmbireRecoveryAction.Transaction memory _consume,
      IAmbireRecoveryAction.Transaction memory _grant,
      IAmbireRecoveryAction.Transaction memory _revoke
    ) = _handoverCalls(_payload);
    bytes memory _signature = _kitSignature();

    // The bot sends the approved handover paying itself the 10 USDC instead of the sponsor.
    IAmbireRecoveryAction.Transaction[] memory _toTheBot = _batch(
      _consume, _grant, _revoke, _call(address(_usdc), abi.encodeCall(IERC20.transfer, (_executor, uint256(10e6))))
    );
    vm.prank(_executor);
    vm.expectPartialRevert(IRecoveryAction.RecoveryAction_BatchNotApproved.selector);
    IAmbireAccount(_account).execute(_toTheBot, _signature);

    // The bot sends it paying the sponsor all 100 USDC.
    IAmbireRecoveryAction.Transaction[] memory _more = _batch(
      _consume, _grant, _revoke, _call(address(_usdc), abi.encodeCall(IERC20.transfer, (_sponsor, uint256(100e6))))
    );
    vm.prank(_executor);
    vm.expectPartialRevert(IRecoveryAction.RecoveryAction_BatchNotApproved.selector);
    IAmbireAccount(_account).execute(_more, _signature);

    // The attempt keeps waiting, nothing moved, and the approved execution pays the sponsor 10 USDC.
    assertEq(uint8(_attempt(_account).state), uint8(IPolicyManager.AttemptState.Waiting), 'the attempt keeps waiting');
    assertEq(_usdc.balanceOf(_executor), 0, 'the bot got nothing');
    _executes(_executor, _account, _payload);
    assertEq(_usdc.balanceOf(_sponsor), 10e6, 'the sponsor was paid the agreed amount');
  }

  /// @notice A three-call batch that drops the payment of an order with an amount is refused, so the handover cannot
  ///         land without the sponsor being paid.
  function test_RevertWhen_ABatchDropsThePayment() external {
    // The approvers open the attempt with the agreed order, and the wait passes.
    bytes memory _payload = _approversOpenTheAttempt(_agreedOrder());
    skip(5 days);

    // Someone sends the consume, the grant and the revoke alone, with the kit's signature.
    (
      IAmbireRecoveryAction.Transaction memory _consume,
      IAmbireRecoveryAction.Transaction memory _grant,
      IAmbireRecoveryAction.Transaction memory _revoke
    ) = _handoverCalls(_payload);
    IAmbireRecoveryAction.Transaction[] memory _unpaid = _batch(_consume, _grant, _revoke);
    bytes memory _signature = _kitSignature();
    vm.prank(_executor);
    vm.expectPartialRevert(IRecoveryAction.RecoveryAction_BatchNotApproved.selector);
    IAmbireAccount(_account).execute(_unpaid, _signature);

    // The attempt keeps waiting, the new key holds nothing and the sponsor is unpaid.
    assertEq(uint8(_attempt(_account).state), uint8(IPolicyManager.AttemptState.Waiting), 'the attempt keeps waiting');
    assertEq(_privilegeOf(_account, _newKey.addr), bytes32(0), 'the new key holds nothing');
    assertEq(_usdc.balanceOf(_sponsor), 0, 'the sponsor is unpaid');
  }

  /*///////////////////////////////////////////////////////////////
                             TRADE-OFFS
  ///////////////////////////////////////////////////////////////*/

  /// @notice A token whose transfer answers false, a token address with no code, and a token address whose fallback
  ///         swallows the call, here the Ambire account itself, each let the handover complete with nobody paid. The
  ///         action does not read the answer, so a bad token cannot block a recovery.
  function test_WhenTheTokenPaysNobody() external {
    // The account holds 100 units of a token whose transfer answers false.
    FalseReturningToken _falseToken = new FalseReturningToken();
    _falseToken.mint(_account, 100e6);

    // Three holders' recoveries name a bad token in their orders, and each completes with the sponsor unpaid.
    _recoveryPaysNobody(address(_falseToken), 'holder with a token that answers false');
    _recoveryPaysNobody(makeAddr('token on another chain'), 'holder with a token address with no code');
    address _swallowing = _openAccount(makeAddr('a token that is an Ambire account'));
    _recoveryPaysNobody(_swallowing, 'holder with a token whose fallback swallows the call');

    // Nobody paid the sponsor in any asset.
    assertEq(_falseToken.balanceOf(_sponsor), 0, 'the sponsor got none of the false token');
    assertEq(_usdc.balanceOf(_sponsor), 0, 'the sponsor got no USDC');
  }

  /// @notice A holder's account, set up with Maya's rule and holding 100 USDC, is recovered under an order paying the
  ///         sponsor 10 of a bad token. The handover completes and the account keeps its USDC.
  function _recoveryPaysNobody(address _token, string memory _who) internal {
    Person memory _lost = _person(string.concat(_who, ' lost key'));
    Person memory _new = _person(string.concat(_who, ' new key'));
    address _holderAccount = _openAccount(_lost.addr);
    _usdc.mint(_holderAccount, 100e6);
    Rule memory _r = _mayaRule(_holderAccount);
    _setUpRecovery(_holderAccount, _lost, _r);
    bytes memory _payload = _handover(_new.addr, _lost.addr);
    IPolicyManager.AttemptRequest memory _req = _request(
      _holderAccount,
      _r,
      _payload,
      IPolicyManager.PaymentOrder(_token, 10e6, _sponsor),
      uint48(block.timestamp + 24 hours)
    );
    _approversApprove(_req, _r);
    _submits(_sponsor, _req);
    skip(5 days);
    _executes(_executor, _holderAccount, _payload);
    _assertKeyControls(_holderAccount, _new, string.concat(_who, ' new key'));
    assertEq(_usdc.balanceOf(_holderAccount), 100e6, 'the account kept its USDC');
  }
}

/// @notice The account pays the sponsor 0.004 ETH, about 10 dollars, a named payee in native ETH. This kind also
///         carries the re-entering payee and the trade-offs a native payment brings.
contract SponsorRepaidAtExecutionInEth is SponsorRepaidAtExecution {
  function _agreedOrder() internal view override returns (IPolicyManager.PaymentOrder memory _order) {
    _order = IPolicyManager.PaymentOrder(address(0), 0.004 ether, _sponsor);
  }

  function _heldBy(address _holder) internal view override returns (uint256 _balance) {
    _balance = _holder.balance;
  }

  function _whoIsPaid(address) internal view override returns (address _paid) {
    _paid = _sponsor;
  }

  function _holderMovesEverythingOut() internal override {
    // The holder's key sends all the account's ETH to the holder's exchange address.
    _keyTransfers(_account, _originalKey, makeAddr('exchange'), _account.balance);
  }

  function _friendFundsTheAccount(uint256 _amount) internal override {
    // The friend sends the ETH from their own wallet.
    vm.prank(_friend);
    (bool _sent,) = _account.call{value: _amount}('');
    assertTrue(_sent, 'the friend funded the account');
  }

  function _expectTheAccountCannotPay() internal override {
    // A native call with more value than the account holds fails with no reason.
    vm.expectRevert(bytes(''));
  }

  /*///////////////////////////////////////////////////////////////
                              EVEN IF
  ///////////////////////////////////////////////////////////////*/

  /// @notice The payee contract receives the ETH, sends the same batch to the account again and catches the failure:
  ///         the nested run reverts because the attempt is already spent, not on a later check, and the handover
  ///         completes once, paying once.
  function test_WhenThePayeeReentersWithTheSameBatch() external {
    // The sponsor's contract wallet is the payee, and the approvers open the attempt paying it 0.004 ETH.
    ReenteringPayee _payee = new ReenteringPayee();
    bytes memory _payload =
      _approversOpenTheAttempt(IPolicyManager.PaymentOrder(address(0), 0.004 ether, address(_payee)));
    skip(5 days);

    // The payee is set to send the approved batch again from inside its payment.
    (
      IAmbireRecoveryAction.Transaction memory _consume,
      IAmbireRecoveryAction.Transaction memory _grant,
      IAmbireRecoveryAction.Transaction memory _revoke
    ) = _handoverCalls(_payload);
    _payee.aim(
      _account, _batch(_consume, _grant, _revoke, _transferCall(address(_payee), 0.004 ether)), _kitSignature()
    );
    uint256 _accountEth = _account.balance;
    uint256 _payeeEth = address(_payee).balance;

    // A bot executes.
    _executes(_executor, _account, _payload);

    // The nested run failed on the spent attempt, the payee was paid once, and the handover completed once.
    IPolicyManager.Attempt memory _spent = _attempt(_account);
    assertTrue(_payee.nestedRunFailed(), 'the nested run failed');
    assertEq(
      _payee.nestedRevertData(),
      abi.encodeWithSelector(
        IRecoveryAction.RecoveryAction_NotConsumable.selector,
        _account,
        IPolicyManager.AttemptState.Consumed,
        _spent.consumableAfter,
        _spent.payloadHash
      ),
      'the nested run met the spent attempt'
    );
    assertEq(_payee.payments(), 1, 'the payee was paid once');
    assertEq(address(_payee).balance - _payeeEth, 0.004 ether, 'the payee received one payment');
    assertEq(_accountEth - _account.balance, 0.004 ether, 'the account paid once');
    assertEq(uint8(_attempt(_account).state), uint8(IPolicyManager.AttemptState.Consumed), 'the attempt is spent');
    _assertKeyControls(_account, _newKey, 'the new key');
  }

  /*///////////////////////////////////////////////////////////////
                             TRADE-OFFS
  ///////////////////////////////////////////////////////////////*/

  /// @notice A named payee that refuses ETH holds the attempt hostage: nothing executes, a month later still nothing,
  ///         and no other set can open meanwhile. The keyless holder's approvers clear it by a cancel by proofs and
  ///         open the next id.
  function test_WhenTheNamedPayeeRevertsAndHoldsTheSlot() external {
    // The sponsor's contract wallet refuses ETH, and the approvers open the attempt paying it.
    RefusingPayee _payee = new RefusingPayee();
    bytes memory _payload =
      _approversOpenTheAttempt(IPolicyManager.PaymentOrder(address(0), 0.004 ether, address(_payee)));

    // The wait passes, and a bot executes. It reverts.
    skip(5 days);
    vm.prank(_executor);
    vm.expectPartialRevert(RefusingPayee.RefusingPayee_Refused.selector);
    _action.executeHandover(_account, _payload);

    // A month later another satisfying set, Ana, Carla and the hardware wallet, sends its request, and it cannot open.
    skip(30 days);
    Rule memory _r = _holderRule;
    IPolicyManager.AttemptRequest memory _other = _request(
      _account, _r, _handover(_newKey.addr, _originalKey.addr), _agreedOrder(), uint48(block.timestamp + 24 hours)
    );
    _signApproval(_other, _r, 0);
    _signApproval(_other, _r, 2);
    _signApproval(_other, _r, 3);
    vm.prank(_friend);
    vm.expectPartialRevert(IPolicyManager.PolicyManager_AttemptAlreadyActive.selector);
    _manager.startAttempt(_other);

    // The bot tries again, and it still reverts.
    vm.prank(_executor);
    vm.expectPartialRevert(RefusingPayee.RefusingPayee_Refused.selector);
    _action.executeHandover(_account, _payload);
    assertEq(_privilegeOf(_account, _newKey.addr), bytes32(0), 'the new key is not installed');

    // Ben, Carla and Maya's passkey cancel the stuck attempt by proofs.
    _approversCancel();

    // The approvers open the next id paying the sponsor's plain wallet, the wait passes, and a bot executes.
    bytes memory _fresh = _approversOpenTheAttempt(_agreedOrder());
    assertEq(_attempt(_account).attemptId, 2, 'the next id opened');
    skip(5 days);
    _executes(_executor, _account, _fresh);

    // The new key holds the account at last, and the sponsor was paid.
    _assertKeyControls(_account, _newKey, 'the new key');
    assertEq(_sponsor.balance, 10 ether + 0.004 ether, 'the sponsor was paid');
  }

  /// @notice The price is fixed at signing and paid days later. ETH halves during the wait, so the approvers cancel and
  ///         open a fresh attempt at the new price: the sponsor who paid for the first opening is never repaid for it,
  ///         and the fresh attempt pays the new price once, after its own full wait.
  function test_WhenTheAttemptIsCancelledAndTheSponsorIsUnpaid() external {
    // The sponsor pays for the opening, which carries 0.004 ETH, about 10 dollars at signing.
    bytes memory _first = _approversOpenTheAttempt(_agreedOrder());

    // Two days later ETH has halved, and the approvers cancel to sign a new price.
    skip(2 days);
    _approversCancel();

    // The first wait would have ended, and the sponsor tries to execute the first attempt. Nothing pays.
    skip(3 days);
    vm.prank(_sponsor);
    vm.expectPartialRevert(IRecoveryAction.RecoveryAction_NotConsumable.selector);
    _action.executeHandover(_account, _first);
    assertEq(_sponsor.balance, 10 ether, 'the sponsor was not repaid for the first opening');

    // The approvers open a fresh attempt at 0.008 ETH, which waits its own five days.
    bytes memory _repriced = _approversOpenTheAttempt(IPolicyManager.PaymentOrder(address(0), 0.008 ether, _sponsor));
    skip(5 days);
    _executes(_executor, _account, _repriced);

    // The sponsor received the new price, once.
    assertEq(_sponsor.balance, 10 ether + 0.008 ether, 'the sponsor was paid the new price once');
    _assertKeyControls(_account, _newKey, 'the new key');
  }
}

/// @notice The order names no payee and pays 10 USDC to whoever calls executeHandover. This kind also carries the hand-
///         built batch that names the zero address as payee of an open native order.
contract SponsorRepaidAtExecutionToTheCaller is SponsorRepaidAtExecutionInUsdc {
  function _agreedOrder() internal view override returns (IPolicyManager.PaymentOrder memory _order) {
    _order = IPolicyManager.PaymentOrder(address(_usdc), 10e6, address(0));
  }

  function _whoIsPaid(address _caller) internal pure override returns (address _paid) {
    _paid = _caller;
  }

  /// @notice For an open order in ETH, someone sends the batch by hand naming the zero address as payee. The account
  ///         skips a call to the zero address, so the handover completes and nobody is paid.
  function test_WhenAnOpenNativeOrderNamesTheZeroPayee() external {
    // The approvers open the attempt with an open order of 0.004 ETH, and the wait passes.
    bytes memory _payload = _approversOpenTheAttempt(IPolicyManager.PaymentOrder(address(0), 0.004 ether, address(0)));
    skip(5 days);
    uint256 _accountEth = _account.balance;

    // Someone builds the batch by hand, paying 0.004 ETH to the zero address, and sends it with the kit's signature.
    (
      IAmbireRecoveryAction.Transaction memory _consume,
      IAmbireRecoveryAction.Transaction memory _grant,
      IAmbireRecoveryAction.Transaction memory _revoke
    ) = _handoverCalls(_payload);
    IAmbireRecoveryAction.Transaction[] memory _calls = _batch(
      _consume, _grant, _revoke, IAmbireRecoveryAction.Transaction({to: address(0), value: 0.004 ether, data: ''})
    );
    bytes memory _signature = _kitSignature();
    vm.prank(_friend);
    IAmbireAccount(_account).execute(_calls, _signature);

    // The handover landed, and no ETH left the account.
    assertEq(_account.balance, _accountEth, 'nobody was paid');
    _assertKeyControls(_account, _newKey, 'the new key');
    _assertKeyLocked(_account, _originalKey);
  }
}
