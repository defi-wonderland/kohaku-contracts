// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {IPolicyManager} from 'interfaces/IPolicyManager.sol';
import {IRecoveryAction} from 'interfaces/IRecoveryAction.sol';

import {IAmbireAccount} from 'contracts/actions/ambire/IAmbireAccount.sol';
import {IAmbireRecoveryAction} from 'contracts/actions/ambire/IAmbireRecoveryAction.sol';

import {IntegrationBase} from 'test/integration/base/IntegrationBase.sol';

/// @notice Bob still holds his account key, but his bag with the synced passkey and the hardware wallet is in an
///         attacker's hands. The attacker opens a recovery to their own key, and Bob stops it with his key alone, then
///         commits a new setup without the stolen credentials. The story is told once; each kind below says how Bob's
///         key sends the account batch.
abstract contract OwnerCancelsUnwantedRecovery is IntegrationBase {
  /// @notice Bob's account.
  address internal _account;
  /// @notice Bob's rule: any 2 of his passkey, his hardware wallet and his passport, with a 48-hour wait.
  Rule internal _bobsRule;

  function setUp() public virtual override {
    super.setUp();
    _account = _openBobsAccount();
    Rule memory _r = _rule(
      _account,
      48 hours,
      false,
      _thresholds(2),
      _sizes(3),
      _credentials(_passkey(_mayaPasskey), _walletGuardian(_hardwareWallet), _passport(keccak256('Bob passport chip')))
    );
    _keep(_bobsRule, _r);
    _setUpRecovery(_account, _originalKey, _r);
  }

  /*///////////////////////////////////////////////////////////////
                         WHAT EACH KIND SAYS
  ///////////////////////////////////////////////////////////////*/

  /// @notice Opens Bob's account with his key.
  function _openBobsAccount() internal virtual returns (address _bobsAccount) {
    _bobsAccount = _openAccount(_originalKey.addr);
  }

  /// @notice Bob's key sends an account batch.
  function _bobSends(IAmbireRecoveryAction.Transaction[] memory _calls) internal virtual;

  /*///////////////////////////////////////////////////////////////
                              THE WALK
  ///////////////////////////////////////////////////////////////*/

  /// @notice Bob's own key cancels the attacker's recovery, the attacker's execution after the wait reverts, and once
  ///         Bob commits a new setup the stolen credentials open nothing. Holding the key is enough to stop any
  ///         recovery, whatever the attacker holds.
  function test_WhenTheHolderCancelsAndReplacesTheRule() external {
    uint256 _accountBalance = _account.balance;

    // The attacker signs approvals with Bob's passkey and hardware wallet, handing the account to their own key.
    bytes memory _payload = _openAttackersAttempt();

    // Some hours pass.
    skip(6 hours);

    // Bob's account sends cancelByOwner.
    _bobSends(_batch(_cancelByOwnerCall()));

    // The 48 hours pass, and the attacker sends executeHandover. It reverts.
    skip(48 hours);
    vm.prank(_attacker.addr);
    vm.expectPartialRevert(IRecoveryAction.RecoveryAction_NotConsumable.selector);
    _action.executeHandover(_account, _payload);

    // Bob commits a new setup without the stolen credentials, his passport and a new hardware wallet, in its own
    // transaction.
    Rule memory _newRule = _rule(
      _account,
      48 hours,
      false,
      _thresholds(2),
      _sizes(2),
      _credentials(_passport(keccak256('Bob passport chip')), _walletGuardian(_person('Bob new hardware wallet')))
    );
    _bobSends(_batch(_commitCall(_account, _newRule, 2)));

    // The attacker signs a new request with the passkey and the hardware wallet and sends it. It fails.
    IPolicyManager.AttemptRequest memory _next = _attackersRequest();
    vm.prank(_attacker.addr);
    vm.expectPartialRevert(IPolicyManager.PolicyManager_SetupCommitmentMismatch.selector);
    _manager.startAttempt(_next);

    // The attacker's attempt was cancelled, and Bob's key is still the only key on the account.
    assertEq(uint8(_attempt(_account).state), uint8(IPolicyManager.AttemptState.Cancelled), 'the attempt is cancelled');
    assertEq(_privilegeOf(_account, _attacker.addr), bytes32(0), 'the attacker holds nothing');
    assertEq(_account.balance, _accountBalance, 'nothing left the account');
    _assertKeyControls(_account, _originalKey, 'Bob key');
  }

  /*///////////////////////////////////////////////////////////////
                              UTILITIES
  ///////////////////////////////////////////////////////////////*/

  /// @notice The attacker's request for the next attempt, handing the account from Bob's key to theirs, approved with
  ///         the stolen passkey at place 0 and the stolen hardware wallet at place 1 under the rule Bob set up.
  function _attackersRequest() internal view returns (IPolicyManager.AttemptRequest memory _req) {
    Rule memory _r = _bobsRule;
    _req = _request(
      _account, _r, _handover(_attacker.addr, _originalKey.addr), _noPayment(), uint48(block.timestamp + 24 hours)
    );
    _signApproval(_req, _r, 0);
    _signApproval(_req, _r, 1);
  }

  /// @notice The attacker approves with the stolen devices and opens the attempt, and the payload is returned.
  function _openAttackersAttempt() internal returns (bytes memory _payload) {
    IPolicyManager.AttemptRequest memory _req = _attackersRequest();
    _payload = _req.payload;
    _submits(_attacker.addr, _req);
  }

  /// @notice Bob's own request: his hardware wallet at place 1 and his passport at place 2 approve the payload, with
  ///         the given order and window.
  function _bobsOwnRequest(bytes memory _payload, IPolicyManager.PaymentOrder memory _order, uint48 _validUntil)
    internal
    view
    returns (IPolicyManager.AttemptRequest memory _req)
  {
    Rule memory _r = _bobsRule;
    _req = _request(_account, _r, _payload, _order, _validUntil);
    _signApproval(_req, _r, 1);
    _signApproval(_req, _r, 2);
  }
}

/// @notice Bob's key signs the account batch and a relayer sends it. This kind also carries the cases where the cancel
///         must hold even if someone tries something else, and the trade-offs the kit accepts.
contract OwnerCancelsUnwantedRecoveryWithARelayedBatch is OwnerCancelsUnwantedRecovery {
  /// @notice Local only: its own cases lean on Bob's passport, which no story can prove on a fork.
  function _runsOnForks() internal pure override returns (bool _runs) {
    _runs = false;
  }

  function _bobSends(IAmbireRecoveryAction.Transaction[] memory _calls) internal override {
    // Bob's key signs the batch, and a relayer sends it.
    _keySignsAndRelayerSends(_account, _originalKey, _calls);
  }

  /*///////////////////////////////////////////////////////////////
                              EVEN IF
  ///////////////////////////////////////////////////////////////*/

  /// @notice After the wait, Bob's cancel and the attacker's execution land in the same block, the cancel first. The
  ///         cancel wins and the execution reverts, so a late cancel still counts if it is ordered first.
  function test_WhenTheCancelComesBeforeTheSpend() external {
    // The attacker opens the attempt, and the wait passes.
    bytes memory _payload = _openAttackersAttempt();
    skip(48 hours);

    // In one block, Bob's cancel comes first.
    _bobSends(_batch(_cancelByOwnerCall()));

    // Then, in the same block, the attacker calls executeHandover.
    vm.prank(_attacker.addr);
    vm.expectPartialRevert(IRecoveryAction.RecoveryAction_NotConsumable.selector);
    _action.executeHandover(_account, _payload);

    // Bob keeps the account.
    _assertKeyControls(_account, _originalKey, 'Bob key');
    assertEq(_privilegeOf(_account, _attacker.addr), bytes32(0), 'the attacker holds nothing');
  }

  /// @notice After the wait, the attacker's execution and Bob's cancel land in the same block, the execution first. The
  ///         execution wins and Bob's key is gone before his cancel runs: past the wait, ordering decides.
  function test_WhenTheSpendComesBeforeTheCancel() external {
    // The attacker opens the attempt, and the wait passes. Bob signs his cancel.
    bytes memory _payload = _openAttackersAttempt();
    skip(48 hours);
    IAmbireRecoveryAction.Transaction[] memory _cancel = _batch(_cancelByOwnerCall());
    bytes memory _bobsSignature = _keySigns(_account, _originalKey.key, _cancel);

    // In one block, the attacker's executeHandover comes first.
    _executes(_attacker.addr, _account, _payload);

    // Then, in the same block, Bob's signed cancel arrives, and the account no longer knows his key.
    vm.prank(_relayer);
    vm.expectRevert(bytes('INSUFFICIENT_PRIVILEGE'));
    IAmbireAccount(_account).execute(_cancel, _bobsSignature);

    // The attacker controls the account, and Bob's key is locked out.
    _assertKeyControls(_account, _attacker, 'the attacker key');
    _assertKeyLocked(_account, _originalKey);
  }

  /*///////////////////////////////////////////////////////////////
                             TRADE-OFFS
  ///////////////////////////////////////////////////////////////*/

  /// @notice Right after Bob cancels, the attacker reopens at the next attempt id with the same stolen devices, and Bob
  ///         must cancel again. Each attempt costs Bob one cancel until he changes the rule.
  function test_WhenTheAttackerReopensAfterTheCancel() external {
    // The attacker opens attempt 1, and Bob's key cancels it.
    _openAttackersAttempt();
    _bobSends(_batch(_cancelByOwnerCall()));

    // Right away the attacker opens attempt 2 with the same stolen devices.
    bytes memory _payload = _openAttackersAttempt();
    assertEq(_attempt(_account).attemptId, 2, 'attempt 2 opened');

    // Bob's key cancels again, and the attacker opens attempt 3.
    _bobSends(_batch(_cancelByOwnerCall()));
    _payload = _openAttackersAttempt();
    assertEq(_attempt(_account).attemptId, 3, 'attempt 3 opened');

    // Had Bob not cancelled this one too, it would hand the account over once the wait passes.
    skip(48 hours);
    _executes(_attacker.addr, _account, _payload);
    _assertKeyLocked(_account, _originalKey);
    _assertKeyControls(_account, _attacker, 'the attacker key');
  }

  /// @notice Bob opened his own recovery to move the account to a new key, and then sends cancelByOwner to stop what he
  ///         takes for a hostile attempt. The cancel names no attempt id, so it cancels whatever attempt is live, his
  ///         own included.
  function test_WhenTheCancelMeetsTheHoldersOwnAttempt() external {
    // Bob's hardware wallet and passport open his own recovery to his new key.
    bytes memory _payload = _handover(_newKey.addr, _originalKey.addr);
    _submits(_friend, _bobsOwnRequest(_payload, _noPayment(), uint48(block.timestamp + 24 hours)));

    // Bob's key sends cancelByOwner, meaning to stop an attacker's attempt.
    _bobSends(_batch(_cancelByOwnerCall()));

    // The wait passes, and Bob's own handover cannot run.
    skip(48 hours);
    vm.prank(_executor);
    vm.expectPartialRevert(IRecoveryAction.RecoveryAction_NotConsumable.selector);
    _action.executeHandover(_account, _payload);
    assertEq(uint8(_attempt(_account).state), uint8(IPolicyManager.AttemptState.Cancelled), 'his attempt is cancelled');
    assertEq(_privilegeOf(_account, _newKey.addr), bytes32(0), 'the new key was never installed');
  }

  /// @notice A thief found Bob's lost key. Each time Bob's approvers open his own recovery, the thief cancels it with
  ///         that key, and the keyless Bob cannot win: the kit defends against loss, not theft.
  function test_WhenAThiefWithALostKeyCancelsEveryRecovery() external {
    // Bob lost the laptop holding his key, and a thief found it. Bob's hardware wallet and passport approve a
    // handover to his new key.
    bytes memory _payload = _handover(_newKey.addr, _originalKey.addr);
    _submits(_friend, _bobsOwnRequest(_payload, _noPayment(), uint48(block.timestamp + 24 hours)));

    // The thief signs cancelByOwner with the laptop key, and it cancels Bob's recovery.
    _bobSends(_batch(_cancelByOwnerCall()));
    assertEq(uint8(_attempt(_account).state), uint8(IPolicyManager.AttemptState.Cancelled), 'attempt 1 is cancelled');

    // Bob's approvers open attempt 2, and the thief cancels it the same way.
    _submits(_friend, _bobsOwnRequest(_payload, _noPayment(), uint48(block.timestamp + 24 hours)));
    _bobSends(_batch(_cancelByOwnerCall()));
    assertEq(uint8(_attempt(_account).state), uint8(IPolicyManager.AttemptState.Cancelled), 'attempt 2 is cancelled');

    // The wait passes, and nobody can execute Bob's handover.
    skip(48 hours);
    vm.prank(_executor);
    vm.expectPartialRevert(IRecoveryAction.RecoveryAction_NotConsumable.selector);
    _action.executeHandover(_account, _payload);

    // The thief still moves funds with the laptop key, and the new key holds nothing.
    assertEq(_privilegeOf(_account, _newKey.addr), bytes32(0), 'the new key was never installed');
    _assertKeyControls(_account, _originalKey, 'the thief with the laptop key');
  }

  /// @notice Bob started a recovery repaying a sponsor, found his key again and forgot the attempt. Nothing expires: a
  ///         year later whoever holds the new key's device executes it and removes the key Bob still uses, and the
  ///         sponsor, who gains by leaving the attempt alone, is paid. Meanwhile the attempt holds the slot.
  function test_WhenNobodyCancelsAForgottenAttempt() external {
    // A sponsor paid for the opening, and Bob's approvers opened the attempt repaying them 10 USDC.
    _usdc.mint(_account, 100e6);
    address _sponsor = _funded('sponsor');
    bytes memory _payload = _handover(_newKey.addr, _originalKey.addr);
    _submits(
      _sponsor,
      _bobsOwnRequest(
        _payload, IPolicyManager.PaymentOrder(address(_usdc), 10e6, _sponsor), uint48(block.timestamp + 24 hours)
      )
    );

    // Bob finds his key again, keeps using it every day, and forgets the attempt.
    skip(5 days);
    _assertKeyControls(_account, _originalKey, 'Bob key');

    // Months later Bob's approvers try to open another recovery, and the forgotten attempt still holds the slot.
    skip(180 days);
    IPolicyManager.AttemptRequest memory _other =
      _bobsOwnRequest(_handover(_secondNewKey.addr, _originalKey.addr), _noPayment(), uint48(block.timestamp + 1 days));
    vm.prank(_friend);
    vm.expectPartialRevert(IPolicyManager.PolicyManager_AttemptAlreadyActive.selector);
    _manager.startAttempt(_other);

    // A year after the opening, whoever holds the new key's old device sends executeHandover.
    skip(180 days);
    _executes(_newKey.addr, _account, _payload);

    // The account is the new key's, the key Bob still used is removed, and the sponsor was paid.
    _assertKeyControls(_account, _newKey, 'the new key');
    _assertKeyLocked(_account, _originalKey);
    assertEq(_usdc.balanceOf(_sponsor), 10e6, 'the sponsor was paid');
  }

  /// @notice Bob's approvers signed a request handing the account to a new key whose device Bob then lost, and the
  ///         signed request leaked. Until its window ends anyone can send it, and a keyless Bob has nothing he can
  ///         send to retire it.
  function test_WhenALeakedRequestIsSentByAnyone() external {
    // Bob's key is gone. His hardware wallet and passport sign a request handing the account to his new key, valid for
    // three days.
    bytes memory _payload = _handover(_newKey.addr, _originalKey.addr);
    IPolicyManager.AttemptRequest memory _leaked =
      _bobsOwnRequest(_payload, _noPayment(), uint48(block.timestamp + 3 days));

    // Bob loses the device holding the new key, and the signed request leaks. Nothing is open, so nothing can be
    // cancelled yet.
    assertEq(uint8(_attempt(_account).state), uint8(IPolicyManager.AttemptState.None), 'nothing to cancel');

    // An hour before the window ends, someone else sends the leaked request, and it opens.
    vm.warp(_leaked.validUntil - 1 hours);
    _submits(makeAddr('someone else'), _leaked);
    assertEq(uint8(_attempt(_account).state), uint8(IPolicyManager.AttemptState.Waiting), 'the leaked request opened');

    // Once the wait passes, whoever found the lost device holds the account.
    skip(48 hours);
    _executes(_executor, _account, _payload);
    _assertKeyControls(_account, _newKey, 'the finder of the new key device');
  }
}

/// @notice Bob's key sends the account batch itself, with no signature.
contract OwnerCancelsUnwantedRecoveryWithBobsKeySendingItself is OwnerCancelsUnwantedRecovery {
  function _bobSends(IAmbireRecoveryAction.Transaction[] memory _calls) internal override {
    // Bob's key calls executeBySender on the account.
    _keySendsItself(_account, _originalKey, _calls);
  }
}

/// @notice Bob's key signs an ERC-4337 operation that a paymaster sponsors, on an account that lets the entry point run
///         its operations.
contract OwnerCancelsUnwantedRecoveryThroughASponsoredOperation is OwnerCancelsUnwantedRecovery {
  function _openBobsAccount() internal override returns (address _bobsAccount) {
    _bobsAccount = _openAccountWithEntryPoint(_originalKey.addr);
  }

  function _bobSends(IAmbireRecoveryAction.Transaction[] memory _calls) internal override {
    // Bob's key signs an operation running the batch, and the paymaster sponsors it.
    _keySendsSponsoredOperation(_account, _originalKey, _calls);
  }
}
