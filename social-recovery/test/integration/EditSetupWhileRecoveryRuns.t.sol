// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {IPolicyManager} from 'interfaces/IPolicyManager.sol';
import {IRecoveryAction} from 'interfaces/IRecoveryAction.sol';

import {IAmbireAccount} from 'contracts/actions/ambire/IAmbireAccount.sol';
import {IAmbireRecoveryAction} from 'contracts/actions/ambire/IAmbireRecoveryAction.sol';

import {IntegrationBase} from 'test/integration/base/IntegrationBase.sol';

/// @notice The holder still has their key and edits the setup while an attacker's attempt waits. The edit cancels the
///         attempt in its own transaction, and every approval signed before it stops counting, even when the rule
///         written back is the very same one.
contract EditSetupWhileRecoveryRuns is IntegrationBase {
  /// @notice The holder's account.
  address internal _account;
  /// @notice The holder's rule, Maya's rule, as the backup holds it.
  Rule internal _holderRule;

  function setUp() public override {
    super.setUp();
    _account = _openAccount(_originalKey.addr);
    Rule memory _r = _mayaRule(_account);
    _keep(_holderRule, _r);
    _setUpRecovery(_account, _originalKey, _r);
  }

  /*///////////////////////////////////////////////////////////////
                              THE WALK
  ///////////////////////////////////////////////////////////////*/

  /// @notice The holder commits the identical rule under nonce 2. The attacker's waiting attempt is cancelled in that
  ///         transaction, and the approvals the attacker gathered under nonce 1 are dead, even rewritten to nonce 2.
  ///         Editing is how a holder with their key shuts out approvers they no longer trust.
  function test_WhenTheHolderRewritesTheIdenticalRule() external {
    // Attempt 1 waits under nonce 1, and the attacker holds a satisfying set of approvals for attempt 2.
    (bytes memory _payload, IPolicyManager.AttemptRequest memory _next) = _attackerWaitsAndHoldsTheNext();

    // The holder sends commitSetup with the identical body under nonce 2.
    _keySignsAndRelayerSends(_account, _originalKey, _batch(_commitCall(_account, _holderRule, 2)));
    assertEq(uint8(_attempt(_account).state), uint8(IPolicyManager.AttemptState.Cancelled), 'the edit cancelled it');

    // The attacker sends the request for attempt 2, signed under nonce 1. It fails.
    vm.prank(_attacker.addr);
    vm.expectPartialRevert(IPolicyManager.PolicyManager_WrongSetupNonce.selector);
    _manager.startAttempt(_next);

    // The attacker rewrites the same request to nonce 2, keeping the signatures. It fails too.
    IPolicyManager.AttemptRequest memory _restamped = _copy(_next);
    _restamped.setupNonce = 2;
    vm.prank(_attacker.addr);
    vm.expectPartialRevert(IPolicyManager.PolicyManager_ProofRejected.selector);
    _manager.startAttempt(_restamped);

    // The wait passes, and the attacker sends executeHandover for attempt 1. It reverts.
    skip(5 days);
    vm.prank(_attacker.addr);
    vm.expectPartialRevert(IRecoveryAction.RecoveryAction_NotConsumable.selector);
    _action.executeHandover(_account, _payload);

    // The holder's key still controls the account, and the attacker holds nothing.
    _assertKeyControls(_account, _originalKey, 'the holder key');
    assertEq(_privilegeOf(_account, _attacker.addr), bytes32(0), 'the attacker holds nothing');
  }

  /*///////////////////////////////////////////////////////////////
                              EVEN IF
  ///////////////////////////////////////////////////////////////*/

  /// @notice The holder clears the setup and then commits the very same body again, and the proofs signed before the
  ///         clear still fail, rewritten to the new nonce or not.
  function test_WhenTheHolderClearsAndRecommitsTheSameRule() external {
    // Attempt 1 waits, and the attacker holds approvals for attempt 2.
    (, IPolicyManager.AttemptRequest memory _next) = _attackerWaitsAndHoldsTheNext();

    // The holder clears the setup, then commits the very same body under the next nonce.
    _keySignsAndRelayerSends(_account, _originalKey, _batch(_clearCall()));
    uint64 _nonce = _stateOf(_account).setupNonce + 1;
    _keySignsAndRelayerSends(_account, _originalKey, _batch(_commitCall(_account, _holderRule, _nonce)));

    // The attacker sends the old approvals as they were signed. They fail.
    vm.prank(_attacker.addr);
    vm.expectPartialRevert(IPolicyManager.PolicyManager_WrongSetupNonce.selector);
    _manager.startAttempt(_next);

    // The attacker rewrites them to the current nonce, keeping the signatures. They fail.
    IPolicyManager.AttemptRequest memory _restamped = _copy(_next);
    _restamped.setupNonce = _nonce;
    vm.prank(_attacker.addr);
    vm.expectPartialRevert(IPolicyManager.PolicyManager_ProofRejected.selector);
    _manager.startAttempt(_restamped);
    assertEq(uint8(_attempt(_account).state), uint8(IPolicyManager.AttemptState.Cancelled), 'nothing waits');
  }

  /// @notice In the first block after the wait, the holder's edit is ordered before the attacker's execute. The edit
  ///         wins, and the execute in the same block finds nothing to spend.
  function test_WhenTheEditComesBeforeTheSpend() external {
    // The attacker's attempt waits, and the first block after the wait arrives.
    (bytes memory _payload,) = _attackerWaitsAndHoldsTheNext();
    vm.warp(_attempt(_account).consumableAfter);

    // The holder's edit is ordered first in the block.
    _keySignsAndRelayerSends(_account, _originalKey, _batch(_commitCall(_account, _holderRule, 2)));

    // The attacker's execute comes next in the same block, and reverts.
    vm.prank(_attacker.addr);
    vm.expectPartialRevert(IRecoveryAction.RecoveryAction_NotConsumable.selector);
    _action.executeHandover(_account, _payload);

    // The holder keeps the account.
    _assertKeyControls(_account, _originalKey, 'the holder key');
    assertEq(_privilegeOf(_account, _attacker.addr), bytes32(0), 'the attacker holds nothing');
  }

  /// @notice In the first block after the wait, the attacker's execute is ordered before the holder's edit. The account
  ///         is handed over, and the edit the holder signed is refused. Waiting until the last moment can lose the
  ///         account.
  function test_WhenTheSpendComesBeforeTheEdit() external {
    // The attacker's attempt waits, the first block after the wait arrives, and the holder signs the edit.
    (bytes memory _payload,) = _attackerWaitsAndHoldsTheNext();
    vm.warp(_attempt(_account).consumableAfter);
    IAmbireRecoveryAction.Transaction[] memory _edit = _batch(_commitCall(_account, _holderRule, 2));
    bytes memory _signature = _keySigns(_account, _originalKey.key, _edit);

    // The attacker's execute is ordered first in the block, and hands the account to the attacker's key.
    _executes(_attacker.addr, _account, _payload);

    // The holder's edit comes next in the same block, and the account no longer knows the holder's key.
    vm.prank(_relayer);
    vm.expectRevert(bytes('INSUFFICIENT_PRIVILEGE'));
    IAmbireAccount(_account).execute(_edit, _signature);

    // The account is the attacker's.
    _assertKeyControls(_account, _attacker, 'the attacker key');
    _assertKeyLocked(_account, _originalKey);
  }

  /*///////////////////////////////////////////////////////////////
                             TRADE-OFFS
  ///////////////////////////////////////////////////////////////*/

  /// @notice A thief who took the holder's key replaces the setup with his own rule, and it holds in the same block,
  ///         with no wait and no notice: Maya's guardians are shut out at once and the thief's own attempt opens.
  function test_WhenAThiefReplacesTheRule() external {
    // Maya's phone, with her key, is stolen. The thief commits a rule of his own wallet alone, with a one-hour wait.
    Rule memory _thiefRule =
      _rule(_account, 1 hours, false, _thresholds(1), _sizes(1), _credentials(_walletGuardian(_attacker)));
    _keySignsAndRelayerSends(_account, _originalKey, _batch(_commitCall(_account, _thiefRule, 2)));

    // In the same block, Maya's guardians approve a handover to her new key under the rule her backup holds, and it
    // fails.
    Rule memory _r = _holderRule;
    IPolicyManager.AttemptRequest memory _maya = _request(
      _account, _r, _handover(_newKey.addr, _originalKey.addr), _noPayment(), uint48(block.timestamp + 24 hours)
    );
    _signApproval(_maya, _r, 1);
    _signApproval(_maya, _r, 2);
    _signApproval(_maya, _r, 4);
    vm.prank(_friend);
    vm.expectPartialRevert(IPolicyManager.PolicyManager_SetupCommitmentMismatch.selector);
    _manager.startAttempt(_maya);

    // In the same block, the thief opens an attempt under his own rule, and an hour later it hands him the account.
    bytes memory _payload = _handover(_attacker.addr, _originalKey.addr);
    IPolicyManager.AttemptRequest memory _thief =
      _request(_account, _thiefRule, _payload, _noPayment(), uint48(block.timestamp + 24 hours));
    _signApproval(_thief, _thiefRule, 0);
    _submits(_attacker.addr, _thief);
    skip(1 hours);
    _executes(_attacker.addr, _account, _payload);
    _assertKeyControls(_account, _attacker, 'the thief key');
  }

  /*///////////////////////////////////////////////////////////////
                              UTILITIES
  ///////////////////////////////////////////////////////////////*/

  /// @notice The given: the attacker phished Ben, Carla and Maya's hardware wallet. With their approvals the attacker
  ///         opens attempt 1 handing the account to the attacker's key, then has them sign the same handover again for
  ///         attempt 2, under the same setup nonce.
  function _attackerWaitsAndHoldsTheNext()
    internal
    returns (bytes memory _payload, IPolicyManager.AttemptRequest memory _next)
  {
    Rule memory _r = _holderRule;
    _payload = _handover(_attacker.addr, _originalKey.addr);
    IPolicyManager.AttemptRequest memory _req =
      _request(_account, _r, _payload, _noPayment(), uint48(block.timestamp + 30 days));
    _phishedGuardiansApprove(_req, _r);
    _submits(_attacker.addr, _req);
    _next = _request(_account, _r, _payload, _noPayment(), uint48(block.timestamp + 30 days));
    _phishedGuardiansApprove(_next, _r);
  }

  /// @notice Ben, Carla and Maya's hardware wallet, in the attacker's hands, sign the approval for their places.
  function _phishedGuardiansApprove(IPolicyManager.AttemptRequest memory _req, Rule memory _r) internal view {
    _signApproval(_req, _r, 1);
    _signApproval(_req, _r, 2);
    _signApproval(_req, _r, 3);
  }
}
