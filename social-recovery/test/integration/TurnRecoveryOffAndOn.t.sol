// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {IPolicyManager} from 'interfaces/IPolicyManager.sol';
import {IRecoveryAction} from 'interfaces/IRecoveryAction.sol';

import {IAmbireAccount} from 'contracts/actions/ambire/IAmbireAccount.sol';
import {IAmbireRecoveryAction} from 'contracts/actions/ambire/IAmbireRecoveryAction.sol';

import {IntegrationBase} from 'test/integration/base/IntegrationBase.sol';
import {LocalAmbireAccount} from 'test/integration/base/LocalAmbire.sol';

/// @notice A holder with their key turns recovery off, clearing the setup and removing the kit's binding in one batch,
///         and months later turns it back on. Turning it off halfway, by removing the binding alone, leaves a live
///         setup that releases a waiting attempt the moment the binding returns.
contract TurnRecoveryOffAndOn is IntegrationBase {
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

  /// @notice After recovery is turned off no request opens anything and the kit's signature moves nothing. After it is
  ///         turned back on a recovery works, and the attempt id continues where it was rather than restarting at 1, so
  ///         no approval signed for an old id can come back.
  function test_WhenTheHolderTurnsRecoveryOffAndOn() external {
    // Earlier, Maya tried her approvers once: attempt 1 opened and she cancelled it with her key.
    _approversOpen(_handover(_newKey.addr, _originalKey.addr));
    _keySignsAndRelayerSends(_account, _originalKey, _batch(_cancelByOwnerCall(_attempt(_account).attemptId)));

    // The approvers had also signed a request for attempt 2, valid for a year, which someone kept.
    IPolicyManager.AttemptRequest memory _old =
      _approversSign(_handover(_newKey.addr, _originalKey.addr), uint48(block.timestamp + 365 days));

    // The holder sends one batch, clearSetup then setAddrPrivilege(KIT_SLOT, 0).
    _keySignsAndRelayerSends(
      _account, _originalKey, _batch(_clearCall(_stateOf(_account).setupNonce), _unbindKitCall(_account))
    );

    // Someone sends the old signed request. It fails.
    vm.prank(_attacker.addr);
    vm.expectPartialRevert(IPolicyManager.PolicyManager_NoSetup.selector);
    _manager.startAttempt(_old);

    // Someone sends a handover batch straight to the account with the kit's signature, and the account refuses it.
    IAmbireRecoveryAction.Transaction[] memory _calls = _handoverBatch(_attacker.addr, 2);
    bytes memory _signature = _kitSignature();
    vm.prank(_attacker.addr);
    vm.expectRevert(bytes('EXTERNAL_VALIDATION_NOT_SET'));
    IAmbireAccount(_account).execute(_calls, _signature);

    // Months pass.
    skip(180 days);

    // The holder sends one batch, setAddrPrivilege(KIT_SLOT, binding) then commitSetup under the next nonce, 3.
    _keySignsAndRelayerSends(
      _account, _originalKey, _batch(_bindKitCall(_account), _commitCall(_account, _holderRule, 3))
    );

    // The approvers recover the account under the new setup, at attempt 2.
    bytes memory _payload = _approversOpen(_handover(_newKey.addr, _originalKey.addr));
    assertEq(_attempt(_account).attemptId, 2, 'the attempt id continued at 2');
    skip(5 days);
    _executes(_executor, _account, _payload);
    _assertKeyControls(_account, _newKey, 'the new key');
    _assertKeyLocked(_account, _originalKey);
  }

  /// @notice The holder removes the binding alone, leaving the setup live. An attempt opens under it and its wait runs
  ///         out unseen; months later the holder writes the binding back alone, and the attacker's bot executes in the
  ///         next block with none of the notice window left. Nothing tells the manager the binding was removed.
  function test_WhenTheHolderUninstallsTheKitWithoutClearing() external {
    // The holder writes setAddrPrivilege(KIT_SLOT, 0) without clearSetup.
    _keySignsAndRelayerSends(_account, _originalKey, _batch(_unbindKitCall(_account)));

    // The attacker opens an attempt, which the live setup accepts.
    bytes memory _payload = _attackerOpens(_account, _holderRule, _originalKey.addr);

    // The wait passes, and the attacker's executeHandover reverts, since the account has no binding.
    skip(5 days);
    vm.prank(_attacker.addr);
    vm.expectRevert(bytes('EXTERNAL_VALIDATION_NOT_SET'));
    _action.executeHandover(_account, _payload);

    // Months later the holder writes the binding back alone.
    skip(180 days);
    _keySignsAndRelayerSends(_account, _originalKey, _batch(_bindKitCall(_account)));

    // The attacker's bot sends executeHandover in the next block.
    vm.roll(block.number + 1);
    _executes(_executor, _account, _payload);

    // The account passes to the attacker.
    _assertKeyControls(_account, _attacker, 'the attacker key');
    _assertKeyLocked(_account, _originalKey);
  }

  /// @notice A wallet commits the setup and never writes the kit's binding. The setup still admits an attempt, whose
  ///         spend fails while the binding is missing, and the day the wallet finally writes the binding alone the
  ///         waiting attempt is released at once. The holder believed recovery was set up for them, and it was set up
  ///         for the attacker.
  function test_WhenTheSetupWasCommittedWithoutTheBinding() external {
    // Another holder's wallet commits Maya's rule but never writes the kit's binding.
    Person memory _holder = _person('unbound holder');
    address _unbound = _openAccount(_holder.addr);
    Rule memory _r = _mayaRule(_unbound);
    _keySignsAndRelayerSends(_unbound, _holder, _batch(_commitCall(_unbound, _r, 1)));

    // The attacker opens an attempt, which the setup accepts.
    bytes memory _payload = _attackerOpens(_unbound, _r, _holder.addr);

    // The wait passes, and the attacker's executeHandover reverts, since the account has no binding.
    skip(_r.wait);
    vm.prank(_executor);
    vm.expectRevert(bytes('EXTERNAL_VALIDATION_NOT_SET'));
    _action.executeHandover(_unbound, _payload);

    // Months later the wallet writes the binding alone, as an update.
    skip(180 days);
    _keySignsAndRelayerSends(_unbound, _holder, _batch(_bindKitCall(_unbound)));

    // The attacker's bot executes in the next block, and the account is the attacker's.
    vm.roll(block.number + 1);
    _executes(_executor, _unbound, _payload);
    _assertKeyControls(_unbound, _attacker, 'the attacker key');
    _assertKeyLocked(_unbound, _holder);
  }

  /*///////////////////////////////////////////////////////////////
                    EVEN IF, AFTER AN UNINSTALL
  ///////////////////////////////////////////////////////////////*/

  /// @notice The holder rebinds in a batch that also commits the setup again. The commit cancels the waiting attempt,
  ///         and the bot's execute in the next block reverts. Turning it back on the full way releases nothing.
  function test_WhenTheRebindIsPairedWithACommit() external {
    // The holder removes the binding, and the attacker's attempt opens and waits out its time.
    _keySignsAndRelayerSends(_account, _originalKey, _batch(_unbindKitCall(_account)));
    bytes memory _payload = _attackerOpens(_account, _holderRule, _originalKey.addr);
    skip(5 days);

    // Months later the holder sends one batch: bind the kit, then commit the rule under nonce 2.
    skip(180 days);
    _keySignsAndRelayerSends(
      _account, _originalKey, _batch(_bindKitCall(_account), _commitCall(_account, _holderRule, 2))
    );

    // In the next block the attacker's bot executes, and it reverts.
    vm.roll(block.number + 1);
    vm.prank(_executor);
    vm.expectPartialRevert(IRecoveryAction.RecoveryAction_NotConsumable.selector);
    _action.executeHandover(_account, _payload);

    // The holder's key still controls the account, and the attacker holds nothing.
    assertEq(_privilegeOf(_account, _attacker.addr), bytes32(0), 'the attacker holds nothing');
    _assertKeyControls(_account, _originalKey, 'the holder key');
  }

  /// @notice The holder sends cancelByOwner before writing the binding back alone, and nothing is released.
  function test_WhenTheHolderCancelsBeforeRebinding() external {
    // The holder removes the binding, and the attacker's attempt opens and waits out its time.
    _keySignsAndRelayerSends(_account, _originalKey, _batch(_unbindKitCall(_account)));
    bytes memory _payload = _attackerOpens(_account, _holderRule, _originalKey.addr);
    skip(5 days);

    // Months later the holder cancels the waiting attempt, then writes the binding back alone.
    skip(180 days);
    _keySignsAndRelayerSends(_account, _originalKey, _batch(_cancelByOwnerCall(_attempt(_account).attemptId)));
    _keySignsAndRelayerSends(_account, _originalKey, _batch(_bindKitCall(_account)));

    // In the next block the attacker's bot executes, and it reverts.
    vm.roll(block.number + 1);
    vm.prank(_executor);
    vm.expectPartialRevert(IRecoveryAction.RecoveryAction_NotConsumable.selector);
    _action.executeHandover(_account, _payload);

    // The holder's key still controls the account, and the attacker holds nothing.
    assertEq(_privilegeOf(_account, _attacker.addr), bytes32(0), 'the attacker holds nothing');
    _assertKeyControls(_account, _originalKey, 'the holder key');
  }

  /// @notice Approvals the attacker gathered before the uninstall still open an attempt after it, since removing the
  ///         binding did not move the setup nonce.
  function test_WhenApprovalsGatheredBeforeTheUninstallStillOpen() external {
    // The attacker, holding Ben's and Carla's keys and Maya's hardware wallet, gathers approvals for attempt 1.
    bytes memory _payload = _handover(_attacker.addr, _originalKey.addr);
    IPolicyManager.AttemptRequest memory _gathered =
      _request(_account, _holderRule, _payload, _noPayment(), uint48(block.timestamp + 30 days));
    _signApproval(_gathered, _holderRule, 1);
    _signApproval(_gathered, _holderRule, 2);
    _signApproval(_gathered, _holderRule, 3);

    // The holder removes the binding alone.
    _keySignsAndRelayerSends(_account, _originalKey, _batch(_unbindKitCall(_account)));

    // A week later the attacker sends the gathered approvals, and the attempt opens.
    skip(7 days);
    _submits(_attacker.addr, _gathered);
    assertEq(uint8(_attempt(_account).state), uint8(IPolicyManager.AttemptState.Waiting), 'the old approvals opened');
    assertEq(_stateOf(_account).setupNonce, 1, 'the nonce never moved');

    // The day the binding returns alone, the attempt is spent at once.
    skip(5 days);
    _keySignsAndRelayerSends(_account, _originalKey, _batch(_bindKitCall(_account)));
    _executes(_executor, _account, _payload);
    _assertKeyControls(_account, _attacker, 'the attacker key');
  }

  /*///////////////////////////////////////////////////////////////
                              EVEN IF
  ///////////////////////////////////////////////////////////////*/

  /// @notice An attempt the holder never asked for was waiting when the holder turned recovery off, and turning it off
  ///         cancels it.
  function test_WhenAnAttemptWaitsAsRecoveryIsTurnedOff() external {
    // The attacker's attempt waits.
    bytes memory _payload = _attackerOpens(_account, _holderRule, _originalKey.addr);

    // The holder turns recovery off in one batch.
    _keySignsAndRelayerSends(
      _account, _originalKey, _batch(_clearCall(_stateOf(_account).setupNonce), _unbindKitCall(_account))
    );
    assertEq(uint8(_attempt(_account).state), uint8(IPolicyManager.AttemptState.Cancelled), 'turning off cancelled it');

    // Months later the holder turns recovery back on in one batch, and the attacker's bot executes in the next block.
    // It reverts.
    skip(180 days);
    _keySignsAndRelayerSends(
      _account, _originalKey, _batch(_bindKitCall(_account), _commitCall(_account, _holderRule, 3))
    );
    vm.roll(block.number + 1);
    vm.prank(_executor);
    vm.expectPartialRevert(IRecoveryAction.RecoveryAction_NotConsumable.selector);
    _action.executeHandover(_account, _payload);
    _assertKeyControls(_account, _originalKey, 'the holder key');
  }

  /// @notice clearSetup alone, with KIT_SLOT still set, leaves nothing spendable, by executeHandover or by the kit's
  ///         signature straight to the account, and a single commitSetup later turns it back on.
  function test_WhenTheHolderClearsButKeepsTheBinding() external {
    // The attacker's attempt waits.
    bytes memory _payload = _attackerOpens(_account, _holderRule, _originalKey.addr);

    // The holder clears the setup, leaving KIT_SLOT set.
    _keySignsAndRelayerSends(_account, _originalKey, _batch(_clearCall(_stateOf(_account).setupNonce)));

    // The wait passes, and the attacker's executeHandover reverts.
    skip(5 days);
    vm.prank(_attacker.addr);
    vm.expectPartialRevert(IRecoveryAction.RecoveryAction_NotConsumable.selector);
    _action.executeHandover(_account, _payload);

    // The attacker sends the handover batch straight to the account with the kit's signature, and it is refused.
    IAmbireRecoveryAction.Transaction[] memory _calls = _handoverBatch(_attacker.addr, 1);
    bytes memory _signature = _kitSignature();
    vm.prank(_attacker.addr);
    vm.expectPartialRevert(IRecoveryAction.RecoveryAction_NotConsumable.selector);
    IAmbireAccount(_account).execute(_calls, _signature);
    assertEq(_privilegeOf(_account, _attacker.addr), bytes32(0), 'the attacker holds nothing');

    // Months later the holder sends a single commit under nonce 3, and a recovery to the new key works.
    skip(180 days);
    _keySignsAndRelayerSends(_account, _originalKey, _batch(_commitCall(_account, _holderRule, 3)));
    bytes memory _honest = _approversOpen(_handover(_newKey.addr, _originalKey.addr));
    skip(5 days);
    _executes(_executor, _account, _honest);
    _assertKeyControls(_account, _newKey, 'the new key');
  }

  /// @notice Maya signs one batch that turns recovery off and pays her friend more than the account holds. It reverts,
  ///         and a reverted batch leaves the account's nonce where it was, so its signed bytes stay valid. She keeps
  ///         recovery on and later commits a new setup with her key sending the batch itself. Whoever kept the old
  ///         bytes sends them again once the account is funded: the clear names the nonce it was signed for, so it
  ///         reverts and the new setup stays. Without the nonce, the old batch would turn off recovery she rebuilt.
  function test_WhenAClearThatRevertedIsSentAgainAfterANewCommit() external {
    // Maya's key signs clearSetup naming the current nonce, the binding removal and a 2 ETH payment, for a relayer.
    uint64 _signedFor = _stateOf(_account).setupNonce;
    IAmbireRecoveryAction.Transaction[] memory _off =
      _batch(_clearCall(_signedFor), _unbindKitCall(_account), _transferCall(_friend, 2 ether));
    bytes memory _signature = _keySigns(_account, _originalKey.key, _off);
    uint256 _accountNonce = LocalAmbireAccount(payable(_account)).nonce();
    uint256 _friendBalance = _friend.balance;

    // The account holds less than 2 ETH, so the payment fails and the whole batch reverts, keeping the nonce.
    assertLt(_account.balance, 2 ether, 'the account cannot pay');
    vm.prank(_relayer);
    vm.expectRevert();
    IAmbireAccount(_account).execute(_off, _signature);
    assertEq(LocalAmbireAccount(payable(_account)).nonce(), _accountNonce, 'the reverted batch kept the nonce');

    // Maya keeps recovery on, and later her key sends a new commit itself, under the next nonce.
    skip(30 days);
    uint64 _current = _signedFor + 1;
    _keySendsItself(_account, _originalKey, _batch(_commitCall(_account, _holderRule, _current)));
    assertEq(LocalAmbireAccount(payable(_account)).nonce(), _accountNonce, 'the old bytes are still valid');

    // The account is funded, and whoever kept the old bytes sends them again. The clear names the old nonce, and the
    // account's call reverts with both nonces.
    vm.deal(_account, 5 ether);
    bytes4 _wrongNonce = IPolicyManager.PolicyManager_WrongSetupNonce.selector;
    vm.prank(_attacker.addr);
    vm.expectRevert(abi.encodeWithSelector(_wrongNonce, _signedFor, _current));
    IAmbireAccount(_account).execute(_off, _signature);

    // The new setup and the kit's binding stay, and the friend was paid nothing.
    assertEq(_stateOf(_account).setupNonce, _current, 'the nonce stays');
    assertEq(_stateOf(_account).setupCommitment, _commitment(_account, _current, _holderRule), 'the new setup stays');
    assertEq(_privilegeOf(_account, _action.KIT_SLOT()), _action.BINDING(), 'the binding stays');
    assertEq(_friend.balance, _friendBalance, 'nothing was paid');
  }

  /*///////////////////////////////////////////////////////////////
                              UTILITIES
  ///////////////////////////////////////////////////////////////*/

  /// @notice Ben, Carla and the passkey sign a request for the next attempt with a payload and a window.
  function _approversSign(bytes memory _payload, uint48 _validUntil)
    internal
    view
    returns (IPolicyManager.AttemptRequest memory _req)
  {
    Rule memory _r = _holderRule;
    _req = _request(_account, _r, _payload, _noPayment(), _validUntil);
    _signApproval(_req, _r, 1);
    _signApproval(_req, _r, 2);
    _signApproval(_req, _r, 4);
  }

  /// @notice Ben, Carla and the passkey sign a request for the next attempt, and a friend submits it.
  function _approversOpen(bytes memory _payload) internal returns (bytes memory _sent) {
    _sent = _payload;
    _submits(_friend, _approversSign(_payload, uint48(block.timestamp + 24 hours)));
  }

  /// @notice The attacker, holding Ben's and Carla's keys and Maya's hardware wallet, approves a handover of an account
  ///         to the attacker's key and submits it.
  function _attackerOpens(address _target, Rule memory _r, address _lostKey) internal returns (bytes memory _payload) {
    _payload = _handover(_attacker.addr, _lostKey);
    IPolicyManager.AttemptRequest memory _req =
      _request(_target, _r, _payload, _noPayment(), uint48(block.timestamp + 24 hours));
    _signApproval(_req, _r, 1);
    _signApproval(_req, _r, 2);
    _signApproval(_req, _r, 3);
    _submits(_attacker.addr, _req);
  }

  /// @notice The batch the action would build to hand the holder's account to a key at an attempt id.
  function _handoverBatch(address _to, uint64 _attemptId)
    internal
    view
    returns (IAmbireRecoveryAction.Transaction[] memory _calls)
  {
    _calls = _batch(
      _call(
        address(_manager),
        abi.encodeCall(
          IPolicyManager.consume, (address(_action), _attemptId, keccak256(_handover(_to, _originalKey.addr)))
        )
      ),
      _setPrivilegeCall(_account, _to, bytes32(uint256(1))),
      _setPrivilegeCall(_account, _originalKey.addr, bytes32(0))
    );
  }
}
