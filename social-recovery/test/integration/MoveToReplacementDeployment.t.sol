// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {IPolicyManager} from 'interfaces/IPolicyManager.sol';
import {IRecoveryAction} from 'interfaces/IRecoveryAction.sol';

import {AmbireRecoveryAction} from 'contracts/actions/ambire/AmbireRecoveryAction.sol';
import {IAmbireAccount} from 'contracts/actions/ambire/IAmbireAccount.sol';
import {IAmbireRecoveryAction} from 'contracts/actions/ambire/IAmbireRecoveryAction.sol';

import {IntegrationBase} from 'test/integration/base/IntegrationBase.sol';

/// @notice A fix shipped as a new manager with a new action. The holder, who still has their key, moves the recovery
///         over in one batch and leaves nothing live behind. Leaving the old setup live beside the new one keeps the
///         old rule able to take the account.
contract MoveToReplacementDeployment is IntegrationBase {
  /// @notice The holder's account, set up on the old manager with the old action.
  address internal _account;
  /// @notice The holder's rule, Maya's rule, as the backup holds it.
  Rule internal _holderRule;
  /// @notice The manager and action the account was set up on.
  IPolicyManager internal _oldManager;
  IAmbireRecoveryAction internal _oldAction;
  /// @notice The replacement manager and action, deployed by the same deployment script.
  IPolicyManager internal _newManager;
  IAmbireRecoveryAction internal _newAction;

  function setUp() public override {
    super.setUp();
    (_oldManager, _oldAction) = (_manager, _action);
    _account = _openAccount(_originalKey.addr);
    Rule memory _r = _mayaRule(_account);
    _keep(_holderRule, _r);
    _setUpRecovery(_account, _originalKey, _r);
    // The fix ships: the deployment script deploys a new manager and a new action.
    Deployment memory _deployment = _deploy(_pinsFor(block.chainid));
    (_newManager, _newAction) = (_deployment.manager, _deployment.action);
  }

  /*///////////////////////////////////////////////////////////////
                              THE WALK
  ///////////////////////////////////////////////////////////////*/

  /// @notice One batch of four calls moves the recovery: the old binding zeroed, the old setup cleared, the new binding
  ///         written and the setup committed on the new manager. The approvers then recover on the new manager, and
  ///         their request at the old one opens nothing. Without the key nobody can send the move, so a keyless holder
  ///         cannot migrate.
  function test_WhenTheHolderMigratesInOneBatch() external {
    // The four-call batch the holder's wallet builds.
    IAmbireRecoveryAction.Transaction[] memory _move = _moveBatch();

    // An approver tries to send it for a keyless holder with the old kit's signature, and the old action refuses it.
    bytes memory _oldKitSignature = _kitSignatureOf(_oldAction);
    vm.prank(_friend);
    vm.expectPartialRevert(IRecoveryAction.RecoveryAction_NotConsumable.selector);
    IAmbireAccount(_account).execute(_move, _oldKitSignature);

    // The holder signs the batch with their key, and a relayer sends it.
    _keySignsAndRelayerSends(_account, _originalKey, _move);

    // The approvers build a request at the old manager, and it opens nothing.
    _clientPointsAt(_oldManager, _oldAction);
    Rule memory _r = _holderRule;
    IPolicyManager.AttemptRequest memory _atOld = _approversSign(_handover(_newKey.addr, _originalKey.addr));
    vm.prank(_friend);
    vm.expectPartialRevert(IPolicyManager.PolicyManager_NoSetup.selector);
    _oldManager.startAttempt(_atOld);

    // The approvers recover the account on the new manager, as in any recovery.
    _clientPointsAt(_newManager, _newAction);
    IPolicyManager.AttemptRequest memory _req = _approversSign(_handover(_newKey.addr, _originalKey.addr));
    _submits(_friend, _req);
    skip(_r.wait);
    _executes(_executor, _account, _req.payload);

    // The new key controls the account, and the old pair holds nothing a recovery could use.
    _assertKeyControls(_account, _newKey, 'the new key');
    _assertKeyLocked(_account, _originalKey);
    assertEq(_oldManager.stateOf(_account, address(_oldAction)).setupCommitment, bytes32(0), 'the old setup is gone');
    assertFalse(_oldAction.isAuthorized(_account), 'the old action is not bound');
  }

  /// @notice The holder sets up the new manager with a rule that drops a stolen hardware wallet, but leaves the old
  ///         setup and binding live. The attacker opens on the old manager with that wallet, the holder's cancel on the
  ///         new manager finds nothing to cancel, and the attacker executes through the old action. The contracts allow
  ///         a live setup on each manager at once.
  function test_WhenTwoSetupsStayLive() external {
    _twoSetupsStayLive(_newManager, _newAction);
  }

  /// @notice The same story with a second recovery action on the same manager, each action under its own KIT_SLOT with
  ///         its own setup: a cancel for the second action leaves the first action's attempt waiting.
  function test_WhenTwoActionsShareOneManager() external {
    // Someone deploys a second recovery action for the same manager and the same Ambire implementation. The deployment
    // script deploys a manager with each action, so the second action is created directly with the arguments the
    // script passes.
    IAmbireRecoveryAction _secondAction = new AmbireRecoveryAction(_oldManager, _ambireImplementation);
    assertTrue(_secondAction.KIT_SLOT() != _oldAction.KIT_SLOT(), 'each action has its own slot');
    _twoSetupsStayLive(_oldManager, _secondAction);
  }

  /*///////////////////////////////////////////////////////////////
                              UTILITIES
  ///////////////////////////////////////////////////////////////*/

  /// @notice Lee sets up the old pair with any 1 of his hardware wallet and his passkey, then sets up a second pair
  ///         with his passkey alone, leaving the old setup and binding live. His hardware wallet is stolen.
  function _twoSetupsStayLive(IPolicyManager _secondManager, IAmbireRecoveryAction _secondAction) internal {
    // Lee's account is set up on the old pair with any 1 of his hardware wallet and his passkey.
    Person memory _lee = _person('Lee key');
    Person memory _leeHardwareWallet = _person('Lee hardware wallet');
    address _leeAccount = _openAccount(_lee.addr);
    _clientPointsAt(_oldManager, _oldAction);
    Rule memory _oldRule = _rule(
      _leeAccount,
      5 days,
      false,
      _thresholds(1),
      _sizes(2),
      _credentials(_walletGuardian(_leeHardwareWallet), _passkey(_mayaPasskey))
    );
    _setUpRecovery(_leeAccount, _lee, _oldRule);

    // Lee sets up the second pair with his passkey alone, without clearing the old setup or zeroing the old binding.
    _clientPointsAt(_secondManager, _secondAction);
    Rule memory _newRule =
      _rule(_leeAccount, 5 days, false, _thresholds(1), _sizes(1), _credentials(_passkey(_mayaPasskey)));
    _setUpRecovery(_leeAccount, _lee, _newRule);

    // The attacker, holding Lee's stolen hardware wallet, opens an attempt on the old manager.
    _clientPointsAt(_oldManager, _oldAction);
    bytes memory _payload = _handover(_attacker.addr, _lee.addr);
    IPolicyManager.AttemptRequest memory _theft =
      _request(_leeAccount, _oldRule, _payload, _noPayment(), uint48(block.timestamp + 24 hours));
    _signApproval(_theft, _oldRule, 0);
    _submits(_attacker.addr, _theft);

    // Lee's cancelByOwner for the second pair reverts, since nothing waits there, and the old attempt keeps waiting.
    IAmbireRecoveryAction.Transaction[] memory _cancel =
      _batch(_call(address(_secondManager), abi.encodeCall(IPolicyManager.cancelByOwner, (address(_secondAction)))));
    bytes memory _signature = _keySigns(_leeAccount, _lee.key, _cancel);
    vm.prank(_relayer);
    vm.expectPartialRevert(IPolicyManager.PolicyManager_NoActiveAttempt.selector);
    IAmbireAccount(_leeAccount).execute(_cancel, _signature);
    assertEq(
      uint8(_oldManager.stateOf(_leeAccount, address(_oldAction)).attempt.state),
      uint8(IPolicyManager.AttemptState.Waiting),
      'the old attempt keeps waiting'
    );

    // The wait passes, and the attacker executes through the old action.
    skip(5 days);
    _executes(_attacker.addr, _leeAccount, _payload);

    // The account is the attacker's.
    _assertKeyControls(_leeAccount, _attacker, 'the attacker key');
    _assertKeyLocked(_leeAccount, _lee);
  }

  /// @notice The four-call move: zero the old action's KIT_SLOT, clear the old setup, write the new action's binding
  ///         and commit the rule on the new manager at nonce 1.
  function _moveBatch() internal returns (IAmbireRecoveryAction.Transaction[] memory _calls) {
    _clientPointsAt(_oldManager, _oldAction);
    IAmbireRecoveryAction.Transaction memory _unbindOld = _unbindKitCall(_account);
    IAmbireRecoveryAction.Transaction memory _clearOld = _clearCall();
    _clientPointsAt(_newManager, _newAction);
    _calls = _batch(_unbindOld, _clearOld, _bindKitCall(_account), _commitCall(_account, _holderRule, 1));
  }

  /// @notice Ben, Carla and the passkey sign a request for the next attempt at the manager the client points at.
  function _approversSign(bytes memory _payload) internal view returns (IPolicyManager.AttemptRequest memory _req) {
    Rule memory _r = _holderRule;
    _req = _request(_account, _r, _payload, _noPayment(), uint48(block.timestamp + 24 hours));
    _signApproval(_req, _r, 1);
    _signApproval(_req, _r, 2);
    _signApproval(_req, _r, 4);
  }

  /// @notice The signature an action hands the account, routing a batch to that action under its KIT_SLOT.
  function _kitSignatureOf(IAmbireRecoveryAction _a) internal view returns (bytes memory _signature) {
    _signature = abi.encodePacked(abi.encode(_a.KIT_SLOT(), address(_a), bytes(''), bytes('')), uint8(255));
  }

  /// @notice The holder's client points at a manager and action pair: every request, signature and account call it
  ///         builds from here on names them.
  function _clientPointsAt(IPolicyManager _m, IAmbireRecoveryAction _a) internal {
    (_manager, _action) = (_m, _a);
  }
}
