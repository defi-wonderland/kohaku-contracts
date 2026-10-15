// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {ECDSA} from '@openzeppelin/contracts/utils/cryptography/ECDSA.sol';

import {BindingDigest} from 'libraries/BindingDigest.sol';
import {IPolicyManager} from 'interfaces/IPolicyManager.sol';
import {IRecoveryAction} from 'interfaces/IRecoveryAction.sol';

import {IAmbireAccount} from 'contracts/actions/ambire/IAmbireAccount.sol';
import {IAmbireRecoveryAction} from 'contracts/actions/ambire/IAmbireRecoveryAction.sol';

import {IntegrationBase} from 'test/integration/base/IntegrationBase.sol';

/// @notice A stand-in for a third-party validator an Ambire account binds under a slot of its own, such as a session-
///         key module: it approves any batch its operator key signed for the account, once.
/// @dev What it replaces: any external validator an Ambire account authorizes by writing
///      keccak256(abi.encode(validator, data)) under a slot, the same route the kit's action uses. Why the real one
///      is not used: no such validator ships with the kit or is pinned by it, and the story needs only a contract,
///      other than the kit, that can make the account act. Which test covers the real route:
///      test/action/fork/AmbireRecoveryActionSpendFork.t.sol runs the slot-bound validator route on Ambire's
///      deployed implementation through the kit's own action; no test runs a third-party validator.
contract OperatorValidator {
  /// @notice The key whose signature over a batch this validator accepts.
  address public immutable OPERATOR;

  /// @notice The batches already approved, so a signed batch runs once.
  mapping(bytes32 _batchHash => bool _used) public used;

  /// @notice The batch was not signed by the operator, or already ran.
  error OperatorValidator_NotApproved();

  constructor(address _operator) {
    OPERATOR = _operator;
  }

  /// @notice Ambire's account asks this before running a batch sent under the validator's slot.
  function validateSig(bytes calldata, bytes calldata _sig, IAmbireRecoveryAction.Transaction[] calldata _calls)
    external
    returns (bool _isValidSignature, uint256 _timestampValidAfter)
  {
    bytes32 _hash = batchHash(msg.sender, _calls);
    require(!used[_hash] && ECDSA.recover(_hash, _sig) == OPERATOR, OperatorValidator_NotApproved());
    used[_hash] = true;
    (_isValidSignature, _timestampValidAfter) = (true, 0);
  }

  /// @notice The hash the operator signs for a batch on an account.
  function batchHash(address _account, IAmbireRecoveryAction.Transaction[] calldata _calls)
    public
    view
    returns (bytes32 _hash)
  {
    _hash = keccak256(abi.encode(address(this), _account, block.chainid, _calls));
  }
}

/// @notice Maya's account holds two keys, her phone's and her laptop's, both at privilege 2, and another validator
///         bound under its own slot, and it holds a setup of Maya's rule. An Ambire account's keys each sign alone, so
///         a recovery replaces one key and leaves every other authority as it was; the other authorities, in turn,
///         reach the kit's state on the account.
contract OtherAuthoritiesOnTheAccount is IntegrationBase {
  /// @notice The holder's account.
  address internal _account;
  /// @notice The holder's rule, as the backup holds it.
  Rule internal _holderRule;
  /// @notice The laptop's key, the one the holder loses, and the phone's key.
  Person internal _laptop;
  Person internal _phone;
  /// @notice The key that signs for the other validator, the validator, and the slot it is bound under.
  Person internal _validatorOperator;
  OperatorValidator internal _otherValidator;
  address internal _otherSlot;

  function setUp() public override {
    super.setUp();
    _laptop = _originalKey;
    _phone = _person('Maya phone key');
    _validatorOperator = _person('session module operator');
    _otherValidator = new OperatorValidator(_validatorOperator.addr);
    _otherSlot = makeAddr('session module slot');
    _account = _openAccount(_laptop.addr);
    Rule memory _r = _mayaRule(_account);
    _keep(_holderRule, _r);
    // The laptop's key adds the phone's key, binds the other validator, binds the kit and commits Maya's rule.
    _keySignsAndRelayerSends(
      _account,
      _laptop,
      _batch(
        _setPrivilegeCall(_account, _phone.addr, _SIGNER_PRIVILEGE),
        _setPrivilegeCall(_account, _otherSlot, _validatorBinding()),
        _bindKitCall(_account),
        _commitCall(_account, _r, 1)
      )
    );
  }

  /*///////////////////////////////////////////////////////////////
                              THE WALK
  ///////////////////////////////////////////////////////////////*/

  /// @notice The holder loses the laptop, and the recovery hands the laptop key's place to a new key. The phone's key
  ///         still signs an ordinary batch, and the other validator and KIT_SLOT are untouched.
  function test_WhenTheHolderRecoversOneOfTwoKeys() external {
    // The approvers open an attempt handing the account from the laptop's key to a new key.
    bytes memory _payload = _approversOpen(_newKey.addr, _laptop.addr);

    // Five days pass, and anyone sends executeHandover.
    skip(5 days);
    _executes(_executor, _account, _payload);

    // The laptop's key is gone and the new key is in.
    _assertKeyLocked(_account, _laptop);
    _assertKeyControls(_account, _newKey, 'the new key');
    // The phone's key still signs an ordinary batch.
    _assertKeyControls(_account, _phone, 'the phone key');
    // The other validator and KIT_SLOT are untouched, and the validator still runs a batch.
    assertEq(_privilegeOf(_account, _otherSlot), _validatorBinding(), 'the other validator stays bound');
    assertTrue(_action.isAuthorized(_account), 'KIT_SLOT still holds the binding');
    address _recipient = makeAddr('recipient of a session module batch');
    _validatorSends(_batch(_transferCall(_recipient, 0.01 ether)));
    assertEq(_recipient.balance, 0.01 ether, 'the other validator moves funds');
  }

  /*///////////////////////////////////////////////////////////////
                             TRADE-OFFS
  ///////////////////////////////////////////////////////////////*/

  /// @notice One handover moves one key. The phone was lost too, and its key still signs after the recovery until the
  ///         new key removes it with an ordinary account write; a second recovery would only add a wait.
  function test_WhenTheNewKeyRemovesTheOtherLostKey() external {
    // The recovery hands the laptop key's place to the new key.
    bytes memory _payload = _approversOpen(_newKey.addr, _laptop.addr);
    skip(5 days);
    _executes(_executor, _account, _payload);

    // Whoever found the lost phone still moves funds with its key.
    _assertKeyControls(_account, _phone, 'the lost phone key');

    // The new key removes the phone's key with an ordinary account write, and from then on it signs nothing.
    _keySignsAndRelayerSends(_account, _newKey, _batch(_setPrivilegeCall(_account, _phone.addr, bytes32(0))));
    _assertKeyLocked(_account, _phone);
    _assertKeyControls(_account, _newKey, 'the new key');
  }

  /// @notice The laptop and the phone sat in the same stolen bag. While the phone's key stays on the account, the thief
  ///         holding it cancels the recovery and clears the setup, so the approvers cannot recover the account.
  function test_WhenTheOtherKeyCancelsTheRecovery() external {
    // The approvers open an attempt handing the laptop key's place to the new key.
    bytes memory _payload = _approversOpen(_newKey.addr, _laptop.addr);

    // The thief, holding the phone's key, sends cancelByOwner, then clears the setup.
    _keySignsAndRelayerSends(_account, _phone, _batch(_cancelByOwnerCall()));
    _keySignsAndRelayerSends(_account, _phone, _batch(_clearCall()));

    // The wait passes, and the approvers' handover cannot run, nor can they open a new one.
    skip(5 days);
    vm.prank(_executor);
    vm.expectPartialRevert(IRecoveryAction.RecoveryAction_NotConsumable.selector);
    _action.executeHandover(_account, _payload);
    Rule memory _r = _holderRule;
    IPolicyManager.AttemptRequest memory _again =
      _request(_account, _r, _payload, _noPayment(), uint48(block.timestamp + 24 hours));
    _signApproval(_again, _r, 1);
    _signApproval(_again, _r, 2);
    _signApproval(_again, _r, 4);
    vm.prank(_friend);
    vm.expectPartialRevert(IPolicyManager.PolicyManager_NoSetup.selector);
    _manager.startAttempt(_again);
    assertEq(_privilegeOf(_account, _newKey.addr), bytes32(0), 'the new key never got the account');
  }

  /// @notice After the wait, the other validator sends a batch holding only the consume. The approvers' approval is
  ///         spent, nothing is installed, and the approved handover can no longer run.
  function test_WhenAnotherValidatorConsumesAlone() external {
    // The approvers open an attempt handing the laptop key's place to the new key, and the wait passes.
    bytes memory _payload = _approversOpen(_newKey.addr, _laptop.addr);
    skip(5 days);

    // The other validator sends a batch that only consumes the attempt.
    _validatorSends(
      _batch(
        _call(
          address(_manager),
          abi.encodeCall(IPolicyManager.consume, (address(_action), _attempt(_account).attemptId, keccak256(_payload)))
        )
      )
    );

    // The executor then sends the handover, and nothing is left to run.
    vm.prank(_executor);
    vm.expectPartialRevert(IRecoveryAction.RecoveryAction_NotConsumable.selector);
    _action.executeHandover(_account, _payload);

    // The approval is spent, the new key holds nothing and the lost laptop key is still the account's key.
    assertEq(uint8(_attempt(_account).state), uint8(IPolicyManager.AttemptState.Consumed), 'the attempt is spent');
    assertEq(_privilegeOf(_account, _newKey.addr), bytes32(0), 'the new key holds nothing');
    assertEq(_privilegeOf(_account, _laptop.addr), _SIGNER_PRIVILEGE, 'the laptop key is still there');
  }

  /// @notice The phone's key zeroes the laptop's key during the wait. The committed handover no longer passes, the
  ///         attempt stays stuck a month later, and only a cancel ends it.
  function test_WhenAnotherAuthorityZeroesTheLostKey() external {
    // The approvers open an attempt handing the laptop key's place to the new key.
    bytes memory _payload = _approversOpen(_newKey.addr, _laptop.addr);

    // Two days into the wait, the phone's key removes the laptop's key.
    skip(2 days);
    _keySignsAndRelayerSends(_account, _phone, _batch(_setPrivilegeCall(_account, _laptop.addr, bytes32(0))));

    // The wait passes, and anyone executes: the laptop's key is no longer a key to remove.
    skip(3 days);
    vm.prank(_executor);
    vm.expectPartialRevert(IRecoveryAction.RecoveryAction_NotAKey.selector);
    _action.executeHandover(_account, _payload);

    // A month later it still fails, and the attempt is stuck waiting.
    skip(30 days);
    vm.prank(_executor);
    vm.expectPartialRevert(IRecoveryAction.RecoveryAction_NotAKey.selector);
    _action.executeHandover(_account, _payload);
    assertEq(uint8(_attempt(_account).state), uint8(IPolicyManager.AttemptState.Waiting), 'the attempt is stuck');
    assertEq(_privilegeOf(_account, _newKey.addr), bytes32(0), 'the new key holds nothing');

    // The approvers cancel it, and that ends it.
    _approversCancel();
    assertEq(uint8(_attempt(_account).state), uint8(IPolicyManager.AttemptState.Cancelled), 'the attempt ended');
  }

  /// @notice The other validator, a contract the holder authorized for something else, cancels the waiting recovery,
  ///         replaces the holder's rule with its operator's, and clears the account's setup under a second kit. Every
  ///         contract the account authorized holds the holder's own powers over every action of the account.
  function test_WhenAnAuthorizedContractReplacesTheRule() external {
    // The account also has recovery set up under a second deployment of the kit, with the same rule.
    Deployment memory _second = _setUpUnderASecondKit();

    // The approvers open an attempt handing the laptop key's place to the new key.
    bytes memory _payload = _approversOpen(_newKey.addr, _laptop.addr);

    // The other validator cancels the waiting attempt as if it were the holder.
    _validatorSends(_batch(_cancelByOwnerCall()));

    // The other validator commits a rule whose only approver is its own operator, with a one-day wait.
    Rule memory _operatorRule =
      _rule(_account, 1 days, false, _thresholds(1), _sizes(1), _credentials(_walletGuardian(_validatorOperator)));
    _validatorSends(_batch(_commitCall(_account, _operatorRule, 2)));

    // The other validator clears the account's setup under the second kit.
    _validatorSends(
      _batch(_call(address(_second.manager), abi.encodeCall(IPolicyManager.clearSetup, (address(_second.action)))))
    );

    // The approvers' recovery is gone, the kit now follows the operator's rule, and the second kit holds no setup.
    skip(5 days);
    vm.prank(_executor);
    vm.expectPartialRevert(IRecoveryAction.RecoveryAction_NotConsumable.selector);
    _action.executeHandover(_account, _payload);
    assertEq(_stateOf(_account).setupCommitment, _commitment(_account, 2, _operatorRule), 'the operator rule stands');
    assertEq(
      _second.manager.stateOf(_account, address(_second.action)).setupCommitment,
      bytes32(0),
      'the second kit is cleared'
    );
  }

  /// @notice On an account that bound the kit's action under another slot, the approvers sign a handover whose new key
  ///         is KIT_SLOT. Sent by hand under that other slot, it installs KIT_SLOT as a key, an address nobody holds a
  ///         private key for, and removes the holder's key: the account is locked for good.
  function test_WhenTheKitSlotIsApprovedAsTheNewKey() external {
    // Lee's account binds the kit's action under a slot of its own choosing and commits Maya's kind of rule.
    Person memory _lee = _person('Lee key');
    address _leeAccount = _openAccount(_lee.addr);
    address _leeSlot = makeAddr('Lee kit slot');
    Rule memory _r = _mayaRule(_leeAccount);
    _keySignsAndRelayerSends(
      _leeAccount,
      _lee,
      _batch(_setPrivilegeCall(_leeAccount, _leeSlot, _action.BINDING()), _commitCall(_leeAccount, _r, 1))
    );

    // Lee's client writes KIT_SLOT as the new key, and the approvers sign it.
    bytes memory _payload = _handover(_action.KIT_SLOT(), _lee.addr);
    IPolicyManager.AttemptRequest memory _req =
      _request(_leeAccount, _r, _payload, _noPayment(), uint48(block.timestamp + 24 hours));
    _signApproval(_req, _r, 1);
    _signApproval(_req, _r, 2);
    _signApproval(_req, _r, 4);
    _submits(_friend, _req);

    // The wait passes, and someone sends the handover batch by hand under Lee's slot.
    skip(5 days);
    IAmbireRecoveryAction.Transaction[] memory _calls = _batch(
      _call(
        address(_manager),
        abi.encodeCall(
          IPolicyManager.consume,
          (address(_action), _manager.stateOf(_leeAccount, address(_action)).attempt.attemptId, keccak256(_payload))
        )
      ),
      _setPrivilegeCall(_leeAccount, _action.KIT_SLOT(), bytes32(uint256(1))),
      _setPrivilegeCall(_leeAccount, _lee.addr, bytes32(0))
    );
    bytes memory _routing = abi.encode(_leeSlot, address(_action), bytes(''), bytes(''));
    bytes memory _signature = abi.encodePacked(_routing, uint8(255));
    vm.prank(_executor);
    IAmbireAccount(_leeAccount).execute(_calls, _signature);

    // KIT_SLOT is now the account's only key, and Lee is locked out.
    assertEq(_privilegeOf(_leeAccount, _action.KIT_SLOT()), bytes32(uint256(1)), 'KIT_SLOT is a key');
    _assertKeyLocked(_leeAccount, _lee);
  }

  /*///////////////////////////////////////////////////////////////
                              UTILITIES
  ///////////////////////////////////////////////////////////////*/

  /// @notice The laptop's key sets up recovery on the account under a second deployment of the kit, with the same rule.
  function _setUpUnderASecondKit() internal returns (Deployment memory _second) {
    _second = _deploy(_pinsFor(block.chainid));
    _keySignsAndRelayerSends(
      _account,
      _laptop,
      _batch(
        _setPrivilegeCall(_account, _second.action.KIT_SLOT(), _second.action.BINDING()),
        _call(
          address(_second.manager),
          abi.encodeCall(
            IPolicyManager.commitSetup,
            (
              address(_second.action),
              BindingDigest.setupCommitment(_account, address(_second.action), 1, _body(_holderRule)),
              1,
              '',
              ''
            )
          )
        )
      )
    );
  }

  /// @notice The privilege value that binds the other validator under its slot.
  function _validatorBinding() internal view returns (bytes32 _binding) {
    _binding = keccak256(abi.encode(address(_otherValidator), bytes('')));
  }

  /// @notice The other validator's operator signs a batch, and a relayer sends it to the account under its slot.
  function _validatorSends(IAmbireRecoveryAction.Transaction[] memory _calls) internal {
    (uint8 _v, bytes32 _r, bytes32 _s) = vm.sign(_validatorOperator.key, _otherValidator.batchHash(_account, _calls));
    bytes memory _signature = abi.encodePacked(
      abi.encode(_otherSlot, address(_otherValidator), bytes(''), abi.encodePacked(_r, _s, _v)), uint8(255)
    );
    vm.prank(_relayer);
    IAmbireAccount(_account).execute(_calls, _signature);
  }

  /// @notice Ben, Carla and Maya's passkey approve a handover, a friend submits it, and the payload comes back.
  function _approversOpen(address _to, address _removed) internal returns (bytes memory _payload) {
    Rule memory _r = _holderRule;
    _payload = _handover(_to, _removed);
    IPolicyManager.AttemptRequest memory _req =
      _request(_account, _r, _payload, _noPayment(), uint48(block.timestamp + 24 hours));
    _signApproval(_req, _r, 1);
    _signApproval(_req, _r, 2);
    _signApproval(_req, _r, 4);
    _submits(_friend, _req);
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
}
