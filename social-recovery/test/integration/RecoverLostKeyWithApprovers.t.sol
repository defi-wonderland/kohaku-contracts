// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {BindingDigest} from 'libraries/BindingDigest.sol';
import {IPolicyManager} from 'interfaces/IPolicyManager.sol';
import {IRecoveryAction} from 'interfaces/IRecoveryAction.sol';

import {IAmbireAccount} from 'contracts/actions/ambire/IAmbireAccount.sol';
import {IAmbireRecoveryAction} from 'contracts/actions/ambire/IAmbireRecoveryAction.sol';

import {IntegrationBase} from 'test/integration/base/IntegrationBase.sol';
import {LocalAmbireAccount, LocalEntryPoint} from 'test/integration/base/LocalAmbire.sol';
import {LocalSafe} from 'test/integration/base/LocalWorld.sol';

/// @notice A holder lost their only key. Their approvers sign a handover to the new key, the wait passes and anyone
///         executes it. Then the new key replaces the rule the recovery made public. The story is told once; each kind
///         below says who the approvers are, which of Maya's devices fills her second clause, and who submits.
abstract contract RecoverLostKeyWithApprovers is IntegrationBase {
  /// @notice The holder's account.
  address internal _account;
  /// @notice The holder's rule, as the backup holds it.
  Rule internal _holderRule;

  function setUp() public virtual override {
    super.setUp();
    _account = _openAccount(_originalKey.addr);
    Rule memory _r = _holdersRule();
    _keep(_holderRule, _r);
    _setUpRecovery(_account, _originalKey, _r);
  }

  /*///////////////////////////////////////////////////////////////
                         WHAT EACH KIND SAYS
  ///////////////////////////////////////////////////////////////*/

  /// @notice The rule the holder committed.
  function _holdersRule() internal virtual returns (Rule memory _r) {
    _r = _mayaRule(_account);
  }

  /// @notice The approvers who answer sign or prove the approval of the request, each for their place.
  function _approversApprove(IPolicyManager.AttemptRequest memory _req, Rule memory _r) internal view virtual {
    // Ben signs the approval for place 1.
    _signApproval(_req, _r, 1);
    // Carla signs the approval for place 2.
    _signApproval(_req, _r, 2);
    // Maya asserts her passkey over the approval for place 4.
    _signApproval(_req, _r, 4);
  }

  /// @notice Someone submits the gathered request.
  function _submitterSends(IPolicyManager.AttemptRequest memory _req) internal virtual {
    // The holder funds the new key from an exchange, and the new key submits.
    vm.deal(_newKey.addr, 0.05 ether);
    _submits(_newKey.addr, _req);
  }

  /*///////////////////////////////////////////////////////////////
                              THE WALK
  ///////////////////////////////////////////////////////////////*/

  /// @notice The approvers' approvals and the wait hand the account to the new key, the lost key loses it, and nobody
  ///         is paid. This is the recovery the kit exists for: the holder gets their account back with no key of their
  ///         own.
  function test_WhenTheApproversHandTheAccountToANewKey() external {
    Rule memory _r = _holderRule;
    uint256 _accountBalance = _account.balance;
    uint256 _executorBalance = _executor.balance;

    // The holder builds the request on their new device: hand the account from the lost key to the new key, pay
    // nobody, valid for 24 hours.
    bytes memory _payload = _handover(_newKey.addr, _originalKey.addr);
    IPolicyManager.AttemptRequest memory _req =
      _request(_account, _r, _payload, _noPayment(), uint48(block.timestamp + 24 hours));

    // The approvers sign the request.
    _approversApprove(_req, _r);

    // The request is submitted, and the attempt opens.
    _submitterSends(_req);

    // Five days pass.
    skip(_r.wait);

    // Anyone executes the handover, which spends the attempt, adds the new key and removes the lost key.
    _executes(_executor, _account, _payload);

    // Nobody was paid.
    assertEq(_account.balance, _accountBalance, 'nothing left the account');
    assertEq(_executor.balance, _executorBalance, 'the executor was not paid');
    // The new key controls the account.
    assertEq(_privilegeOf(_account, _newKey.addr), bytes32(uint256(1)), 'the new key holds privilege 1');
    _assertKeyControls(_account, _newKey, 'the new key');
    // The lost key holds nothing, and a batch it signs reverts.
    assertEq(_privilegeOf(_account, _originalKey.addr), bytes32(0), 'the lost key holds nothing');
    _assertKeyLocked(_account, _originalKey);
  }

  /// @notice The new key, though written at privilege 1, commits a new setup with other approvers, and the old
  ///         approvers, who could reopen at once under the rule the recovery made public, open nothing. Adopting a
  ///         replacement identity method on the same manager is this same commit with other credentials.
  function test_WhenTheNewKeyReplacesThePublishedRule() external {
    // The recovery runs to the end.
    _recoverToTheNewKey();

    // At once, the old approvers open a new attempt under the published rule, handing the account to a key of theirs.
    Rule memory _published = _holderRule;
    Person memory _theirKey = _person('old approvers key');
    bytes memory _theirPayload = _handover(_theirKey.addr, _newKey.addr);
    IPolicyManager.AttemptRequest memory _first =
      _request(_account, _published, _theirPayload, _noPayment(), uint48(block.timestamp + 24 hours));
    _approversApprove(_first, _published);
    _submits(_attacker.addr, _first);
    assertEq(uint8(_attempt(_account).state), uint8(IPolicyManager.AttemptState.Waiting), 'the old rule reopened');

    // The new key signs a commit of a rule with other approvers and salts only its backup knows.
    Rule memory _fresh = _freshRule();
    _keySignsAndRelayerSends(_account, _newKey, _batch(_commitCall(_account, _fresh, 2)));

    // The old approvers sign another request from the published rule and send it.
    IPolicyManager.AttemptRequest memory _second =
      _request(_account, _published, _theirPayload, _noPayment(), uint48(block.timestamp + 24 hours));
    _approversApprove(_second, _published);
    vm.prank(_attacker.addr);
    vm.expectPartialRevert(IPolicyManager.PolicyManager_SetupCommitmentMismatch.selector);
    _manager.startAttempt(_second);

    // The wait of their first attempt passes, and its handover runs nowhere.
    skip(_published.wait);
    vm.prank(_attacker.addr);
    vm.expectPartialRevert(IRecoveryAction.RecoveryAction_NotConsumable.selector);
    _action.executeHandover(_account, _theirPayload);

    // The new rule stands, and the new key still controls the account.
    assertEq(_stateOf(_account).setupCommitment, _commitment(_account, 2, _fresh), 'the new rule stands');
    assertEq(_privilegeOf(_account, _theirKey.addr), bytes32(0), 'the old approvers key holds nothing');
    _assertKeyControls(_account, _newKey, 'the new key');
  }

  /// @notice The new key commits the same approvers again under fresh salts. The approvals the old approvers signed
  ///         under the published rule open nothing, signed before the commit or after it, while the same approvers'
  ///         fresh approvals under the new salts open an attempt and recover the account.
  function test_WhenTheSameApproversSignUnderFreshSalts() external {
    // The recovery runs to the end, and the approvers sign approvals for attempt 2 under the published rule.
    _recoverToTheNewKey();
    Rule memory _published = _holderRule;
    bytes memory _payload = _handover(_secondNewKey.addr, _newKey.addr);
    IPolicyManager.AttemptRequest memory _signedBefore =
      _request(_account, _published, _payload, _noPayment(), uint48(block.timestamp + 30 days));
    _approversApprove(_signedBefore, _published);

    // The new key commits the same approvers under salts only its new backup knows.
    Rule memory _resalted = _holderRule;
    for (uint256 _place; _place < _resalted.places.length; ++_place) {
      _resalted.places[_place].salt = keccak256(abi.encode('Maya fresh salt', _place));
    }
    _keySignsAndRelayerSends(_account, _newKey, _batch(_commitCall(_account, _resalted, 2)));

    // The approvals signed before the commit fail.
    vm.prank(_attacker.addr);
    vm.expectPartialRevert(IPolicyManager.PolicyManager_WrongSetupNonce.selector);
    _manager.startAttempt(_signedBefore);

    // Approvals signed after the commit over the published rule fail too.
    IPolicyManager.AttemptRequest memory _signedAfter =
      _request(_account, _published, _payload, _noPayment(), uint48(block.timestamp + 24 hours));
    _approversApprove(_signedAfter, _published);
    vm.prank(_attacker.addr);
    vm.expectPartialRevert(IPolicyManager.PolicyManager_SetupCommitmentMismatch.selector);
    _manager.startAttempt(_signedAfter);

    // The same approvers sign under the fresh salts, and the attempt opens.
    IPolicyManager.AttemptRequest memory _fresh =
      _request(_account, _resalted, _payload, _noPayment(), uint48(block.timestamp + 24 hours));
    _approversApprove(_fresh, _resalted);
    _submits(_friend, _fresh);

    // The wait passes, and anyone executes: the account moves to the holder's second new key.
    skip(_resalted.wait);
    _executes(_executor, _account, _payload);
    _assertKeyControls(_account, _secondNewKey, 'the second new key');
  }

  /*///////////////////////////////////////////////////////////////
                              UTILITIES
  ///////////////////////////////////////////////////////////////*/

  /// @notice The approvers open the holder's attempt handing the account to the new key, with the given order, and a
  ///         friend submits it. The payload comes back.
  function _openTheHoldersAttempt(IPolicyManager.PaymentOrder memory _order) internal returns (bytes memory _payload) {
    Rule memory _r = _holderRule;
    _payload = _handover(_newKey.addr, _originalKey.addr);
    IPolicyManager.AttemptRequest memory _req =
      _request(_account, _r, _payload, _order, uint48(block.timestamp + 24 hours));
    _approversApprove(_req, _r);
    _submits(_friend, _req);
  }

  /// @notice The approvers recover the account to the new key: open, wait, execute.
  function _recoverToTheNewKey() internal {
    bytes memory _payload = _openTheHoldersAttempt(_noPayment());
    skip(_holderRule.wait);
    _executes(_executor, _account, _payload);
  }

  /// @notice Maya's fresh rule: any 2 of Ana, her sister and her brother, and her passkey, each under a salt only her
  ///         backup knows.
  function _freshRule() internal returns (Rule memory _r) {
    _r = _rule(
      _account,
      5 days,
      false,
      _thresholds(2, 1),
      _sizes(3, 1),
      _credentials(
        _walletGuardian(_ana),
        _walletGuardian(_person('Maya sister')),
        _walletGuardian(_person('Maya brother')),
        _passkey(_mayaPasskey)
      )
    );
    for (uint256 _place; _place < _r.places.length; ++_place) {
      _r.places[_place].salt = keccak256(abi.encode('Maya backup salt after the recovery', _place));
    }
  }
}

/// @notice Maya recovers with Ben and Carla, two guardians with plain wallets, and her passkey, while Ana does not
///         answer. The new key, funded by Maya, submits. This kind also carries the cases where the story must hold
///         even if someone tries something else, and the trade-offs the kit accepts.
contract RecoverLostKeyWithApproversAndPlainGuardians is RecoverLostKeyWithApprovers {
  /// @notice The batch the action builds for the approved handover with no payment.
  function _approvedBatch() internal view returns (IAmbireRecoveryAction.Transaction[] memory _calls) {
    _calls = _batch(
      _call(
        address(_manager),
        abi.encodeCall(
          IPolicyManager.consume,
          (address(_action), _attempt(_account).attemptId, keccak256(_handover(_newKey.addr, _originalKey.addr)))
        )
      ),
      _setPrivilegeCall(_account, _newKey.addr, bytes32(uint256(1))),
      _setPrivilegeCall(_account, _originalKey.addr, bytes32(0))
    );
  }

  /*///////////////////////////////////////////////////////////////
                              EVEN IF
  ///////////////////////////////////////////////////////////////*/

  /// @notice The request's window closes during the wait, and the accepted attempt still executes. The window limits
  ///         when the gathered request may be sent, not when the recovery may finish.
  function test_WhenTheWindowPassesDuringTheWait() external {
    // The approvers open the attempt with a request valid for 24 hours.
    bytes memory _payload = _openTheHoldersAttempt(_noPayment());
    uint48 _validUntil = uint48(block.timestamp + 24 hours);

    // The 24 hours pass, then the rest of the five-day wait.
    skip(5 days);
    assertGt(block.timestamp, _validUntil, 'the window is over');

    // Anyone executes, and the new key takes the account.
    _executes(_executor, _account, _payload);
    _assertKeyControls(_account, _newKey, 'the new key');
  }

  /// @notice Someone builds the handover batch by hand and sends it straight to the account with the kit's signature:
  ///         with a call added, with the new key at privilege 2, or removing another key. The account asks the action
  ///         and refuses each one, the attempt keeps waiting, and the approved handover still executes afterwards.
  function test_RevertWhen_AHandBuiltBatchChangesTheHandover() external {
    // Maya's account also holds her laptop key, which she still uses.
    Person memory _laptop = _person('Maya laptop key');
    _keySignsAndRelayerSends(
      _account, _originalKey, _batch(_setPrivilegeCall(_account, _laptop.addr, bytes32(uint256(2))))
    );

    // The approvers open the attempt, and the wait passes.
    bytes memory _payload = _openTheHoldersAttempt(_noPayment());
    skip(5 days);
    bytes memory _signature = _kitSignature();
    IAmbireRecoveryAction.Transaction[] memory _approved = _approvedBatch();

    // The attacker sends the approved batch with one more call, a transfer of the account's ETH to them.
    IAmbireRecoveryAction.Transaction[] memory _withTransfer =
      _batch(_approved[0], _approved[1], _approved[2], _transferCall(_attacker.addr, 1 ether));
    vm.prank(_attacker.addr);
    vm.expectRevert(abi.encodeWithSelector(IRecoveryAction.RecoveryAction_BatchNotApproved.selector, 3));
    IAmbireAccount(_account).execute(_withTransfer, _signature);

    // The attacker sends it with the new key written at privilege 2 instead of 1.
    IAmbireRecoveryAction.Transaction[] memory _atTwo =
      _batch(_approved[0], _setPrivilegeCall(_account, _newKey.addr, bytes32(uint256(2))), _approved[2]);
    vm.prank(_attacker.addr);
    vm.expectRevert(abi.encodeWithSelector(IRecoveryAction.RecoveryAction_BatchNotApproved.selector, 1));
    IAmbireAccount(_account).execute(_atTwo, _signature);

    // The attacker sends it removing the laptop key instead of the lost key.
    IAmbireRecoveryAction.Transaction[] memory _otherKey =
      _batch(_approved[0], _approved[1], _setPrivilegeCall(_account, _laptop.addr, bytes32(0)));
    vm.prank(_attacker.addr);
    vm.expectRevert(abi.encodeWithSelector(IRecoveryAction.RecoveryAction_BatchNotApproved.selector, 1));
    IAmbireAccount(_account).execute(_otherKey, _signature);

    // Nothing moved and the attempt keeps waiting.
    assertEq(_attacker.addr.balance, 0, 'the attacker got no ETH');
    assertEq(uint8(_attempt(_account).state), uint8(IPolicyManager.AttemptState.Waiting), 'the attempt keeps waiting');
    _assertKeyControls(_account, _laptop, 'the laptop key');

    // The approved handover still executes, at privilege 1.
    _executes(_executor, _account, _payload);
    assertEq(_privilegeOf(_account, _newKey.addr), bytes32(uint256(1)), 'the new key holds privilege 1, not 2');
    _assertKeyLocked(_account, _originalKey);
  }

  /// @notice An ERC-4337 operation with an empty signature, sponsored by a paymaster and carrying the kit's batch,
  ///         reaches the same callback as executeHandover, on an account that never turned ERC-4337 on: a changed
  ///         batch is refused and the approved one runs. The sponsored path is no way around the approval.
  function test_WhenAPaymasterSponsoredOperationRunsTheBatch() external {
    // Maya never turned on ERC-4337: the entry point holds no privilege on her account.
    assertEq(_privilegeOf(_account, address(_entryPoint)), bytes32(0), 'the entry point holds nothing');

    // The approvers open the attempt, and the wait passes.
    _openTheHoldersAttempt(_noPayment());
    skip(5 days);
    IAmbireRecoveryAction.Transaction[] memory _approved = _approvedBatch();
    uint256 _deposit = _entryPoint.deposits(_paymaster);

    // An attacker sends a sponsored operation with no signature, running the batch plus a transfer to them.
    IAmbireRecoveryAction.Transaction[] memory _withTransfer =
      _batch(_approved[0], _approved[1], _approved[2], _transferCall(_attacker.addr, 1 ether));
    LocalEntryPoint.PackedUserOperation memory _diverting = _operationWithoutSignature(_withTransfer);
    vm.prank(_attacker.addr);
    vm.expectRevert(abi.encodeWithSelector(IRecoveryAction.RecoveryAction_BatchNotApproved.selector, 3));
    _entryPoint.handleOp(_diverting);
    assertEq(uint8(_attempt(_account).state), uint8(IPolicyManager.AttemptState.Waiting), 'the attempt keeps waiting');

    // A bundler sends a sponsored operation with no signature, running the approved batch.
    LocalEntryPoint.PackedUserOperation memory _honest = _operationWithoutSignature(_approved);
    vm.prank(_relayer);
    _entryPoint.handleOp(_honest);

    // The approved batch ran once, the paymaster paid the gas, and nothing else left the account.
    assertEq(uint8(_attempt(_account).state), uint8(IPolicyManager.AttemptState.Consumed), 'the attempt is spent');
    assertEq(_deposit - _entryPoint.deposits(_paymaster), _entryPoint.OPERATION_FEE(), 'the paymaster paid');
    assertEq(_attacker.addr.balance, 0, 'the attacker got no ETH');
    _assertKeyControls(_account, _newKey, 'the new key');
    _assertKeyLocked(_account, _originalKey);
  }

  /*///////////////////////////////////////////////////////////////
                             TRADE-OFFS
  ///////////////////////////////////////////////////////////////*/

  /// @notice One second before the wait ends nobody can execute, and in the first block after it any bot
  ///         does. Maya does not choose when her account changes hands.
  function test_WhenAnyoneExecutesInTheFirstBlockAfterTheWait() external {
    // The approvers open the attempt.
    bytes memory _payload = _openTheHoldersAttempt(_noPayment());
    uint48 _end = _attempt(_account).consumableAfter;
    address _anyone = makeAddr('any bot');

    // One second before the wait ends, the bot tries to execute, and it is refused.
    vm.warp(_end - 1);
    vm.prank(_anyone);
    vm.expectPartialRevert(IRecoveryAction.RecoveryAction_NotConsumable.selector);
    _action.executeHandover(_account, _payload);

    // At the first second the wait allows, the bot executes.
    vm.warp(_end);
    vm.roll(block.number + 1);
    _executes(_anyone, _account, _payload);

    // The account is the new key's.
    _assertKeyControls(_account, _newKey, 'the new key');
  }

  /// @notice The new key is written at privilege 1, so the account refuses its unwrapped signature over a plain message
  ///         and over typed data, and accepts each only in Ambire's account-bound envelope, until the wallet wraps the
  ///         new key's signatures.
  function test_WhenTheNewKeySignsAnUnwrappedMessage() external {
    // The recovery runs to the end.
    _recoverToTheNewKey();

    // A dapp asks the new key to sign a plain login message, and then typed data under its own EIP-712 domain.
    bytes32[] memory _hashes = new bytes32[](2);
    _hashes[0] = keccak256(abi.encodePacked('\x19Ethereum Signed Message:\n23', 'Sign in to dapp.example'));
    _hashes[1] = keccak256(
      abi.encodePacked(
        '\x19\x01',
        keccak256(abi.encode(keccak256('EIP712Domain(string name)'), keccak256('dapp.example'))),
        keccak256(abi.encode(keccak256('Login(address account)'), _account))
      )
    );
    assertEq(_privilegeOf(_account, _newKey.addr), bytes32(uint256(1)), 'the new key is at privilege 1');

    for (uint256 _i; _i < _hashes.length; ++_i) {
      // The new key signs the hash unwrapped, and then in the account-bound envelope.
      (uint8 _v, bytes32 _r, bytes32 _s) = vm.sign(_newKey.key, _hashes[_i]);
      bytes memory _unwrapped = abi.encodePacked(_r, _s, _v, uint8(0));
      bytes memory _wrapped = _signsBound(_account, _newKey.key, _hashes[_i]);

      // The account refuses the unwrapped signature and accepts the wrapped one.
      assertEq(
        LocalAmbireAccount(payable(_account)).isValidSignature(_hashes[_i], _unwrapped),
        bytes4(0xffffffff),
        'unwrapped refused'
      );
      assertEq(
        LocalAmbireAccount(payable(_account)).isValidSignature(_hashes[_i], _wrapped),
        bytes4(0x1626ba7e),
        'wrapped accepted'
      );
    }
  }

  /// @notice The new key recommits the identical published rule under the next nonce. The old approvals die with the
  ///         nonce, but the old approvers sign fresh ones over the public rule and take the account: only a changed
  ///         rule or fresh salts protect the holder.
  function test_WhenTheNewKeyRecommitsThePublishedRule() external {
    // The recovery runs to the end, and the old approvers sign approvals for attempt 2 handing the account to their
    // key.
    _recoverToTheNewKey();
    Rule memory _published = _holderRule;
    Person memory _theirKey = _person('old approvers key');
    bytes memory _payload = _handover(_theirKey.addr, _newKey.addr);
    IPolicyManager.AttemptRequest memory _old =
      _request(_account, _published, _payload, _noPayment(), uint48(block.timestamp + 30 days));
    _approversApprove(_old, _published);

    // The new key commits the identical rule under nonce 2.
    _keySignsAndRelayerSends(_account, _newKey, _batch(_commitCall(_account, _published, 2)));

    // The old approvals fail on the nonce.
    vm.prank(_attacker.addr);
    vm.expectPartialRevert(IPolicyManager.PolicyManager_WrongSetupNonce.selector);
    _manager.startAttempt(_old);

    // The old approvers sign fresh approvals over the public rule, and the attempt opens.
    IPolicyManager.AttemptRequest memory _fresh =
      _request(_account, _published, _payload, _noPayment(), uint48(block.timestamp + 24 hours));
    _approversApprove(_fresh, _published);
    _submits(_attacker.addr, _fresh);

    // The wait passes, and the old approvers' key takes the account from the new key.
    skip(_published.wait);
    _executes(_attacker.addr, _account, _payload);
    _assertKeyControls(_account, _theirKey, 'the old approvers key');
    _assertKeyLocked(_account, _newKey);
  }

  /// @notice Under default salts, anyone who knows Ana's address recomputes her credential from the rule the opening
  ///         published and learns she is Maya's guardian, though Ana never approved.
  function test_WhenAGuardianWithADefaultSaltIsRevealed() external {
    // The approvers open the attempt without Ana, and the request they sent is public.
    Rule memory _r = _holderRule;
    IPolicyManager.AttemptRequest memory _sent = _request(
      _account, _r, _handover(_newKey.addr, _originalKey.addr), _noPayment(), uint48(block.timestamp + 24 hours)
    );
    _approversApprove(_sent, _r);
    _submits(_friend, _sent);

    // An observer reads the published body and hashes Ana's address, and someone else's, with the default salt of
    // place 0.
    (,, IPolicyManager.Clause[] memory _clauses) = abi.decode(_sent.setupBody, (uint48, bool, IPolicyManager.Clause[]));
    bytes32 _defaultSalt = keccak256(abi.encode(_account, uint256(0)));
    bytes32 _anaGuess = BindingDigest.credentialCommitment(address(_ecdsaMethod), abi.encode(_ana.addr), _defaultSalt);
    bytes32 _wrongGuess =
      BindingDigest.credentialCommitment(address(_ecdsaMethod), abi.encode(makeAddr('someone else')), _defaultSalt);

    // Ana's guess matches place 0 and the other guess does not: the observer knows Ana is a guardian.
    assertEq(_anaGuess, _clauses[0].credentials[0], 'Ana is recognisable at place 0');
    assertTrue(_wrongGuess != _clauses[0].credentials[0], 'a wrong guess matches nothing');
    for (uint256 _i; _i < _sent.proofs.length; ++_i) {
      assertTrue(_sent.proofs[_i].place != 0, 'Ana never approved');
    }
  }

  /// @notice An operation for the account with no signature, sponsored by the paymaster, whose executeMultiple call
  ///         runs the batch under the kit's signature. Its nonce is the one-time commitment the account requires: the
  ///         hash of the init code, the call data, the gas fields and the paymaster data, shifted into the nonce key.
  function _operationWithoutSignature(IAmbireRecoveryAction.Transaction[] memory _calls)
    internal
    view
    returns (LocalEntryPoint.PackedUserOperation memory _op)
  {
    LocalAmbireAccount.ExecuteArgs[] memory _bundles = new LocalAmbireAccount.ExecuteArgs[](1);
    _bundles[0] = LocalAmbireAccount.ExecuteArgs(_calls, _kitSignature());
    bytes memory _callData = abi.encodeCall(LocalAmbireAccount.executeMultiple, (_bundles));
    _op = _sponsoredOperation(_account, 0, _callData);
    _op.nonce = uint256(
      keccak256(
        abi.encode(
          _op.initCode, _op.callData, _op.accountGasLimits, _op.preVerificationGas, _op.gasFees, _op.paymasterAndData
        )
      )
    ) << 64;
  }
}

/// @notice Ben is a 2-of-3 Safe, which answers ERC-1271 for its owners, and approves with two owner signatures.
contract RecoverLostKeyWithApproversWhenBenIsASafe is RecoverLostKeyWithApprovers {
  function _holdersRule() internal override returns (Rule memory _r) {
    Person memory _owner1 = _person('Ben Safe owner 1');
    Person memory _owner2 = _person('Ben Safe owner 2');
    Person memory _owner3 = _person('Ben Safe owner 3');
    address[] memory _owners = new address[](3);
    (_owners[0], _owners[1], _owners[2]) = (_owner1.addr, _owner2.addr, _owner3.addr);
    uint256[] memory _signingOwners = new uint256[](2);
    (_signingOwners[0], _signingOwners[1]) = (_owner1.key, _owner3.key);
    LocalSafe _benSafe = new LocalSafe(_owners, 2);
    _r = _rule(
      _account,
      5 days,
      false,
      _thresholds(2, 1),
      _sizes(3, 2),
      _credentials(
        _walletGuardian(_ana),
        _safeGuardian(_benSafe, _signingOwners),
        _walletGuardian(_carla),
        _walletGuardian(_hardwareWallet),
        _passkey(_mayaPasskey)
      )
    );
  }
}

/// @notice Maya's second clause is filled by her hardware wallet rather than her passkey.
contract RecoverLostKeyWithApproversAndTheHardwareWallet is RecoverLostKeyWithApprovers {
  function _approversApprove(IPolicyManager.AttemptRequest memory _req, Rule memory _r) internal view override {
    // Ben signs the approval for place 1.
    _signApproval(_req, _r, 1);
    // Carla signs the approval for place 2.
    _signApproval(_req, _r, 2);
    // Maya signs with her hardware wallet for place 3.
    _signApproval(_req, _r, 3);
  }
}

/// @notice A friend submits the gathered request from their own wallet.
contract RecoverLostKeyWithApproversSubmittedByAFriend is RecoverLostKeyWithApprovers {
  function _submitterSends(IPolicyManager.AttemptRequest memory _req) internal override {
    // A friend submits from their own funded wallet.
    _submits(_friend, _req);
  }
}

/// @notice The new key's own fresh smart account submits the request as an ERC-4337 operation a paymaster sponsors, so
///         the holder needs no ETH at all.
contract RecoverLostKeyWithApproversThroughASponsoredOperation is RecoverLostKeyWithApprovers {
  function _submitterSends(IPolicyManager.AttemptRequest memory _req) internal override {
    // The new key's new smart account holds no ETH.
    address _newKeyAccount = _openAccountWithEntryPoint(_newKey.addr);
    vm.deal(_newKeyAccount, 0);
    // The new key signs an operation that submits the request, and the paymaster sponsors it.
    _keySendsSponsoredOperation(
      _newKeyAccount, _newKey, _batch(_call(address(_manager), abi.encodeCall(IPolicyManager.startAttempt, (_req))))
    );
  }
}
