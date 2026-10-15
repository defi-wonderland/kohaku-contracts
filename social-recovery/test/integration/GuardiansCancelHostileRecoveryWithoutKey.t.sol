// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {BindingDigest} from 'libraries/BindingDigest.sol';
import {IPolicyManager} from 'interfaces/IPolicyManager.sol';
import {IRecoveryAction} from 'interfaces/IRecoveryAction.sol';

import {IntegrationBase} from 'test/integration/base/IntegrationBase.sol';
import {LocalSafe} from 'test/integration/base/LocalWorld.sol';

/// @notice The holder lost their key, and a recovery they do not want is running. Their rule is any 2 of five wallet
///         guardians, Omar, Ines, Hana, Theo and Pablo at places 0 to 4, with a five-day wait and default salts. The
///         attacker controls Omar and Pablo. Hana and Theo, the guardians the attacker does not control, cancel the
///         attempt without the holder's key or backup, then recover the account to the holder's new key. The story is
///         told once; each kind below says whether Hana is a plain wallet or a smart wallet.
abstract contract GuardiansCancelHostileRecoveryWithoutKey is IntegrationBase {
  /// @notice The holder's account.
  address internal _account;
  /// @notice The holder's rule, as the backup holds it.
  Rule internal _holderRule;
  /// @notice The guardians the attacker controls, at places 0 and 4, and the one who does not answer, at place 1.
  Person internal _omar;
  Person internal _ines;
  Person internal _pablo;
  /// @notice The guardian at place 3, whom the attacker does not control.
  Person internal _theo;
  /// @notice What Hana and Theo know of their own credentials: the method and their configuration, never the salt.
  Credential internal _hanaKnows;
  Credential internal _theoKnows;

  function setUp() public virtual override {
    super.setUp();
    _omar = _person('Omar');
    _ines = _person('Ines');
    _theo = _person('Theo');
    _pablo = _person('Pablo');
    _account = _openAccount(_originalKey.addr);
    Credential memory _hana = _hanaCredential();
    Credential memory _theoCredential = _walletGuardian(_theo);
    (_hanaKnows.method, _hanaKnows.config) = (_hana.method, _hana.config);
    (_theoKnows.method, _theoKnows.config) = (_theoCredential.method, _theoCredential.config);
    Rule memory _r = _rule(
      _account,
      5 days,
      false,
      _thresholds(2),
      _sizes(5),
      _credentials(_walletGuardian(_omar), _walletGuardian(_ines), _hana, _theoCredential, _walletGuardian(_pablo))
    );
    _keep(_holderRule, _r);
    _setUpRecovery(_account, _originalKey, _r);
    _usdc.mint(_account, 100e6);
  }

  /*///////////////////////////////////////////////////////////////
                         WHAT EACH KIND SAYS
  ///////////////////////////////////////////////////////////////*/

  /// @notice Hana's credential at place 2.
  function _hanaCredential() internal virtual returns (Credential memory _credential);

  /*///////////////////////////////////////////////////////////////
                              THE WALK
  ///////////////////////////////////////////////////////////////*/

  /// @notice Hana and Theo cancel the running attempt with no key and no backup, then open the next attempt to the
  ///         holder's new key, which runs its own full wait. The same path serves three motivations: an attacker opened
  ///         the attempt, the holder opened it and lost the new key's device before executing, or two satisfying sets
  ///         raced for the same attempt id. Whoever sends the cancel gets nothing back from the account.
  function test_WhenTheGuardiansCancelAndRecover() external {
    uint256 _friendEth = _friend.balance;

    // The attacker opens attempt 1 with Omar and Pablo, handing the account to the attacker's key.
    IPolicyManager.AttemptRequest memory _hostile = _attackersRequest();
    _submits(_attacker.addr, _hostile);

    // Hana and Theo sign the cancellation of attempt 1. With default salts they find their places in the body the
    // opening published, and build the cancel without the holder's backup.
    IPolicyManager.CancelRequest memory _cancel = _cancelWithoutTheBackup(_hostile.setupBody, 1);

    // The friend sends cancelByProofs.
    _submitsCancel(_friend, _cancel);

    // The wait passes, and the attacker sends executeHandover. It reverts.
    skip(5 days);
    vm.prank(_attacker.addr);
    vm.expectPartialRevert(IRecoveryAction.RecoveryAction_NotConsumable.selector);
    _action.executeHandover(_account, _hostile.payload);

    // Hana and Theo sign approvals for attempt 2, handing the account to the holder's new key, and the friend sends
    // startAttempt.
    bytes memory _payload = _handover(_newKey.addr, _originalKey.addr);
    _submits(_friend, _approvalWithoutTheBackup(_hostile.setupBody, _payload, _noPayment()));
    uint256 _openedAt = block.timestamp;

    // Five full days pass.
    skip(5 days);

    // Anyone sends executeHandover.
    _executes(_executor, _account, _payload);

    // Attempt 2 ran its own full wait, and the holder's new key controls the account.
    IPolicyManager.Attempt memory _spent = _attempt(_account);
    assertEq(_spent.attemptId, 2, 'attempt 2 ran');
    assertEq(_spent.consumableAfter, _openedAt + 5 days, 'attempt 2 waited its own five days');
    _assertKeyControls(_account, _newKey, 'the new key');
    assertEq(_privilegeOf(_account, _attacker.addr), bytes32(0), 'the attacker holds nothing');
    // The friend who sent the cancel was paid nothing back.
    assertEq(_usdc.balanceOf(_friend), 0, 'the friend got no USDC');
    assertEq(_friend.balance, _friendEth, 'the friend got no ETH');
  }

  /*///////////////////////////////////////////////////////////////
                              UTILITIES
  ///////////////////////////////////////////////////////////////*/

  /// @notice The attacker's request for the next attempt, handing the account from the lost key to the attacker's key,
  ///         approved by Omar and Pablo.
  function _attackersRequest() internal view returns (IPolicyManager.AttemptRequest memory _req) {
    Rule memory _r = _holderRule;
    _req = _request(
      _account, _r, _handover(_attacker.addr, _originalKey.addr), _noPayment(), uint48(block.timestamp + 24 hours)
    );
    _signApproval(_req, _r, 0);
    _signApproval(_req, _r, 4);
  }

  /// @notice Hana and Theo's cancel of an attempt, built from a published body alone: each finds their own place by
  ///         hashing their credential under the default salt of every place.
  function _cancelWithoutTheBackup(bytes memory _publishedBody, uint64 _attemptId)
    internal
    view
    returns (IPolicyManager.CancelRequest memory _cancel)
  {
    _cancel = IPolicyManager.CancelRequest({
      account: _account,
      action: address(_action),
      attemptId: _attemptId,
      setupNonce: _stateOf(_account).setupNonce,
      setupBody: _publishedBody,
      validUntil: uint48(block.timestamp + 24 hours),
      proofs: new IPolicyManager.ProofPlace[](2)
    });
    (Credential memory _hanaSalted, uint256 _hanaPlace) = _findMyPlace(_hanaKnows, _publishedBody);
    (Credential memory _theoSalted, uint256 _theoPlace) = _findMyPlace(_theoKnows, _publishedBody);
    _cancel.proofs[0] =
      _filled(_hanaSalted, _hanaPlace, _proofFor(_hanaSalted, _manager.hashCancel(_cancel, _hanaPlace)));
    _cancel.proofs[1] =
      _filled(_theoSalted, _theoPlace, _proofFor(_theoSalted, _manager.hashCancel(_cancel, _theoPlace)));
  }

  /// @notice Hana and Theo's approval of the next attempt, built from a published body alone.
  function _approvalWithoutTheBackup(
    bytes memory _publishedBody,
    bytes memory _payload,
    IPolicyManager.PaymentOrder memory _order
  ) internal view returns (IPolicyManager.AttemptRequest memory _req) {
    IPolicyManager.ActionState memory _state = _stateOf(_account);
    _req = IPolicyManager.AttemptRequest({
      account: _account,
      action: address(_action),
      attemptId: _state.nextAttemptId,
      setupNonce: _state.setupNonce,
      setupBody: _publishedBody,
      payload: _payload,
      order: _order,
      validUntil: uint48(block.timestamp + 24 hours),
      proofs: new IPolicyManager.ProofPlace[](2)
    });
    (Credential memory _hanaSalted, uint256 _hanaPlace) = _findMyPlace(_hanaKnows, _publishedBody);
    (Credential memory _theoSalted, uint256 _theoPlace) = _findMyPlace(_theoKnows, _publishedBody);
    _req.proofs[0] = _filled(_hanaSalted, _hanaPlace, _proofFor(_hanaSalted, _manager.hashApproval(_req, _hanaPlace)));
    _req.proofs[1] = _filled(_theoSalted, _theoPlace, _proofFor(_theoSalted, _manager.hashApproval(_req, _theoPlace)));
  }

  /// @notice Where a guardian's credential sits in a published body: the place whose default salt, hashed with the
  ///         credential, gives the hash the body holds there. The credential comes back with that salt.
  function _findMyPlace(Credential memory _mine, bytes memory _publishedBody)
    internal
    view
    returns (Credential memory _salted, uint256 _place)
  {
    (,, IPolicyManager.Clause[] memory _clauses) = abi.decode(_publishedBody, (uint48, bool, IPolicyManager.Clause[]));
    bool _found;
    uint256 _next;
    for (uint256 _i; _i < _clauses.length; ++_i) {
      for (uint256 _j; _j < _clauses[_i].credentials.length; ++_j) {
        bytes32 _salt = keccak256(abi.encode(_account, _next));
        if (BindingDigest.credentialCommitment(_mine.method, _mine.config, _salt) == _clauses[_i].credentials[_j]) {
          (_salted, _place, _found) = (Credential(_mine.method, _mine.config, _salt), _next, true);
        }
        ++_next;
      }
    }
    assertTrue(_found, 'the guardian finds their place in the published body');
  }

  /// @notice A filled place: the credential written out and its proof.
  function _filled(Credential memory _c, uint256 _place, bytes memory _proof)
    internal
    pure
    returns (IPolicyManager.ProofPlace memory _p)
  {
    _p = IPolicyManager.ProofPlace({place: _place, method: _c.method, config: _c.config, salt: _c.salt, proof: _proof});
  }
}

/// @notice Hana and Theo sign with plain wallets. This kind also carries the cases where the cancel must hold even if
///         someone tries something else, and the trade-offs the kit accepts.
contract GuardiansCancelHostileRecoveryWithoutKeyWithPlainWallets is GuardiansCancelHostileRecoveryWithoutKey {
  /// @notice Hana's wallet.
  Person internal _hana;
  /// @notice A sponsor who submits the guardians' request against a fee, and a bot that copies pending submissions.
  address internal _sponsor;
  address internal _frontRunner;

  function _hanaCredential() internal override returns (Credential memory _credential) {
    _hana = _person('Hana');
    _credential = _walletGuardian(_hana);
  }

  /// @notice The guardians' request for the next attempt: hand the account to the new key and pay the sponsor 10 USDC,
  ///         signed by Hana and Theo, valid until a given time.
  function _guardiansRequest(uint48 _validUntil) internal view returns (IPolicyManager.AttemptRequest memory _req) {
    Rule memory _r = _holderRule;
    _req = _request(
      _account,
      _r,
      _handover(_newKey.addr, _originalKey.addr),
      IPolicyManager.PaymentOrder(address(_usdc), 10e6, _sponsor),
      _validUntil
    );
    _signApproval(_req, _r, 2);
    _signApproval(_req, _r, 3);
  }

  /// @notice Hana and Theo sign the cancel of an attempt, valid until a given time.
  function _guardiansCancel(uint64 _attemptId, uint48 _validUntil)
    internal
    view
    returns (IPolicyManager.CancelRequest memory _cancel)
  {
    Rule memory _r = _holderRule;
    _cancel = _cancelRequest(_account, _r, _attemptId, _validUntil);
    _signCancel(_cancel, _r, 2);
    _signCancel(_cancel, _r, 3);
  }

  /*///////////////////////////////////////////////////////////////
                              EVEN IF
  ///////////////////////////////////////////////////////////////*/

  /// @notice After the wait, the cancel and the attacker's executeHandover land in the same block, the cancel first.
  ///         The execution, second, reverts, so a cancel ordered first still saves the account.
  function test_WhenTheCancelAndTheSpendLandInOneBlock() external {
    // The attacker opens attempt 1, the wait passes, and Hana and Theo sign a cancel.
    IPolicyManager.AttemptRequest memory _hostile = _attackersRequest();
    _submits(_attacker.addr, _hostile);
    skip(5 days);
    IPolicyManager.CancelRequest memory _cancel = _guardiansCancel(1, uint48(block.timestamp + 24 hours));

    // In one block, the friend's cancel comes first.
    _submitsCancel(_friend, _cancel);

    // Then, in the same block, the attacker calls executeHandover.
    vm.prank(_attacker.addr);
    vm.expectPartialRevert(IRecoveryAction.RecoveryAction_NotConsumable.selector);
    _action.executeHandover(_account, _hostile.payload);

    // The attacker holds nothing, and the lost key is still the account's key.
    assertEq(_privilegeOf(_account, _attacker.addr), bytes32(0), 'the attacker holds nothing');
    assertEq(_privilegeOf(_account, _originalKey.addr), _SIGNER_PRIVILEGE, 'the lost key is still the account key');
  }

  /// @notice While the attacker's attempt waits, the guardians' request for the same id reverts, even with one second
  ///         of the wait left: one attempt runs at a time. The guardians must cancel and send again, two transactions,
  ///         and its attempt starts a full new wait.
  function test_RevertWhen_ASecondSetOpensTheSameId() external {
    _sponsor = _funded('sponsor');

    // Both sets hold a satisfying request for attempt 1, and the attacker's is mined first.
    IPolicyManager.AttemptRequest memory _honest = _guardiansRequest(uint48(block.timestamp + 30 days));
    _submits(_attacker.addr, _attackersRequest());
    uint48 _hostileEnd = _attempt(_account).consumableAfter;

    // One second before the hostile wait ends, the sponsor sends the guardians' request for attempt 1, and it reverts.
    skip(5 days - 1);
    vm.prank(_sponsor);
    vm.expectPartialRevert(IPolicyManager.PolicyManager_AttemptAlreadyActive.selector);
    _manager.startAttempt(_honest);

    // The guardians send their first transaction, the cancel.
    _submitsCancel(_friend, _guardiansCancel(1, uint48(block.timestamp + 24 hours)));

    // The guardians sign again and send their second transaction, the request for attempt 2.
    _submits(_sponsor, _guardiansRequest(uint48(block.timestamp + 24 hours)));

    // The guardians' attempt waits five full days from now, not from when the hostile one opened.
    uint48 _secondEnd = _attempt(_account).consumableAfter;
    assertEq(_secondEnd, block.timestamp + 5 days, 'a full new wait');
    vm.warp(_hostileEnd + 1);
    vm.prank(_executor);
    vm.expectPartialRevert(IRecoveryAction.RecoveryAction_NotConsumable.selector);
    _action.executeHandover(_account, _handover(_newKey.addr, _originalKey.addr));

    // Once its own wait ends, it runs.
    vm.warp(_secondEnd);
    _executes(_executor, _account, _handover(_newKey.addr, _originalKey.addr));
    _assertKeyControls(_account, _newKey, 'the new key');
  }

  /// @notice After the cancel, a front-runner copies the guardians' request for attempt 2 from the mempool and sends it
  ///         first. The attempt opens with the approved handover and the approved payee, whoever sent it, so copying
  ///         can only ever send what Hana and Theo signed.
  function test_WhenAFrontRunnerCopiesTheRequest() external {
    _sponsor = _funded('sponsor');
    _frontRunner = _funded('front-runner bot');

    // The attacker opens attempt 1, and Hana and Theo cancel it.
    _submits(_attacker.addr, _attackersRequest());
    _submitsCancel(_friend, _guardiansCancel(1, uint48(block.timestamp + 24 hours)));

    // Hana and Theo sign the request for attempt 2, and the sponsor sends it.
    IPolicyManager.AttemptRequest memory _retry = _guardiansRequest(uint48(block.timestamp + 24 hours));

    // A front-runner copies it and gets it mined first, so the sponsor's own transaction reverts.
    _submits(_frontRunner, _retry);
    vm.prank(_sponsor);
    vm.expectPartialRevert(IPolicyManager.PolicyManager_AttemptAlreadyActive.selector);
    _manager.startAttempt(_retry);

    // The wait passes, and anyone executes.
    skip(5 days);
    _executes(_executor, _account, _retry.payload);

    // The approved handover ran, the sponsor was paid and the front-runner got nothing.
    _assertKeyControls(_account, _newKey, 'the new key');
    assertEq(_usdc.balanceOf(_sponsor), 10e6, 'the sponsor was paid');
    assertEq(_usdc.balanceOf(_frontRunner), 0, 'the front-runner got nothing');
  }

  /*///////////////////////////////////////////////////////////////
                             TRADE-OFFS
  ///////////////////////////////////////////////////////////////*/

  /// @notice Right after each cancel the attacker reopens at the next id, and the guardians must cancel again. Each
  ///         round costs gas, and a keyless holder cannot end the cycle: after two rounds a third attempt waits.
  function test_WhenTheAttackerReopensAfterEachCancel() external {
    // Round one: the attacker opens attempt 1, and Hana and Theo cancel it.
    _submits(_attacker.addr, _attackersRequest());
    _submitsCancel(_friend, _guardiansCancel(1, uint48(block.timestamp + 24 hours)));

    // Round two: the attacker reopens at attempt 2 at once, and Hana and Theo cancel again.
    _submits(_attacker.addr, _attackersRequest());
    assertEq(_attempt(_account).attemptId, 2, 'the attacker reopened at 2');
    _submitsCancel(_friend, _guardiansCancel(2, uint48(block.timestamp + 24 hours)));

    // The attacker reopens at attempt 3, and the cycle goes on.
    IPolicyManager.AttemptRequest memory _third = _attackersRequest();
    _submits(_attacker.addr, _third);
    assertEq(_attempt(_account).attemptId, 3, 'the attacker reopened at 3');
    assertEq(uint8(_attempt(_account).state), uint8(IPolicyManager.AttemptState.Waiting), 'attempt 3 waits');

    // Had the guardians stopped cancelling, attempt 3 would hand the account over after its wait.
    skip(5 days);
    _executes(_attacker.addr, _account, _third.payload);
    _assertKeyControls(_account, _attacker, 'the attacker key');
  }

  /// @notice Hana and Theo pre-sign cancels for attempts 2, 3 and 4. The one for 2 kills the attacker's reopening, the
  ///         one for 3 kills whatever opens at 3, the holder's own recovery included, and the one for 4 dies with its
  ///         window, so a pre-signed cancel does not last forever.
  function test_WhenACancelSignedAheadMeetsTheHoldersOwnAttempt() external {
    // The attacker opens attempt 1, and Hana and Theo cancel it.
    _submits(_attacker.addr, _attackersRequest());
    _submitsCancel(_friend, _guardiansCancel(1, uint48(block.timestamp + 24 hours)));

    // Hana and Theo pre-sign cancels for attempts 2, 3 and 4, each valid for 30 days.
    uint48 _validUntil = uint48(block.timestamp + 30 days);
    IPolicyManager.CancelRequest memory _forTwo = _guardiansCancel(2, _validUntil);
    IPolicyManager.CancelRequest memory _forThree = _guardiansCancel(3, _validUntil);
    IPolicyManager.CancelRequest memory _forFour = _guardiansCancel(4, _validUntil);

    // The attacker reopens at attempt 2, and the friend sends the pre-signed cancel for it.
    _submits(_attacker.addr, _attackersRequest());
    _submitsCancel(_friend, _forTwo);
    assertEq(uint8(_attempt(_account).state), uint8(IPolicyManager.AttemptState.Cancelled), 'attempt 2 is cancelled');

    // Days later the holder's own recovery to the new key opens at attempt 3 with Ines and Hana.
    skip(3 days);
    Rule memory _r = _holderRule;
    IPolicyManager.AttemptRequest memory _own = _request(
      _account, _r, _handover(_newKey.addr, _originalKey.addr), _noPayment(), uint48(block.timestamp + 24 hours)
    );
    _signApproval(_own, _r, 1);
    _signApproval(_own, _r, 2);
    _submits(_friend, _own);

    // Anyone who kept the pre-signed cancel for 3 sends it, and the holder's recovery dies.
    _submitsCancel(_attacker.addr, _forThree);
    assertEq(uint8(_attempt(_account).state), uint8(IPolicyManager.AttemptState.Cancelled), 'attempt 3 is cancelled');

    // A month on, the holder's recovery opens at attempt 4, and the pre-signed cancel for 4 has expired.
    skip(30 days);
    IPolicyManager.AttemptRequest memory _again = _request(
      _account, _r, _handover(_newKey.addr, _originalKey.addr), _noPayment(), uint48(block.timestamp + 24 hours)
    );
    _signApproval(_again, _r, 1);
    _signApproval(_again, _r, 2);
    _submits(_friend, _again);
    vm.prank(_attacker.addr);
    vm.expectPartialRevert(IPolicyManager.PolicyManager_RequestExpired.selector);
    _manager.cancelByProofs(_forFour);

    // The wait passes, and the holder's recovery at attempt 4 hands the account to the new key.
    skip(5 days);
    _executes(_executor, _account, _again.payload);
    _assertKeyControls(_account, _newKey, 'the new key');
  }

  /// @notice When the guardians the attacker does not control cannot form a satisfying set, here on an account whose
  ///         rule is any 2 of Omar, Hana and Pablo, no cancel is possible without the key and the attacker takes the
  ///         account after the wait.
  function test_RevertWhen_TheGuardiansLeftCannotSatisfyTheRule() external {
    // A second holder, who lost their key, has the rule any 2 of Omar, Hana and Pablo.
    Person memory _lostKey = _person('second holder lost key');
    address _second = _openAccount(_lostKey.addr);
    Rule memory _r = _rule(
      _second,
      5 days,
      false,
      _thresholds(2),
      _sizes(3),
      _credentials(_walletGuardian(_omar), _walletGuardian(_hana), _walletGuardian(_pablo))
    );
    _setUpRecovery(_second, _lostKey, _r);

    // The attacker opens attempt 1 with Omar and Pablo.
    bytes memory _payload = _handover(_attacker.addr, _lostKey.addr);
    IPolicyManager.AttemptRequest memory _req =
      _request(_second, _r, _payload, _noPayment(), uint48(block.timestamp + 24 hours));
    _signApproval(_req, _r, 0);
    _signApproval(_req, _r, 2);
    _submits(_attacker.addr, _req);

    // Hana, the only guardian the attacker does not control, signs a cancel, and it falls short of the rule.
    IPolicyManager.CancelRequest memory _cancel = _cancelRequest(_second, _r, 1, uint48(block.timestamp + 24 hours));
    _signCancel(_cancel, _r, 1);
    vm.prank(_friend);
    vm.expectPartialRevert(IPolicyManager.PolicyManager_RuleUnsatisfied.selector);
    _manager.cancelByProofs(_cancel);

    // The wait passes, and the attacker takes the account.
    skip(5 days);
    _executes(_attacker.addr, _second, _payload);
    _assertKeyControls(_second, _attacker, 'the attacker key');
  }
}

/// @notice Hana is a 2-of-3 Safe, which answers ERC-1271 for its owners and signs with two owner signatures. Theo is a
///         plain wallet.
contract GuardiansCancelHostileRecoveryWithoutKeyWithASmartWallet is GuardiansCancelHostileRecoveryWithoutKey {
  function _hanaCredential() internal override returns (Credential memory _credential) {
    Person memory _owner1 = _person('Hana Safe owner 1');
    Person memory _owner2 = _person('Hana Safe owner 2');
    Person memory _owner3 = _person('Hana Safe owner 3');
    address[] memory _owners = new address[](3);
    (_owners[0], _owners[1], _owners[2]) = (_owner1.addr, _owner2.addr, _owner3.addr);
    uint256[] memory _signingOwners = new uint256[](2);
    (_signingOwners[0], _signingOwners[1]) = (_owner2.key, _owner3.key);
    _credential = _safeGuardian(new LocalSafe(_owners, 2), _signingOwners);
  }
}
