// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {Vm, VmSafe} from 'forge-std/Vm.sol';
import {SetupBody} from 'libraries/SetupBody.sol';
import {IPolicyManager} from 'interfaces/IPolicyManager.sol';
import {IPolicyMethodPause} from 'interfaces/IPolicyMethodPause.sol';
import {IRecoveryAction} from 'interfaces/IRecoveryAction.sol';
import {AmbireRecoveryAction} from 'contracts/actions/ambire/AmbireRecoveryAction.sol';
import {IAmbireAccount} from 'contracts/actions/ambire/IAmbireAccount.sol';
import {IAmbireRecoveryAction} from 'contracts/actions/ambire/IAmbireRecoveryAction.sol';
import {EcdsaMethod} from 'contracts/methods/ecdsa/EcdsaMethod.sol';
import {PasskeyMethod} from 'contracts/methods/passkey/PasskeyMethod.sol';
import {PolicyManager} from 'contracts/manager/PolicyManager.sol';
import {ActionAmbireAccountFixture, ActionPaymentToken} from 'test/mocks/ActionAmbireAccountFixture.sol';
import {IntegrationPausableMethod} from 'test/mocks/IntegrationPausableMethod.sol';
import {ActionAmbireProxy, ActionAmbireProxyDeployer} from 'test/utils/ActionAmbireProxy.sol';
import {ActionBatch} from 'test/utils/ActionBatch.sol';
import {PasskeyMethodHelpers} from 'test/utils/PasskeyMethodHelpers.sol';

/// @notice The demo kit, deployed for the end-to-end tests. The policy manager, the wallet method,
///         the passkey method and the recovery action are the real contracts, built with the
///         deployment script's constructor arguments. The account is a proxy over a copy of Ambire's
///         account, built the way Ambire's factory builds one. It starts with one key, the holder's,
///         at the value 2 the Kohaku extension writes.
/// @dev The holder's rule has two clauses and five places. Clause zero needs two of three friends,
///      each a wallet guardian under the wallet method (places 0, 1 and 2). Clause one needs one of
///      two: the passkey on the holder's phone (place 3), or a credential under a third-party method
///      that can be paused (place 4). Each guardian signs the digest from the manager's hashApproval
///      or hashCancel view. Wallet guardians sign with vm.sign, and the passkey produces a real
///      WebAuthn assertion that the EVM's P256VERIFY precompile checks.
///      The kit slot is the account entry whose value authorizes the action to run a recovery.
// The tests share one deployed kit, its parties and their keys, which needs more state than the default limit.
// solhint-disable-next-line max-states-count
abstract contract IntegrationDemoKitTestBase is PasskeyMethodHelpers {
  /// @notice The data of one opening event, decoded, in the event's order. The account and the
  ///         action are the event's two indexed topics. The decode relies on that order, so the
  ///         fields are not repacked.
  // solhint-disable-next-line gas-struct-packing
  struct StartedLog {
    uint64 attemptId;
    uint64 setupNonce;
    bytes setupBody;
    uint256[] usedPlaces;
    address[] usedMethods;
    bytes payload;
    IPolicyManager.PaymentOrder order;
    uint48 consumableAfter;
  }

  /// @notice The wait the holder commits: three days between acceptance and the spend.
  uint48 internal constant _WAIT = 3 days;
  /// @notice The passkey's P-256 private key, held by the holder's phone.
  uint256 internal constant _PASSKEY_KEY = 0xA11CE;
  /// @notice The relying-party id the passkey was enrolled under.
  string internal constant _RP_ID = 'recover.example';
  /// @notice The amount the payment order pays, in token units.
  uint256 internal constant _PAYMENT = 5e18;
  /// @notice The value the Kohaku extension writes for the account's first key.
  bytes32 internal constant _SIGNER_VALUE = bytes32(uint256(2));
  /// @notice The value a handover writes for the new key.
  bytes32 internal constant _KEY_VALUE = ActionBatch.KEY_VALUE;
  /// @notice The holder's public note published with the setup.
  bytes internal constant _PUBLIC_METADATA = 'friends and my phone';
  /// @notice The holder's backup published with the setup, opaque to the manager.
  bytes internal constant _PRIVATE_METADATA = hex'c0ffee';
  /// @notice The place of the first wallet guardian.
  uint256 internal constant _ALICE = 0;
  /// @notice The place of the second wallet guardian.
  uint256 internal constant _BOB = 1;
  /// @notice The place of the third wallet guardian.
  uint256 internal constant _CAROL = 2;
  /// @notice The place of the holder's passkey.
  uint256 internal constant _PHONE = 3;
  /// @notice The place of the credential under the third-party method that can be paused.
  uint256 internal constant _THIRD_PARTY = 4;

  /// @notice The policy manager.
  PolicyManager internal _manager;
  /// @notice The wallet method.
  EcdsaMethod internal _ecdsa;
  /// @notice The passkey method.
  PasskeyMethod internal _passkey;
  /// @notice The third-party method that can be paused.
  IntegrationPausableMethod internal _thirdParty;
  /// @notice The implementation behind the account's proxy.
  address internal _implementation;
  /// @notice The recovery action for Ambire's account.
  AmbireRecoveryAction internal _action;
  /// @notice The holder's account.
  address internal _account;
  /// @notice The token the payment order pays in.
  ActionPaymentToken internal _token;
  /// @notice The account's one key at the start, the key a recovery removes.
  address internal _holderKey;
  /// @notice The key a recovery installs.
  address internal _newKey;
  /// @notice Who the payment order pays.
  address internal _payee;
  /// @notice Who sends the opening requests, with no authority of their own.
  address internal _submitter;
  /// @notice Who calls the action once the wait is over.
  address internal _executor;
  /// @notice Who can pause the third-party method.
  address internal _pauseHolder;
  /// @notice The wallet guardians' addresses, by place.
  address[3] internal _guardians;
  /// @notice The wallet guardians' private keys, by place.
  uint256[3] internal _guardianKeys;
  /// @notice sha256 of the relying-party id.
  bytes32 internal _rpIdHash;

  function setUp() public virtual {
    vm.warp(1_700_000_000);
    _manager = new PolicyManager();
    _ecdsa = new EcdsaMethod();
    _passkey = new PasskeyMethod();
    _implementation = address(new ActionAmbireAccountFixture());
    _action = new AmbireRecoveryAction(IPolicyManager(address(_manager)), _implementation);
    // The factory writes the implementation address at full width only when it has no leading zero byte.
    assertTrue(bytes20(_implementation)[0] != 0, 'fixture: the implementation address starts with a zero byte');

    _holderKey = makeAddr('holderKey');
    _account = new ActionAmbireProxyDeployer()
      .deploy(ActionAmbireProxy.creationCode(_implementation, _holderKey, _SIGNER_VALUE), 0);
    _token = new ActionPaymentToken();
    _token.mint(_account, 100e18);
    vm.deal(_account, 10 ether);

    (_guardians[0], _guardianKeys[0]) = makeAddrAndKey('guardianAlice');
    (_guardians[1], _guardianKeys[1]) = makeAddrAndKey('guardianBob');
    (_guardians[2], _guardianKeys[2]) = makeAddrAndKey('guardianCarol');
    _rpIdHash = sha256(bytes(_RP_ID));
    _pauseHolder = makeAddr('pauseHolder');
    _thirdParty = new IntegrationPausableMethod(_pauseHolder);

    _newKey = makeAddr('newKey');
    _payee = makeAddr('payee');
    _submitter = makeAddr('submitter');
    _executor = makeAddr('executor');
    vm.deal(_submitter, 1 ether);
    vm.deal(_executor, 1 ether);
  }

  /*///////////////////////////////////////////////////////////////
                          THE HOLDER'S RULE
  ///////////////////////////////////////////////////////////////*/

  /// @notice The method, config and salt the holder committed at a place. The salt is a supplied
  ///         word per place.
  function _credential(uint256 _place) internal view returns (address _method, bytes memory _config, bytes32 _salt) {
    _salt = keccak256(abi.encode('salt', _place));
    if (_place < _PHONE) {
      _method = address(_ecdsa);
      _config = abi.encode(_guardians[_place]);
    } else if (_place == _PHONE) {
      _method = address(_passkey);
      _config = _buildConfig(_PASSKEY_KEY, _rpIdHash);
    } else {
      _method = address(_thirdParty);
      _config = abi.encode('third party credential');
    }
  }

  /// @notice A credential hash: keccak256(abi.encode(method, config, salt)).
  function _credentialHash(uint256 _place) internal view returns (bytes32 _hash) {
    (address _method, bytes memory _config, bytes32 _salt) = _credential(_place);
    _hash = keccak256(abi.encode(_method, _config, _salt));
  }

  /// @notice The holder's rule with a given wait and pause choice: two of the three friends, and
  ///         one of the phone and the third-party credential.
  function _rule(uint48 _wait, bool _ignoresPause) internal view returns (bytes memory _setupBody) {
    IPolicyManager.Clause[] memory _clauses = new IPolicyManager.Clause[](2);
    _clauses[0].threshold = 2;
    _clauses[0].credentials = new bytes32[](3);
    _clauses[0].credentials[0] = _credentialHash(_ALICE);
    _clauses[0].credentials[1] = _credentialHash(_BOB);
    _clauses[0].credentials[2] = _credentialHash(_CAROL);
    _clauses[1].threshold = 1;
    _clauses[1].credentials = new bytes32[](2);
    _clauses[1].credentials[0] = _credentialHash(_PHONE);
    _clauses[1].credentials[1] = _credentialHash(_THIRD_PARTY);
    _setupBody = SetupBody.encode(_wait, _ignoresPause, _clauses);
  }

  /// @notice The holder's default rule: a three day wait, and pauses apply to the holder's attempts.
  function _body() internal view returns (bytes memory _setupBody) {
    _setupBody = _rule(_WAIT, false);
  }

  /// @notice The setup commitment: keccak256(abi.encode(account, action, nonce, body)).
  function _commitmentOf(uint64 _nonce, bytes memory _setupBody) internal view returns (bytes32 _commitment) {
    _commitment = keccak256(abi.encode(_account, address(_action), _nonce, _setupBody));
  }

  /*///////////////////////////////////////////////////////////////
                        THE ACCOUNT'S OWN WRITES
  ///////////////////////////////////////////////////////////////*/

  /// @notice Runs a batch on the account under the holder's key, through the account's own
  ///         execution function.
  function _asHolder(IAmbireRecoveryAction.Transaction[] memory _calls) internal {
    _asKey(_holderKey, _calls);
  }

  /// @notice Runs a batch on the account under `_key`, through the account's own execution function.
  function _asKey(address _key, IAmbireRecoveryAction.Transaction[] memory _calls) internal {
    vm.prank(_key);
    ActionAmbireAccountFixture(payable(_account)).executeBySender(_calls);
  }

  /// @notice The account's cancelByOwner call for the holder's action.
  function _cancelByOwnerCall() internal view returns (IAmbireRecoveryAction.Transaction memory _call) {
    _call = _managerCall(abi.encodeCall(IPolicyManager.cancelByOwner, (address(_action))));
  }

  /// @notice The account's call to itself that authorizes the action under its kit slot.
  function _authorizeCall() internal view returns (IAmbireRecoveryAction.Transaction memory _call) {
    _call = IAmbireRecoveryAction.Transaction({
      to: _account,
      value: 0,
      data: abi.encodeCall(
        IAmbireAccount.setAddrPrivilege, (ActionBatch.kitSlot(address(_action)), ActionBatch.binding(address(_action)))
      )
    });
  }

  /// @notice A call from the account to the manager.
  function _managerCall(bytes memory _data) internal view returns (IAmbireRecoveryAction.Transaction memory _call) {
    _call = IAmbireRecoveryAction.Transaction({to: address(_manager), value: 0, data: _data});
  }

  /// @notice The account's commitSetup call for a nonce and a commitment, with the holder's metadata.
  function _commitCall(uint64 _nonce, bytes32 _commitment)
    internal
    view
    returns (IAmbireRecoveryAction.Transaction memory _call)
  {
    _call = _managerCall(
      abi.encodeCall(
        IPolicyManager.commitSetup, (address(_action), _commitment, _nonce, _PUBLIC_METADATA, _PRIVATE_METADATA)
      )
    );
  }

  /// @notice A batch of one call.
  function _one(IAmbireRecoveryAction.Transaction memory _a)
    internal
    pure
    returns (IAmbireRecoveryAction.Transaction[] memory _calls)
  {
    _calls = new IAmbireRecoveryAction.Transaction[](1);
    _calls[0] = _a;
  }

  /// @notice A batch of two calls, in order.
  function _two(IAmbireRecoveryAction.Transaction memory _a, IAmbireRecoveryAction.Transaction memory _b)
    internal
    pure
    returns (IAmbireRecoveryAction.Transaction[] memory _calls)
  {
    _calls = new IAmbireRecoveryAction.Transaction[](2);
    _calls[0] = _a;
    _calls[1] = _b;
  }

  /// @notice Sets up recovery in one batch under the holder's key. It authorizes the action under the
  ///         kit slot, then commits the setup at nonce one.
  function _authorizeAndCommit() internal {
    _asHolder(_two(_authorizeCall(), _commitCall(1, _commitmentOf(1, _body()))));
  }

  /// @notice Commits `_setupBody` as the next setup, alone, under the holder's key.
  function _commitNext(bytes memory _setupBody) internal returns (uint64 _nonce) {
    _nonce = _manager.stateOf(_account, address(_action)).setupNonce + 1;
    _asHolder(_one(_commitCall(_nonce, _commitmentOf(_nonce, _setupBody))));
  }

  /*///////////////////////////////////////////////////////////////
                        REQUESTS AND PROOFS
  ///////////////////////////////////////////////////////////////*/

  /// @notice The handover the guardians approve: the new key added, the holder's key removed.
  function _payload() internal view returns (bytes memory _encoded) {
    _encoded = ActionBatch.payload(_newKey, _holderKey);
  }

  /// @notice The payment order: the token amount to the payee.
  function _order() internal view returns (IPolicyManager.PaymentOrder memory _paymentOrder) {
    _paymentOrder = IPolicyManager.PaymentOrder({token: address(_token), amount: _PAYMENT, payee: _payee});
  }

  /// @notice A window that stays open for one day from now.
  function _window() internal view returns (uint48 _validUntil) {
    _validUntil = uint48(block.timestamp + 1 days);
  }

  /// @notice A list of three places.
  function _places(uint256 _a, uint256 _b, uint256 _c) internal pure returns (uint256[] memory _list) {
    _list = new uint256[](3);
    _list[0] = _a;
    _list[1] = _b;
    _list[2] = _c;
  }

  /// @notice A list of two places.
  function _places(uint256 _a, uint256 _b) internal pure returns (uint256[] memory _list) {
    _list = new uint256[](2);
    _list[0] = _a;
    _list[1] = _b;
  }

  /// @notice The default opening set: Alice, Bob and the phone.
  function _openingSet() internal pure returns (uint256[] memory _list) {
    _list = _places(_ALICE, _BOB, _PHONE);
  }

  /// @notice The proof the credential at `_place` gives for `_digest`: a wallet signature r || s
  ///         || v, a passkey assertion signed over the standard client data, or the third-party
  ///         method's abi.encode(config, digest).
  function _prove(uint256 _place, bytes32 _digest) internal view returns (bytes memory _proof) {
    if (_place < _PHONE) {
      (uint8 _v, bytes32 _r, bytes32 _s) = vm.sign(_guardianKeys[_place], _digest);
      _proof = abi.encodePacked(_r, _s, _v);
    } else if (_place == _PHONE) {
      _proof =
        _signedProof(_PASSKEY_KEY, _buildAuthenticatorData(_rpIdHash, _FLAGS_UP_UV), _standardClientData(_digest));
    } else {
      (, bytes memory _config,) = _credential(_place);
      _proof = abi.encode(_config, _digest);
    }
  }

  /// @notice The places of `_placeList`, filled with their committed credential and no proof yet.
  function _unsignedPlaces(uint256[] memory _placeList)
    internal
    view
    returns (IPolicyManager.ProofPlace[] memory _proofs)
  {
    _proofs = new IPolicyManager.ProofPlace[](_placeList.length);
    for (uint256 _i; _i < _placeList.length; ++_i) {
      (address _method, bytes memory _config, bytes32 _salt) = _credential(_placeList[_i]);
      _proofs[_i] =
        IPolicyManager.ProofPlace({place: _placeList[_i], method: _method, config: _config, salt: _salt, proof: ''});
    }
  }

  /// @notice An opening request over `_setupBody`, each place signed by its credential over the
  ///         approval digest for that place.
  function _requestOver(
    bytes memory _setupBody,
    uint256[] memory _placeList,
    uint64 _attemptId,
    uint64 _nonce,
    uint48 _validUntil
  ) internal view returns (IPolicyManager.AttemptRequest memory _req) {
    _req = IPolicyManager.AttemptRequest({
      account: _account,
      action: address(_action),
      attemptId: _attemptId,
      setupNonce: _nonce,
      setupBody: _setupBody,
      payload: _payload(),
      order: _order(),
      validUntil: _validUntil,
      proofs: _unsignedPlaces(_placeList)
    });
    for (uint256 _i; _i < _placeList.length; ++_i) {
      _req.proofs[_i].proof = _prove(_placeList[_i], _manager.hashApproval(_req, _placeList[_i]));
    }
  }

  /// @notice An opening request over the default rule.
  function _request(uint256[] memory _placeList, uint64 _attemptId, uint64 _nonce, uint48 _validUntil)
    internal
    view
    returns (IPolicyManager.AttemptRequest memory _req)
  {
    _req = _requestOver(_body(), _placeList, _attemptId, _nonce, _validUntil);
  }

  /// @notice A request for the next attempt under the stored setup nonce, over the default rule and window.
  function _nextRequest(uint256[] memory _placeList) internal view returns (IPolicyManager.AttemptRequest memory _req) {
    IPolicyManager.ActionState memory _now = _state();
    _req = _request(_placeList, _now.nextAttemptId, _now.setupNonce, _window());
  }

  /// @notice A cancellation over the default rule, each place signed over the cancellation digest.
  function _cancelRequest(uint256[] memory _placeList, uint64 _attemptId, uint64 _nonce, uint48 _validUntil)
    internal
    view
    returns (IPolicyManager.CancelRequest memory _req)
  {
    _req = IPolicyManager.CancelRequest({
      account: _account,
      action: address(_action),
      attemptId: _attemptId,
      setupNonce: _nonce,
      setupBody: _body(),
      validUntil: _validUntil,
      proofs: _unsignedPlaces(_placeList)
    });
    for (uint256 _i; _i < _placeList.length; ++_i) {
      _req.proofs[_i].proof = _prove(_placeList[_i], _manager.hashCancel(_req, _placeList[_i]));
    }
  }

  /// @notice Signs every place of `_req` again over its approval digest, after a field of the
  ///         request changed.
  function _resign(IPolicyManager.AttemptRequest memory _req) internal view {
    for (uint256 _i; _i < _req.proofs.length; ++_i) {
      _req.proofs[_i].proof = _prove(_req.proofs[_i].place, _manager.hashApproval(_req, _req.proofs[_i].place));
    }
  }

  /// @notice A request for the next attempt over the default rule and window, committed to
  ///         `_committed` and paying `_paymentOrder`, each place signed over that outcome.
  function _nextRequestWith(
    uint256[] memory _placeList,
    bytes memory _committed,
    IPolicyManager.PaymentOrder memory _paymentOrder
  ) internal view returns (IPolicyManager.AttemptRequest memory _req) {
    _req = _nextRequest(_placeList);
    _req.payload = _committed;
    _req.order = _paymentOrder;
    _resign(_req);
  }

  /// @notice Opens the next attempt as the submitter, committed to `_committed` and paying `_paymentOrder`.
  function _openWith(
    uint256[] memory _placeList,
    bytes memory _committed,
    IPolicyManager.PaymentOrder memory _paymentOrder
  ) internal returns (IPolicyManager.AttemptRequest memory _req) {
    _req = _nextRequestWith(_placeList, _committed, _paymentOrder);
    _send(_req);
  }

  /// @notice Sends `_req` as the submitter.
  function _send(IPolicyManager.AttemptRequest memory _req) internal {
    vm.prank(_submitter);
    _manager.startAttempt(_req);
  }

  /// @notice Opens the next attempt with `_placeList` as the submitter.
  function _open(uint256[] memory _placeList) internal returns (IPolicyManager.AttemptRequest memory _req) {
    _req = _nextRequest(_placeList);
    _send(_req);
  }

  /// @notice Calls the action as the executor, with the account and the default payload.
  function _executeHandover() internal {
    _executeHandoverOf(_payload());
  }

  /// @notice Calls the action as the executor, with the account and `_committed`.
  function _executeHandoverOf(bytes memory _committed) internal {
    vm.prank(_executor);
    _action.executeHandover(_account, _committed);
  }

  /// @notice The batch the action builds for `_attempt` and the default handover, paying `_paidTo`.
  function _approvedBatch(IPolicyManager.Attempt memory _attempt, address _paidTo)
    internal
    view
    returns (IAmbireRecoveryAction.Transaction[] memory _calls)
  {
    _calls = ActionBatch.approvedBatch(
      address(_manager), address(_action), _account, _attempt, _newKey, _holderKey, _paidTo
    );
  }

  /*///////////////////////////////////////////////////////////////
                              READS
  ///////////////////////////////////////////////////////////////*/

  /// @notice The manager's summary of the holder's action.
  function _state() internal view returns (IPolicyManager.ActionState memory _actionState) {
    _actionState = _manager.stateOf(_account, address(_action));
  }

  /// @notice The account's privilege entry for an address.
  function _privilege(address _addr) internal view returns (bytes32 _value) {
    _value = IAmbireAccount(_account).privileges(_addr);
  }

  /// @notice The pause read as the manager makes it: true only for a successful call returning
  ///         exactly the ABI encoding of true.
  function _answersStopped(address _method) internal view returns (bool _stopped) {
    (bool _ok, bytes memory _ret) = _method.staticcall(abi.encodeCall(IPolicyMethodPause.paused, ()));
    _stopped = _ok && _ret.length == 32 && abi.decode(_ret, (bytes32)) == bytes32(uint256(1));
  }

  /// @notice Pauses the third-party method, as its pause holder.
  function _stopThirdParty() internal {
    vm.prank(_pauseHolder);
    _thirdParty.pause();
  }

  /// @notice Unpauses the third-party method, as its pause holder.
  function _liftThirdParty() internal {
    vm.prank(_pauseHolder);
    _thirdParty.unpause();
  }

  /// @notice An address built from a tag and a fuzzed seed. It differs from every address the tests
  ///         set up, so the fuzzer cannot reuse one of those.
  function _fresh(string memory _tag, uint256 _seed) internal pure returns (address _addr) {
    _addr = address(uint160(uint256(keccak256(abi.encode(_tag, _seed)))));
  }

  /// @notice The manager's refusal of a nonce: `_supplied` named where `_expected` is stored or due.
  function _wrongNonce(uint64 _supplied, uint64 _expected) internal pure returns (bytes memory _err) {
    _err = abi.encodeWithSelector(IPolicyManager.PolicyManager_WrongSetupNonce.selector, _supplied, _expected);
  }

  /// @notice The action's refusal of an attempt it may not spend, carrying `_attempt`'s clock and
  ///         committed payload hash beside `_attemptState`.
  function _notConsumable(IPolicyManager.AttemptState _attemptState, IPolicyManager.Attempt memory _attempt)
    internal
    view
    returns (bytes memory _err)
  {
    _err = abi.encodeWithSelector(
      IRecoveryAction.RecoveryAction_NotConsumable.selector,
      _account,
      _attemptState,
      _attempt.consumableAfter,
      _attempt.payloadHash
    );
  }

  /// @notice The manager's refusal of the proof at `_place`, judged by `_method`.
  function _proofRejected(uint256 _place, address _method) internal pure returns (bytes memory _err) {
    _err = abi.encodeWithSelector(IPolicyManager.PolicyManager_ProofRejected.selector, _place, _method);
  }

  /// @notice Sends `_req` as the submitter, expects it to revert with `_err`, and asserts that the call
  ///         reached no method. The refusal came before any pause or proof was read.
  function _sendRefusedBeforeAnyMethod(IPolicyManager.AttemptRequest memory _req, bytes memory _err) internal {
    vm.startStateDiffRecording();
    vm.expectRevert(_err);
    _send(_req);
    Vm.AccountAccess[] memory _accesses = vm.stopAndReturnStateDiff();
    for (uint256 _i; _i < _accesses.length; ++_i) {
      address _target = _accesses[_i].account;
      assertTrue(
        _target != address(_ecdsa) && _target != address(_passkey) && _target != address(_thirdParty),
        'the refused request reached a method'
      );
    }
  }

  /// @notice How many logs the manager emitted with the given topic.
  function _countLogs(Vm.Log[] memory _logs, bytes32 _topic) internal view returns (uint256 _count) {
    for (uint256 _i; _i < _logs.length; ++_i) {
      if (_logs[_i].emitter == address(_manager) && _logs[_i].topics[0] == _topic) ++_count;
    }
  }

  /// @notice The index of the first manager log with the given topic, or the log count when none.
  function _indexOfLog(Vm.Log[] memory _logs, bytes32 _topic) internal view returns (uint256 _index) {
    for (_index = 0; _index < _logs.length; ++_index) {
      if (_logs[_index].emitter == address(_manager) && _logs[_index].topics[0] == _topic) return _index;
    }
  }

  /// @notice Whether any log's topics or data carry `_needle` as a run of bytes, the way a watcher
  ///         scanning the chain for a known value would find it.
  function _anyLogCarries(Vm.Log[] memory _logs, bytes memory _needle) internal pure returns (bool _found) {
    for (uint256 _i; _i < _logs.length; ++_i) {
      bytes memory _all = abi.encodePacked(_logs[_i].topics, _logs[_i].data);
      for (uint256 _at; _at + _needle.length < _all.length + 1; ++_at) {
        uint256 _j;
        while (_j < _needle.length && _all[_at + _j] == _needle[_j]) ++_j;
        if (_j == _needle.length) return true;
      }
    }
  }

  /// @notice Decodes the first opening event the manager emitted in `_logs`, as a watcher reads it.
  function _startedLog(Vm.Log[] memory _logs) internal view returns (StartedLog memory _started) {
    uint256 _index = _indexOfLog(_logs, IPolicyManager.AttemptStarted.selector);
    assertLt(_index, _logs.length, 'no opening event');
    Vm.Log memory _log = _logs[_index];
    assertEq(address(uint160(uint256(_log.topics[1]))), _account, 'the opening event names another account');
    assertEq(address(uint160(uint256(_log.topics[2]))), address(_action), 'the opening event names another action');
    // The event data is the tuple of its unindexed fields. A leading offset word reads it as one struct.
    _started = abi.decode(abi.encodePacked(uint256(32), _log.data), (StartedLog));
  }

  /// @notice Asserts two summaries of the holder's action are identical, field by field.
  function _assertSameState(
    IPolicyManager.ActionState memory _before,
    IPolicyManager.ActionState memory _after,
    string memory _what
  ) internal pure {
    assertEq(abi.encode(_after), abi.encode(_before), _what);
  }

  /// @notice Asserts that every access to a method in `_accesses` was a static call and that no
  ///         storage slot outside the manager was written.
  function _assertMethodsOnlyReadAndOnlyTheManagerWrites(Vm.AccountAccess[] memory _accesses) internal view {
    for (uint256 _i; _i < _accesses.length; ++_i) {
      address _target = _accesses[_i].account;
      if (_target == address(_ecdsa) || _target == address(_passkey) || _target == address(_thirdParty)) {
        assertTrue(
          _accesses[_i].kind == VmSafe.AccountAccessKind.StaticCall, 'a method was reached by a non-static call'
        );
      }
      for (uint256 _j; _j < _accesses[_i].storageAccesses.length; ++_j) {
        Vm.StorageAccess memory _slot = _accesses[_i].storageAccesses[_j];
        if (_slot.isWrite && !_slot.reverted) {
          assertEq(_slot.account, address(_manager), 'a write outside the manager');
        }
      }
    }
  }
}
