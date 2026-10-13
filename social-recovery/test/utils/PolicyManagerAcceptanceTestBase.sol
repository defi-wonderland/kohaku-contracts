// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {Vm, VmSafe} from 'forge-std/Vm.sol';
import {BindingDigest} from 'libraries/BindingDigest.sol';
import {SetupBody} from 'libraries/SetupBody.sol';
import {IPolicyManager} from 'interfaces/IPolicyManager.sol';
import {IPolicyMethod} from 'interfaces/IPolicyMethod.sol';
import {IPolicyMethodPause} from 'interfaces/IPolicyMethodPause.sol';
import {PolicyManagerTestBase} from 'test/utils/PolicyManagerTestBase.sol';

/// @notice Shared helpers for the tests of the two calls that read proofs, startAttempt and
///         cancelByProofs. They build a committed rule, requests over it, and method answers
///         through vm.mockCall. Every assertion lives in the test contracts.
/// @dev The default rule has four places. Clause 0 needs 1 of place 0. Clause 1 needs 2 of places
///      1, 2 and 3. Method A judges places 0 and 1, method B judges places 2 and 3. Both methods
///      are addresses whose code stops at once, so any call they are not mocked for succeeds and
///      returns nothing: a verify then reads as rejected and a pause read as not stopped.
abstract contract PolicyManagerAcceptanceTestBase is PolicyManagerTestBase {
  /// @notice One credential of the rule, written out.
  struct Credential {
    address method;
    bytes config;
    bytes32 salt;
  }

  /// @notice The magic value a method returns to approve a proof: the verify selector.
  bytes4 internal constant _MAGIC = IPolicyMethod.verify.selector;

  /// @notice The method of places 0 and 1 of the default rule.
  address internal _methodA;
  /// @notice The method of places 2 and 3 of the default rule.
  address internal _methodB;
  /// @notice The credentials of the current rule, in place order.
  Credential[] internal _credentials;
  /// @notice The setup body of the current rule.
  bytes internal _setupBody;

  /// @dev Adds the two silent methods to the base setup.
  function setUp() public virtual override {
    super.setUp();
    _methodA = _silentMethod('methodA');
    _methodB = _silentMethod('methodB');
  }

  /*///////////////////////////////////////////////////////////////
                               RULES
  ///////////////////////////////////////////////////////////////*/

  /// @notice An address whose code is a single STOP, so every call to it succeeds and returns
  ///         nothing unless a test mocks it.
  function _silentMethod(string memory _label) internal returns (address _method) {
    _method = makeAddr(_label);
    vm.etch(_method, hex'00');
  }

  /// @notice Makes the default four-place rule the current rule, with this wait and pause choice.
  function _useDefaultRule(uint48 _wait, bool _ignoresPause) internal returns (bytes memory _body) {
    delete _credentials;
    _credentials.push(Credential(_methodA, 'config-0', keccak256('salt-0')));
    _credentials.push(Credential(_methodA, 'config-1', keccak256('salt-1')));
    _credentials.push(Credential(_methodB, 'config-2', keccak256('salt-2')));
    _credentials.push(Credential(_methodB, 'config-3', keccak256('salt-3')));
    _body = _reshapeDefault(_wait, _ignoresPause);
  }

  /// @notice Makes the four credentials now in `_credentials` the current rule, in the default rule's
  ///         shape: clause 0 needs 1 of place 0, clause 1 needs 2 of places 1, 2 and 3. A test changes
  ///         a credential of the default rule and then calls this.
  function _reshapeDefault(uint48 _wait, bool _ignoresPause) internal returns (bytes memory _body) {
    uint8[] memory _thresholds = new uint8[](2);
    _thresholds[0] = 1;
    _thresholds[1] = 2;
    uint256[] memory _sizes = new uint256[](2);
    _sizes[0] = 1;
    _sizes[1] = 3;
    _body = _useRule(_wait, _ignoresPause, _thresholds, _sizes);
  }

  /// @notice Makes the credentials already in `_credentials` the current rule, cut into clauses of
  ///         `_sizes` credentials with `_thresholds`, in order.
  function _useRule(uint48 _wait, bool _ignoresPause, uint8[] memory _thresholds, uint256[] memory _sizes)
    internal
    returns (bytes memory _body)
  {
    IPolicyManager.Clause[] memory _clauses = new IPolicyManager.Clause[](_thresholds.length);
    uint256 _next;
    for (uint256 _i; _i < _clauses.length; ++_i) {
      bytes32[] memory _hashes = new bytes32[](_sizes[_i]);
      for (uint256 _j; _j < _hashes.length; ++_j) {
        Credential storage _credential = _credentials[_next++];
        _hashes[_j] = BindingDigest.credentialCommitment(_credential.method, _credential.config, _credential.salt);
      }
      _clauses[_i] = IPolicyManager.Clause({threshold: _thresholds[_i], credentials: _hashes});
    }
    _setupBody = SetupBody.encode(_wait, _ignoresPause, _clauses);
    _body = _setupBody;
  }

  /// @notice Commits the current rule as the account's next setup for the action.
  function _commitRule() internal returns (uint64 _nonce) {
    _nonce = _state(_account, _action).setupNonce + 1;
    vm.prank(_account);
    _manager.commitSetup(_action, BindingDigest.setupCommitment(_account, _action, _nonce, _setupBody), _nonce, '', '');
  }

  /*///////////////////////////////////////////////////////////////
                              REQUESTS
  ///////////////////////////////////////////////////////////////*/

  /// @notice A list of one place.
  function _places(uint256 _a) internal pure returns (uint256[] memory _list) {
    _list = new uint256[](1);
    _list[0] = _a;
  }

  /// @notice A list of two places.
  function _places(uint256 _a, uint256 _b) internal pure returns (uint256[] memory _list) {
    _list = new uint256[](2);
    _list[0] = _a;
    _list[1] = _b;
  }

  /// @notice A list of three places.
  function _places(uint256 _a, uint256 _b, uint256 _c) internal pure returns (uint256[] memory _list) {
    _list = new uint256[](3);
    _list[0] = _a;
    _list[1] = _b;
    _list[2] = _c;
  }

  /// @notice A list of four places.
  function _places(uint256 _a, uint256 _b, uint256 _c, uint256 _d) internal pure returns (uint256[] memory _list) {
    _list = new uint256[](4);
    _list[0] = _a;
    _list[1] = _b;
    _list[2] = _c;
    _list[3] = _d;
  }

  /// @notice The proofs for `_placeList`, each naming the method, config and salt the rule holds at
  ///         its place and carrying the proof bytes 'proof at <place>'. A place past the rule gets
  ///         method A with an empty config and salt.
  function _proofsAt(uint256[] memory _placeList) internal view returns (IPolicyManager.ProofPlace[] memory _proofs) {
    _proofs = new IPolicyManager.ProofPlace[](_placeList.length);
    for (uint256 _i; _i < _placeList.length; ++_i) {
      uint256 _place = _placeList[_i];
      Credential memory _credential =
        _place < _credentials.length ? _credentials[_place] : Credential(_methodA, '', bytes32(0));
      _proofs[_i] = IPolicyManager.ProofPlace({
        place: _place,
        method: _credential.method,
        config: _credential.config,
        salt: _credential.salt,
        proof: abi.encodePacked('proof at ', _place)
      });
    }
  }

  /// @notice The places a list of proofs fills, in order.
  function _placesOf(IPolicyManager.ProofPlace[] memory _proofs) internal pure returns (uint256[] memory _list) {
    _list = new uint256[](_proofs.length);
    for (uint256 _i; _i < _proofs.length; ++_i) {
      _list[_i] = _proofs[_i].place;
    }
  }

  /// @notice An opening request over the current rule for `_placeList`. It names the next attempt
  ///         id and the stored nonce, carries a fixed payload and order, and is valid for a day, or
  ///         until the largest uint48 second when that comes first.
  function _request(uint256[] memory _placeList) internal view returns (IPolicyManager.AttemptRequest memory _req) {
    IPolicyManager.ActionState memory _actionState = _state(_account, _action);
    _req.account = _account;
    _req.action = _action;
    _req.attemptId = _actionState.nextAttemptId;
    _req.setupNonce = _actionState.setupNonce;
    _req.setupBody = _setupBody;
    _req.payload = bytes('new key 0xbeef, removed key 0xdead');
    _req.order = _order();
    _req.validUntil = _aDayFromNow();
    _req.proofs = _proofsAt(_placeList);
  }

  /// @notice A cancellation over the current rule for `_placeList`. It names the live attempt and the
  ///         stored nonce, and is valid for a day, or until the largest uint48 second when that comes
  ///         first.
  function _cancelRequest(uint256[] memory _placeList)
    internal
    view
    returns (IPolicyManager.CancelRequest memory _req)
  {
    IPolicyManager.ActionState memory _actionState = _state(_account, _action);
    _req.account = _account;
    _req.action = _action;
    _req.attemptId = _actionState.attempt.attemptId;
    _req.setupNonce = _actionState.setupNonce;
    _req.setupBody = _setupBody;
    _req.validUntil = _aDayFromNow();
    _req.proofs = _proofsAt(_placeList);
  }

  /// @notice A day from the block's timestamp, capped at the largest uint48 second.
  function _aDayFromNow() internal view returns (uint48 _until) {
    uint256 _day = block.timestamp + 1 days;
    // casting to 'uint48' is safe because the branch takes it only when _day fits the width
    // forge-lint: disable-next-line(unsafe-typecast)
    _until = _day > type(uint48).max ? type(uint48).max : uint48(_day);
  }

  /*///////////////////////////////////////////////////////////////
                           METHOD ANSWERS
  ///////////////////////////////////////////////////////////////*/

  /// @notice The exact verify call a method receives for `_proof` and `_digest`.
  function _verifyCall(IPolicyManager.ProofPlace memory _proof, bytes32 _digest)
    internal
    pure
    returns (bytes memory _call)
  {
    _call = abi.encodeCall(IPolicyMethod.verify, (_proof.config, _digest, _proof.proof));
  }

  /// @notice The pause read.
  function _pausedCall() internal pure returns (bytes memory _call) {
    _call = abi.encodeCall(IPolicyMethodPause.paused, ());
  }

  /// @notice Makes each proof's method approve that proof, and only for the approval digest the
  ///         manager's own hashApproval view gives for this request and place.
  function _approve(IPolicyManager.AttemptRequest memory _req) internal {
    for (uint256 _i; _i < _req.proofs.length; ++_i) {
      IPolicyManager.ProofPlace memory _proof = _req.proofs[_i];
      vm.mockCall(_proof.method, _verifyCall(_proof, _manager.hashApproval(_req, _proof.place)), abi.encode(_MAGIC));
    }
  }

  /// @notice Makes each proof's method approve that proof, and only for the cancellation digest the
  ///         manager's own hashCancel view gives for this cancellation and place.
  function _approveCancel(IPolicyManager.CancelRequest memory _req) internal {
    for (uint256 _i; _i < _req.proofs.length; ++_i) {
      IPolicyManager.ProofPlace memory _proof = _req.proofs[_i];
      vm.mockCall(_proof.method, _verifyCall(_proof, _manager.hashCancel(_req, _proof.place)), abi.encode(_MAGIC));
    }
  }

  /// @notice Expects each proof's method to receive exactly one verify of that proof, over the
  ///         approval digest the manager's own hashApproval view gives for this request and place.
  function _expectEachProofVerifiedOnce(IPolicyManager.AttemptRequest memory _req) internal {
    for (uint256 _i; _i < _req.proofs.length; ++_i) {
      IPolicyManager.ProofPlace memory _proof = _req.proofs[_i];
      vm.expectCall(_proof.method, _verifyCall(_proof, _manager.hashApproval(_req, _proof.place)), 1);
    }
  }

  /// @notice Expects each proof's method to receive exactly one verify of that proof, over the
  ///         cancellation digest the manager's own hashCancel view gives for this cancellation and
  ///         place.
  function _expectEachProofVerifiedOnce(IPolicyManager.CancelRequest memory _req) internal {
    for (uint256 _i; _i < _req.proofs.length; ++_i) {
      IPolicyManager.ProofPlace memory _proof = _req.proofs[_i];
      vm.expectCall(_proof.method, _verifyCall(_proof, _manager.hashCancel(_req, _proof.place)), 1);
    }
  }

  /// @notice Makes `_method` answer the pause read with exactly true.
  function _stop(address _method) internal {
    vm.mockCall(_method, _pausedCall(), abi.encode(true));
  }

  /// @notice Expects that neither default method is called at all during the next call.
  function _expectNoMethodCalled() internal {
    vm.expectCall(_methodA, '', 0);
    vm.expectCall(_methodB, '', 0);
  }

  /*///////////////////////////////////////////////////////////////
                             SEQUENCES
  ///////////////////////////////////////////////////////////////*/

  /// @notice Opens an attempt over the current rule with the proofs at `_placeList`, sent by the
  ///         stranger, and returns the request.
  function _open(uint256[] memory _placeList) internal returns (IPolicyManager.AttemptRequest memory _req) {
    _req = _request(_placeList);
    _approve(_req);
    vm.prank(_stranger);
    _manager.startAttempt(_req);
  }

  /*///////////////////////////////////////////////////////////////
                         READING WHAT A CALL DID
  ///////////////////////////////////////////////////////////////*/

  /// @notice Asserts `_log` is AttemptStarted for `_req`, with these places, methods and end of wait.
  function _assertStartedLog(
    Vm.Log memory _log,
    IPolicyManager.AttemptRequest memory _req,
    uint256[] memory _usedPlaces,
    address[] memory _usedMethods,
    uint48 _consumableAfter
  ) internal view {
    assertEq(_log.emitter, address(_manager), 'AttemptStarted emitter');
    assertEq(_log.topics.length, 3, 'AttemptStarted topics');
    assertEq(_log.topics[0], IPolicyManager.AttemptStarted.selector, 'AttemptStarted topic0');
    assertEq(_log.topics[1], bytes32(uint256(uint160(_req.account))), 'AttemptStarted account');
    assertEq(_log.topics[2], bytes32(uint256(uint160(_req.action))), 'AttemptStarted action');
    assertEq(
      _log.data,
      abi.encode(
        _req.attemptId,
        _req.setupNonce,
        _req.setupBody,
        _usedPlaces,
        _usedMethods,
        _req.payload,
        _req.order,
        _consumableAfter
      ),
      'AttemptStarted data'
    );
  }

  /// @notice Asserts `_log` is AttemptCancelled for a cancel by proofs: these values, no vetoing
  ///         method and these places.
  function _assertCancelledByProofsLog(
    Vm.Log memory _log,
    uint64 _attemptId,
    address _canceller,
    uint64 _setupNonce,
    uint256[] memory _usedPlaces
  ) internal view {
    assertEq(_log.emitter, address(_manager), 'AttemptCancelled emitter');
    assertEq(_log.topics.length, 3, 'AttemptCancelled topics');
    assertEq(_log.topics[0], IPolicyManager.AttemptCancelled.selector, 'AttemptCancelled topic0');
    assertEq(_log.topics[1], bytes32(uint256(uint160(_account))), 'AttemptCancelled account');
    assertEq(_log.topics[2], bytes32(uint256(uint160(_action))), 'AttemptCancelled action');
    assertEq(
      _log.data, abi.encode(_attemptId, _canceller, address(0), _setupNonce, _usedPlaces), 'AttemptCancelled data'
    );
  }

  /// @notice Asserts that the setup's commitment, nonce and block are what they were before.
  function _assertSetupKept(IPolicyManager.ActionState memory _before, IPolicyManager.ActionState memory _after)
    internal
    pure
  {
    assertEq(_after.setupCommitment, _before.setupCommitment, 'commitment');
    assertEq(_after.setupNonce, _before.setupNonce, 'nonce');
    assertEq(_after.setupCommittedAtBlock, _before.setupCommittedAtBlock, 'setupCommittedAtBlock');
  }

  /// @notice Asserts that every call the manager made to another contract during the recorded call
  ///         was a static call.
  function _assertOnlyStaticCalls(Vm.AccountAccess[] memory _accesses) internal view {
    for (uint256 _i; _i < _accesses.length; ++_i) {
      if (_accesses[_i].accessor != address(_manager) || _accesses[_i].account == address(_manager)) continue;
      if (_accesses[_i].kind == VmSafe.AccountAccessKind.Resume) continue;
      assertEq(uint256(_accesses[_i].kind), uint256(VmSafe.AccountAccessKind.StaticCall), 'a call that was not static');
    }
  }

  /// @notice Asserts that no storage word the manager wrote during the recorded call holds a
  ///         credential hash of the current rule, a credential's salt or the hash of the setup
  ///         body. Those values would reveal the rule, which storage must keep behind the
  ///         commitment.
  function _assertStoresNoRuleSecret(Vm.AccountAccess[] memory _accesses) internal view {
    bytes32 _bodyHash = keccak256(_setupBody);
    for (uint256 _i; _i < _accesses.length; ++_i) {
      Vm.StorageAccess[] memory _storage = _accesses[_i].storageAccesses;
      for (uint256 _k; _k < _storage.length; ++_k) {
        if (_storage[_k].account != address(_manager) || !_storage[_k].isWrite) continue;
        bytes32 _written = _storage[_k].newValue;
        assertTrue(_written != _bodyHash, 'storage holds the body hash');
        for (uint256 _c; _c < _credentials.length; ++_c) {
          Credential storage _credential = _credentials[_c];
          assertTrue(_written != _credential.salt, 'storage holds a salt');
          assertTrue(
            _written != BindingDigest.credentialCommitment(_credential.method, _credential.config, _credential.salt),
            'storage holds a credential hash'
          );
        }
      }
    }
  }

  /// @notice A list of one method.
  function _methodList(address _a) internal pure returns (address[] memory _list) {
    _list = new address[](1);
    _list[0] = _a;
  }

  /// @notice A list of two methods.
  function _methodList(address _a, address _b) internal pure returns (address[] memory _list) {
    _list = new address[](2);
    _list[0] = _a;
    _list[1] = _b;
  }
}
