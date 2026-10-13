// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {Test} from 'forge-std/Test.sol';
import {Vm, VmSafe} from 'forge-std/Vm.sol';
import {BindingDigest} from 'libraries/BindingDigest.sol';
import {IPolicyManager} from 'interfaces/IPolicyManager.sol';
import {PolicyManagerMockAction} from 'test/mocks/PolicyManagerMockAction.sol';
import {PolicyManagerMockMethod} from 'test/mocks/PolicyManagerMockMethod.sol';
import {PolicyManagerHarness} from 'test/utils/PolicyManagerHarness.sol';

/// @notice Shared helpers for the manager's configuration tests. Every assertion lives in the test
///         contracts. These helpers only build state and read it back. A pair is one account and
///         one action, whose setup and attempt the manager keeps together.
abstract contract PolicyManagerTestBase is Test {
  /// @notice The manager under test, with the harness door that plants an attempt record.
  PolicyManagerHarness internal _manager;
  /// @notice The account whose setup the tests write.
  address internal _account;
  /// @notice The action the setup governs. Its code is the mock action, which serves every account
  ///         until a test sets another answer.
  address internal _action;
  /// @notice A second action on the same account, also serving every account.
  address internal _otherAction;
  /// @notice Any address other than the account.
  address internal _stranger;
  /// @notice A method that reports itself stopped and reverts on every other call.
  address internal _stoppedMethod;

  /// @notice A deployed mock action whose runtime code the tests etch where an action must serve.
  PolicyManagerMockAction private _actionTemplate;

  /// @dev Deploys the manager harness and the stopped mock method, and names the addresses. Both
  ///      actions carry the mock action's code, since commitSetup refuses an action that does not
  ///      answer true to supportsAccount for the caller.
  function setUp() public virtual {
    _manager = new PolicyManagerHarness();
    _actionTemplate = new PolicyManagerMockAction();
    _account = makeAddr('account');
    _action = _servingAction(makeAddr('action'));
    _otherAction = _servingAction(makeAddr('otherAction'));
    _stranger = makeAddr('stranger');
    _stoppedMethod = address(new PolicyManagerMockMethod());
  }

  /*///////////////////////////////////////////////////////////////
                           SETUP WRITES
  ///////////////////////////////////////////////////////////////*/

  /// @notice Etches the mock action's code at `_at`, so it answers true to supportsAccount for every
  ///         account, and returns `_at`.
  function _servingAction(address _at) internal returns (address _servingAt) {
    vm.etch(_at, address(_actionTemplate).code);
    _servingAt = _at;
  }

  /// @notice A fresh action address derived from `_seed`, carrying the mock action's code so it
  ///         serves every account.
  function _servingActionFrom(uint256 _seed) internal returns (address _servingAt) {
    _servingAt = _servingAction(_addressFrom('action', _seed));
  }

  /// @notice A nonempty setup body that differs per nonce, so each write stores a new commitment.
  function _body(uint64 _nonce) internal pure returns (bytes memory _setupBody) {
    _setupBody = abi.encodePacked('setup body at nonce ', _nonce);
  }

  /// @notice The commitment of `_body(_nonce)` for this account, action and nonce.
  function _commitmentFor(address _pairAccount, address _pairAction, uint64 _nonce)
    internal
    pure
    returns (bytes32 _commitment)
  {
    _commitment = BindingDigest.setupCommitment(_pairAccount, _pairAction, _nonce, _body(_nonce));
  }

  /// @notice The commitment of zero-length bytes for the nonce a write will hold.
  function _emptyBodyCommitment(address _pairAccount, address _pairAction, uint64 _nonce)
    internal
    pure
    returns (bytes32 _commitment)
  {
    _commitment = BindingDigest.setupCommitment(_pairAccount, _pairAction, _nonce, '');
  }

  /// @notice Makes the mock action at `_servingAt` stop serving every account, in the way
  ///         `_answerSeed` picks: it answers false, it reverts, or its code is gone.
  function _stopServing(address _servingAt, uint256 _answerSeed) internal {
    uint256 _way = bound(_answerSeed, 0, 2);
    if (_way == 0) PolicyManagerMockAction(_servingAt).setAnswer(PolicyManagerMockAction.Answer.AnswersFalse);
    if (_way == 1) PolicyManagerMockAction(_servingAt).setAnswer(PolicyManagerMockAction.Answer.Reverts);
    if (_way == 2) vm.etch(_servingAt, '');
  }

  /// @notice Commits the next setup as `_pairAccount`, with the right nonce and a valid commitment.
  function _commit(address _pairAccount, address _pairAction) internal returns (uint64 _nonce, bytes32 _commitment) {
    _nonce = _manager.stateOf(_pairAccount, _pairAction).setupNonce + 1;
    _commitment = _commitmentFor(_pairAccount, _pairAction, _nonce);
    vm.prank(_pairAccount);
    _manager.commitSetup(_pairAction, _commitment, _nonce, '', '');
  }

  /// @notice Clears `_pairAccount`'s setup for `_pairAction`, as the account.
  function _clear(address _pairAccount, address _pairAction) internal {
    vm.prank(_pairAccount);
    _manager.clearSetup(_pairAction);
  }

  /// @notice The manager's summary of one action on one account.
  function _state(address _pairAccount, address _pairAction)
    internal
    view
    returns (IPolicyManager.ActionState memory _actionState)
  {
    _actionState = _manager.stateOf(_pairAccount, _pairAction);
  }

  /*///////////////////////////////////////////////////////////////
                ATTEMPT RECORDS, PLANTED THROUGH THE HARNESS
  ///////////////////////////////////////////////////////////////*/

  /// @notice A payment order with recognisable nonzero fields.
  function _order() internal pure returns (IPolicyManager.PaymentOrder memory _paymentOrder) {
    _paymentOrder = IPolicyManager.PaymentOrder({token: address(0x7070), amount: 12_345, payee: address(0x9a9e)});
  }

  /// @notice An attempt record in the given state, using the given methods.
  function _attempt(
    uint64 _attemptId,
    uint64 _setupNonce,
    IPolicyManager.AttemptState _attemptState,
    bool _ignoresPause,
    address[] memory _usedMethods
  ) internal pure returns (IPolicyManager.Attempt memory _record) {
    _record = IPolicyManager.Attempt({
      attemptId: _attemptId,
      setupNonce: _setupNonce,
      consumableAfter: uint48(1_000_000),
      state: _attemptState,
      ignoresPause: _ignoresPause,
      payloadHash: keccak256(abi.encodePacked('payload', _attemptId)),
      order: _order(),
      usedMethods: _usedMethods
    });
  }

  /// @notice One stopped mock method with code and one address with no code.
  function _methods() internal view returns (address[] memory _usedMethods) {
    _usedMethods = new address[](2);
    _usedMethods[0] = _stoppedMethod;
    _usedMethods[1] = address(0xDEAD0001);
  }

  /// @notice Plants a Waiting attempt under the stored setup nonce and returns it.
  function _plantWaiting(address _pairAccount, address _pairAction, uint64 _attemptId, bool _ignoresPause)
    internal
    returns (IPolicyManager.Attempt memory _record)
  {
    _record = _attempt(
      _attemptId,
      _state(_pairAccount, _pairAction).setupNonce,
      IPolicyManager.AttemptState.Waiting,
      _ignoresPause,
      _methods()
    );
    _plant(_pairAccount, _pairAction, _record);
  }

  /// @notice Writes `_record` as the pair's attempt record through the harness and checks stateOf
  ///         reads it back exactly.
  function _plant(address _pairAccount, address _pairAction, IPolicyManager.Attempt memory _record) internal {
    _manager.harnessWriteAttempt(_pairAccount, _pairAction, _record);
    assertEq(
      abi.encode(_manager.stateOf(_pairAccount, _pairAction).attempt),
      abi.encode(_record),
      'harness: stateOf reads the planted attempt'
    );
  }

  /*///////////////////////////////////////////////////////////////
                          FUZZ INPUT BUILDERS
  ///////////////////////////////////////////////////////////////*/

  /// @notice Any uint64 other than `_value`: `_value` plus an offset of 1 to 2^64 - 1, wrapping, so
  ///         every other value is reachable and `_value` itself never is.
  function _otherThan(uint64 _value, uint64 _offsetSeed) internal pure returns (uint64 _other) {
    uint64 _offset = uint64(bound(_offsetSeed, 1, type(uint64).max));
    unchecked {
      _other = _value + _offset;
    }
  }

  /// @notice An address derived by hashing `_label` and `_seed`. It is never zero, never a cheatcode
  ///         or deployed test address, and never an address made by makeAddr with another label.
  function _addressFrom(string memory _label, uint256 _seed) internal pure returns (address _derived) {
    _derived = address(uint160(uint256(keccak256(abi.encode(_label, _seed)))));
  }

  /*///////////////////////////////////////////////////////////////
                        READING WHAT A CALL DID
  ///////////////////////////////////////////////////////////////*/

  /// @notice Asserts that no call the manager made reached another account: no method, no pause
  ///         read, no account.
  function _assertReachedNoOtherContract(Vm.AccountAccess[] memory _accesses) internal view {
    for (uint256 _i; _i < _accesses.length; ++_i) {
      if (_accesses[_i].accessor != address(_manager)) continue;
      if (_accesses[_i].kind == VmSafe.AccountAccessKind.Resume) continue;
      assertEq(_accesses[_i].account, address(_manager), 'the manager reached another contract');
    }
  }

  /// @notice Asserts `_log` is AttemptCancelled with these values, no vetoing method and no places.
  function _assertCancelledLog(
    Vm.Log memory _log,
    address _pairAccount,
    address _pairAction,
    uint64 _attemptId,
    address _canceller,
    uint64 _setupNonce
  ) internal view {
    assertEq(_log.emitter, address(_manager), 'AttemptCancelled emitter');
    assertEq(_log.topics.length, 3, 'AttemptCancelled topics');
    assertEq(_log.topics[0], IPolicyManager.AttemptCancelled.selector, 'AttemptCancelled topic0');
    assertEq(_log.topics[1], bytes32(uint256(uint160(_pairAccount))), 'AttemptCancelled account');
    assertEq(_log.topics[2], bytes32(uint256(uint160(_pairAction))), 'AttemptCancelled action');
    assertEq(
      _log.data, abi.encode(_attemptId, _canceller, address(0), _setupNonce, new uint256[](0)), 'AttemptCancelled data'
    );
  }

  /// @notice Asserts `_log` is SetupCommitted with these values.
  function _assertCommittedLog(
    Vm.Log memory _log,
    address _pairAccount,
    address _pairAction,
    uint64 _nonce,
    bytes32 _commitment,
    bytes memory _publicMetadata,
    bytes memory _privateMetadata
  ) internal view {
    assertEq(_log.emitter, address(_manager), 'SetupCommitted emitter');
    assertEq(_log.topics.length, 3, 'SetupCommitted topics');
    assertEq(_log.topics[0], IPolicyManager.SetupCommitted.selector, 'SetupCommitted topic0');
    assertEq(_log.topics[1], bytes32(uint256(uint160(_pairAccount))), 'SetupCommitted account');
    assertEq(_log.topics[2], bytes32(uint256(uint160(_pairAction))), 'SetupCommitted action');
    assertEq(_log.data, abi.encode(_nonce, _commitment, _publicMetadata, _privateMetadata), 'SetupCommitted data');
  }

  /// @notice Asserts `_log` is SetupCleared with these values.
  function _assertClearedLog(Vm.Log memory _log, address _pairAccount, address _pairAction, uint64 _nonce)
    internal
    view
  {
    assertEq(_log.emitter, address(_manager), 'SetupCleared emitter');
    assertEq(_log.topics.length, 3, 'SetupCleared topics');
    assertEq(_log.topics[0], IPolicyManager.SetupCleared.selector, 'SetupCleared topic0');
    assertEq(_log.topics[1], bytes32(uint256(uint160(_pairAccount))), 'SetupCleared account');
    assertEq(_log.topics[2], bytes32(uint256(uint160(_pairAction))), 'SetupCleared action');
    assertEq(_log.data, abi.encode(_nonce), 'SetupCleared data');
  }

  /// @notice Asserts the attempt record equals `_expected` in every field but the state, and holds
  ///         `_attemptState`.
  function _assertRecordKept(
    IPolicyManager.Attempt memory _actual,
    IPolicyManager.Attempt memory _expected,
    IPolicyManager.AttemptState _attemptState
  ) internal pure {
    _expected.state = _attemptState;
    assertEq(abi.encode(_actual), abi.encode(_expected), 'attempt record');
  }
}
