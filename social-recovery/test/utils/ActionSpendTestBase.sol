// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {IPolicyManager} from 'interfaces/IPolicyManager.sol';
import {IRecoveryAction} from 'interfaces/IRecoveryAction.sol';
import {IAmbireAccount} from 'contracts/actions/ambire/IAmbireAccount.sol';
import {IAmbireRecoveryAction} from 'contracts/actions/ambire/IAmbireRecoveryAction.sol';
import {ActionAmbireAccountFixture, ActionPaymentToken} from 'test/mocks/ActionAmbireAccountFixture.sol';
import {ActionAmbireProxy, ActionAmbireProxyDeployer} from 'test/utils/ActionAmbireProxy.sol';
import {ActionBatch} from 'test/utils/ActionBatch.sol';
import {ActionTestBase} from 'test/utils/ActionTestBase.sol';
import {PolicyManagerHarness} from 'test/utils/PolicyManagerHarness.sol';

/// @notice Shared setup for the recovery action's spend. It renders the batch the specification
///         defines for a handover, so a test compares what the action does against that rendering,
///         and it builds two worlds. In the mocked world the manager's attempt is a mocked stateOf
///         answer and the account is the privilege-table mock. In the live world a real manager, with
///         a harness door that writes an attempt record, serves an account built as Ambire's factory
///         builds it, a proxy over a transcription of Ambire's account, holding this action's
///         binding under its kit slot.
abstract contract ActionSpendTestBase is ActionTestBase {
  /// @notice The value a handover writes for the new key.
  bytes32 internal constant _KEY_VALUE = ActionBatch.KEY_VALUE;
  /// @notice The value the Kohaku extension writes for the account's first key.
  bytes32 internal constant _SIGNER_VALUE = bytes32(uint256(2));
  /// @notice The ERC-20 transfer selector.
  bytes4 internal constant _TRANSFER = ActionBatch.TRANSFER;
  /// @notice When the mocked attempt's wait ends.
  uint48 internal constant _WAIT_ENDS = 1_000_000;

  /// @notice The new key of the default handover.
  address internal _newKey;
  /// @notice The removed key of the default handover.
  address internal _removedKey;
  /// @notice The token of the default token order.
  address internal _token;
  /// @notice The fixed payee of the default orders.
  address internal _payee;

  /// @notice The real manager of the live world.
  PolicyManagerHarness internal _liveManager;
  /// @notice The action of the live world, bound to the real manager.
  IRecoveryAction internal _liveAction;
  /// @notice The account of the live world.
  address internal _live;
  /// @notice The implementation the live action pins and the live account's proxy runs.
  address internal _liveImplementation;
  /// @notice The token of the live world.
  ActionPaymentToken internal _liveToken;

  function setUp() public virtual override {
    super.setUp();
    _newKey = makeAddr('newKey');
    _removedKey = makeAddr('removedKey');
    _token = makeAddr('paymentToken');
    _payee = makeAddr('payee');
    vm.warp(_WAIT_ENDS);
    _serveTheMockedAccount();
    assertEq(ActionBatch.kitSlot(address(_action)), _expectedKitSlot(address(_action)), 'rendering: the kit slot');
    assertEq(ActionBatch.binding(address(_action)), _expectedBinding(address(_action)), 'rendering: the binding');
  }

  /*///////////////////////////////////////////////////////////////
                              RENDERINGS
  ///////////////////////////////////////////////////////////////*/

  /// @notice The payload the guardians approve: abi.encode of the Handover struct.
  function _payload(address _new, address _removed) internal pure returns (bytes memory _encoded) {
    _encoded = ActionBatch.payload(_new, _removed);
  }

  /// @notice The first call: consume at the manager, with no value, naming the action, the attempt
  ///         id and the payload hash.
  function _consumeCall(address _mgr, address _act, uint64 _attemptId, bytes32 _payloadHash)
    internal
    pure
    returns (IAmbireRecoveryAction.Transaction memory _call)
  {
    _call = ActionBatch.consumeCall(_mgr, _act, _attemptId, _payloadHash);
  }

  /// @notice The second call: the account writes the key value for the new key, with no value.
  function _grantCall(address _acct, address _new)
    internal
    pure
    returns (IAmbireRecoveryAction.Transaction memory _call)
  {
    _call = ActionBatch.grantCall(_acct, _new);
  }

  /// @notice The third call: the account zeroes the removed key's entry, with no value.
  function _revokeCall(address _acct, address _removed)
    internal
    pure
    returns (IAmbireRecoveryAction.Transaction memory _call)
  {
    _call = ActionBatch.revokeCall(_acct, _removed);
  }

  /// @notice The fourth call for an order and the payee it pays: a transfer of the amount in the
  ///         token, or, for the zero token, a call to the payee carrying the amount and no data.
  function _paymentCall(IPolicyManager.PaymentOrder memory _order, address _paidTo)
    internal
    pure
    returns (IAmbireRecoveryAction.Transaction memory _call)
  {
    _call = ActionBatch.paymentCall(_order, _paidTo);
  }

  /// @notice The whole approved batch: consume, grant, revoke, and the payment when the order has
  ///         an amount, paying `_paidTo`.
  function _approvedBatch(
    address _mgr,
    address _act,
    address _acct,
    IPolicyManager.Attempt memory _attempt,
    address _new,
    address _removed,
    address _paidTo
  ) internal pure returns (IAmbireRecoveryAction.Transaction[] memory _calls) {
    _calls = ActionBatch.approvedBatch(_mgr, _act, _acct, _attempt, _new, _removed, _paidTo);
  }

  /// @notice The signature the action hands the account: abi.encode of the kit slot, the action,
  ///         empty validator data and an empty inner signature, followed by the byte 255.
  function _kitSignature(address _act) internal pure returns (bytes memory _signature) {
    _signature = ActionBatch.kitSignature(_act);
  }

  /// @notice A copy of a batch, so a test can alter one call and keep the original.
  function _copy(IAmbireRecoveryAction.Transaction[] memory _calls)
    internal
    pure
    returns (IAmbireRecoveryAction.Transaction[] memory _out)
  {
    _out = new IAmbireRecoveryAction.Transaction[](_calls.length);
    for (uint256 _i; _i < _calls.length; ++_i) {
      _out[_i] = IAmbireRecoveryAction.Transaction({to: _calls[_i].to, value: _calls[_i].value, data: _calls[_i].data});
    }
  }

  /// @notice The error the action raises for a batch that differs from the approved one at `_index`.
  function _notApproved(uint256 _index) internal pure returns (bytes memory _err) {
    _err = abi.encodeWithSelector(IRecoveryAction.RecoveryAction_BatchNotApproved.selector, _index);
  }

  /// @notice The error the action raises for an attempt it may not spend.
  function _notConsumable(address _acct, IPolicyManager.Attempt memory _attempt)
    internal
    pure
    returns (bytes memory _e)
  {
    _e = abi.encodeWithSelector(
      IRecoveryAction.RecoveryAction_NotConsumable.selector,
      _acct,
      _attempt.state,
      _attempt.consumableAfter,
      _attempt.payloadHash
    );
  }

  /*///////////////////////////////////////////////////////////////
                            MOCKED WORLD
  ///////////////////////////////////////////////////////////////*/

  /// @notice The runtime of the 45-byte proxy over `_impl` that Ambire's factory deploys: the nine
  ///         head bytes, PUSH20 and the implementation, then the fifteen tail bytes.
  function _servedProxyRuntime(address _impl) internal pure returns (bytes memory _code) {
    _code = abi.encodePacked(ActionAmbireProxy.RUNTIME_HEAD, bytes1(0x73), _impl, ActionAmbireProxy.RUNTIME_TAIL);
  }

  /// @notice Turns the privilege-table mock into an account the action serves: the mock's code moves
  ///         to the pinned implementation address, and the account's address gets the proxy over it,
  ///         so every call to the account runs the mock against the account's own storage.
  function _serveTheMockedAccount() internal {
    vm.etch(_implementation, address(_account).code);
    vm.etch(address(_account), _servedProxyRuntime(_implementation));
    assertEq(address(_account).code.length, 45, 'fixture: the mocked account is a 45-byte proxy');
    assertTrue(_action.supportsAccount(address(_account)), 'fixture: the action serves the mocked account');
  }

  /// @notice An order that pays nothing.
  function _noPayment() internal pure returns (IPolicyManager.PaymentOrder memory _order) {
    _order = IPolicyManager.PaymentOrder({token: address(0), amount: 0, payee: address(0)});
  }

  /// @notice A waiting attempt, its wait ended at `_WAIT_ENDS`, committed to `_committed` and `_order`.
  function _waiting(bytes memory _committed, IPolicyManager.PaymentOrder memory _order)
    internal
    pure
    returns (IPolicyManager.Attempt memory _attempt)
  {
    _attempt = IPolicyManager.Attempt({
      attemptId: 7,
      setupNonce: 3,
      consumableAfter: _WAIT_ENDS,
      state: IPolicyManager.AttemptState.Waiting,
      ignoresPause: false,
      payloadHash: keccak256(_committed),
      order: _order,
      usedMethods: new address[](0)
    });
  }

  /// @notice Makes the mocked manager answer stateOf(`_acct`, the action) with `_attempt`.
  function _mockAttempt(address _acct, IPolicyManager.Attempt memory _attempt) internal {
    uint64 _next;
    unchecked {
      _next = _attempt.attemptId + 1;
    }
    IPolicyManager.ActionState memory _state = IPolicyManager.ActionState({
      setupCommitment: keccak256('setup'),
      setupNonce: _attempt.setupNonce,
      nextAttemptId: _next,
      setupCommittedAtBlock: 1,
      attempt: _attempt
    });
    vm.mockCall(_manager, abi.encodeCall(IPolicyManager.stateOf, (_acct, address(_action))), abi.encode(_state));
  }

  /// @notice The batch the mocked world approves for `_attempt` and the default handover.
  function _mockedBatch(IPolicyManager.Attempt memory _attempt, address _paidTo)
    internal
    view
    returns (IAmbireRecoveryAction.Transaction[] memory _calls)
  {
    _calls = _approvedBatch(_manager, address(_action), address(_account), _attempt, _newKey, _removedKey, _paidTo);
  }

  /// @notice Gives the default removed key a key value and leaves the new key empty, the table a
  ///         handover expects.
  function _keysReady() internal {
    _account.setPrivilege(_removedKey, _SIGNER_VALUE);
  }

  /*///////////////////////////////////////////////////////////////
                              LIVE WORLD
  ///////////////////////////////////////////////////////////////*/

  /// @notice Deploys the real manager, an action bound to it, the account transcription behind a
  ///         factory-built proxy whose first key is `_removedKey` at 2, and a token. The account
  ///         holds the action's binding under its kit slot and a setup at nonce 1, and is
  ///         funded with 100 ether and 1e24 token units.
  function _buildLiveWorld() internal {
    _liveManager = new PolicyManagerHarness();
    address _impl = address(new ActionAmbireAccountFixture());
    _liveImplementation = _impl;
    _liveAction = _deployAction(address(_liveManager), _impl);
    ActionAmbireProxyDeployer _factory = new ActionAmbireProxyDeployer();
    _live = _factory.deploy(ActionAmbireProxy.creationCode(_impl, _removedKey, _SIGNER_VALUE), 0);
    vm.prank(_live);
    IAmbireAccount(_live)
      .setAddrPrivilege(_expectedKitSlot(address(_liveAction)), _expectedBinding(address(_liveAction)));
    _liveManager.harnessWriteSetup(
      _live,
      address(_liveAction),
      IPolicyManager.Setup({
        commitment: keccak256('live setup'), nonce: 1, attemptCounter: 0, setupCommittedAtBlock: uint48(block.number)
      })
    );
    _liveToken = new ActionPaymentToken();
    _liveToken.mint(_live, 1e24);
    vm.deal(_live, 100 ether);
  }

  /// @notice Writes a waiting attempt for the live account, the next id under the stored setup,
  ///         committed to `_committed` and `_order`, whose wait ends `_wait` seconds from now.
  function _plantLive(bytes memory _committed, IPolicyManager.PaymentOrder memory _order, uint48 _wait)
    internal
    returns (IPolicyManager.Attempt memory _attempt)
  {
    IPolicyManager.ActionState memory _state = _liveManager.stateOf(_live, address(_liveAction));
    uint64 _id = _state.nextAttemptId;
    _liveManager.harnessWriteSetup(
      _live,
      address(_liveAction),
      IPolicyManager.Setup({
        commitment: _state.setupCommitment,
        nonce: _state.setupNonce,
        attemptCounter: _id,
        setupCommittedAtBlock: _state.setupCommittedAtBlock
      })
    );
    _attempt = IPolicyManager.Attempt({
      attemptId: _id,
      setupNonce: _state.setupNonce,
      consumableAfter: uint48(block.timestamp) + _wait,
      state: IPolicyManager.AttemptState.Waiting,
      ignoresPause: false,
      payloadHash: keccak256(_committed),
      order: _order,
      usedMethods: new address[](0)
    });
    _liveManager.harnessWriteAttempt(_live, address(_liveAction), _attempt);
  }

  /// @notice The live account's privilege entry for `_addr`.
  function _livePrivilege(address _addr) internal view returns (bytes32 _value) {
    _value = IAmbireAccount(_live).privileges(_addr);
  }

  /// @notice The live attempt's state.
  function _liveState() internal view returns (IPolicyManager.AttemptState _state) {
    _state = _liveManager.stateOf(_live, address(_liveAction)).attempt.state;
  }

  /// @notice The batch the live world approves for `_attempt` and the default handover.
  function _liveBatch(IPolicyManager.Attempt memory _attempt, address _paidTo)
    internal
    view
    returns (IAmbireRecoveryAction.Transaction[] memory _calls)
  {
    address _mgr = address(_liveManager);
    _calls = _approvedBatch(_mgr, address(_liveAction), _live, _attempt, _newKey, _removedKey, _paidTo);
  }
}
