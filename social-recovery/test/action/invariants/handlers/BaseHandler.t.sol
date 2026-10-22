// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {CommonBase} from 'forge-std/Base.sol';
import {StdUtils} from 'forge-std/StdUtils.sol';
import {IPolicyManager} from 'interfaces/IPolicyManager.sol';
import {IRecoveryAction} from 'interfaces/IRecoveryAction.sol';
import {IAmbireAccount} from 'contracts/actions/ambire/IAmbireAccount.sol';
import {IAmbireRecoveryAction} from 'contracts/actions/ambire/IAmbireRecoveryAction.sol';
import {ActionPaymentToken, ActionCallbackPayee, ActionRefusingPayee} from 'test/mocks/ActionAmbireAccountFixture.sol';
import {ActionGhostStorage} from 'test/action/invariants/handlers/GhostStorage.t.sol';
import {ActionBatch} from 'test/utils/ActionBatch.sol';
import {PolicyManagerHarness} from 'test/utils/PolicyManagerHarness.sol';

/// @notice The state and checks that every handler of the recovery action's invariant suite shares.
///         The account is built the way Ambire's factory builds it, as a proxy over a copy of
///         Ambire's account code, and a real policy manager serves it. The account authorizes the
///         action while it holds the action's binding under the kit slot.
///         Attempts are written into the manager through a test harness, because the manager's own
///         suite tests how it opens attempts. Everything after that runs for real.
///         The handlers keep no copy of the action's logic. Around each call they take a snapshot of
///         the account's privilege entries, the balances and the attempt. They compare the change
///         with what the specification says a handover does, and set a flag when the two differ.
/// @dev The watched entries belong to every address a handover or a write can name: the key pool,
///      the entry point, the kit slot, the zero address and the attacker. The watched balances
///      belong to every address a payment can reach.
// solhint-disable-next-line max-states-count
abstract contract ActionBaseHandler is ActionGhostStorage, CommonBase, StdUtils {
  /// @notice The attempt the handlers last wrote, in the terms the handlers built it: the payload
  ///         bytes, the two keys it names, and whether it is the canonical encoding of those keys.
  struct Committed {
    address newKey;
    bool exists;
    bool canonical;
    address removedKey;
    bytes payload;
  }

  /// @notice The account's watched state at one moment.
  struct Snapshot {
    bytes32[] privileges;
    uint256[] native;
    uint256[] tokens;
    IPolicyManager.AttemptState state;
    uint64 attemptId;
  }

  /// @notice The entry point's marker, code the account trusts rather than a key.
  bytes32 internal constant _ENTRY_POINT_MARKER = bytes32(uint256(0x7171));

  /// @notice The manager.
  PolicyManagerHarness public manager;
  /// @notice The action under test.
  IRecoveryAction public action;
  /// @notice The account.
  address public account;
  /// @notice The token orders pay in.
  ActionPaymentToken public token;
  /// @notice A second token, never ordered, for payments in the wrong token.
  ActionPaymentToken public otherToken;
  /// @notice A payee that, while being paid, sends the account the same batch again.
  ActionCallbackPayee public callbackPayee;
  /// @notice A payee that refuses the native asset.
  address public refusingPayee;
  /// @notice An address that an altered batch tries to make a key or to pay.
  address public attacker;
  /// @notice The entry point's address, holding its marker.
  address public entryPoint;

  /// @notice The addresses a handover may name as either key.
  address[] internal _keys;
  /// @notice The payees an order may name.
  address[] internal _payees;
  /// @notice The addresses that send executeHandover and batches.
  address[] internal _senders;
  /// @notice Every address whose privilege entry is watched.
  address[] internal _watched;
  /// @notice Every address whose balances are watched.
  address[] internal _holders;

  /// @notice The attempt the handlers last wrote.
  Committed internal _committed;
  /// @notice The last batch that ran.
  IAmbireRecoveryAction.Transaction[] internal _lastRun;

  /// @dev Stores the world and builds the watched lists.
  constructor(
    PolicyManagerHarness _managerUnderTest,
    IRecoveryAction _actionUnderTest,
    address _accountUnderTest,
    ActionPaymentToken _orderToken,
    address[] memory _keyList,
    address[] memory _senderList
  ) {
    manager = _managerUnderTest;
    action = _actionUnderTest;
    account = _accountUnderTest;
    token = _orderToken;
    otherToken = new ActionPaymentToken();
    otherToken.mint(_accountUnderTest, 1e24);
    callbackPayee = new ActionCallbackPayee();
    refusingPayee = address(new ActionRefusingPayee());
    attacker = address(0xA77AC4E7);
    entryPoint = address(0xE4747);
    _keys = _keyList;
    _senders = _senderList;
    _payees.push(address(0xBA7EE1));
    _payees.push(address(0xBA7EE2));
    _payees.push(address(callbackPayee));
    _payees.push(refusingPayee);

    for (uint256 _i; _i < _keyList.length; ++_i) {
      _watched.push(_keyList[_i]);
    }
    _watched.push(entryPoint);
    _watched.push(ActionBatch.kitSlot(address(_actionUnderTest)));
    _watched.push(address(0));
    _watched.push(attacker);

    _holders.push(_accountUnderTest);
    _holders.push(attacker);
    for (uint256 _i; _i < _payees.length; ++_i) {
      _holders.push(_payees[_i]);
    }
    for (uint256 _i; _i < _senderList.length; ++_i) {
      _holders.push(_senderList[_i]);
    }
  }

  /*///////////////////////////////////////////////////////////////
                          SHARED HANDLERS
  ///////////////////////////////////////////////////////////////*/

  /// @notice Moves time 1 second to 2 days forward, so waits end. Time alone spends nothing.
  function handler_warp(uint256 _seconds) external {
    Snapshot memory _before = _snapshot();
    vm.warp(block.timestamp + bound(_seconds, 1, 2 days));
    _checkNothingSpent(_before);
  }

  /*///////////////////////////////////////////////////////////////
                              READS
  ///////////////////////////////////////////////////////////////*/

  /// @notice The attempt the manager holds for the account under the action.
  function _attempt() internal view returns (IPolicyManager.Attempt memory _record) {
    _record = manager.stateOf(account, address(action)).attempt;
  }

  /// @notice The account's privilege entry for `_addr`.
  function _privilege(address _addr) internal view returns (bytes32 _value) {
    _value = IAmbireAccount(account).privileges(_addr);
  }

  /// @notice Whether `_value` marks a key: 1 or 2.
  function _isKeyValue(bytes32 _value) internal pure returns (bool _isKey) {
    _isKey = _value == bytes32(uint256(1)) || _value == bytes32(uint256(2));
  }

  /// @notice The watched state now.
  function _snapshot() internal view returns (Snapshot memory _snap) {
    _snap.privileges = new bytes32[](_watched.length);
    for (uint256 _i; _i < _watched.length; ++_i) {
      _snap.privileges[_i] = _privilege(_watched[_i]);
    }
    _snap.native = new uint256[](_holders.length);
    _snap.tokens = new uint256[](_holders.length);
    for (uint256 _i; _i < _holders.length; ++_i) {
      _snap.native[_i] = _holders[_i].balance;
      _snap.tokens[_i] = token.balanceOf(_holders[_i]) + otherToken.balanceOf(_holders[_i]);
    }
    IPolicyManager.Attempt memory _record = _attempt();
    _snap.state = _record.state;
    _snap.attemptId = _record.attemptId;
  }

  /// @notice The entry `_snap` holds for `_addr`, which must be watched.
  function _entryIn(Snapshot memory _snap, address _addr) internal view returns (bytes32 _value) {
    for (uint256 _i; _i < _watched.length; ++_i) {
      if (_watched[_i] == _addr) return _snap.privileges[_i];
    }
  }

  /// @notice Who an order pays when `_chosen` is the payee the sender picks: the order's payee, or
  ///         `_chosen` when the order is open.
  function _paidTo(IPolicyManager.PaymentOrder memory _order, address _chosen) internal pure returns (address _to) {
    _to = _order.payee == address(0) ? _chosen : _order.payee;
  }

  /// @notice The batch the committed attempt approves, paying `_to`.
  function _renderApproved(IPolicyManager.Attempt memory _record, address _to)
    internal
    view
    returns (IAmbireRecoveryAction.Transaction[] memory _calls)
  {
    _calls = ActionBatch.approvedBatch(
      address(manager), address(action), account, _record, _committed.newKey, _committed.removedKey, _to
    );
  }

  /// @notice Whether the approved batch, paying `_to`, should run now. It should when the attempt
  ///         waits and its wait is over, the committed payload is the canonical encoding of two
  ///         distinct nonzero keys, the new key holds no entry, and the removed key holds a key value.
  ///         The account must also authorize the action, and the payment must be possible: the
  ///         account holds the amount or the token answers false, and the payee accepts the native
  ///         asset.
  function _approvedCanRun(address _to) internal view returns (bool _can) {
    IPolicyManager.Attempt memory _record = _attempt();
    if (!_committed.exists || _record.state != IPolicyManager.AttemptState.Waiting) return false;
    // The wait is a timestamp by design, and the handler reads it the way the manager does.
    // forge-lint: disable-next-line(block-timestamp)
    if (block.timestamp < _record.consumableAfter) return false;
    address _new = _committed.newKey;
    address _removed = _committed.removedKey;
    if (!_committed.canonical || _new == address(0) || _removed == address(0) || _new == _removed) return false;
    if (_privilege(_new) != bytes32(0) || !_isKeyValue(_privilege(_removed))) return false;
    if (_privilege(ActionBatch.kitSlot(address(action))) != ActionBatch.binding(address(action))) return false;
    uint256 _amount = _record.order.amount;
    if (_amount == 0) return true;
    if (_record.order.token == address(0)) return !(account.balance < _amount) && _to != refusingPayee;
    return token.answersFalse() || !(token.balanceOf(account) < _amount);
  }

  /// @notice Whether the committed attempt can never run as it stands, however much time passes.
  ///         That is so when its payload is not the canonical encoding of two distinct nonzero keys,
  ///         the new key holds an entry, the removed key holds no key value, the account does not
  ///         authorize the action, or its native payment goes to the payee that refuses it.
  function _attemptIsStuck() internal view returns (bool _stuck) {
    address _new = _committed.newKey;
    address _removed = _committed.removedKey;
    if (!_committed.canonical || _new == address(0) || _removed == address(0) || _new == _removed) return true;
    if (_privilege(_new) != bytes32(0) || !_isKeyValue(_privilege(_removed))) return true;
    if (_privilege(ActionBatch.kitSlot(address(action))) != ActionBatch.binding(address(action))) return true;
    IPolicyManager.PaymentOrder memory _order = _attempt().order;
    _stuck = _order.amount != 0 && _order.token == address(0) && _order.payee == refusingPayee;
  }

  /*///////////////////////////////////////////////////////////////
                              CHECKS
  ///////////////////////////////////////////////////////////////*/

  /// @notice After a call that must spend nothing, checks that the attempt is still unspent.
  function _checkNothingSpent(Snapshot memory _before) internal {
    if (
      _before.state != IPolicyManager.AttemptState.Consumed && _attempt().state == IPolicyManager.AttemptState.Consumed
    ) {
      ghost_spendWithoutWrites = true;
    }
  }

  /// @notice After a batch paying `_to` ran, checks what a handover must leave. The attempt is
  ///         spent. The removed key is zero after holding a key value. The new key is 1 after holding
  ///         nothing. Every other watched entry is unchanged, and exactly the order's payment moved.
  ///         Records the batch as the last one that ran.
  function _checkHandoverRan(Snapshot memory _before, address _to, IAmbireRecoveryAction.Transaction[] memory _batch)
    internal
  {
    Snapshot memory _after = _snapshot();
    if (_before.state != IPolicyManager.AttemptState.Waiting || _after.state != IPolicyManager.AttemptState.Consumed) {
      ghost_writesWithoutSpend = true;
    }
    if (!_committed.canonical) ghost_otherBatchRan = true;
    address _new = _committed.newKey;
    address _removed = _committed.removedKey;
    if (_entryIn(_before, _new) != bytes32(0) || _entryIn(_after, _new) != ActionBatch.KEY_VALUE) {
      ghost_newKeyWrong = true;
    }
    if (!_isKeyValue(_entryIn(_before, _removed)) || _entryIn(_after, _removed) != bytes32(0)) {
      ghost_lostKeyKeptPower = true;
    }
    for (uint256 _i; _i < _watched.length; ++_i) {
      if (_watched[_i] == _new || _watched[_i] == _removed) continue;
      if (_before.privileges[_i] != _after.privileges[_i]) ghost_otherEntryChanged = true;
    }
    bool _paid = _checkPayment(_before, _after, _to);
    if (
      _after.state == IPolicyManager.AttemptState.Consumed
        && (_entryIn(_after, _new) != ActionBatch.KEY_VALUE || _entryIn(_after, _removed) != bytes32(0) || !_paid)
    ) ghost_spendWithoutWrites = true;
    if (callbackPayee.successes() != 0) ghost_batchRanTwice = true;

    delete _lastRun;
    for (uint256 _i; _i < _batch.length; ++_i) {
      _lastRun.push(_batch[_i]);
    }
  }

  /// @notice Whether exactly the order's payment moved: the amount from the account to `_to` in
  ///         the order's asset, nothing when the order has no amount or the token answers false, and
  ///         no other watched balance changed.
  function _checkPayment(Snapshot memory _before, Snapshot memory _after, address _to) internal returns (bool _ok) {
    IPolicyManager.PaymentOrder memory _order = _attempt().order;
    bool _native = _order.token == address(0);
    uint256 _moved = _order.amount;
    if (!_native && token.answersFalse()) _moved = 0;
    if (_order.amount != 0) ++ghost_ranWithPayment;
    if (_order.payee == address(0) && _order.amount != 0) ++ghost_ranWithOpenOrder;
    if (_to == address(callbackPayee) && _order.amount != 0 && _native) ++ghost_payeeCallbacks;
    _ok = true;
    for (uint256 _i; _i < _holders.length; ++_i) {
      uint256 _expectNative = _before.native[_i];
      uint256 _expectTokens = _before.tokens[_i];
      if (_native) {
        if (_holders[_i] == account) _expectNative -= _moved;
        if (_holders[_i] == _to) _expectNative += _moved;
      } else {
        if (_holders[_i] == account) _expectTokens -= _moved;
        if (_holders[_i] == _to) _expectTokens += _moved;
      }
      if (_after.native[_i] != _expectNative || _after.tokens[_i] != _expectTokens) _ok = false;
    }
    if (!_ok) ghost_paymentWrong = true;
  }

  /// @notice Names a refusal for the run's log, and says whether the action's own check raised it
  ///         with one of the action's five errors.
  function _labelRefusal(bytes memory _ret) internal returns (bool _fromCheck) {
    // casting to 'bytes4' is safe because it keeps the first four bytes, the error selector
    // forge-lint: disable-next-line(unsafe-typecast)
    bytes4 _selector = _ret.length < 4 ? bytes4(0) : bytes4(_ret);
    string memory _label = 'other';
    _fromCheck = true;
    if (_selector == IRecoveryAction.RecoveryAction_NotConsumable.selector) {
      _label = 'NotConsumable';
    } else if (_selector == IRecoveryAction.RecoveryAction_BatchNotApproved.selector) {
      uint256 _index;
      assembly {
        _index := mload(add(_ret, 36))
      }
      _label = string.concat('BatchNotApproved(', vm.toString(_index), ')');
    } else if (_selector == IRecoveryAction.RecoveryAction_MalformedHandover.selector) {
      _label = 'MalformedHandover';
    } else if (_selector == IRecoveryAction.RecoveryAction_NotAKey.selector) {
      _label = 'NotAKey';
    } else if (_selector == IRecoveryAction.RecoveryAction_AlreadyPrivileged.selector) {
      _label = 'AlreadyPrivileged';
    } else {
      _fromCheck = false;
      if (_selector == bytes4(keccak256('Error(string)'))) {
        _label = string.concat('Error: ', _decodeReason(_ret));
      } else if (_selector == ActionRefusingPayee.ActionRefusingPayee_Refused.selector) {
        _label = 'payee refused';
      } else if (_selector == ActionPaymentToken.ActionPaymentToken_Insufficient.selector) {
        _label = 'token balance short';
      } else if (_ret.length == 0) {
        _label = 'empty revert';
      }
    }
    _countRefusal(_label);
  }

  /// @notice The reason string of an Error(string) revert.
  function _decodeReason(bytes memory _ret) internal pure returns (string memory _reason) {
    bytes memory _body = new bytes(_ret.length - 4);
    for (uint256 _i; _i < _body.length; ++_i) {
      _body[_i] = _ret[_i + 4];
    }
    _reason = abi.decode(_body, (string));
  }

  /// @notice A key for the new side of a handover: in three draws of four, the first pool key
  ///         `_seed` reaches that holds no entry, so handovers can often run; otherwise any address
  ///         of the pool.
  function _pickNewKey(uint256 _seed) internal view returns (address _key) {
    if (_seed % 4 != 0) {
      for (uint256 _k; _k < _keys.length; ++_k) {
        address _candidate = _keys[(_seed / 4 + _k) % _keys.length];
        if (_privilege(_candidate) == bytes32(0)) return _candidate;
      }
    }
    _key = _pickKey(_seed / 4);
  }

  /// @notice A key for the removed side of a handover: in three draws of four, the first pool key
  ///         `_seed` reaches that holds a key value; otherwise any address of the pool.
  function _pickRemovedKey(uint256 _seed) internal view returns (address _key) {
    if (_seed % 4 != 0) {
      for (uint256 _k; _k < _keys.length; ++_k) {
        address _candidate = _keys[(_seed / 4 + _k) % _keys.length];
        if (_isKeyValue(_privilege(_candidate))) return _candidate;
      }
    }
    _key = _pickKey(_seed / 4);
  }

  /// @notice The address `_seed` picks from the pool a handover may name: a key, the entry point,
  ///         the kit slot or the zero address.
  function _pickKey(uint256 _seed) internal view returns (address _key) {
    uint256 _i = _seed % (_keys.length + 3);
    if (_i < _keys.length) return _keys[_i];
    if (_i == _keys.length) return entryPoint;
    if (_i == _keys.length + 1) return ActionBatch.kitSlot(address(action));
    return address(0);
  }
}
