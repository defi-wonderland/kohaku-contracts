// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {IPolicyManager} from 'interfaces/IPolicyManager.sol';
import {IAmbireAccount} from 'contracts/actions/ambire/IAmbireAccount.sol';
import {IAmbireRecoveryAction} from 'contracts/actions/ambire/IAmbireRecoveryAction.sol';
import {ActionBaseHandler} from 'test/action/invariants/handlers/BaseHandler.t.sol';
import {ActionBatch} from 'test/utils/ActionBatch.sol';

/// @notice Anyone sends a batch straight to the account's execute under the kit's signature,
///         without calling executeHandover. The batch is the approved one, or one that differs from it.
abstract contract ActionHandlerExecuteBatch is ActionBaseHandler {
  /// @notice The ways a batch can differ from the approved one.
  uint256 internal constant _SAME = 0;
  uint256 internal constant _REORDER = 1;
  uint256 internal constant _DROP = 2;
  uint256 internal constant _ADD = 3;
  uint256 internal constant _ALTER_TARGET = 4;
  uint256 internal constant _ALTER_VALUE = 5;
  uint256 internal constant _ALTER_DATA = 6;
  uint256 internal constant _ALTER_PAYMENT = 7;
  uint256 internal constant _SPLIT = 8;

  /// @notice Builds the batch the committed attempt approves, with a payee `_argSeed` picks when the
  ///         order leaves it open. Then applies the change `_changeSeed` picks. Out of sixteen draws,
  ///         five change nothing and three alter a call's value. The rest swap two calls, drop a call,
  ///         add a call, alter a call's target or data, alter the payment, or split the spend from the
  ///         key writes. Half the changes hit the revoke, and three value changes in four hit the grant
  ///         or the revoke, because a check that skips a field lets a change there through. Sends the
  ///         batch from a sender `_senderSeed` picks. Only the unchanged batch may run. While the
  ///         account authorizes the action, its own check must refuse every changed batch.
  function handler_executeBatch(uint256 _senderSeed, uint256 _changeSeed, uint256 _argSeed) external {
    if (!_committed.exists) return;
    address _sender = _senders[_senderSeed % _senders.length];
    IPolicyManager.Attempt memory _record = _attempt();
    address _to = _paidTo(_record.order, _payees[_argSeed % 2]);
    IAmbireRecoveryAction.Transaction[] memory _batch = _renderApproved(_record, _to);
    uint256 _change = _pickChange(_changeSeed);
    if (_change != _SAME) _batch = _alter(_batch, _record.order, _change, _argSeed);
    bool _shouldRun = _change == _SAME && _approvedCanRun(_to);
    bool _authorizes = _privilege(ActionBatch.kitSlot(address(action))) == ActionBatch.binding(address(action));
    Snapshot memory _before = _snapshot();

    vm.prank(_sender);
    try IAmbireAccount(account).execute(_batch, ActionBatch.kitSignature(address(action))) {
      if (_change != _SAME) {
        ghost_otherBatchRan = true;
        return;
      }
      ++ghost_ranThroughExecute;
      _checkHandoverRan(_before, _to, _batch);
    } catch (bytes memory _ret) {
      bool _fromCheck = _labelRefusal(_ret);
      if (_change != _SAME) {
        ++ghost_otherBatchesSent;
        if (_authorizes && !_fromCheck) {
          ghost_otherBatchPassedTheCheck = true;
          ghost_lastUnexpectedRevert = _ret;
        }
      } else if (_shouldRun) {
        ghost_approvedBatchRefused = true;
        ghost_lastUnexpectedRevert = _ret;
      }
    }
  }

  /// @notice The change `_seed` picks: none for 0 to 4 of sixteen, a value change for 5 to 7, and
  ///         one of the other changes for each of 8 to 15.
  function _pickChange(uint256 _seed) internal pure returns (uint256 _change) {
    uint256 _draw = _seed % 16;
    if (_draw < 5) return _SAME;
    if (_draw < 8) return _ALTER_VALUE;
    uint256[8] memory _others =
      [_REORDER, _DROP, _ADD, _ALTER_TARGET, _ALTER_DATA, _ALTER_PAYMENT, _SPLIT, _ALTER_VALUE];
    _change = _others[_draw - 8];
  }

  /// @notice The index of the call change `_change` alters in a batch of `_length` calls: the
  ///         revoke, index 2, in half the draws, the grant or the revoke in three value changes of
  ///         four, and otherwise any index. `_argSeed` bits from 128 up pick it, apart from the low
  ///         bits the change itself reads.
  function _pickIndex(uint256 _change, uint256 _length, uint256 _argSeed) internal pure returns (uint256 _i) {
    uint256 _bits = _argSeed >> 128;
    if (_change == _ALTER_VALUE && _bits % 4 != 0) return 1 + (_bits / 4) % 2;
    if ((_bits / 8) % 2 == 0) return 2;
    _i = (_bits / 16) % _length;
  }

  /// @notice Applies change `_change` to the approved batch `_calls`, so the result always differs
  ///         from it in at least one byte or in length.
  function _alter(
    IAmbireRecoveryAction.Transaction[] memory _calls,
    IPolicyManager.PaymentOrder memory _order,
    uint256 _change,
    uint256 _argSeed
  ) internal view returns (IAmbireRecoveryAction.Transaction[] memory _out) {
    uint256 _length = _calls.length;
    uint256 _i = _pickIndex(_change, _length, _argSeed);
    if (_change == _REORDER) {
      uint256 _j = (_i + 1 + (_argSeed / 7) % (_length - 1)) % _length;
      (_calls[_i], _calls[_j]) = (_calls[_j], _calls[_i]);
      return _calls;
    }
    if (_change == _DROP) return _without(_calls, _i);
    if (_change == _ADD) return _with(_calls, _argSeed % (_length + 1), _extraCall(_calls, _argSeed));
    // An open order leaves the payee free: the native payment's target and the transfer's payee
    // word may differ there, so those changes move to a field the order fixes.
    bool _freePayee = _order.payee == address(0) && _order.amount != 0 && _i == 3;
    if (_freePayee && _change == _ALTER_TARGET && _order.token == address(0)) _change = _ALTER_VALUE;
    if (_change == _ALTER_TARGET) {
      _calls[_i].to = address(uint160(_calls[_i].to) ^ uint160(1 + (_argSeed / 11) % 255));
      return _calls;
    }
    if (_change == _ALTER_VALUE) {
      _calls[_i].value += 1 + (_argSeed / 11) % 3;
      return _calls;
    }
    if (_change == _ALTER_DATA) return _alterData(_calls, _i, _argSeed, _freePayee);
    if (_change == _ALTER_PAYMENT) return _alterPayment(_calls, _order, _argSeed);
    return _split(_calls, _argSeed);
  }

  /// @notice The batch with the call at `_at` removed.
  function _without(IAmbireRecoveryAction.Transaction[] memory _calls, uint256 _at)
    internal
    pure
    returns (IAmbireRecoveryAction.Transaction[] memory _out)
  {
    _out = new IAmbireRecoveryAction.Transaction[](_calls.length - 1);
    for (uint256 _k; _k < _out.length; ++_k) {
      _out[_k] = _calls[_k < _at ? _k : _k + 1];
    }
  }

  /// @notice The batch with `_extra` inserted at `_at`.
  function _with(
    IAmbireRecoveryAction.Transaction[] memory _calls,
    uint256 _at,
    IAmbireRecoveryAction.Transaction memory _extra
  ) internal pure returns (IAmbireRecoveryAction.Transaction[] memory _out) {
    _out = new IAmbireRecoveryAction.Transaction[](_calls.length + 1);
    for (uint256 _k; _k < _out.length; ++_k) {
      if (_k < _at) _out[_k] = _calls[_k];
      else if (_k == _at) _out[_k] = _extra;
      else _out[_k] = _calls[_k - 1];
    }
  }

  /// @notice A call an altered batch could slip in: a key for the attacker, a token transfer to the
  ///         attacker, or a copy of one of the approved calls.
  function _extraCall(IAmbireRecoveryAction.Transaction[] memory _calls, uint256 _argSeed)
    internal
    view
    returns (IAmbireRecoveryAction.Transaction memory _extra)
  {
    uint256 _kind = (_argSeed / 13) % 3;
    if (_kind == 0) return ActionBatch.grantCall(account, attacker);
    if (_kind == 1) {
      return IAmbireRecoveryAction.Transaction({
        to: address(token), value: 0, data: abi.encodeWithSelector(ActionBatch.TRANSFER, attacker, uint256(1))
      });
    }
    IAmbireRecoveryAction.Transaction memory _copied = _calls[(_argSeed / 17) % _calls.length];
    _extra = IAmbireRecoveryAction.Transaction({to: _copied.to, value: _copied.value, data: _copied.data});
  }

  /// @notice The batch with the data of call `_at` changed: one byte flipped, or one byte appended.
  ///         When `_freePayee` is set the flipped byte is never in the transfer's payee word.
  function _alterData(IAmbireRecoveryAction.Transaction[] memory _calls, uint256 _at, uint256 _argSeed, bool _freePayee)
    internal
    pure
    returns (IAmbireRecoveryAction.Transaction[] memory _out)
  {
    bytes memory _data = _calls[_at].data;
    if (_data.length == 0 || (_argSeed / 11) % 2 == 0) {
      // casting to 'uint8' is safe because only the low byte is wanted, any byte alters the batch
      // forge-lint: disable-next-line(unsafe-typecast)
      _calls[_at].data = abi.encodePacked(_data, bytes1(uint8(_argSeed / 23)));
    } else {
      bytes memory _copy = abi.encodePacked(_data);
      uint256 _byte = (_argSeed / 29) % _copy.length;
      if (_freePayee && _byte > 3 && _byte < 36) _byte += 32;
      _copy[_byte] = bytes1(uint8(_copy[_byte]) ^ uint8(1 + (_argSeed / 31) % 255));
      _calls[_at].data = _copy;
    }
    _out = _calls;
  }

  /// @notice The batch with its payment changed: another token, another amount, another payee
  ///         where the order fixes one, or the other asset's form. A batch with no payment gets one.
  function _alterPayment(
    IAmbireRecoveryAction.Transaction[] memory _calls,
    IPolicyManager.PaymentOrder memory _order,
    uint256 _argSeed
  ) internal view returns (IAmbireRecoveryAction.Transaction[] memory _out) {
    if (_calls.length == 3) {
      return _with(_calls, 3, IAmbireRecoveryAction.Transaction({to: attacker, value: 1, data: ''}));
    }
    bool _native = _order.token == address(0);
    address _to = _native ? _calls[3].to : _payeeOf(_calls[3].data);
    IPolicyManager.PaymentOrder memory _other =
      IPolicyManager.PaymentOrder({token: _order.token, amount: _order.amount, payee: _to});
    uint256 _kind = (_argSeed / 11) % 4;
    if (_kind == 0) {
      _other.token = _native ? address(token) : address(otherToken);
    } else if (_kind == 1) {
      _other.amount = _order.amount == 1 ? 2 : _order.amount - 1;
    } else if (_kind == 2 && _order.payee != address(0)) {
      _other.payee = attacker;
    } else {
      _other.token = _native ? address(token) : address(0);
    }
    _calls[3] = ActionBatch.paymentCall(_other, _other.payee);
    _out = _calls;
  }

  /// @notice The spend of the attempt alone, or the key writes and the payment without the spend.
  function _split(IAmbireRecoveryAction.Transaction[] memory _calls, uint256 _argSeed)
    internal
    pure
    returns (IAmbireRecoveryAction.Transaction[] memory _out)
  {
    if (_argSeed % 2 == 0) {
      _out = new IAmbireRecoveryAction.Transaction[](1);
      _out[0] = _calls[0];
    } else {
      _out = _without(_calls, 0);
    }
  }

  /// @notice The payee a transfer's calldata names.
  function _payeeOf(bytes memory _data) internal pure returns (address _to) {
    assembly {
      _to := mload(add(_data, 36))
    }
  }
}
