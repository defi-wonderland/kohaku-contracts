// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {IPolicyManager} from 'interfaces/IPolicyManager.sol';
import {IRecoveryAction} from 'interfaces/IRecoveryAction.sol';
import {IAmbireAccount} from 'contracts/actions/ambire/IAmbireAccount.sol';
import {IAmbireRecoveryAction} from 'contracts/actions/ambire/IAmbireRecoveryAction.sol';

/// @notice Renders what the specification defines for one handover on Ambire's account, so the
///         spend's tests compare what the action and the account do against it. The payload is
///         abi.encode(Handover). The batch is consume at the manager, the grant of the key value
///         1 to the new key, the revoke writing 0 for the removed key, each with no value, and,
///         when the order has an amount, the payment: a raw transfer of the amount in the token to
///         the payee, or for the zero token a call to the payee carrying the amount and no data.
///         The signature is abi.encode(KIT_SLOT, action, "", "") followed by the byte 255. The kit
///         slot and the binding equal ActionTestBase's renderings, which the vector test in test/kat
///         checks against their frozen vector, and ActionSpendTestBase asserts that equality.
library ActionBatch {
  /// @notice The value a handover writes for the new key.
  bytes32 internal constant KEY_VALUE = bytes32(uint256(1));
  /// @notice The ERC-20 transfer selector.
  bytes4 internal constant TRANSFER = bytes4(keccak256('transfer(address,uint256)'));

  /// @notice The payload the guardians approve.
  function payload(address _new, address _removed) internal pure returns (bytes memory _encoded) {
    _encoded = abi.encode(IRecoveryAction.Handover({newAuthority: _new, removedAuthority: _removed}));
  }

  /// @notice The consume call.
  function consumeCall(address _mgr, address _act, uint64 _attemptId, bytes32 _payloadHash)
    internal
    pure
    returns (IAmbireRecoveryAction.Transaction memory _call)
  {
    _call = IAmbireRecoveryAction.Transaction({
      to: _mgr, value: 0, data: abi.encodeCall(IPolicyManager.consume, (_act, _attemptId, _payloadHash))
    });
  }

  /// @notice The grant call.
  function grantCall(address _acct, address _new)
    internal
    pure
    returns (IAmbireRecoveryAction.Transaction memory _call)
  {
    _call = IAmbireRecoveryAction.Transaction({
      to: _acct, value: 0, data: abi.encodeCall(IAmbireAccount.setAddrPrivilege, (_new, KEY_VALUE))
    });
  }

  /// @notice The revoke call.
  function revokeCall(address _acct, address _removed)
    internal
    pure
    returns (IAmbireRecoveryAction.Transaction memory _call)
  {
    _call = IAmbireRecoveryAction.Transaction({
      to: _acct, value: 0, data: abi.encodeCall(IAmbireAccount.setAddrPrivilege, (_removed, bytes32(0)))
    });
  }

  /// @notice The payment call for an order, paying `_paidTo`.
  function paymentCall(IPolicyManager.PaymentOrder memory _order, address _paidTo)
    internal
    pure
    returns (IAmbireRecoveryAction.Transaction memory _call)
  {
    if (_order.token == address(0)) {
      _call = IAmbireRecoveryAction.Transaction({to: _paidTo, value: _order.amount, data: ''});
    } else {
      _call = IAmbireRecoveryAction.Transaction({
        to: _order.token, value: 0, data: abi.encodeWithSelector(TRANSFER, _paidTo, _order.amount)
      });
    }
  }

  /// @notice The approved batch for an attempt and its two keys, paying `_paidTo`.
  function approvedBatch(
    address _mgr,
    address _act,
    address _acct,
    IPolicyManager.Attempt memory _attempt,
    address _new,
    address _removed,
    address _paidTo
  ) internal pure returns (IAmbireRecoveryAction.Transaction[] memory _calls) {
    _calls = new IAmbireRecoveryAction.Transaction[](_attempt.order.amount == 0 ? 3 : 4);
    _calls[0] = consumeCall(_mgr, _act, _attempt.attemptId, _attempt.payloadHash);
    _calls[1] = grantCall(_acct, _new);
    _calls[2] = revokeCall(_acct, _removed);
    if (_attempt.order.amount != 0) _calls[3] = paymentCall(_attempt.order, _paidTo);
  }

  /// @notice The kit slot of an action: the low twenty bytes of keccak256(abi.encode("kit",
  ///         action)) with "kit" typed as a string.
  function kitSlot(address _act) internal pure returns (address _slot) {
    string memory _kit = 'kit';
    _slot = address(uint160(uint256(keccak256(abi.encode(_kit, _act)))));
  }

  /// @notice The binding the account holds under the kit slot: keccak256(abi.encode(action, "")).
  function binding(address _act) internal pure returns (bytes32 _binding) {
    _binding = keccak256(abi.encode(_act, bytes('')));
  }

  /// @notice The signature that routes the account's execute to the action.
  function kitSignature(address _act) internal pure returns (bytes memory _signature) {
    _signature = abi.encodePacked(abi.encode(kitSlot(_act), _act, bytes(''), bytes('')), uint8(255));
  }
}
