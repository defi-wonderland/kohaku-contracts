// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {IPolicyManager} from 'interfaces/IPolicyManager.sol';
import {IRecoveryAction} from 'interfaces/IRecoveryAction.sol';

/// @title IAmbireRecoveryAction
/// @author defi-wonderland
/// @notice The Ambire action's own interface, beyond what every recovery action shares: Ambire's
///         ExternalSigValidator callback and the constants its account binds.
/// @dev It is not a kit interface. Another account's action declares its own.
interface IAmbireRecoveryAction is IRecoveryAction {
  /*///////////////////////////////////////////////////////////////
                              STRUCTS
  ///////////////////////////////////////////////////////////////*/

  /// @notice One account call as Ambire's account carries it.
  /// @param to The call's target.
  /// @param value The native value the call carries.
  /// @param data The call's calldata.
  struct Transaction {
    address to;
    uint256 value;
    bytes data;
  }

  /*///////////////////////////////////////////////////////////////
                              LOGIC
  ///////////////////////////////////////////////////////////////*/

  /// @notice Ambire's account calls this before it runs a batch sent through this action, and
  ///         runs the batch only on true. It is the only check between the batch and the
  ///         account. It returns true only for the exact batch the waiting attempt approves once
  ///         its wait is over: consume, grant the new key, revoke the old one, and the payment
  ///         when the order has an amount. Anything else reverts, and so does a call from an
  ///         account this action does not serve.
  /// @dev The signature is that of Ambire's ExternalSigValidator at kohaku-commons commit
  ///      29227cc, the account revision this action serves. The account is the caller. The second
  ///      return value is the timestamp the account compares on a false answer, and this action
  ///      leaves it at zero.
  /// @param _data The validator data the account passes through.
  /// @param _innerSignature The signature bytes the account passes through.
  /// @param _calls The batch the account is about to run.
  /// @return _isValidSignature True when the batch is the one the waiting attempt approves.
  /// @return _timestampValidAfter The timestamp the account compares on a false answer, always
  ///         zero.
  function validateSig(bytes calldata _data, bytes calldata _innerSignature, Transaction[] calldata _calls)
    external
    returns (bool _isValidSignature, uint256 _timestampValidAfter);

  /// @notice The privilege value that the grant writes for the new key.
  /// @dev The account keeps a privilege value for each key. A key at 1 passes only signatures
  ///      that include the account's own address, so a signature made for one account cannot be
  ///      reused on another. A key at 2 also passes a plain signature that names no account,
  ///      which is safe only for a key that one account uses alone. The action cannot know that
  ///      about a new key, so the grant writes 1.
  /// @return _keyValue bytes32(uint256(1)).
  function KEY_VALUE() external view returns (bytes32 _keyValue);

  /// @notice The policy manager whose attempts this action spends.
  /// @return _manager The manager set at deployment.
  function MANAGER() external view returns (IPolicyManager _manager);

  /// @notice The AmbireAccount implementation that this action serves. The account's proxy
  ///         delegates to it.
  /// @dev An Ambire account is a minimal proxy whose code holds its implementation's address,
  ///      and it has no way to change it, so an account keeps its implementation for life. This
  ///      action serves only accounts whose proxy points at this address. When Ambire ships a
  ///      new implementation, its accounts need a new action deployed with the new address,
  ///      since this value is immutable.
  /// @return _implementation The pinned implementation set at deployment.
  function AMBIRE_IMPLEMENTATION() external view returns (address _implementation);

  /// @notice The pseudo-address under which the account holds this action's binding.
  /// @dev The slot is address(uint160(uint256(keccak256(abi.encode("kit", address(this)))))),
  ///      where address(this) is this action's own address. Each action derives its own slot,
  ///      so two actions on one account never share an entry. Nobody holds a key for the slot,
  ///      so the account acts on the entry only by asking this action through validateSig.
  /// @return _kitSlot The slot derived from this action's address.
  function KIT_SLOT() external view returns (address _kitSlot);

  /// @notice The value the account must hold under KIT_SLOT before it asks this action.
  /// @dev The binding is keccak256(abi.encode(address(this), bytes(""))), where address(this)
  ///      is this action's own address. The account binds an outside validator to a slot by
  ///      holding keccak256(abi.encode(validator, data)) under it, where validator is the
  ///      validator's address and data is what the account passes to it. The binding is that
  ///      value with this action as the validator and empty data. The data is empty because
  ///      this action reads nothing from it.
  /// @return _binding The binding derived from this action's address.
  function BINDING() external view returns (bytes32 _binding);
}
