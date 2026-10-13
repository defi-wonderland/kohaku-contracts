// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {IPolicyAction} from 'interfaces/IPolicyAction.sol';
import {IPolicyManager} from 'interfaces/IPolicyManager.sol';

/// @title IRecoveryAction
/// @notice What every recovery action shares beyond the views every action exposes, whatever
///         account it serves. It carries out one key handover on the account once the manager
///         has approved it, through executeHandover.
interface IRecoveryAction is IPolicyAction {
  /*///////////////////////////////////////////////////////////////
                              STRUCTS
  ///////////////////////////////////////////////////////////////*/

  /// @notice The recovery action's payload: `abi.encode(Handover)`. The manager stores and signs the
  ///         payload as opaque bytes, and this action decodes it to build and check the handover.
  /// @param newAuthority The key to install. It is never zero, and the account grants it nothing
  ///        today.
  /// @param removedAuthority The exact key to remove. It is never zero, and the account honors it as
  ///        a key today.
  struct Handover {
    address newAuthority;
    address removedAuthority;
  }

  /*///////////////////////////////////////////////////////////////
                              ERRORS
  ///////////////////////////////////////////////////////////////*/

  /// @notice The batch the account is about to run is not the one this attempt approves. _callIndex
  ///         is the position in the account's batch where it departs from the approved one. A batch
  ///         with too few calls names the first position it lacks.
  /// @dev On Ambire's account the approved batch is 0 consume, 1 grant, 2 revoke and 3 payment,
  ///      and a grant and revoke that do not rebuild the payload name the grant's index.
  /// @param _callIndex The position of the offending call.
  error RecoveryAction_BatchNotApproved(uint256 _callIndex);

  /// @notice The payload does not decode in this action's layout, names a zero key, or names one
  ///         address on both sides.
  /// @param _payload The payload refused.
  error RecoveryAction_MalformedHandover(bytes _payload);

  /// @notice The address the handover removes is not a key the account honors today, so the
  ///         handover would remove no key.
  /// @dev On Ambire's account the address's privilege entry is empty or holds something other than
  ///      a key value, such as a validator binding.
  /// @param _authority The address refused.
  error RecoveryAction_NotAKey(address _authority);

  /// @notice The account already grants something to the address the handover installs, so
  ///         installing it as a key would change what the account grants it.
  /// @dev On Ambire's account the address already has an entry in the privilege table, and the
  ///      grant would overwrite that entry.
  /// @param _authority The address refused.
  error RecoveryAction_AlreadyPrivileged(address _authority);

  /// @notice The attempt is not consumable. The error carries its state, clock and committed hash at
  ///         the failed call, so the caller sees which condition failed.
  /// @param _account The account asked about.
  /// @param _state The attempt's state at the failed call.
  /// @param _consumableAfter The attempt's clock at the failed call.
  /// @param _committedPayloadHash The attempt's committed payload hash at the failed call.
  error RecoveryAction_NotConsumable(
    address _account, IPolicyManager.AttemptState _state, uint48 _consumableAfter, bytes32 _committedPayloadHash
  );

  /// @notice The account is not one this action serves. Its code is not the account implementation
  ///         this action handles, so the action refuses to build or approve a batch for it.
  /// @dev On Ambire's account the account's code hash is not the hash of the 45-byte proxy over the
  ///      pinned implementation, the comparison supportsAccount makes.
  /// @param _account The account refused.
  error RecoveryAction_AccountNotServed(address _account);

  /*///////////////////////////////////////////////////////////////
                              LOGIC
  ///////////////////////////////////////////////////////////////*/

  /// @notice Execute an approved handover on the account. Anyone may call it.
  /// @dev Reverts with RecoveryAction_AccountNotServed when the action does not serve the account.
  ///      Reads the manager's attempt as a view. It reverts unless the attempt is waiting, at or
  ///      past its wait and committed to this payload's hash. That read is an early exit, since
  ///      the account's authorization check and consume check again inside the batch. It builds
  ///      the batch of consume, grant, revoke and payment. It hands the batch to the account's
  ///      execution function with the authorization blob that account expects, so the spend and
  ///      the writes land or revert as one.
  /// @param _account The account whose attempt is executed.
  /// @param _payload The committed handover, as the opening event published it.
  function executeHandover(address _account, bytes calldata _payload) external;

  /// @notice Whether `_account` already grants `_candidate` anything, in the account's own terms.
  ///         isAuthority answers only for keys, so this check is broader. A handover refuses to
  ///         install a new key the account already grants something, and the request builder calls
  ///         this view to catch that before the guardians sign.
  /// @dev On Ambire's account it answers whether the candidate has any entry in the privilege table:
  ///      a key, a slot, a validator or anything else the account stores there.
  /// @param _account The account asked about.
  /// @param _candidate The address a handover would install.
  /// @return _reserved True when the account already grants that address anything.
  function holdsAnyPrivilege(address _account, address _candidate) external view returns (bool _reserved);
}
