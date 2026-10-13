// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {IRecoveryAction} from 'interfaces/IRecoveryAction.sol';
import {InterfacesArtifacts} from 'test/utils/InterfacesArtifacts.sol';

/// @notice Checks the selectors of the recovery action's custom errors and their parameters in the compiled ABI.
contract RecoveryActionErrorsTest is InterfacesArtifacts {
  /// Checks each custom error selector is the first four bytes of keccak256 of its signature.
  /// Clients decode a failed recovery by this selector, so a drift turns a named error into an unknown revert.
  function test_WhenTheErrorSelectorsAreDerived() external pure {
    // it should match each error's canonical signature
    _interfacesAssertSelector(
      IRecoveryAction.RecoveryAction_BatchNotApproved.selector, 'RecoveryAction_BatchNotApproved(uint256)'
    );
    _interfacesAssertSelector(
      IRecoveryAction.RecoveryAction_MalformedHandover.selector, 'RecoveryAction_MalformedHandover(bytes)'
    );
    _interfacesAssertSelector(IRecoveryAction.RecoveryAction_NotAKey.selector, 'RecoveryAction_NotAKey(address)');
    _interfacesAssertSelector(
      IRecoveryAction.RecoveryAction_AlreadyPrivileged.selector, 'RecoveryAction_AlreadyPrivileged(address)'
    );
    _interfacesAssertSelector(
      IRecoveryAction.RecoveryAction_NotConsumable.selector,
      'RecoveryAction_NotConsumable(address,uint8,uint48,bytes32)'
    );
    _interfacesAssertSelector(
      IRecoveryAction.RecoveryAction_AccountNotServed.selector, 'RecoveryAction_AccountNotServed(address)'
    );
  }

  /// Checks the parameter types and names of every custom error in the compiled ABI of IRecoveryAction: the call
  /// index, the refused payload, the refused authority twice, the account with the attempt's state, clock and
  /// committed payload hash, and the account the action does not serve. A client shows the offending values by
  /// these names, so a renamed or reordered parameter mislabels them.
  function test_WhenTheErrorsAreReadFromTheAbi() external {
    // it should declare each with the specified parameters
    string memory _json = _interfacesLoad('IRecoveryAction');
    _interfacesAssertError(_json, 'RecoveryAction_BatchNotApproved', 'uint256 _callIndex');
    _interfacesAssertError(_json, 'RecoveryAction_MalformedHandover', 'bytes _payload');
    _interfacesAssertError(_json, 'RecoveryAction_NotAKey', 'address _authority');
    _interfacesAssertError(_json, 'RecoveryAction_AlreadyPrivileged', 'address _authority');
    _interfacesAssertError(
      _json,
      'RecoveryAction_NotConsumable',
      'address _account,enum IPolicyManager.AttemptState _state,uint48 _consumableAfter,bytes32 '
      '_committedPayloadHash'
    );
    _interfacesAssertError(_json, 'RecoveryAction_AccountNotServed', 'address _account');
  }
}
