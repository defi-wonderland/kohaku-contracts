// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {IPolicyManager} from 'interfaces/IPolicyManager.sol';
import {InterfacesArtifacts} from 'test/utils/InterfacesArtifacts.sol';

/// @notice Checks the policy manager's custom errors. Each test covers one group of errors. The selector tests
///         check each selector is the first four bytes of keccak256 of the error's signature: clients decode a
///         failed recovery by this selector, so a drift turns a named error into an unknown revert. The parameter
///         tests read each error's parameter types and names from the compiled ABI of IPolicyManager: a client
///         shows the offending values by these names, so a renamed or reordered parameter mislabels them.
contract PolicyManagerErrorsTest is InterfacesArtifacts {
  /// Checks the selectors of the errors a setup check raises: a commitment that means no setup, a request signed
  /// under another setup nonce, an action that does not serve the committing account, an action with no setup, and
  /// a written-out body that does not hash to the stored commitment.
  function test_WhenTheSetupErrorSelectorsAreDerived() external pure {
    // it should match each error's canonical signature
    _interfacesAssertSelector(
      IPolicyManager.PolicyManager_InvalidCommitment.selector, 'PolicyManager_InvalidCommitment(bytes32)'
    );
    _interfacesAssertSelector(
      IPolicyManager.PolicyManager_WrongSetupNonce.selector, 'PolicyManager_WrongSetupNonce(uint64,uint64)'
    );
    _interfacesAssertSelector(
      IPolicyManager.PolicyManager_ActionDoesNotServeAccount.selector,
      'PolicyManager_ActionDoesNotServeAccount(address,address)'
    );
    _interfacesAssertSelector(IPolicyManager.PolicyManager_NoSetup.selector, 'PolicyManager_NoSetup(address,address)');
    _interfacesAssertSelector(
      IPolicyManager.PolicyManager_SetupCommitmentMismatch.selector,
      'PolicyManager_SetupCommitmentMismatch(bytes32,bytes32)'
    );
  }

  /// Checks the selectors of the errors an attempt's lifecycle raises: no live attempt, an attempt
  /// already live, a wrong attempt id, an attempt judged under an older setup, and a request past its
  /// validUntil.
  function test_WhenTheAttemptErrorSelectorsAreDerived() external pure {
    // it should match each error's canonical signature
    _interfacesAssertSelector(
      IPolicyManager.PolicyManager_NoActiveAttempt.selector, 'PolicyManager_NoActiveAttempt(address,address)'
    );
    _interfacesAssertSelector(
      IPolicyManager.PolicyManager_AttemptAlreadyActive.selector,
      'PolicyManager_AttemptAlreadyActive(address,address,uint64)'
    );
    _interfacesAssertSelector(
      IPolicyManager.PolicyManager_WrongAttemptId.selector, 'PolicyManager_WrongAttemptId(uint64,uint64)'
    );
    _interfacesAssertSelector(
      IPolicyManager.PolicyManager_StaleAttempt.selector, 'PolicyManager_StaleAttempt(uint64,uint64)'
    );
    _interfacesAssertSelector(
      IPolicyManager.PolicyManager_RequestExpired.selector, 'PolicyManager_RequestExpired(uint48,uint48)'
    );
  }

  /// Checks the selectors of the errors the proofs and the rule raise: a place outside the body, a
  /// credential that does not hash to its place, places out of order, a proof the method rejects, and a
  /// clause left unsatisfied.
  function test_WhenTheProofAndRuleErrorSelectorsAreDerived() external pure {
    // it should match each error's canonical signature
    _interfacesAssertSelector(
      IPolicyManager.PolicyManager_PlaceOutOfRange.selector, 'PolicyManager_PlaceOutOfRange(uint256,uint256)'
    );
    _interfacesAssertSelector(
      IPolicyManager.PolicyManager_CredentialMismatch.selector, 'PolicyManager_CredentialMismatch(uint256,bytes32)'
    );
    _interfacesAssertSelector(
      IPolicyManager.PolicyManager_PlacesNotStrictlyIncreasing.selector,
      'PolicyManager_PlacesNotStrictlyIncreasing(uint256)'
    );
    _interfacesAssertSelector(
      IPolicyManager.PolicyManager_ProofRejected.selector, 'PolicyManager_ProofRejected(uint256,address)'
    );
    _interfacesAssertSelector(
      IPolicyManager.PolicyManager_RuleUnsatisfied.selector, 'PolicyManager_RuleUnsatisfied(uint256)'
    );
  }

  /// Checks the selectors of the errors a method's stop raises: a stopped method at an opening or a cancel
  /// by proofs, a used method stopped at the spend, and the three refusals of a cancel by veto, which are a
  /// method the attempt did not use, an attempt that ignores stops and a method that is not stopped.
  function test_WhenThePauseAndVetoErrorSelectorsAreDerived() external pure {
    // it should match each error's canonical signature
    _interfacesAssertSelector(
      IPolicyManager.PolicyManager_MethodStopped.selector, 'PolicyManager_MethodStopped(uint256,address)'
    );
    _interfacesAssertSelector(
      IPolicyManager.PolicyManager_MethodVetoedSpend.selector, 'PolicyManager_MethodVetoedSpend(address)'
    );
    _interfacesAssertSelector(
      IPolicyManager.PolicyManager_MethodNotUsed.selector, 'PolicyManager_MethodNotUsed(uint64,address)'
    );
    _interfacesAssertSelector(
      IPolicyManager.PolicyManager_AttemptIgnoresPause.selector, 'PolicyManager_AttemptIgnoresPause(uint64)'
    );
    _interfacesAssertSelector(
      IPolicyManager.PolicyManager_MethodNotStopped.selector, 'PolicyManager_MethodNotStopped(address)'
    );
  }

  /// Checks the selectors of the errors the spend raises: a wait that is not over, and a payload whose
  /// hash differs from the one the attempt committed.
  function test_WhenTheSpendErrorSelectorsAreDerived() external pure {
    // it should match each error's canonical signature
    _interfacesAssertSelector(
      IPolicyManager.PolicyManager_WaitNotOver.selector, 'PolicyManager_WaitNotOver(uint48,uint48)'
    );
    _interfacesAssertSelector(
      IPolicyManager.PolicyManager_WrongPayload.selector, 'PolicyManager_WrongPayload(bytes32,bytes32)'
    );
  }

  /// Checks the parameter types and names of the setup errors in the compiled ABI: the supplied commitment, the
  /// supplied and expected nonces, the account and the action it does not serve, the account and action with no
  /// setup, and the recomputed and committed commitments, in that order.
  function test_WhenTheSetupErrorsAreReadFromTheAbi() external {
    // it should declare the specified parameters
    string memory _json = _interfacesLoad('IPolicyManager');
    _interfacesAssertError(_json, 'PolicyManager_InvalidCommitment', 'bytes32 _supplied');
    _interfacesAssertError(_json, 'PolicyManager_WrongSetupNonce', 'uint64 _supplied,uint64 _expected');
    _interfacesAssertError(_json, 'PolicyManager_ActionDoesNotServeAccount', 'address _account,address _action');
    _interfacesAssertError(_json, 'PolicyManager_NoSetup', 'address _account,address _action');
    _interfacesAssertError(_json, 'PolicyManager_SetupCommitmentMismatch', 'bytes32 _recomputed,bytes32 _committed');
  }

  /// Checks the parameter types and names of the attempt errors in the compiled ABI: the account and action asked
  /// about, the running attempt's id, the supplied and expected ids, the judged and current nonces, and the block's
  /// timestamp beside the request's deadline, in that order.
  function test_WhenTheAttemptErrorsAreReadFromTheAbi() external {
    // it should declare the specified parameters
    string memory _json = _interfacesLoad('IPolicyManager');
    _interfacesAssertError(_json, 'PolicyManager_NoActiveAttempt', 'address _account,address _action');
    _interfacesAssertError(
      _json, 'PolicyManager_AttemptAlreadyActive', 'address _account,address _action,uint64 _attemptId'
    );
    _interfacesAssertError(_json, 'PolicyManager_WrongAttemptId', 'uint64 _supplied,uint64 _expected');
    _interfacesAssertError(_json, 'PolicyManager_StaleAttempt', 'uint64 _judgedUnder,uint64 _currentNonce');
    _interfacesAssertError(_json, 'PolicyManager_RequestExpired', 'uint48 _blockTimestamp,uint48 _validUntil');
  }

  /// Checks the parameter types and names of the proof and rule errors in the compiled ABI: the place and the
  /// place count, the place and the recomputed credential, the out of order place, the place and the rejecting
  /// method, and the failing clause, in that order.
  function test_WhenTheProofAndRuleErrorsAreReadFromTheAbi() external {
    // it should declare the specified parameters
    string memory _json = _interfacesLoad('IPolicyManager');
    _interfacesAssertError(_json, 'PolicyManager_PlaceOutOfRange', 'uint256 _place,uint256 _count');
    _interfacesAssertError(_json, 'PolicyManager_CredentialMismatch', 'uint256 _place,bytes32 _recomputed');
    _interfacesAssertError(_json, 'PolicyManager_PlacesNotStrictlyIncreasing', 'uint256 _place');
    _interfacesAssertError(_json, 'PolicyManager_ProofRejected', 'uint256 _place,address _method');
    _interfacesAssertError(_json, 'PolicyManager_RuleUnsatisfied', 'uint256 _clause');
  }

  /// Checks the parameter types and names of the pause and veto errors in the compiled ABI: the place and the
  /// stopped method, the vetoing method, the attempt and the unused method, the attempt that ignores stops, and the
  /// method that is not stopped, in that order.
  function test_WhenThePauseAndVetoErrorsAreReadFromTheAbi() external {
    // it should declare the specified parameters
    string memory _json = _interfacesLoad('IPolicyManager');
    _interfacesAssertError(_json, 'PolicyManager_MethodStopped', 'uint256 _place,address _method');
    _interfacesAssertError(_json, 'PolicyManager_MethodVetoedSpend', 'address _method');
    _interfacesAssertError(_json, 'PolicyManager_MethodNotUsed', 'uint64 _attemptId,address _method');
    _interfacesAssertError(_json, 'PolicyManager_AttemptIgnoresPause', 'uint64 _attemptId');
    _interfacesAssertError(_json, 'PolicyManager_MethodNotStopped', 'address _method');
  }

  /// Checks the parameter types and names of the spend errors in the compiled ABI: the block's timestamp beside
  /// the end of the wait, and the supplied payload hash beside the committed one, in that order.
  function test_WhenTheSpendErrorsAreReadFromTheAbi() external {
    // it should declare the specified parameters
    string memory _json = _interfacesLoad('IPolicyManager');
    _interfacesAssertError(_json, 'PolicyManager_WaitNotOver', 'uint48 _blockTimestamp,uint48 _consumableAfter');
    _interfacesAssertError(_json, 'PolicyManager_WrongPayload', 'bytes32 _supplied,bytes32 _committed');
  }
}
