// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {IPolicyMethod} from 'interfaces/IPolicyMethod.sol';

import {Deploy} from 'script/Deploy.s.sol';
import {IAmbireRecoveryAction} from 'contracts/actions/ambire/IAmbireRecoveryAction.sol';

/// @notice Test harness. It is the deployment script with one extra door per internal step, so a
///         test can run one check, the record builder, the label rule or the chain table alone. It
///         adds no behavior to the script's own functions.
contract DeployHarness is Deploy {
  /*///////////////////////////////////////////////////////////////
                        EXTERNAL FUNCTIONS
  ///////////////////////////////////////////////////////////////*/

  /// @notice Exposes the internal deploy step for tests.
  /// @param _pins The pins to deploy with.
  /// @return _deployment What the step deployed.
  function deploy(Pins calldata _pins) external returns (Deployment memory _deployment) {
    _deployment = _deploy(_pins);
  }

  /// @notice Exposes the internal P256VERIFY liveness check for tests.
  function checkP256Verify() external {
    _checkP256Verify();
  }

  /// @notice Exposes the internal record builder for tests.
  /// @param _deployment The deployment to record.
  /// @param _pins The pins it was deployed with.
  /// @param _chainId The chain the deployment lives on.
  /// @return _json The record.
  function recordJson(Deployment calldata _deployment, Pins calldata _pins, uint256 _chainId)
    external
    returns (string memory _json)
  {
    _json = _recordJson(_deployment, _pins, _chainId);
  }

  /// @notice Exposes the internal implementation check for tests.
  /// @param _pins The pins naming the implementation and its code hash.
  function checkImplementation(Pins calldata _pins) external view {
    _checkImplementation(_pins);
  }

  /// @notice Exposes the internal P256VERIFY input builder for tests.
  /// @return _input The 160-byte input.
  function p256VerifyInput() external view returns (bytes memory _input) {
    _input = _p256VerifyInput();
  }

  /// @notice Exposes the internal record label reader for tests.
  /// @param _chainId The chain id used when no label is set.
  /// @return _label The label.
  function recordLabel(uint256 _chainId) external view returns (string memory _label) {
    _label = _recordLabel(_chainId);
  }

  /// @notice Exposes the internal deployment check for tests.
  /// @param _deployment The deployment to check.
  /// @param _pins The pins it was deployed with.
  function checkDeployment(Deployment calldata _deployment, Pins calldata _pins) external view {
    _checkDeployment(_deployment, _pins);
  }

  /// @notice Exposes the internal action check for tests.
  /// @param _action The action.
  /// @param _manager The manager the action must name.
  /// @param _implementation The implementation the action must name.
  function checkAction(IAmbireRecoveryAction _action, address _manager, address _implementation) external view {
    _checkAction(_action, _manager, _implementation);
  }

  /// @notice Exposes the internal slot check for tests.
  /// @param _action The action.
  function checkKitSlot(IAmbireRecoveryAction _action) external view {
    _checkKitSlot(_action);
  }

  /// @notice Exposes the internal method roles check for tests.
  /// @param _method The method.
  function checkMethodRoles(IPolicyMethod _method) external view {
    _checkMethodRoles(_method);
  }

  /// @notice Exposes the internal ERC-165 check for tests.
  /// @param _deployment The deployment to check.
  function checkInterfaces(Deployment calldata _deployment) external view {
    _checkInterfaces(_deployment);
  }

  /// @notice Exposes the internal P256VERIFY answer check for tests.
  /// @param _answer What the precompile answered.
  function checkP256VerifyAnswer(bytes calldata _answer) external pure {
    _checkP256VerifyAnswer(_answer);
  }

  /// @notice Exposes the internal label rule for tests.
  /// @param _isSet Whether a label value was given.
  /// @param _value The label value.
  /// @param _chainId The chain id used when no value is set.
  /// @return _label The label.
  function labelFor(bool _isSet, string calldata _value, uint256 _chainId)
    external
    pure
    returns (string memory _label)
  {
    _label = _labelFor(_isSet, _value, _chainId);
  }

  /// @notice Exposes the internal per-chain table for tests.
  /// @param _chainId The chain id.
  /// @return _pins The pins for that chain.
  function pinsFor(uint256 _chainId) external pure returns (Pins memory _pins) {
    _pins = _pinsFor(_chainId);
  }
}
