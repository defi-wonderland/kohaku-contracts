// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {BindingDigest} from 'libraries/BindingDigest.sol';
import {IPolicyManager} from 'interfaces/IPolicyManager.sol';

/// @notice Exposes the binding digest library's functions as external calls so tests can reach them. Every argument
///         arrives as calldata, the way the policy manager hands a request over, and the library accepts it whether
///         it declares its parameters calldata or memory.
contract BindingDigestHarness {
  /// @dev Returns `BindingDigest.DIGEST_VERSION`.
  function digestVersion() external pure returns (string memory _version) {
    _version = BindingDigest.DIGEST_VERSION;
  }

  /// @dev Calls `BindingDigest.domainSeparator`, which reads the chain id of the chain running the call.
  function domainSeparator(address _verifyingContract) external view returns (bytes32 _separator) {
    _separator = BindingDigest.domainSeparator(_verifyingContract);
  }

  /// @dev Calls `BindingDigest.approvalDigest` with a calldata request.
  function approvalDigest(bytes32 _separator, IPolicyManager.AttemptRequest calldata _request, uint256 _place)
    external
    pure
    returns (bytes32 _digest)
  {
    _digest = BindingDigest.approvalDigest(_separator, _request, _place);
  }

  /// @dev Calls `BindingDigest.cancelDigest` with a calldata request.
  function cancelDigest(bytes32 _separator, IPolicyManager.CancelRequest calldata _request, uint256 _place)
    external
    pure
    returns (bytes32 _digest)
  {
    _digest = BindingDigest.cancelDigest(_separator, _request, _place);
  }

  /// @dev Calls `BindingDigest.setupCommitment` with a calldata body.
  function setupCommitment(address _account, address _action, uint64 _nonce, bytes calldata _body)
    external
    pure
    returns (bytes32 _commitment)
  {
    _commitment = BindingDigest.setupCommitment(_account, _action, _nonce, _body);
  }

  /// @dev Calls `BindingDigest.credentialCommitment` with a calldata config.
  function credentialCommitment(address _method, bytes calldata _config, bytes32 _salt)
    external
    pure
    returns (bytes32 _commitment)
  {
    _commitment = BindingDigest.credentialCommitment(_method, _config, _salt);
  }
}
