// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {BindingDigest} from 'libraries/BindingDigest.sol';
import {IPolicyManager} from 'interfaces/IPolicyManager.sol';

/// @notice Test helper. Calls the binding digest library with the request in calldata, the
///         way the manager's views receive it, so a test can compare the views with the library.
///         The library reads the chain id of the chain running the call, so every digest here is
///         under the live chain id, as the manager's are.
contract PolicyManagerDigestProbe {
  /*///////////////////////////////////////////////////////////////
                        EXTERNAL FUNCTIONS
  ///////////////////////////////////////////////////////////////*/

  /// @notice The library's approval digest under the live chain id and `_verifyingContract`.
  /// @param _verifyingContract The manager address the domain names.
  /// @param _request The approval request.
  /// @param _place The place the digest is for.
  /// @return _digest The approval digest.
  function approval(address _verifyingContract, IPolicyManager.AttemptRequest calldata _request, uint256 _place)
    external
    view
    returns (bytes32 _digest)
  {
    _digest = BindingDigest.approvalDigest(BindingDigest.domainSeparator(_verifyingContract), _request, _place);
  }

  /// @notice The library's cancellation digest under the live chain id and `_verifyingContract`.
  /// @param _verifyingContract The manager address the domain names.
  /// @param _request The cancellation request.
  /// @param _place The place the digest is for.
  /// @return _digest The cancellation digest.
  function cancellation(address _verifyingContract, IPolicyManager.CancelRequest calldata _request, uint256 _place)
    external
    view
    returns (bytes32 _digest)
  {
    _digest = BindingDigest.cancelDigest(BindingDigest.domainSeparator(_verifyingContract), _request, _place);
  }

  /// @notice The library's domain separator under the live chain id.
  /// @param _verifyingContract The manager address the domain names.
  /// @return _separator The domain separator.
  function separator(address _verifyingContract) external view returns (bytes32 _separator) {
    _separator = BindingDigest.domainSeparator(_verifyingContract);
  }

  /// @notice The library's domain name.
  /// @return _name The name.
  function domainName() external pure returns (string memory _name) {
    _name = BindingDigest.DOMAIN_NAME;
  }

  /// @notice The library's digest format version.
  /// @return _version The version.
  function digestVersion() external pure returns (string memory _version) {
    _version = BindingDigest.DIGEST_VERSION;
  }
}
