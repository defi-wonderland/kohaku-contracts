// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {BindingDigestMemberChanges} from 'test/utils/BindingDigestMemberChanges.sol';
import {BindingDigestTestBase} from 'test/utils/BindingDigestTestBase.sol';

/// @notice Unit tests for the credential commitment, `credentialCommitment(_method, _config, _salt)`, the hash a
///         setup body names at each place. Tree: BindingDigestCredentialCommitment.tree.
contract BindingDigestCredentialCommitmentTest is BindingDigestTestBase {
  /*///////////////////////////////////////////////////////////////
                             TREE TESTS
  ///////////////////////////////////////////////////////////////*/

  /// The credential commitment changes with the method, the config and the salt, so a proof naming another method,
  /// config or salt fails the credential check at its place.
  function test_WhenComputingTheCredentialCommitment() external view {
    address _method = address(0x3333333333333333333333333333333333333333);
    bytes memory _config = hex'1234';
    bytes32 _salt = bytes32(uint256(0xaa));
    bytes32 _commitment = _harness.credentialCommitment(_method, _config, _salt);

    // it should change with any one member.
    for (uint256 _which; _which < BindingDigestMemberChanges.CREDENTIAL_MEMBERS; ++_which) {
      (address _newMethod, bytes memory _newConfig, bytes32 _newSalt) =
        BindingDigestMemberChanges.changeCredential(_method, _config, _salt, _which, 1);
      assertTrue(
        _harness.credentialCommitment(_newMethod, _newConfig, _newSalt) != _commitment,
        string.concat('credential member ignored: ', vm.toString(_which))
      );
    }
  }
}
