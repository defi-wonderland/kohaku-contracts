// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {BindingDigestTestBase} from 'test/utils/BindingDigestTestBase.sol';

/// @notice Unit tests for the domain separator, `domainSeparator(_manager)`, and the digest version it hashes. The
///         separator is computed under the live chain id, so these tests move between chains with `vm.chainId`.
///         Tree: BindingDigestDomainSeparator.tree.
contract BindingDigestDomainSeparatorTest is BindingDigestTestBase {
  /*///////////////////////////////////////////////////////////////
                             TREE TESTS
  ///////////////////////////////////////////////////////////////*/

  /// The digest version is the string "1". Wallets sign it inside the domain, so a different value would make every
  /// gathered approval fail to verify.
  function test_WhenReadingTheDigestVersion() external view {
    // it should be the string one.
    assertEq(_harness.digestVersion(), '1', 'DIGEST_VERSION');
  }

  /// The separator changes with the chain id and with the manager's address, so an approval signed for one chain or
  /// one deployment can never be replayed on another.
  function test_WhenBuildingTheDomainSeparator() external {
    // it should differ between two chains.
    vm.chainId(1);
    bytes32 _onChainOne = _harness.domainSeparator(_MANAGER);
    vm.chainId(2);
    assertTrue(_harness.domainSeparator(_MANAGER) != _onChainOne, 'chain id ignored');
    // it should differ between two managers.
    vm.chainId(1);
    assertTrue(_harness.domainSeparator(address(0x7777)) != _onChainOne, 'manager ignored');
  }

  /// The separator follows the chain the call runs on: the same manager under two chain ids gives two separators. No
  /// caller can pass a chain id, so a separator kept from before a chain split cannot make an approval signed on one
  /// branch verify on the other.
  function test_WhenTheLiveChainChanges() external {
    vm.chainId(10);
    bytes32 _first = _harness.domainSeparator(_MANAGER);
    vm.chainId(8453);
    // it should follow the live chain id.
    assertTrue(_harness.domainSeparator(_MANAGER) != _first, 'separator did not follow the chain');
  }
}
