// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {DeployTestBase} from 'test/utils/DeployTestBase.sol';

/// @notice The probe asks the node the script runs against, not forge's own EVM, whose precompiles
///         follow the local configuration. Without a node there is no chain to deploy to, so the
///         probe stops the script. The probe's answer on real chains is tested on forks.
contract DeployCheckP256VerifyTest is DeployTestBase {
  /// checkP256Verify reverts when no fork is active, since it has no node to ask. A probe that
  /// fell back to forge's local precompile would pass here and prove nothing about the chain.
  function test_RevertWhen_NoForkIsActive() external {
    // it should revert
    vm.expectRevert();
    _script.checkP256Verify();
  }
}
