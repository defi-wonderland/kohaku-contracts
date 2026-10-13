// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {DeployTestBase} from 'test/utils/DeployTestBase.sol';

/// @notice deploy without a chain. Its first step is the P256VERIFY probe, which asks the node, so
///         with no fork active deploy stops before it creates anything. The deploy tests that need a
///         chain run on forks of mainnet and Sepolia.
contract DeployDeployTest is DeployTestBase {
  /// deploy reverts with no fork active and creates no contract first. Every account access is
  /// recorded, reverted ones included, so a contract created before the probe and then undone by
  /// the revert still counts. This shows the probe runs before any creation.
  function test_RevertWhen_NoForkIsActive() external {
    bool _reverted;
    vm.startStateDiffRecording();
    try _script.deploy(_pins) {
      _reverted = false;
    } catch {
      _reverted = true;
    }
    // it should revert
    assertTrue(_reverted, 'deploy did not revert');
    // it should create no contract
    assertEq(_creations(vm.stopAndReturnStateDiff()), 0, 'contracts created before the probe');
  }
}
