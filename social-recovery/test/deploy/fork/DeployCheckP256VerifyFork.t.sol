// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {DeployForkTestBase} from 'test/utils/DeployForkTestBase.sol';

/// @notice The probe against real nodes. checkP256Verify sends the frozen valid signature to
///         0x100 through the node's own eth_call, so it reads the chain's precompile rather than
///         forge's. Both chains the table supports have activated P256VERIFY, so the probe passes
///         on each. Each test skips cleanly when its endpoint is unset.
contract DeployCheckP256VerifyForkTest is DeployForkTestBase {
  /// checkP256Verify passes against a mainnet node, which verifies the frozen signature.
  function test_WhenTheProbeAsksAMainnetNode() external {
    if (!_forkMainnet()) return;
    // it should pass
    _script.checkP256Verify();
  }

  /// checkP256Verify passes against a Sepolia node, which verifies the frozen signature.
  function test_WhenTheProbeAsksASepoliaNode() external {
    if (!_forkSepolia()) return;
    // it should pass
    _script.checkP256Verify();
  }
}
