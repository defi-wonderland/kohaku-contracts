// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {ActionForkBlocks} from 'test/utils/ActionForkBlocks.sol';
import {DeployHarness} from 'test/utils/DeployHarness.sol';
import {DeployTestBase} from 'test/utils/DeployTestBase.sol';

/// @notice Shared setup for the deployment tests that need a chain. The script asks the node for
///         the P256VERIFY answer, so deploy runs only on a fork. Each test forks first and then
///         creates the script on the forked chain, and skips cleanly when its endpoint is unset.
abstract contract DeployForkTestBase is DeployTestBase, ActionForkBlocks {
  /// @notice Forks `_envName`'s endpoint at `_block` and creates the script there. Returns false,
  ///         after marking the test skipped, when the endpoint is unset.
  function _fork(string memory _envName, uint256 _block) internal returns (bool _forked) {
    string memory _url = vm.envOr(_envName, string(''));
    if (bytes(_url).length == 0) {
      vm.skip(true);
      return false;
    }
    vm.createSelectFork(_url, _block);
    _script = new DeployHarness();
    _forked = true;
  }

  /// @notice Forks mainnet at the pinned block and creates the script there.
  function _forkMainnet() internal returns (bool _forked) {
    _forked = _fork('MAINNET_RPC_URL', _MAINNET_BLOCK);
  }

  /// @notice Forks Sepolia at the pinned block and creates the script there.
  function _forkSepolia() internal returns (bool _forked) {
    _forked = _fork('SEPOLIA_RPC_URL', _SEPOLIA_BLOCK);
  }
}
