// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {IDeployIdentity} from 'script/IDeployIdentity.sol';
import {DeployIdentityTestBase} from 'test/utils/DeployIdentityTestBase.sol';

/// @notice The operator's entry point. It reads the table for the chain it runs on, so on a chain the table does
///         not list it deploys nothing and records nothing. These tests never run it on mainnet or Sepolia, so a
///         test run never overwrites a real deployment record.
contract DeployIdentityRunTest is DeployIdentityTestBase {
  /// run() on the local test chain, id 31337, reverts naming the chain, creates no contract and writes neither a
  /// candidate nor a published identity record. A run on a chain without a table must leave nothing an SDK
  /// could mistake for a deployment of the identity methods.
  function test_RevertWhen_TheChainIsTheLocalTestChain() external {
    uint256 _chainId = block.chainid;
    vm.startStateDiffRecording();
    try _script.run() {
      fail('run did not revert');
    } catch (bytes memory _reason) {
      // it should revert
      // it should name the chain in the unsupported chain error
      assertEq(_reason, abi.encodeWithSelector(IDeployIdentity.DeployIdentity_UnsupportedChain.selector, _chainId));
    }
    // it should create no contract
    assertEq(_creations(vm.stopAndReturnStateDiff()), 0, 'contracts created');
    // it should write no identity record
    string memory _base = string.concat('script/deployments/', vm.toString(_chainId), '.identity');
    assertFalse(vm.exists(string.concat(_base, '.json')), 'published record');
    assertFalse(vm.exists(string.concat(_base, '.pending.json')), 'candidate record');
  }

  /// run() reverts naming the chain on any chain id other than 1 and 11155111. `_raw` is mapped onto the chain
  /// ids the test chain accepts, skipping those two rather than filtering the run.
  function test_RevertWhen_TheChainIsNotSupported(uint256 _raw) external {
    uint256 _chainId = bound(_raw, 0, type(uint64).max - 3);
    if (_chainId > _MAINNET_CHAIN_ID - 1) ++_chainId;
    if (_chainId > _SEPOLIA_CHAIN_ID - 1) ++_chainId;
    vm.chainId(_chainId);
    // it should revert
    // it should name the chain in the unsupported chain error
    vm.expectRevert(abi.encodeWithSelector(IDeployIdentity.DeployIdentity_UnsupportedChain.selector, _chainId));
    _script.run();
  }
}
