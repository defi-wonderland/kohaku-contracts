// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {IDeploy} from 'script/IDeploy.sol';
import {IActionAmbireFactory} from 'test/utils/ActionAmbireForkAbi.sol';
import {ActionAmbireProxy} from 'test/utils/ActionAmbireProxy.sol';
import {DeployForkTestBase} from 'test/utils/DeployForkTestBase.sol';

/// @notice Runs deploy with the table's own pins on a fork of mainnet and of Sepolia, against the
///         Ambire implementation and factory deployed there and the chain's own P256VERIFY. Every
///         assertion must pass, and the deployed action must accept an account the real factory
///         builds on the pinned implementation, so a wrong pin, a wrong codehash, a wrong account ABI
///         or a missing precompile breaks the test. Each test skips cleanly when its endpoint is unset.
contract DeployForkTest is DeployForkTestBase {
  /// @notice Ambire's account factory on both chains.
  address internal constant _AMBIRE_FACTORY = 0x26cE6745A633030A6faC5e64e41D21fb6246dc2d;
  /// @notice The privilege value the Kohaku extension writes for an account's signer key.
  bytes32 internal constant _SIGNER_VALUE = bytes32(uint256(2));

  /// @notice Deploys the kit with the pins the table gives the forked chain, then builds an account
  ///         through Ambire's factory on that pin and checks the action serves it.
  function _deployAndServeAnAccount() internal {
    IDeploy.Pins memory _chainPins = _script.pinsFor(block.chainid);
    IDeploy.Deployment memory _deployment = _script.deploy(_chainPins);
    assertEq(address(_deployment.action.MANAGER()), address(_deployment.manager), 'manager');
    assertEq(_deployment.action.AMBIRE_IMPLEMENTATION(), _chainPins.ambireImplementation, 'implementation');

    address _signer = makeAddr('deployForkSigner');
    bytes memory _creation = ActionAmbireProxy.creationCode(_chainPins.ambireImplementation, _signer, _SIGNER_VALUE);
    address _account = IActionAmbireFactory(_AMBIRE_FACTORY).deploy(_creation, 0);
    assertTrue(_deployment.action.supportsAccount(_account), 'the action serves a factory-built account');
    assertTrue(_deployment.action.isAuthority(_account, _signer), 'the action reads the account signer key');
  }

  /// On a mainnet fork, deploy with mainnet's pins passes every assertion and returns an action
  /// that serves an account Ambire's factory builds there, the account a holder actually has.
  function test_WhenTheKitIsDeployedOnAMainnetFork() external {
    if (!_forkMainnet()) return;
    // it should pass every assertion and serve a factory-built account
    _deployAndServeAnAccount();
  }

  /// On a Sepolia fork, deploy with Sepolia's pins passes every assertion and returns an action
  /// that serves an account Ambire's factory builds there.
  function test_WhenTheKitIsDeployedOnASepoliaFork() external {
    if (!_forkSepolia()) return;
    // it should pass every assertion and serve a factory-built account
    _deployAndServeAnAccount();
  }
}
