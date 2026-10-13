// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {IDeploy} from 'script/IDeploy.sol';
import {DeployTestBase} from 'test/utils/DeployTestBase.sol';

/// @notice The per-chain table the script reads every pin from. Mainnet and Sepolia pin the
///         AmbireAccount implementation the factory builds every Kohaku account on, and any other
///         chain has no entry, so the script never deploys an action serving an unknown account.
contract DeployPinsForTest is DeployTestBase {
  /// pinsFor(1) pins the AmbireAccount implementation 0x0F2AA7bcda3d9D210dF69a394b6965CB2566c828 and
  /// its codehash. An action deployed with another address refuses every account the factory builds,
  /// and the codehash lets the deployment tell the real implementation from any other code.
  function test_WhenTheChainIsMainnet() external view {
    // it should pin the AmbireAccount implementation and its codehash
    IDeploy.Pins memory _chainPins = _script.pinsFor(_MAINNET_CHAIN_ID);
    assertEq(_chainPins.ambireImplementation, _PINNED_IMPLEMENTATION, 'implementation');
    assertEq(_chainPins.ambireImplementationCodehash, _PINNED_CODEHASH, 'codehash');
  }

  /// pinsFor(11155111) pins the same implementation and codehash, since Ambire deployed the same code
  /// at the same address on Sepolia, so the demo path there serves the same accounts as on mainnet.
  function test_WhenTheChainIsSepolia() external view {
    // it should pin the AmbireAccount implementation and its codehash
    IDeploy.Pins memory _chainPins = _script.pinsFor(_SEPOLIA_CHAIN_ID);
    assertEq(_chainPins.ambireImplementation, _PINNED_IMPLEMENTATION, 'implementation');
    assertEq(_chainPins.ambireImplementationCodehash, _PINNED_CODEHASH, 'codehash');
  }

  /// pinsFor reverts naming the chain for any id other than 1 and 11155111. `_raw` is mapped onto
  /// every chain id except those two, by skipping them rather than filtering the run, so an
  /// operator on an unknown chain gets no deployment with a guessed pin.
  function test_RevertWhen_TheChainIsNotSupported(uint256 _raw) external {
    uint256 _chainId = bound(_raw, 0, type(uint256).max - 2);
    if (_chainId > _MAINNET_CHAIN_ID - 1) ++_chainId;
    if (_chainId > _SEPOLIA_CHAIN_ID - 1) ++_chainId;
    // it should revert
    // it should name the chain in the unsupported chain error
    vm.expectRevert(abi.encodeWithSelector(IDeploy.Deploy_UnsupportedChain.selector, _chainId));
    _script.pinsFor(_chainId);
  }

  /// pinsFor reverts for the ids right next to Sepolia's, the exact-equality boundary of the
  /// table's comparison, so a range check in place of an exact match fails here.
  function test_RevertWhen_TheChainIdNeighboursSepolia() external {
    // it should revert
    // it should name the chain in the unsupported chain error
    vm.expectRevert(abi.encodeWithSelector(IDeploy.Deploy_UnsupportedChain.selector, _SEPOLIA_CHAIN_ID - 1));
    _script.pinsFor(_SEPOLIA_CHAIN_ID - 1);
    vm.expectRevert(abi.encodeWithSelector(IDeploy.Deploy_UnsupportedChain.selector, _SEPOLIA_CHAIN_ID + 1));
    _script.pinsFor(_SEPOLIA_CHAIN_ID + 1);
  }

  /// pinsFor reverts for chain id 0 and chain id 2, the ids on each side of mainnet's.
  /// A table that treated an unset id as mainnet would deploy with mainnet's pin anywhere.
  function test_RevertWhen_TheChainIdNeighboursMainnet() external {
    // it should revert
    // it should name the chain in the unsupported chain error
    vm.expectRevert(abi.encodeWithSelector(IDeploy.Deploy_UnsupportedChain.selector, uint256(0)));
    _script.pinsFor(0);
    vm.expectRevert(abi.encodeWithSelector(IDeploy.Deploy_UnsupportedChain.selector, uint256(2)));
    _script.pinsFor(2);
  }
}
