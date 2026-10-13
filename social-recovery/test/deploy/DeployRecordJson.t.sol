// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {DeployTestBase} from 'test/utils/DeployTestBase.sol';

/// @notice The deployment record the SDK and the screens read to find the kit's addresses. A wrong
///         or missing value sends every client to the wrong contract, so the record must hold
///         exactly the deployment's addresses, the pin and the chain it was written for.
contract DeployRecordJsonTest is DeployTestBase {
  /// recordJson for a deployment on Sepolia holds the chain id, the four deployed addresses and the
  /// pinned implementation and codehash, each under its own key, read back with vm.parseJson.
  function test_WhenADeploymentIsRecorded() external {
    string memory _json = _script.recordJson(_good, _pins, _SEPOLIA_CHAIN_ID);
    // it should hold the chain id
    assertEq(vm.parseJsonUint(_json, '.chainId'), _SEPOLIA_CHAIN_ID, 'chainId');
    // it should hold the four deployed addresses
    assertEq(vm.parseJsonAddress(_json, '.policyManager'), address(_good.manager), 'policyManager');
    assertEq(vm.parseJsonAddress(_json, '.ecdsaMethod'), address(_good.ecdsaMethod), 'ecdsaMethod');
    assertEq(vm.parseJsonAddress(_json, '.passkeyMethod'), address(_good.passkeyMethod), 'passkeyMethod');
    assertEq(vm.parseJsonAddress(_json, '.recoveryAction'), address(_good.action), 'recoveryAction');
    // it should hold the pinned implementation and its codehash
    assertEq(vm.parseJsonAddress(_json, '.ambireImplementation'), _implementation, 'ambireImplementation');
    assertEq(
      vm.parseJsonBytes32(_json, '.ambireImplementationCodehash'),
      _pins.ambireImplementationCodehash,
      'ambireImplementationCodehash'
    );
    // it should hold no other key
    assertEq(vm.parseJsonKeys(_json, '$').length, 7, 'key count');
  }

  /// recordJson writes the chain id it is given, so a record names the chain it describes.
  /// `_raw` is bounded to the 64-bit chain ids a chain can carry.
  function test_WhenAnyChainIdIsRecorded(uint256 _raw) external {
    uint256 _chainId = bound(_raw, 0, type(uint64).max);
    string memory _json = _script.recordJson(_good, _pins, _chainId);
    // it should hold that chain id
    assertEq(vm.parseJsonUint(_json, '.chainId'), _chainId);
  }
}
