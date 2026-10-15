// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {IPolicyMethod} from 'interfaces/IPolicyMethod.sol';
import {IDeployIdentity} from 'script/IDeployIdentity.sol';
import {DeployIdentityTestBase} from 'test/utils/DeployIdentityTestBase.sol';

/// @notice The identity deployment's record, which the SDK and the setup screens read to find the two methods and
///         to show who holds their roles and what they trust. A wrong or missing value sends every client to the
///         wrong method or shows a holder the wrong parties, so the record holds exactly the deployment, each
///         method's Safe, the eight words, the Aadhaar pins with the verifier's code hash and the chain it was
///         written for.
contract DeployIdentityRecordJsonTest is DeployIdentityTestBase {
  /// recordJson for a deployment on Sepolia holds the chain id, both method addresses, each method's Safe under its
  /// own key, which the inputs make two different addresses so a swap shows, the eight
  /// zkPassport words in order, the Aadhaar verifier, its code hash and the key, each under its own key, and no
  /// other key.
  function test_WhenASepoliaDeploymentIsRecorded() external {
    IDeployIdentity.Pins memory _table = _script.pinsFor(_SEPOLIA_CHAIN_ID);
    string memory _json = _script.recordJson(_good, _table, _inputs, _SEPOLIA_CHAIN_ID);
    // it should hold the chain id
    assertEq(vm.parseJsonUint(_json, '.chainId'), _SEPOLIA_CHAIN_ID, 'chainId');
    // it should hold both method addresses
    assertEq(vm.parseJsonAddress(_json, '.zkPassportMethod'), address(_good.zkPassportMethod), 'zkPassportMethod');
    assertEq(vm.parseJsonAddress(_json, '.aadhaarMethod'), address(_good.aadhaarMethod), 'aadhaarMethod');
    // it should hold each method's safe under its own key
    assertEq(vm.parseJsonAddress(_json, '.zkPassportMethodSafe'), _inputs.zkPassportMethodSafe, 'zkPassportMethodSafe');
    assertEq(vm.parseJsonAddress(_json, '.aadhaarMethodSafe'), _inputs.aadhaarMethodSafe, 'aadhaarMethodSafe');
    // it should hold the eight zkPassport words in order
    bytes32[] memory _recorded = vm.parseJsonBytes32Array(_json, '.zkPassportKeys');
    bytes32[] memory _expected = _words(_table, _inputs);
    assertEq(_recorded.length, _KEY_COUNT, 'word count');
    for (uint256 _i; _i < _KEY_COUNT; ++_i) {
      assertEq(_recorded[_i], _expected[_i], 'zkPassport word');
    }
    // it should hold the Aadhaar verifier, its code hash and the key
    assertEq(vm.parseJsonAddress(_json, '.aadhaarVerifier'), _SEPOLIA_AADHAAR_VERIFIER, 'aadhaarVerifier');
    assertEq(
      vm.parseJsonBytes32(_json, '.aadhaarVerifierCodehash'),
      _SEPOLIA_AADHAAR_VERIFIER_CODEHASH,
      'aadhaarVerifierCodehash'
    );
    assertEq(vm.parseJsonBytes32(_json, '.aadhaarKey'), _UIDAI_KEY, 'aadhaarKey');
    // it should hold no other key
    assertEq(vm.parseJsonKeys(_json, '$').length, 9, 'key count');
  }

  /// recordJson for a mainnet deployment, which ships no Aadhaar method, records the zero address for the
  /// Aadhaar method, its Safe and its verifier and the zero word for its code hash and key, so a client reads that
  /// no Aadhaar method exists. The inputs hold the zero Aadhaar Safe, as a mainnet run reads them.
  function test_WhenAMainnetDeploymentIsRecorded() external {
    IDeployIdentity.Deployment memory _deployment = _good;
    _deployment.aadhaarMethod = IPolicyMethod(address(0));
    IDeployIdentity.Inputs memory _operator = _inputs;
    _operator.aadhaarMethodSafe = address(0);
    string memory _json =
      _script.recordJson(_deployment, _script.pinsFor(_MAINNET_CHAIN_ID), _operator, _MAINNET_CHAIN_ID);
    // it should hold the zkPassport method's safe
    assertEq(
      vm.parseJsonAddress(_json, '.zkPassportMethodSafe'), _operator.zkPassportMethodSafe, 'zkPassportMethodSafe'
    );
    // it should record no Aadhaar method, safe, verifier, code hash or key
    assertEq(vm.parseJsonAddress(_json, '.aadhaarMethod'), address(0), 'aadhaarMethod');
    assertEq(vm.parseJsonAddress(_json, '.aadhaarMethodSafe'), address(0), 'aadhaarMethodSafe');
    assertEq(vm.parseJsonAddress(_json, '.aadhaarVerifier'), address(0), 'aadhaarVerifier');
    assertEq(vm.parseJsonBytes32(_json, '.aadhaarVerifierCodehash'), bytes32(0), 'aadhaarVerifierCodehash');
    assertEq(vm.parseJsonBytes32(_json, '.aadhaarKey'), bytes32(0), 'aadhaarKey');
    // it should hold the same nine keys
    assertEq(vm.parseJsonKeys(_json, '$').length, 9, 'key count');
  }

  /// recordJson writes the chain id it is given, so a record names the chain it describes. `_raw` is bounded to
  /// the 64-bit chain ids a chain can carry.
  function test_WhenAnyChainIdIsRecorded(uint256 _raw) external {
    uint256 _chainId = bound(_raw, 0, type(uint64).max);
    string memory _json = _script.recordJson(_good, _pins, _inputs, _chainId);
    // it should hold that chain id
    assertEq(vm.parseJsonUint(_json, '.chainId'), _chainId);
  }
}
