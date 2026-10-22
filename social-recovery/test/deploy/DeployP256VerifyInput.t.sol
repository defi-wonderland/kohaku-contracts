// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {DeployTestBase} from 'test/utils/DeployTestBase.sol';

/// @notice The input the probe sends to P256VERIFY: the signed hash, r and s of the valid row of
///         the frozen passkey proof vectors, then the x and y of the frozen passkey config vector,
///         each as one 32-byte word. A probe with any other input would test a signature nobody
///         froze, and a node would answer it with a refusal on a live chain.
contract DeployP256VerifyInputTest is DeployTestBase {
  /// p256VerifyInput is exactly signedHash, r, s, x and y read from the frozen vector rows, 160
  /// bytes in that order. The test reads the same rows, checking each row's id first.
  function test_WhenTheInputIsRead() external view {
    string memory _proof = vm.readFile('test/fixtures/kats/method-passkey-proof.json');
    string memory _config = vm.readFile('test/fixtures/kats/method-passkey-config.json');
    assertEq(vm.parseJsonString(_proof, '.vectors[0].id'), 'valid-extra-client-field', 'proof row');
    assertEq(vm.parseJsonString(_config, '.vectors[0].id'), 'recover-example', 'config row');
    bytes memory _expected = abi.encodePacked(
      vm.parseJsonBytes32(_proof, '.vectors[0].expected.signedHash'),
      vm.parseJsonBytes32(_proof, '.vectors[0].input.r'),
      vm.parseJsonBytes32(_proof, '.vectors[0].input.s'),
      vm.parseJsonUint(_config, '.vectors[0].input.x'),
      vm.parseJsonUint(_config, '.vectors[0].input.y')
    );
    bytes memory _input = _script.p256VerifyInput();
    // it should be one hundred sixty bytes
    assertEq(_input.length, 160, 'length');
    // it should be the signed hash, r, s, x and y of the frozen vectors
    assertEq(_input, _expected, 'input');
  }

  /// The local test chain runs Osaka and carries P256VERIFY, so the input the script builds
  /// verifies there: the precompile answers the word 1 for it.
  function test_WhenTheInputIsSentToTheLocalPrecompile() external view {
    (bool _success, bytes memory _answer) = address(0x100).staticcall(_script.p256VerifyInput());
    // it should be accepted by the precompile
    assertTrue(_success, 'call');
    assertEq(_answer, abi.encode(uint256(1)), 'answer');
  }
}
