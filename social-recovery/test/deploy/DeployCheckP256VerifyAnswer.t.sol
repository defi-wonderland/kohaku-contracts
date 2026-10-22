// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {IDeploy} from 'script/IDeploy.sol';
import {DeployTestBase} from 'test/utils/DeployTestBase.sol';

/// @notice How the probe reads the node's answer to the P256VERIFY call. The passkey method checks
///         every signature through the precompile at 0x100, and on a chain without it the call
///         succeeds with no bytes, which the method reads as a refusal. Only the exact word 1 says
///         the chain verified the frozen valid signature, so every other answer blocks the deployment.
contract DeployCheckP256VerifyAnswerTest is DeployTestBase {
  function _expectNotLive(bytes memory _answer) internal {
    vm.expectRevert(abi.encodeWithSelector(IDeploy.Deploy_P256VerifyNotLive.selector, _answer));
  }

  /// checkP256VerifyAnswer accepts the 32-byte word 1, the answer of a chain whose precompile
  /// verified the signature, so a live chain is never blocked.
  function test_WhenTheAnswerIsTheWordOne() external view {
    // it should pass
    _script.checkP256VerifyAnswer(abi.encode(uint256(1)));
  }

  /// checkP256VerifyAnswer reverts with the empty answer, the answer of a chain that has not
  /// activated the precompile.
  function test_RevertWhen_TheAnswerIsEmpty() external {
    // it should revert
    // it should carry the answer in the error
    _expectNotLive(bytes(''));
    _script.checkP256VerifyAnswer(bytes(''));
  }

  /// checkP256VerifyAnswer reverts with the word 0. A precompile that refuses the frozen valid
  /// signature would refuse a holder's passkey too.
  function test_RevertWhen_TheAnswerIsTheWordZero() external {
    bytes memory _answer = abi.encode(uint256(0));
    // it should revert
    // it should carry the answer in the error
    _expectNotLive(_answer);
    _script.checkP256VerifyAnswer(_answer);
  }

  /// checkP256VerifyAnswer reverts with any word above 1. `_raw` is bounded to 2 and above.
  /// A check reading any nonzero word as success would accept an answer that means nothing.
  function test_RevertWhen_TheAnswerIsAWordAboveOne(uint256 _raw) external {
    bytes memory _answer = abi.encode(bound(_raw, 2, type(uint256).max));
    // it should revert
    // it should carry the answer in the error
    _expectNotLive(_answer);
    _script.checkP256VerifyAnswer(_answer);
  }

  /// checkP256VerifyAnswer reverts with a 64-byte answer whose first word is 1. The precompile
  /// answers exactly one word, so a longer answer comes from something else.
  function test_RevertWhen_TheAnswerIsSixtyFourBytes() external {
    bytes memory _answer = abi.encode(uint256(1), uint256(1));
    // it should revert
    // it should carry the answer in the error
    _expectNotLive(_answer);
    _script.checkP256VerifyAnswer(_answer);
  }
}
