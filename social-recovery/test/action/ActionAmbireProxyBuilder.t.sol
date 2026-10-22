// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {Test} from 'forge-std/Test.sol';
import {ActionAmbireProxy, ActionAmbireProxyDeployer} from 'test/utils/ActionAmbireProxy.sol';

/// @notice Checks the test suite's Solidity transcription of Ambire's proxy builder against bytes
///         the builder itself produced. The expected strings are the output of
///         `getProxyDeployBytecode` from kohaku-commons src/libs/proxyDeploy/deploy.ts at commit
///         29227cc, run unmodified with privSlot 0 as the extension's account builder passes it.
///         Every fit-check test builds its proxies with this transcription, so a drift here would
///         make those tests exercise bytes no Kohaku account carries.
contract ActionAmbireProxyBuilderTest is Test {
  address internal constant _PINNED = 0x0F2AA7bcda3d9D210dF69a394b6965CB2566c828;
  address internal constant _SHORT = 0x00Abcdef0123456789abcDef0123456789ABcDef;
  address internal constant _KEY_A = 0x1111111111111111111111111111111111111111;
  address internal constant _KEY_B = 0x2222222222222222222222222222222222222222;
  address internal constant _KEY_C = 0x3333333333333333333333333333333333333333;

  /// @notice The builder's output for `_PINNED` with `_KEY_A` at value 2.
  function _builtPinnedOneKey() internal pure returns (bytes memory _code) {
    _code = bytes.concat(
      hex'7f00000000000000000000000000000000000000000000000000000000000000027ff043c50fe795c69f30b8',
      hex'ff78b84032dc53a9d87ca283ae10a1dacfbb648e83ef553d602d80604d3d3981f3363d3d373d3d3d363d730f',
      hex'2aa7bcda3d9d210df69a394b6965cb2566c8285af43d82803e903d91602b57fd5bf3'
    );
  }

  /// @notice The builder's output for `_SHORT` with `_KEY_B` at value 1.
  function _builtShortOneKey() internal pure returns (bytes memory _code) {
    _code = bytes.concat(
      hex'7f00000000000000000000000000000000000000000000000000000000000000017f56136bdb02b44e818120',
      hex'154143c922d9485e19e5b7288e7176da184391d4457c553d602d80604d3d3981f3363d3d373d3d3d363d72ab',
      hex'cdef0123456789abcdef0123456789abcdef5af43d82803e903d91602b57fd5bf3'
    );
  }

  /// @notice The builder's output for `_PINNED` with `_KEY_A` at 2, `_KEY_B` at 1 and `_KEY_C` at 0x7171.
  function _builtPinnedThreeKeys() internal pure returns (bytes memory _code) {
    _code = bytes.concat(
      hex'7f00000000000000000000000000000000000000000000000000000000000000027ff043c50fe795c69f30b8',
      hex'ff78b84032dc53a9d87ca283ae10a1dacfbb648e83ef557f0000000000000000000000000000000000000000',
      hex'0000000000000000000000017f56136bdb02b44e818120154143c922d9485e19e5b7288e7176da184391d445',
      hex'7c557f00000000000000000000000000000000000000000000000000000000000071717f0ae1369e98a926a2',
      hex'595ace665f90c7976b6a86afbcadb3c1ceee24998c087435553d602d8060d33d3981f3363d3d373d3d3d363d',
      hex'730f2aa7bcda3d9d210df69a394b6965cb2566c8285af43d82803e903d91602b57fd5bf3'
    );
  }

  /// @notice The transcription reproduces the builder byte for byte for the shape every Kohaku
  ///         account is created with, one key over the pinned implementation.
  function test_WhenOneKeyIsWrittenOverThePinnedImplementation() external pure {
    // it should equal the builder's own output
    assertEq(ActionAmbireProxy.creationCode(_PINNED, _KEY_A, bytes32(uint256(2))), _builtPinnedOneKey());
  }

  /// @notice The transcription drops a leading zero byte of the implementation and pushes 19
  ///         bytes, as the builder does, so the fit check is shown to refuse the shortened proxy it emits.
  function test_WhenTheImplementationHasALeadingZeroByte() external pure {
    // it should equal the builder's own output
    assertEq(ActionAmbireProxy.creationCode(_SHORT, _KEY_B, bytes32(uint256(1))), _builtShortOneKey());
  }

  /// @notice The transcription handles the builder's maximum of three initial privileges, which
  ///         moves the runtime offset the creation code copies from.
  function test_WhenThreePrivilegesAreWritten() external pure {
    address[] memory _keys = new address[](3);
    bytes32[] memory _values = new bytes32[](3);
    (_keys[0], _keys[1], _keys[2]) = (_KEY_A, _KEY_B, _KEY_C);
    (_values[0], _values[1], _values[2]) = (bytes32(uint256(2)), bytes32(uint256(1)), bytes32(uint256(0x7171)));
    // it should equal the builder's own output
    assertEq(ActionAmbireProxy.creationCode(_PINNED, _keys, _values), _builtPinnedThreeKeys());
  }

  /// @notice Running the builder's own creation code leaves the runtime the transcription's
  ///         `runtime` renders and the key's value at the slot its `privilegeSlot` renders.
  function test_WhenTheBuildersCreationCodeRuns() external {
    address _proxy = new ActionAmbireProxyDeployer().deploy(_builtPinnedOneKey(), 0);
    // it should leave the runtime and the privileges the transcription names
    assertEq(_proxy.code, ActionAmbireProxy.runtime(_PINNED));
    assertEq(_proxy.code.length, 45);
    assertEq(vm.load(_proxy, ActionAmbireProxy.privilegeSlot(_KEY_A)), bytes32(uint256(2)));
  }

  /// @notice The builder's creation code always returns 45 bytes, so a proxy over a shortened
  ///         address is the 44-byte runtime followed by one zero byte.
  function test_WhenTheBuildersCreationCodeRunsForAShortenedAddress() external {
    address _proxy = new ActionAmbireProxyDeployer().deploy(_builtShortOneKey(), 0);
    // it should leave forty five bytes of runtime padded with zeros
    assertEq(_proxy.code, abi.encodePacked(ActionAmbireProxy.runtime(_SHORT), hex'00'));
    assertEq(vm.load(_proxy, ActionAmbireProxy.privilegeSlot(_KEY_B)), bytes32(uint256(1)));
  }
}
