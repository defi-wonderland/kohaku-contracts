// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {IDeploy} from 'script/IDeploy.sol';
import {DeployTestBase} from 'test/utils/DeployTestBase.sol';

/// @notice confirm and confirmLabel, the operator's second step, before they touch the chain or the
///         candidate. Both look up this chain's pins first, so on a chain the table does not list they
///         stop with the unsupported chain error, and the label rule comes next. None of these tests
///         needs a fork, since both checks run before the P256VERIFY probe, and each label is one no
///         other test uses.
contract DeployConfirmTest is DeployTestBase {
  /// @notice A valid label no other test uses.
  string internal constant _LABEL = 'test-confirm-unsupported-chain';

  function _publishedPath(string memory _label) internal pure returns (string memory _path) {
    _path = string.concat('script/deployments/', _label, '.json');
  }

  /// confirm() on the local test chain, id 31337, reverts naming the chain and publishes no record
  /// under the chain's default name. A record published for a chain the kit was never reviewed on
  /// would send SDK clients to contracts nobody checked. The chain check runs before the label is
  /// read, so this test reads no environment variable.
  function test_RevertWhen_ConfirmRunsOnTheLocalTestChain() external {
    uint256 _chainId = block.chainid;
    bytes memory _reason;
    try _script.confirm() {
      fail('confirm did not revert');
    } catch (bytes memory _caught) {
      _reason = _caught;
    }
    // it should revert
    // it should name the chain in the unsupported chain error
    assertEq(_reason, abi.encodeWithSelector(IDeploy.Deploy_UnsupportedChain.selector, _chainId), 'revert data');
    // it should publish no record
    assertFalse(vm.exists(_publishedPath(vm.toString(_chainId))), 'published record');
  }

  /// confirmLabel reverts naming the chain on any chain id other than 1 and 11155111, and publishes
  /// nothing. No candidate exists under the label, so a confirm that read the candidate before the
  /// chain check would fail with forge's file error instead. `_raw` is mapped onto the chain ids the
  /// test chain accepts, skipping those two rather than filtering the run.
  function test_RevertWhen_ConfirmLabelRunsOnAnUnsupportedChain(uint256 _raw) external {
    uint256 _chainId = bound(_raw, 0, type(uint64).max - 3);
    if (_chainId > _MAINNET_CHAIN_ID - 1) ++_chainId;
    if (_chainId > _SEPOLIA_CHAIN_ID - 1) ++_chainId;
    vm.chainId(_chainId);
    bytes memory _reason;
    try _script.confirmLabel(_LABEL) {
      fail('confirmLabel did not revert');
    } catch (bytes memory _caught) {
      _reason = _caught;
    }
    bool _published = vm.exists(_publishedPath(_LABEL));
    if (_published) vm.removeFile(_publishedPath(_LABEL));
    // it should revert
    // it should name the chain in the unsupported chain error
    assertEq(_reason, abi.encodeWithSelector(IDeploy.Deploy_UnsupportedChain.selector, _chainId), 'revert data');
    // it should publish no record
    assertFalse(_published, 'published record');
  }

  /// confirmLabel reports the unsupported chain, not the invalid label, when both are wrong, since
  /// the chain's pins are looked up before the label rule. The label holds digits only.
  function test_RevertWhen_TheChainIsUnsupportedAndTheLabelIsInvalid() external {
    // it should revert
    // it should raise the unsupported chain error first
    vm.expectRevert(abi.encodeWithSelector(IDeploy.Deploy_UnsupportedChain.selector, block.chainid));
    _script.confirmLabel('12345');
  }

  /// confirmLabel on mainnet's chain id with a label of digits only reverts with the invalid label
  /// error before the P256VERIFY probe, which with no fork would fail with forge's own error. A
  /// label the rule refuses must stop confirm before it reads or writes any file.
  function test_RevertWhen_TheChainIsSupportedAndTheLabelIsInvalid() external {
    vm.chainId(_MAINNET_CHAIN_ID);
    // it should revert
    // it should raise the invalid label error before the probe
    vm.expectRevert(abi.encodeWithSelector(IDeploy.Deploy_InvalidLabel.selector, '12345'));
    _script.confirmLabel('12345');
  }
}
