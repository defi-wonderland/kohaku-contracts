// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {IDeployIdentity} from 'script/IDeployIdentity.sol';
import {DeployIdentityForkTestBase} from 'test/utils/DeployIdentityForkTestBase.sol';

/// @notice The second and third assertions against zkPassport's live contracts, over a set of eight words: the
///         deployment's own, or a set the method's Safe proposes to install with setTrustedKeys. The words are a
///         reviewed snapshot of zkPassport's route and roles, and the zkPassport method trusts that route between
///         reviews, so a set that disagrees with the chain must be caught before it is deployed or installed. Each bad
///         set changes one word of a good set. The good set takes the table's words and the three role words the test
///         reads from the live contracts; the property under test is that the script compares, not what the live values
///         are. The local suite proves the same comparisons and every malformed read against mocks; this one proves
///         them against the real contracts. Each test skips cleanly when its endpoint is unset.
contract DeployIdentityCheckZkPassportKeysForkTest is DeployIdentityForkTestBase {
  /// checkZkPassportKeys passes on a mainnet fork for mainnet's table words and the live role words.
  function test_WhenMainnetsWordsMatchTheLiveContracts() external {
    if (!_forkMainnet()) return;
    // it should pass
    _script.checkZkPassportKeys(_goodWords());
  }

  /// checkZkPassportKeys passes on a Sepolia fork for Sepolia's table words and the live role words.
  function test_WhenSepoliasWordsMatchTheLiveContracts() external {
    if (!_forkSepolia()) return;
    // it should pass
    _script.checkZkPassportKeys(_goodWords());
  }

  /// checkZkPassportKeys reverts with the component mismatch when word three names another sub-verifier than the
  /// one the live root routes the accepted version to, carrying the word and the live route. The word here is the
  /// root verifier itself, a contract with code and an admin.
  function test_RevertWhen_TheSubVerifierWordDiffersFromTheLiveRoute() external {
    if (!_forkSepolia()) return;
    // it should revert
    // it should carry the word and the live sub-verifier
    _expectMismatch(
      2, _ROOT_VERIFIER, IDeployIdentity.DeployIdentity_ComponentMismatch.selector, 'subVerifier', _SEPOLIA_SUB_VERIFIER
    );
  }

  /// checkZkPassportKeys reverts with the component mismatch when word four names another verifier helper than the
  /// one the live root names for the accepted version, carrying the word and the live verifier helper.
  function test_RevertWhen_TheVerifierHelperWordDiffersFromTheLiveRoute() external {
    if (!_forkSepolia()) return;
    address _other = _freshAddress('otherVerifierHelper', 0);
    // it should revert
    // it should carry the word and the live verifier helper
    _expectMismatch(
      3, _other, IDeployIdentity.DeployIdentity_ComponentMismatch.selector, 'verifierHelper', _SEPOLIA_VERIFIER_HELPER
    );
  }

  /// checkZkPassportKeys reverts with the component mismatch when word five names another registry than the live
  /// root's, carrying the word and the live registry.
  function test_RevertWhen_TheRegistryWordDiffersFromTheLiveRoot() external {
    if (!_forkSepolia()) return;
    address _other = _freshAddress('otherRegistry', 0);
    // it should revert
    // it should carry the word and the live registry
    _expectMismatch(
      4, _other, IDeployIdentity.DeployIdentity_ComponentMismatch.selector, 'rootRegistry', _ROOT_REGISTRY
    );
  }

  /// checkZkPassportKeys reverts with the role mismatch when word six names another root admin than the live
  /// root's, carrying the word and the live admin.
  function test_RevertWhen_TheRootAdminWordDiffersFromTheLiveAdmin() external {
    if (!_forkSepolia()) return;
    address _other = _freshAddress('otherRootAdmin', 0);
    address _live = _liveInputs(_script.pinsFor(block.chainid)).rootAdmin;
    // it should revert
    // it should carry the word and the live root admin
    _expectMismatch(5, _other, IDeployIdentity.DeployIdentity_RoleMismatch.selector, 'rootAdmin', _live);
  }

  /// checkZkPassportKeys reverts with the role mismatch when word seven names another root guardian than the live
  /// root's, carrying the word and the live root guardian.
  function test_RevertWhen_TheRootGuardianWordDiffersFromTheLiveRootGuardian() external {
    if (!_forkSepolia()) return;
    address _other = _freshAddress('otherRootGuardian', 0);
    address _live = _liveInputs(_script.pinsFor(block.chainid)).rootGuardian;
    // it should revert
    // it should carry the word and the live root guardian
    _expectMismatch(6, _other, IDeployIdentity.DeployIdentity_RoleMismatch.selector, 'rootGuardian', _live);
  }

  /// checkZkPassportKeys reverts with the role mismatch when word eight names another sub-verifier admin than the
  /// live sub-verifier's, carrying the word and the live admin.
  function test_RevertWhen_TheSubVerifierAdminWordDiffersFromTheLiveAdmin() external {
    if (!_forkSepolia()) return;
    address _other = _freshAddress('otherSubVerifierAdmin', 0);
    address _live = _liveInputs(_script.pinsFor(block.chainid)).subVerifierAdmin;
    // it should revert
    // it should carry the word and the live sub-verifier admin
    _expectMismatch(7, _other, IDeployIdentity.DeployIdentity_RoleMismatch.selector, 'subVerifierAdmin', _live);
  }

  /// @notice The forked chain's table words with the live role words.
  function _goodWords() internal view returns (bytes32[] memory _keys) {
    IDeployIdentity.Pins memory _table = _script.pinsFor(block.chainid);
    _keys = _words(_table, _liveInputs(_table));
  }

  /// @notice Replaces word `_index` of a good set with `_replacement` and expects checkZkPassportKeys to revert
  ///         with `_selector`, `_name`, the replacement as the expected value and `_actual` as the live one.
  function _expectMismatch(uint256 _index, address _replacement, bytes4 _selector, string memory _name, address _actual)
    internal
  {
    bytes32[] memory _keys = _goodWords();
    _keys[_index] = _word(_replacement);
    try _script.checkZkPassportKeys(_keys) {
      fail('checkZkPassportKeys did not revert');
    } catch (bytes memory _reason) {
      _assertNamedMismatch(_reason, _selector, _name, _replacement, _actual);
    }
  }
}
