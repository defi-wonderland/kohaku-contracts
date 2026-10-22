// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {IPolicyMethodAdmin} from 'interfaces/IPolicyMethodAdmin.sol';
import {AadhaarMethod} from 'contracts/methods/aadhaar/AadhaarMethod.sol';
import {IAadhaarMethod} from 'contracts/methods/aadhaar/IAadhaarMethod.sol';
import {MethodAadhaarTestBase} from 'test/utils/MethodAadhaarTestBase.sol';

/// @notice The Aadhaar method's own trusted-key rule. The method trusts exactly one nonzero word, the hash of the
///         issuer's public key. The constructor and setTrustedKeys both apply the rule to a list of words, with the
///         same errors: a list of any length but one reverts with its length, and a zero word reverts with its
///         position.
contract AadhaarMethodValidateTrustedKeysTest is MethodAadhaarTestBase {
  /// Any nonzero key deploys and becomes the one trusted word. A holder can rely on the key the method reports.
  /// The fuzz input `_seed` is bounded to a nonzero word and used as the key.
  function test_WhenTheConstructorGetsOneNonzeroWord(uint256 _seed) external {
    bytes32 _key = bytes32(bound(_seed, 1, type(uint256).max));
    AadhaarMethod _deployed = _aadhaarDeploy(_owner, _admin, _aadhaarOneKey(_key), address(_verifier));
    // it should store it as the one trusted word.
    (,, bytes32[] memory _keys,,) = _deployed.trustedParties();
    assertEq(_keys.length, 1, 'one word');
    assertEq(_keys[0], _key, 'the issuer key');
  }

  /// A zero key reverts the deployment and names position zero. No real proof carries a zero issuer hash. A method
  /// trusting it would never accept a guardian's proof.
  function test_RevertWhen_TheConstructorGetsAZeroWord() external {
    // it should revert.
    // it should carry AadhaarMethod_ZeroTrustedKey of index zero.
    vm.expectRevert(abi.encodeWithSelector(IAadhaarMethod.AadhaarMethod_ZeroTrustedKey.selector, uint256(0)));
    _aadhaarDeploy(_owner, _admin, _aadhaarOneKey(bytes32(0)), address(_verifier));
  }

  /// An empty initial list reverts the deployment with the length zero. A method deployed with no issuer key would
  /// accept no guardian's proof until the key admin acted.
  function test_RevertWhen_TheConstructorGetsAnEmptyList() external {
    // it should revert.
    // it should carry AadhaarMethod_InvalidTrustedKeysLength of zero.
    vm.expectRevert(abi.encodeWithSelector(IAadhaarMethod.AadhaarMethod_InvalidTrustedKeysLength.selector, uint256(0)));
    _aadhaarDeploy(_owner, _admin, new bytes32[](0), address(_verifier));
  }

  /// Two nonzero initial words revert the deployment with the length two. The method checks proofs against one
  /// issuer key, so a second word would be trusted on paper and never used.
  function test_RevertWhen_TheConstructorGetsTwoWords() external {
    bytes32[] memory _keys = new bytes32[](2);
    _keys[0] = bytes32(uint256(0xb0b));
    _keys[1] = bytes32(uint256(0xc0c));
    // it should revert.
    // it should carry AadhaarMethod_InvalidTrustedKeysLength of two.
    vm.expectRevert(abi.encodeWithSelector(IAadhaarMethod.AadhaarMethod_InvalidTrustedKeysLength.selector, uint256(2)));
    _aadhaarDeploy(_owner, _admin, _keys, address(_verifier));
  }

  /// Any initial list of two to 255 nonzero words reverts the deployment with its length. The fuzz input `_length`
  /// is bounded to that range, because the empty list has its own test. Word `i` of the list is `i + 1`.
  function test_RevertWhen_TheConstructorGetsAnyLengthButOne(uint256 _length) external {
    _length = bound(_length, 2, 255);
    bytes32[] memory _keys = new bytes32[](_length);
    for (uint256 _i; _i < _keys.length; ++_i) {
      _keys[_i] = bytes32(_i + 1);
    }
    // it should revert.
    // it should carry AadhaarMethod_InvalidTrustedKeysLength of that length.
    vm.expectRevert(abi.encodeWithSelector(IAadhaarMethod.AadhaarMethod_InvalidTrustedKeysLength.selector, _length));
    _aadhaarDeploy(_owner, _admin, _keys, address(_verifier));
  }

  /// The key admin can replace the key with any nonzero word, and an event announces the change. Holders who use
  /// the method can then be alerted. The fuzz input `_seed` is bounded to a nonzero word and used as the new key.
  function test_WhenTheKeyAdminSetsOneNonzeroWord(uint256 _seed) external {
    bytes32 _key = bytes32(bound(_seed, 1, type(uint256).max));
    bytes32[] memory _current = _aadhaarOneKey(_key);
    // it should emit TrustedKeysUpdated from the previous key to the new one.
    vm.expectEmit(address(_method));
    emit IPolicyMethodAdmin.TrustedKeysUpdated(_aadhaarOneKey(_issuerKey), _current);
    vm.prank(_admin);
    _method.setTrustedKeys(_current);
    // it should store the new key as the one trusted word.
    (,, bytes32[] memory _keys,,) = _method.trustedParties();
    assertEq(_keys.length, 1, 'one word');
    assertEq(_keys[0], _key, 'the new key');
  }

  /// Two key changes in a row both succeed, even when the second sets the same key again. An issuer changes its key
  /// more than once over a method's life. The rule must not depend on the key being replaced. `_firstSeed` and
  /// `_secondSeed` are bounded to nonzero words and used as the two keys.
  function test_WhenTheKeyAdminSetsOneNonzeroWordTwiceInARow(uint256 _firstSeed, uint256 _secondSeed) external {
    bytes32 _first = bytes32(bound(_firstSeed, 1, type(uint256).max));
    bytes32 _second = bytes32(bound(_secondSeed, 1, type(uint256).max));
    vm.startPrank(_admin);
    _method.setTrustedKeys(_aadhaarOneKey(_first));
    _method.setTrustedKeys(_aadhaarOneKey(_second));
    vm.stopPrank();
    // it should store the second key as the one trusted word.
    (,, bytes32[] memory _keys,,) = _method.trustedParties();
    assertEq(_keys.length, 1, 'one word');
    assertEq(_keys[0], _second, 'the second key');
  }

  /// An empty list reverts with its length and leaves the stored key in place. A mistake by the key admin cannot
  /// lock out every Aadhaar guardian.
  function test_RevertWhen_TheKeyAdminSetsAnEmptyList() external {
    // it should revert.
    // it should carry AadhaarMethod_InvalidTrustedKeysLength of zero.
    vm.expectRevert(abi.encodeWithSelector(IAadhaarMethod.AadhaarMethod_InvalidTrustedKeysLength.selector, uint256(0)));
    vm.prank(_admin);
    _method.setTrustedKeys(new bytes32[](0));
    // it should keep the previous key.
    _assertKeyUnchanged();
  }

  /// Two nonzero words revert with the length two and leave the stored key in place. Two is the nearest length above
  /// the one the method accepts.
  function test_RevertWhen_TheKeyAdminSetsTwoWords() external {
    bytes32[] memory _keys = new bytes32[](2);
    _keys[0] = bytes32(uint256(0xb0b));
    _keys[1] = bytes32(uint256(0xc0c));
    // it should revert.
    // it should carry AadhaarMethod_InvalidTrustedKeysLength of two.
    vm.expectRevert(abi.encodeWithSelector(IAadhaarMethod.AadhaarMethod_InvalidTrustedKeysLength.selector, uint256(2)));
    vm.prank(_admin);
    _method.setTrustedKeys(_keys);
    // it should keep the previous key.
    _assertKeyUnchanged();
  }

  /// Any list of two to 255 nonzero words reverts with its length and leaves the stored key in place. The fuzz input
  /// `_length` is bounded to that range, because the empty list has its own test. Word `i` of the list is `i + 1`.
  function test_RevertWhen_TheKeyAdminSetsAnyLengthButOne(uint256 _length) external {
    _length = bound(_length, 2, 255);
    bytes32[] memory _keys = new bytes32[](_length);
    for (uint256 _i; _i < _keys.length; ++_i) {
      _keys[_i] = bytes32(_i + 1);
    }
    // it should revert.
    // it should carry AadhaarMethod_InvalidTrustedKeysLength of that length.
    vm.expectRevert(abi.encodeWithSelector(IAadhaarMethod.AadhaarMethod_InvalidTrustedKeysLength.selector, _length));
    vm.prank(_admin);
    _method.setTrustedKeys(_keys);
    // it should keep the previous key.
    _assertKeyUnchanged();
  }

  /// One zero word reverts with position zero and leaves the stored key in place. The key admin cannot replace the
  /// issuer with a hash no real proof carries.
  function test_RevertWhen_TheKeyAdminSetsAZeroWord() external {
    // it should revert.
    // it should carry AadhaarMethod_ZeroTrustedKey of index zero.
    vm.expectRevert(abi.encodeWithSelector(IAadhaarMethod.AadhaarMethod_ZeroTrustedKey.selector, uint256(0)));
    vm.prank(_admin);
    _method.setTrustedKeys(_aadhaarOneKey(bytes32(0)));
    // it should keep the previous key.
    _assertKeyUnchanged();
  }

  /// @dev Asserts the method still trusts exactly the fixture's issuer key and nothing else.
  function _assertKeyUnchanged() internal view {
    (,, bytes32[] memory _keys,,) = _method.trustedParties();
    assertEq(_keys.length, 1, 'still one word');
    assertEq(_keys[0], _issuerKey, 'still the issuer key');
  }
}
