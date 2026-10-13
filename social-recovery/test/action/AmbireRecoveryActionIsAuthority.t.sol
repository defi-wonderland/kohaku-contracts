// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {ActionSilentAccountMock} from 'test/mocks/ActionAmbireAccountMock.sol';
import {ActionTestBase} from 'test/utils/ActionTestBase.sol';

/// @notice The view `isAuthority` over Ambire's privilege table. In that table 1 and 2 mark a key,
///         zero marks nothing and every other value marks code the account trusts. The request
///         builder relies on it to name the key a handover removes, so it must be true for a key only.
contract AmbireRecoveryActionIsAuthorityTest is ActionTestBase {
  address internal _key;

  function setUp() public override {
    super.setUp();
    _key = makeAddr('key');
  }

  /// @notice Writes `_value` for the test key and returns what `isAuthority` answers for it.
  function _isAuthorityWith(bytes32 _value) internal returns (bool _holds) {
    _account.setPrivilege(_key, _value);
    _holds = _action.isAuthority(address(_account), _key);
  }

  /// @notice The value 1, the one the recovery writes for a new key, is a key.
  function test_WhenThePrivilegeIsOne() external {
    // it should return true
    assertTrue(_isAuthorityWith(bytes32(uint256(1))));
  }

  /// @notice The value 2, the one the Kohaku extension writes at account creation, is a key.
  function test_WhenThePrivilegeIsTwo() external {
    // it should return true
    assertTrue(_isAuthorityWith(bytes32(uint256(2))));
  }

  /// @notice An address never written, or written to zero, holds no key.
  function test_WhenThePrivilegeIsZero() external {
    // it should return false
    assertFalse(_action.isAuthority(address(_account), _key), 'never written');
    assertFalse(_isAuthorityWith(bytes32(0)), 'written as zero');
  }

  /// @notice The value 3, the first one past the key values, is not a key.
  function test_WhenThePrivilegeIsThree() external {
    // it should return false
    assertFalse(_isAuthorityWith(bytes32(uint256(3))));
  }

  /// @notice The entry point's marker is code the account trusts, never a key a handover may remove.
  function test_WhenThePrivilegeIsTheEntryPointMarker() external {
    // it should return false
    assertFalse(_isAuthorityWith(_ENTRY_POINT_MARKER));
  }

  /// @notice A validator binding, this action's own included, is code the account trusts rather
  ///         than a key, so a handover naming it is refused before it can switch recovery off.
  function test_WhenThePrivilegeIsAValidatorBinding() external {
    // it should return false
    assertFalse(_isAuthorityWith(_expectedBinding(address(_action))));
    assertFalse(_isAuthorityWith(keccak256(abi.encode(makeAddr('validator'), bytes('data')))));
  }

  /// @notice A 1 or 2 in the wrong byte of the word is not a key, so the view compares the whole
  ///         word rather than one byte of it.
  function test_WhenThePrivilegeHasAOneInTheHighByte() external {
    // it should return false
    assertFalse(_isAuthorityWith(bytes32(bytes1(0x01))));
    assertFalse(_isAuthorityWith(bytes32(bytes1(0x02))));
    assertFalse(_isAuthorityWith(bytes32(type(uint256).max)));
    assertFalse(_isAuthorityWith(bytes32((uint256(1) << 128) | 1)));
  }

  /// @notice Values that share the key values' low bits are still not keys.
  function test_WhenThePrivilegeIsAnyOtherValue() external {
    // it should return false
    assertFalse(_isAuthorityWith(bytes32(uint256(0x100))));
    assertFalse(_isAuthorityWith(bytes32(uint256(0x101))));
  }

  /// @notice No value from 3 up is a key. `_authority` is any address and `_raw` is bounded to 3
  ///         through the largest word.
  function testFuzz_WhenThePrivilegeIsAnyOtherValue(address _authority, uint256 _raw) external {
    _account.setPrivilege(_authority, bytes32(bound(_raw, 3, type(uint256).max)));
    // it should return false
    assertFalse(_action.isAuthority(address(_account), _authority));
  }

  /// @notice An address with no code has no privilege getter to read, so the view reverts rather
  ///         than answer for an account that does not exist.
  function test_RevertWhen_TheAccountHasNoCode() external {
    // it should revert
    vm.expectRevert();
    _action.isAuthority(makeAddr('emptyAccount'), _key);
  }

  /// @notice A contract that accepts the getter call and returns nothing gives no word to read, so
  ///         the view reverts rather than read the silence as an answer.
  function test_RevertWhen_TheAccountReturnsNothing() external {
    address _silent = address(new ActionSilentAccountMock());
    // it should revert
    vm.expectRevert();
    _action.isAuthority(_silent, _key);
  }
}
