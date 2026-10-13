// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {ActionSilentAccountMock} from 'test/mocks/ActionAmbireAccountMock.sol';
import {ActionTestBase} from 'test/utils/ActionTestBase.sol';

/// @notice The view `holdsAnyPrivilege` over Ambire's privilege table. The action refuses to install
///         a new key over any nonzero entry, and the request builder pre-checks exactly that through
///         this view, so it must be true for every nonzero entry and false for zero.
contract AmbireRecoveryActionHoldsAnyPrivilegeTest is ActionTestBase {
  address internal _key;

  function setUp() public override {
    super.setUp();
    _key = makeAddr('key');
  }

  /// @notice Writes `_value` for the test key and returns what `holdsAnyPrivilege` answers for it.
  function _holdsAnyWith(bytes32 _value) internal returns (bool _reserved) {
    _account.setPrivilege(_key, _value);
    _reserved = _action.holdsAnyPrivilege(address(_account), _key);
  }

  /// @notice An address never written, or written to zero, holds no privilege, so the builder may
  ///         install it as the new key.
  function test_WhenTheEntryIsZero() external {
    // it should return false
    assertFalse(_action.holdsAnyPrivilege(address(_account), _key), 'never written');
    assertFalse(_holdsAnyWith(bytes32(0)), 'written as zero');
  }

  /// @notice Keys, markers and bindings all count as a privilege, because the action refuses to
  ///         install a key over any of them.
  function test_WhenTheEntryIsNonzero() external {
    // it should return true
    assertTrue(_holdsAnyWith(bytes32(uint256(1))));
    assertTrue(_holdsAnyWith(bytes32(uint256(2))));
    assertTrue(_holdsAnyWith(bytes32(uint256(3))));
    assertTrue(_holdsAnyWith(_ENTRY_POINT_MARKER));
    assertTrue(_holdsAnyWith(_expectedBinding(address(_action))));
    assertTrue(_holdsAnyWith(bytes32(bytes1(0x01))));
    assertTrue(_holdsAnyWith(bytes32(type(uint256).max)));
  }

  /// @notice Any nonzero entry counts. `_candidate` is any address and `_raw` is bounded to 1
  ///         through the largest word.
  function testFuzz_WhenTheEntryIsNonzero(address _candidate, uint256 _raw) external {
    _account.setPrivilege(_candidate, bytes32(bound(_raw, 1, type(uint256).max)));
    // it should return true
    assertTrue(_action.holdsAnyPrivilege(address(_account), _candidate));
  }

  /// @notice An address with no code has no privilege getter to read, so the view reverts rather
  ///         than report a free slot on an account that does not exist.
  function test_RevertWhen_TheAccountHasNoCode() external {
    // it should revert
    vm.expectRevert();
    _action.holdsAnyPrivilege(makeAddr('emptyAccount'), _key);
  }

  /// @notice A contract that accepts the getter call and returns nothing gives no word to read, so
  ///         the view reverts rather than read the silence as a free slot.
  function test_RevertWhen_TheAccountReturnsNothing() external {
    address _silent = address(new ActionSilentAccountMock());
    // it should revert
    vm.expectRevert();
    _action.holdsAnyPrivilege(_silent, _key);
  }
}
