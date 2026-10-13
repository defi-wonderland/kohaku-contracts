// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {IRecoveryAction} from 'interfaces/IRecoveryAction.sol';
import {ActionSilentAccountMock} from 'test/mocks/ActionAmbireAccountMock.sol';
import {ActionTestBase} from 'test/utils/ActionTestBase.sol';

/// @notice The view `isAuthorized`, which reads whether the account's entry under this action's kit
///         slot holds this action's binding, the value that routes the account's callback here. The
///         setup screen shows the holder this answer, so it must be true for that one entry and value.
contract AmbireRecoveryActionIsAuthorizedTest is ActionTestBase {
  /// @notice The kit slot of the action under test.
  function _kitSlot() internal view returns (address _slot) {
    _slot = _expectedKitSlot(address(_action));
  }

  /// @notice The account honors this action once the kit slot holds its binding.
  function test_WhenTheKitSlotHoldsThisActionsBinding() external {
    _account.setPrivilege(_kitSlot(), _expectedBinding(address(_action)));
    // it should return true
    assertTrue(_action.isAuthorized(address(_account)));
  }

  /// @notice Before the account authorizes the action, and after the holder zeroes the slot, it is not
  ///         authorized, which is what the setup screen shows the holder.
  function test_WhenTheKitSlotIsEmpty() external {
    // it should return false
    assertFalse(_action.isAuthorized(address(_account)));
    _account.setPrivilege(_kitSlot(), _expectedBinding(address(_action)));
    _account.setPrivilege(_kitSlot(), bytes32(0));
    assertFalse(_action.isAuthorized(address(_account)), 'no longer authorizes the action');
  }

  /// @notice A key value under the kit slot is not this action's binding, so it does not count.
  function test_WhenTheKitSlotHoldsAKeyValue() external {
    // it should return false
    _account.setPrivilege(_kitSlot(), bytes32(uint256(1)));
    assertFalse(_action.isAuthorized(address(_account)));
    _account.setPrivilege(_kitSlot(), bytes32(uint256(2)));
    assertFalse(_action.isAuthorized(address(_account)));
  }

  /// @notice Another action's binding, this action bound with nonempty data, or a packed preimage
  ///         under the kit slot would not route the account's callback to this action, so none
  ///         counts as authorized.
  function test_WhenTheKitSlotHoldsAnotherActionsBinding() external {
    // it should return false
    _account.setPrivilege(_kitSlot(), _expectedBinding(makeAddr('otherAction')));
    assertFalse(_action.isAuthorized(address(_account)));
    _account.setPrivilege(_kitSlot(), keccak256(abi.encode(address(_action), bytes('x'))));
    assertFalse(_action.isAuthorized(address(_account)), 'the action bound with nonempty data');
    _account.setPrivilege(_kitSlot(), keccak256(abi.encodePacked(address(_action))));
    assertFalse(_action.isAuthorized(address(_account)), 'a packed preimage');
  }

  /// @notice The binding under any address other than the kit slot does not count: the action's
  ///         own address, Ambire's getSignerKey slot, and slots hashed from a fixed bytes3 or a packed
  ///         "kit" preimage.
  function test_WhenTheBindingSitsUnderAnotherAddress() external {
    bytes32 _binding = _expectedBinding(address(_action));
    // it should return false
    _account.setPrivilege(address(_action), _binding);
    assertFalse(_action.isAuthorized(address(_account)), 'under the action address');
    _account.setPrivilege(_ambireSignerKeySlot(address(_action), bytes('')), _binding);
    assertFalse(_action.isAuthorized(address(_account)), 'under the Ambire getSignerKey slot');
    bytes3 _kitWord = 0x6b6974;
    _account.setPrivilege(address(uint160(uint256(keccak256(abi.encode(_kitWord, address(_action)))))), _binding);
    assertFalse(_action.isAuthorized(address(_account)), 'under a slot hashed from a fixed bytes3 literal');
    _account.setPrivilege(address(uint160(uint256(keccak256(abi.encodePacked('kit', address(_action)))))), _binding);
    assertFalse(_action.isAuthorized(address(_account)), 'under a slot hashed from a packed preimage');
  }

  /// @notice The same for any address. `_raw` is mapped onto a nonzero address other than the kit slot.
  function testFuzz_WhenTheBindingSitsUnderAnotherAddress(uint256 _raw) external {
    _account.setPrivilege(_addressOtherThan(_raw, _kitSlot()), _expectedBinding(address(_action)));
    // it should return false
    assertFalse(_action.isAuthorized(address(_account)));
  }

  /// @notice The entry point's marker, or the binding with one bit flipped, under the kit slot does
  ///         not count as authorized.
  function test_WhenTheKitSlotHoldsAnyOtherValue() external {
    // it should return false
    _account.setPrivilege(_kitSlot(), _ENTRY_POINT_MARKER);
    assertFalse(_action.isAuthorized(address(_account)));
    _account.setPrivilege(_kitSlot(), _expectedBinding(address(_action)) ^ bytes32(uint256(1)));
    assertFalse(_action.isAuthorized(address(_account)));
  }

  /// @notice Any value but the binding under the kit slot does not count. `_flip`, bounded to 1
  ///         through the largest word, is XORed into the binding, so the value always differs.
  function testFuzz_WhenTheKitSlotHoldsAnyOtherValue(uint256 _flip) external {
    bytes32 _value = _expectedBinding(address(_action)) ^ bytes32(bound(_flip, 1, type(uint256).max));
    _account.setPrivilege(_kitSlot(), _value);
    // it should return false
    assertFalse(_action.isAuthorized(address(_account)));
  }

  /// @notice Two kit actions on one account use two different slots, so authorizing or dropping one
  ///         never authorizes or drops the other.
  function test_WhenTwoActionsShareOneAccount() external {
    IRecoveryAction _second = _deployAction(_manager, _implementation);
    address _secondSlot = _expectedKitSlot(address(_second));
    assertTrue(_secondSlot != _kitSlot(), 'one slot per action');
    // it should read each action's own slot
    _account.setPrivilege(_kitSlot(), _expectedBinding(address(_action)));
    assertTrue(_action.isAuthorized(address(_account)));
    assertFalse(_second.isAuthorized(address(_account)));
    _account.setPrivilege(_secondSlot, _expectedBinding(address(_second)));
    assertTrue(_second.isAuthorized(address(_account)));
    _account.setPrivilege(_kitSlot(), bytes32(0));
    assertFalse(_action.isAuthorized(address(_account)));
    assertTrue(_second.isAuthorized(address(_account)));
  }

  /// @notice An address with no code has no privilege getter to read, so the view reverts rather
  ///         than answer for an account that does not exist.
  function test_RevertWhen_TheAccountHasNoCode() external {
    // it should revert
    vm.expectRevert();
    _action.isAuthorized(makeAddr('emptyAccount'));
  }

  /// @notice A contract that accepts the getter call and returns nothing gives no word to read, so
  ///         the view reverts rather than read the silence as an answer.
  function test_RevertWhen_TheAccountReturnsNothing() external {
    address _silent = address(new ActionSilentAccountMock());
    // it should revert
    vm.expectRevert();
    _action.isAuthorized(_silent);
  }
}
