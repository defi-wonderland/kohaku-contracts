// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {IDeploy} from 'script/IDeploy.sol';
import {IAmbireRecoveryAction} from 'contracts/actions/ambire/IAmbireRecoveryAction.sol';
import {DeployMockAction} from 'test/mocks/DeployMockAction.sol';
import {DeployMockLookAlike} from 'test/mocks/DeployMockLookAlike.sol';
import {DeployMockRawAnswer} from 'test/mocks/DeployMockRawAnswer.sol';
import {DeployTestBase} from 'test/utils/DeployTestBase.sol';

/// @notice The third assertion: the action's KIT_SLOT differs from the slot Ambire's own helper
///         would derive for the action's binding, the low twenty bytes of
///         keccak256(abi.encode(action, bytes(""))). An Ambire tool that follows its helper reads
///         and writes a binding under that address, so a kit slot equal to it would put the kit's
///         one authorization entry within reach of code that never meant to touch it.
contract DeployCheckKitSlotTest is DeployTestBase {
  /// checkKitSlot passes for the kit's action, whose slot the kit derives from the string "kit"
  /// and the action's address rather than from the binding.
  function test_WhenTheKitSlotDiffersFromTheAmbireHelperSlot() external view {
    // it should pass
    _script.checkKitSlot(_good.action);
  }

  /// checkKitSlot passes for the kit's action deployed at any address. `_seed` is hashed into the
  /// address the action is deployed at, and both slots move with that address.
  function test_WhenTheActionSitsAtAnyAddress(uint256 _seed) external {
    address _where = _freshAddress('actionAt', _seed);
    deployCodeTo(
      'AmbireRecoveryAction.sol:AmbireRecoveryAction', abi.encode(address(_good.manager), _implementation), _where
    );
    // it should pass
    _script.checkKitSlot(IAmbireRecoveryAction(_where));
  }

  /// checkKitSlot reverts naming the action and its slot when KIT_SLOT equals the slot Ambire's
  /// helper derives for that action's own address. The mock action answers exactly that slot.
  function test_RevertWhen_TheKitSlotEqualsTheAmbireHelperSlot() external {
    DeployMockAction _action = new DeployMockAction(address(_good.manager), _implementation, true);
    address _ambireSlot = _ambireHelperSlot(address(_action));
    assertEq(_action.KIT_SLOT(), _ambireSlot, 'the mock collides');
    // it should revert
    // it should name the action and its kit slot
    vm.expectRevert(abi.encodeWithSelector(IDeploy.Deploy_KitSlotCollides.selector, address(_action), _ambireSlot));
    _script.checkKitSlot(IAmbireRecoveryAction(address(_action)));
  }

  /// checkKitSlot reverts for a colliding action at any address. `_seed` is hashed into the
  /// address the mock action is deployed at, so the check must derive the Ambire helper slot from the
  /// action it is given rather than from a fixed address.
  function test_RevertWhen_ACollidingActionSitsAtAnyAddress(uint256 _seed) external {
    address _where = _freshAddress('collidingActionAt', _seed);
    deployCodeTo(
      'DeployMockAction.sol:DeployMockAction', abi.encode(address(_good.manager), _implementation, true), _where
    );
    assertEq(DeployMockAction(_where).KIT_SLOT(), _ambireHelperSlot(_where), 'the mock collides');
    // it should revert
    // it should name the action and its kit slot
    vm.expectRevert(abi.encodeWithSelector(IDeploy.Deploy_KitSlotCollides.selector, _where, _ambireHelperSlot(_where)));
    _script.checkKitSlot(IAmbireRecoveryAction(_where));
  }

  /// checkKitSlot reverts naming recoveryAction and the address when the action's address holds the
  /// kit's manager, a contract with no KIT_SLOT view, as when a broadcast lands out of order. A
  /// failed read must name what was read where, not surface as a bare revert.
  function test_RevertWhen_TheActionAddressHoldsAContractWithoutKitSlot() external {
    address _manager = address(_good.manager);
    // it should revert
    // it should name recoveryAction and the address in the read failure
    vm.expectRevert(abi.encodeWithSelector(IDeploy.Deploy_ReadFailed.selector, 'recoveryAction', _manager));
    _script.checkKitSlot(IAmbireRecoveryAction(_manager));
  }

  /// checkKitSlot reverts with the read failure when the kit's good action, seen through a look-alike
  /// that passes every other call on to it, answers KIT_SLOT with no bytes, an answer that encodes
  /// no address, so an empty answer never reads as a zero slot that differs from Ambire's.
  function test_RevertWhen_TheKitSlotAnswerIsEmpty() external {
    DeployMockLookAlike _lookAlike = new DeployMockLookAlike(address(_good.action));
    _lookAlike.setAnswer(IAmbireRecoveryAction.KIT_SLOT.selector, '');
    // it should revert
    // it should name recoveryAction and the address in the read failure
    vm.expectRevert(abi.encodeWithSelector(IDeploy.Deploy_ReadFailed.selector, 'recoveryAction', address(_lookAlike)));
    _script.checkKitSlot(IAmbireRecoveryAction(address(_lookAlike)));
  }

  /// checkKitSlot reverts with the read failure when the action answers KIT_SLOT with a word whose
  /// upper twelve bytes are not all zero, so a dirty word is never cut down to an address and
  /// compared. `_word` is the fuzzed answer, its upper twelve bytes forced to a nonzero value.
  function test_RevertWhen_TheKitSlotAnswerHasBitsAboveAnAddress(uint256 _word) external {
    uint256 _upper = bound(_word >> 160, 1, type(uint96).max);
    bytes32 _answer = bytes32((_upper << 160) | (_word & type(uint160).max));
    address _action = address(new DeployMockRawAnswer(abi.encode(_answer)));
    // it should revert
    // it should name recoveryAction and the address in the read failure
    vm.expectRevert(abi.encodeWithSelector(IDeploy.Deploy_ReadFailed.selector, 'recoveryAction', _action));
    _script.checkKitSlot(IAmbireRecoveryAction(_action));
  }
}
