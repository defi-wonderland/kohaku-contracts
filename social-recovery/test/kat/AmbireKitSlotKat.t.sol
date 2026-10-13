// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {IAmbireRecoveryAction} from 'contracts/actions/ambire/IAmbireRecoveryAction.sol';
import {ManagerKatBase} from 'test/kat/ManagerKatBase.sol';
import {ActionTestBase} from 'test/utils/ActionTestBase.sol';

/// @notice Replays the preimage fields of ambire-kit-slot.json against the action's own getters. The slot and the
///         authorization by the binding are replayed in AmbireRecoveryActionKat.t.sol; this file adds the bytes the
///         SDK hashes for each, and the action's BINDING getter, so a client that builds either preimage another way
///         fails here. Tree: AmbireKitSlotKat.tree.
contract AmbireKitSlotKatTest is ActionTestBase, ManagerKatBase {
  /// The action deployed at each row's address reports a KIT_SLOT that is the low twenty bytes of the row's slot
  /// hash, which is the keccak256 of the row's slot preimage, the abi.encode of the string "kit" and the action. It
  /// reports a BINDING equal to the row's binding, the keccak256 of the row's binding preimage, the abi.encode of the
  /// action and empty bytes. The SDK writes BINDING under KIT_SLOT at setup, so a drift arms an entry the account
  /// never honors for this action.
  function test_WhenReplayingTheKitSlotPreimagesThroughTheAction() external {
    // it should reproduce every expected preimage, hash, slot and binding.
    string memory _json = vm.readFile(_KIT_SLOT_FILE);
    uint256 _rows = _rowCount(_json);
    assertGt(_rows, 0, 'no kit slot vector');
    for (uint256 _i; _i < _rows; ++_i) {
      string memory _row = _rowPath(_i);
      string memory _id = _rowId(_json, _row);
      address _where = vm.parseJsonAddress(_json, string.concat(_row, '.input.action'));
      _deployActionAt(_where, _manager, _implementation);
      IAmbireRecoveryAction _deployed = IAmbireRecoveryAction(_where);

      string memory _kit = 'kit';
      bytes memory _slotPreimage = vm.parseJsonBytes(_json, string.concat(_row, '.expected.slotPreimage'));
      bytes32 _slotHash = vm.parseJsonBytes32(_json, string.concat(_row, '.expected.slotHash'));
      assertEq(abi.encode(_kit, _where), _slotPreimage, _what('slot preimage', _id));
      assertEq(keccak256(_slotPreimage), _slotHash, _what('slot hash', _id));
      assertEq(_deployed.KIT_SLOT(), address(uint160(uint256(_slotHash))), _what('KIT_SLOT from the slot hash', _id));
      assertEq(
        _deployed.KIT_SLOT(), vm.parseJsonAddress(_json, string.concat(_row, '.expected.slot')), _what('KIT_SLOT', _id)
      );

      bytes memory _bindingPreimage = vm.parseJsonBytes(_json, string.concat(_row, '.expected.bindingPreimage'));
      bytes32 _binding = vm.parseJsonBytes32(_json, string.concat(_row, '.expected.binding'));
      assertEq(abi.encode(_where, bytes('')), _bindingPreimage, _what('binding preimage', _id));
      assertEq(keccak256(_bindingPreimage), _binding, _what('binding hash', _id));
      assertEq(_deployed.BINDING(), _binding, _what('BINDING', _id));
    }
  }
}
