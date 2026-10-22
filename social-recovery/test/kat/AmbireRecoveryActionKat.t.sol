// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {IRecoveryAction} from 'interfaces/IRecoveryAction.sol';
import {ActionAmbireAccountMock} from 'test/mocks/ActionAmbireAccountMock.sol';
import {ActionTestBase} from 'test/utils/ActionTestBase.sol';

/// @notice Replays test/fixtures/kats/ambire-kit-slot.json, the frozen slot and binding the SDK and the
///         action must both compute. If the two sides drift, the SDK arms an entry the action never
///         reads and every armed account becomes unrecoverable.
contract AmbireRecoveryActionKatTest is ActionTestBase {
  string internal constant _VECTOR_FILE = 'test/fixtures/kats/ambire-kit-slot.json';

  function _vector(uint256 _index) internal pure returns (string memory _path) {
    _path = string.concat('.vectors[', vm.toString(_index), ']');
  }

  /// @notice The action deployed at each vector's address reports the vector's slot as KIT_SLOT
  ///         and is authorized exactly when that slot holds the vector's binding.
  function test_WhenReplayingTheKitSlotVectorsThroughTheAction() external {
    // it should report each vector's slot and be authorized only by its binding
    string memory _file = vm.readFile(_VECTOR_FILE);
    assertEq(vm.parseJsonString(_file, '.format'), 'ambire-kit-slot-v1');
    uint256 _replayed;
    for (uint256 _i; vm.keyExistsJson(_file, _vector(_i)); ++_i) {
      string memory _v = _vector(_i);
      address _where = vm.parseJsonAddress(_file, string.concat(_v, '.input.action'));
      address _slot = vm.parseJsonAddress(_file, string.concat(_v, '.expected.slot'));
      bytes32 _binding = vm.parseJsonBytes32(_file, string.concat(_v, '.expected.binding'));

      _deployActionAt(_where, _manager, _implementation);
      assertEq(_kitSlotOf(_where), _slot, 'KIT_SLOT');

      ActionAmbireAccountMock _fresh = new ActionAmbireAccountMock();
      assertFalse(IRecoveryAction(_where).isAuthorized(address(_fresh)), 'empty slot');
      _fresh.setPrivilege(_slot, _binding);
      assertTrue(IRecoveryAction(_where).isAuthorized(address(_fresh)), 'binding under the slot');
      _fresh.setPrivilege(_slot, _binding ^ bytes32(uint256(1)));
      assertFalse(IRecoveryAction(_where).isAuthorized(address(_fresh)), 'any other value');
      ++_replayed;
    }
    assertGt(_replayed, 0, 'the vector file carries vectors');
  }

  /// @notice The suite's renderings of the slot and the binding reproduce the vector, so the unit
  ///         tests that use them compare against the frozen format.
  function test_WhenReplayingTheKitSlotVectorsThroughTheRenderings() external view {
    // it should reproduce every expected slot and binding
    string memory _file = vm.readFile(_VECTOR_FILE);
    uint256 _replayed;
    for (uint256 _i; vm.keyExistsJson(_file, _vector(_i)); ++_i) {
      string memory _v = _vector(_i);
      address _actionAt = vm.parseJsonAddress(_file, string.concat(_v, '.input.action'));
      bytes32 _binding = vm.parseJsonBytes32(_file, string.concat(_v, '.expected.binding'));
      assertEq(_expectedKitSlot(_actionAt), vm.parseJsonAddress(_file, string.concat(_v, '.expected.slot')), 'slot');
      assertEq(_expectedBinding(_actionAt), _binding, 'binding');
      ++_replayed;
    }
    assertGt(_replayed, 0, 'the vector file carries vectors');
  }
}
