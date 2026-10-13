// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {IPolicyAction} from 'interfaces/IPolicyAction.sol';
import {IRecoveryAction} from 'interfaces/IRecoveryAction.sol';
import {IAmbireRecoveryAction} from 'contracts/actions/ambire/IAmbireRecoveryAction.sol';
import {ActionTestBase} from 'test/utils/ActionTestBase.sol';

/// @notice The action's ERC-165 answers, name and version. The setup screen probes a bare address
///         with ERC-165 before offering it as an action, and shows the name and version to the holder.
contract AmbireRecoveryActionDeclarationsTest is ActionTestBase {
  /// @notice The action claims the view interface every action exposes to the setup screen.
  function test_WhenAskedForThePolicyActionInterface() external view {
    // it should return true
    assertTrue(_action.supportsInterface(type(IPolicyAction).interfaceId));
  }

  /// @notice The action claims the interface every recovery action shares, which carries the spend.
  ///         A screen asks for it to learn whether an address is a recovery action at all.
  function test_WhenAskedForTheRecoveryActionInterface() external view {
    // it should return true
    assertTrue(_action.supportsInterface(type(IRecoveryAction).interfaceId));
  }

  /// @notice The action claims its own Ambire interface, which carries the account's callback and the
  ///         getters, so a client can tell an Ambire action apart from a recovery action for another
  ///         account.
  function test_WhenAskedForTheAmbireRecoveryActionInterface() external view {
    // it should return true
    assertTrue(_action.supportsInterface(type(IAmbireRecoveryAction).interfaceId));
  }

  /// @notice The id of the shared recovery interface is 0x4ca82439, the XOR of the selectors of
  ///         executeHandover and holdsAnyPrivilege. Clients and the deployment probe the action with
  ///         this fixed value, so a different id makes every probe miss the action.
  function test_WhenTheRecoveryActionInterfaceIdIsComputed() external pure {
    // it should equal 0x4ca82439
    assertEq(type(IRecoveryAction).interfaceId, bytes4(0x4ca82439));
  }

  /// @notice The id of the Ambire interface is 0xdb7b0011, the XOR of the selectors of validateSig
  ///         and the five getters. Clients and the deployment probe the action with this fixed value,
  ///         so a different id makes every probe miss the action.
  function test_WhenTheAmbireRecoveryActionInterfaceIdIsComputed() external pure {
    // it should equal 0xdb7b0011
    assertEq(type(IAmbireRecoveryAction).interfaceId, bytes4(0xdb7b0011));
  }

  /// @notice The action claims ERC-165 itself, as the standard requires of any implementer.
  function test_WhenAskedForErc165() external view {
    // it should return true
    assertTrue(_action.supportsInterface(_ERC165_ID));
  }

  /// @notice The action answers false for 0xffffffff, as ERC-165 requires.
  function test_WhenAskedForTheInvalidInterfaceId() external view {
    // it should return false
    assertFalse(_action.supportsInterface(0xffffffff));
  }

  /// @notice The action does not claim interfaces it does not implement, ERC-1271 among them.
  function test_WhenAskedForAnyOtherInterface() external view {
    // it should return false
    assertFalse(_action.supportsInterface(0x00000000));
    assertFalse(_action.supportsInterface(0x1626ba7e), 'ERC-1271');
    assertFalse(_action.supportsInterface(IAmbireRecoveryAction.validateSig.selector), 'validateSig selector');
  }

  /// @notice The same for any other id. `_raw` is mapped onto a four-byte id that skips the four
  ///         ids the action claims, so no run can land on one of them.
  function testFuzz_WhenAskedForAnyOtherInterface(uint256 _raw) external view {
    uint32[4] memory _claimed = [
      uint32(type(IPolicyAction).interfaceId),
      uint32(type(IRecoveryAction).interfaceId),
      uint32(type(IAmbireRecoveryAction).interfaceId),
      uint32(_ERC165_ID)
    ];
    // sort the four claimed ids so the skips below run in ascending order
    for (uint256 _i; _i < 4; ++_i) {
      for (uint256 _j = _i + 1; _j < 4; ++_j) {
        if (_claimed[_j] < _claimed[_i]) (_claimed[_i], _claimed[_j]) = (_claimed[_j], _claimed[_i]);
      }
    }
    uint256 _id = bound(_raw, 0, uint256(type(uint32).max) - 4);
    for (uint256 _i; _i < 4; ++_i) {
      _id += _id < _claimed[_i] ? 0 : 1;
    }
    // casting to 'uint32' is safe because _id stays at or below the largest four-byte value
    // forge-lint: disable-next-line(unsafe-typecast)
    bytes4 _interfaceId = bytes4(uint32(_id));
    // it should return false
    assertFalse(_action.supportsInterface(_interfaceId));
  }

  /// @notice The action no longer claims the two interface ids it had before the interface split,
  ///         0xb0539e74 and 0x2780ba5c. A client written against the old ids must learn the action
  ///         no longer matches them, rather than call it as if it had the old shape.
  function test_WhenAskedForTheInterfaceIdsFromBeforeTheSplit() external view {
    // it should return false
    assertFalse(_action.supportsInterface(0xb0539e74), 'old IRecoveryAction id');
    assertFalse(_action.supportsInterface(0x2780ba5c), 'old IAmbireRecoveryAction id');
  }

  /// @notice name answers 'AmbireRecoveryAction'. The setup screen shows it to the holder, so it
  ///         must name this action and no other.
  function test_WhenTheNameIsRead() external view {
    // it should answer AmbireRecoveryAction
    assertEq(_action.name(), 'AmbireRecoveryAction');
  }

  /// @notice version answers '1.0.0'. The setup screen shows it to the holder, so it must name the
  ///         release that was reviewed.
  function test_WhenTheVersionIsRead() external view {
    // it should answer 1.0.0
    assertEq(_action.version(), '1.0.0');
  }
}
