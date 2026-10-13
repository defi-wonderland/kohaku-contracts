// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {ActionTestBase} from 'test/utils/ActionTestBase.sol';

/// @notice The values the constructor fixes. KIT_SLOT is the made-up address whose privilege entry
///         lets an account authorize the action, MANAGER and AMBIRE_IMPLEMENTATION are the two
///         addresses the constructor receives, and KEY_VALUE is the privilege a recovery writes for
///         the new key. The SDK computes the slot on its own, so a mismatch leaves every account that
///         authorizes the action unrecoverable.
contract AmbireRecoveryActionConstructorTest is ActionTestBase {
  /// @notice KIT_SLOT is the low twenty bytes of keccak256(abi.encode("kit", action)), the
  ///         derivation the SDK repeats off chain.
  function test_WhenTheKitSlotIsRead() external view {
    // it should equal the low twenty bytes of the hash of the string kit and the action
    assertEq(_kitSlotOf(address(_action)), _expectedKitSlot(address(_action)));
  }

  /// @notice The slot binds the address the action is deployed at, so two deployments never share
  ///         an entry on one account.
  function test_WhenTheActionIsDeployedAtAnotherAddress() external {
    address _where = makeAddr('actionElsewhere');
    _deployActionAt(_where, _manager, _implementation);
    // it should derive the kit slot from that address
    assertEq(_kitSlotOf(_where), _expectedKitSlot(_where));
    assertTrue(_kitSlotOf(_where) != _kitSlotOf(address(_action)));
  }

  /// @notice The same for any deployment address. `_seed` is hashed into the address, so it is a
  ///         fresh address with no code.
  function testFuzz_WhenTheActionIsDeployedAtAnotherAddress(uint256 _seed) external {
    address _where = address(uint160(uint256(keccak256(abi.encode('actionAt', _seed)))));
    _deployActionAt(_where, _manager, _implementation);
    // it should derive the kit slot from that address
    assertEq(_kitSlotOf(_where), _expectedKitSlot(_where));
  }

  /// @notice MANAGER is the manager the constructor received, the only contract whose attempt
  ///         state the action trusts when it spends an approval.
  function test_WhenTheManagerIsRead() external {
    // it should equal the manager the constructor received
    assertEq(_addressGetter(address(_action), 'MANAGER()'), _manager);
    address _otherManager = makeAddr('otherManager');
    vm.etch(_otherManager, hex'00');
    assertEq(_addressGetter(address(_deployAction(_otherManager, _implementation)), 'MANAGER()'), _otherManager);
  }

  /// @notice AMBIRE_IMPLEMENTATION is the implementation the constructor received, the one address
  ///         the fit check accepts behind a proxy.
  function test_WhenThePinnedImplementationIsRead() external {
    // it should equal the implementation the constructor received
    assertEq(_addressGetter(address(_action), 'AMBIRE_IMPLEMENTATION()'), _implementation);
    address _otherImpl = makeAddr('otherImplementation');
    vm.etch(_otherImpl, hex'00');
    assertEq(_addressGetter(address(_deployAction(_manager, _otherImpl)), 'AMBIRE_IMPLEMENTATION()'), _otherImpl);
  }

  /// @notice KEY_VALUE is 1, the privilege that lets the new key sign only signatures bound to
  ///         this account, so a signature it makes cannot be reused on another account.
  function test_WhenTheKeyValueIsRead() external view {
    // it should equal one as a word
    assertEq(_keyValueOf(address(_action)), bytes32(uint256(1)));
  }

  /// @notice Ambire's own function getSignerKey would place this action's binding at the binding's low twenty
  ///         bytes, and the kit slot is a different address, so the two conventions never write
  ///         the same entry.
  function test_WhenTheKitSlotIsComparedWithTheSignerKeySlotOfTheActionsOwnBinding() external view {
    // it should differ
    assertTrue(_kitSlotOf(address(_action)) != _ambireSignerKeySlot(address(_action), bytes('')));
  }
}
