// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {stdError} from 'forge-std/StdError.sol';
import {IERC165} from '@openzeppelin/contracts/utils/introspection/IERC165.sol';
import {IPolicyMethod} from 'interfaces/IPolicyMethod.sol';
import {IPolicyMethodAdmin} from 'interfaces/IPolicyMethodAdmin.sol';
import {IPolicyMethodPause} from 'interfaces/IPolicyMethodPause.sol';
import {MethodRolesHarness} from 'test/mocks/MethodRolesHarness.sol';
import {MethodRolesTestBase} from 'test/utils/MethodRolesTestBase.sol';

/// @notice What the method reports about its roles, its keys, its interfaces and itself.
contract PolicyMethodRolesViewsTest is MethodRolesTestBase {
  /// @notice With both handovers open, trustedParties reports each nominee beside the current holder, so a
  ///         holder sees a role about to move and not only who holds it today.
  function test_WhenBothTransfersAreOpen() external {
    vm.prank(_keyAdmin);
    _roles.transferAdmin(_nominee);
    vm.prank(_pauseHolder);
    _roles.transferOwnership(_secondNominee);

    (address _admin, address _pendingAdmin, bytes32[] memory _keys, address _holder, address _pendingHolder) =
      _roles.trustedParties();
    assertEq(_admin, _keyAdmin, 'admin');
    assertEq(_pendingAdmin, _nominee, 'pendingAdmin');
    assertEq(_pendingAdmin, _roles.pendingAdmin(), 'pendingAdmin matches pendingAdmin()');
    _assertKeys(_keys, _initialKeys);
    assertEq(_holder, _pauseHolder, '_pauseHolder');
    assertEq(_holder, _roles.owner(), '_pauseHolder is owner()');
    assertEq(_pendingHolder, _secondNominee, 'pendingPauseHolder');
    assertEq(_pendingHolder, _roles.pendingOwner(), 'pendingPauseHolder is pendingOwner()');
  }

  /// @notice After both handovers complete and the new admin sets keys, trustedParties reports the new
  ///         holders, the new keys and empty pending slots.
  function test_WhenBothTransfersAreAccepted() external {
    vm.prank(_keyAdmin);
    _roles.transferAdmin(_nominee);
    vm.prank(_pauseHolder);
    _roles.transferOwnership(_secondNominee);
    vm.prank(_nominee);
    _roles.acceptAdmin();
    vm.prank(_secondNominee);
    _roles.acceptOwnership();
    bytes32[] memory _fresh = _keyList(keccak256('n0'), keccak256('n1'), keccak256('n2'));
    vm.prank(_nominee);
    _roles.setTrustedKeys(_fresh);

    (address _admin, address _pendingAdmin, bytes32[] memory _keys, address _holder, address _pendingHolder) =
      _roles.trustedParties();
    assertEq(_admin, _nominee, 'admin');
    assertEq(_pendingAdmin, address(0), 'pendingAdmin');
    _assertKeys(_keys, _fresh);
    assertEq(_holder, _secondNominee, '_pauseHolder');
    assertEq(_pendingHolder, address(0), 'pendingPauseHolder');
  }

  /// @notice supportsInterface answers true for the method, pause, key admin and ERC-165 interface ids, so a
  ///         setup screen can recognise a policy method and its two role surfaces from a bare address.
  function test_WhenAskedAboutASupportedInterface() external view {
    assertTrue(_roles.supportsInterface(type(IPolicyMethod).interfaceId), 'IPolicyMethod');
    assertTrue(_roles.supportsInterface(type(IPolicyMethodPause).interfaceId), 'IPolicyMethodPause');
    assertTrue(_roles.supportsInterface(type(IPolicyMethodAdmin).interfaceId), 'IPolicyMethodAdmin');
    assertTrue(_roles.supportsInterface(type(IERC165).interfaceId), 'IERC165');
    assertTrue(_roles.supportsInterface(0x01ffc9a7), 'IERC165 literal');
  }

  /// @notice supportsInterface answers false for 0xffffffff, which ERC-165 reserves as never supported, and
  ///         for ids the method does not implement.
  function test_WhenAskedAboutAnUnsupportedInterface() external view {
    assertFalse(_roles.supportsInterface(0xffffffff), '0xffffffff');
    assertFalse(_roles.supportsInterface(0x00000000), '0x00000000');
    assertFalse(_roles.supportsInterface(IPolicyMethod.verify.selector), 'a single selector');
  }

  /// @notice name and version return the strings each deployment passed to its constructor, which is what an
  ///         adoption screen shows for the method.
  function test_WhenAskedForTheNameAndTheVersion() external {
    assertEq(_roles.name(), _NAME, 'name');
    assertEq(_roles.version(), _VERSION, 'version');

    MethodRolesHarness _other = new MethodRolesHarness(_pauseHolder, _keyAdmin, _initialKeys, 'Other Method', '2.3.4');
    assertEq(_other.name(), 'Other Method', 'other name');
    assertEq(_other.version(), '2.3.4', 'other version');
  }

  /// @notice Asking for each position of the stored key set returns the word stored there, in the order
  ///         the deployment passed them.
  function test_WhenAskedForEachStoredKeyByIndex() external view {
    assertEq(_roles.trustedKey(0), _initialKeys[0], 'key 0');
    assertEq(_roles.trustedKey(1), _initialKeys[1], 'key 1');
  }

  /// @notice For a stored list of 1 to 16 words and any index below its length, the one-word getter
  ///         returns the word at that position of the full list trustedParties reports. `_wordSeed`
  ///         derives each word, and `_lengthSeed` and `_indexSeed` are bounded, never discarded.
  function test_WhenAskedForAKeyAtAnyIndexBelowTheLength(uint256 _lengthSeed, uint256 _wordSeed, uint256 _indexSeed)
    external
  {
    uint256 _length = bound(_lengthSeed, 1, 16);
    bytes32[] memory _keys = new bytes32[](_length);
    for (uint256 _i = 0; _i < _length; _i++) {
      _keys[_i] = keccak256(abi.encode(_wordSeed, _i));
    }
    vm.prank(_keyAdmin);
    _roles.setTrustedKeys(_keys);
    uint256 _index = bound(_indexSeed, 0, _length - 1);

    assertEq(_roles.trustedKey(_index), _reportedKeys()[_index], 'word at index');
  }

  /// @notice Asking for the index equal to the stored length reverts with the array bounds panic, so a
  ///         method never reads a word past the list as if it were a key.
  function test_RevertWhen_AskedForTheKeyAtTheLength() external {
    vm.expectRevert(stdError.indexOOBError);
    _roles.trustedKey(_initialKeys.length);
  }

  /// @notice After the key admin replaces the keys with a longer list, each index returns the new word,
  ///         including the position past the old length. So the getter reads the current list.
  function test_WhenAskedForAKeyAfterTheKeysAreReplaced() external {
    bytes32[] memory _fresh = _keyList(keccak256('r0'), keccak256('r1'), keccak256('r2'));
    vm.prank(_keyAdmin);
    _roles.setTrustedKeys(_fresh);

    assertEq(_roles.trustedKey(0), _fresh[0], 'new key 0');
    assertEq(_roles.trustedKey(1), _fresh[1], 'new key 1');
    assertEq(_roles.trustedKey(2), _fresh[2], 'new key 2');
  }
}
