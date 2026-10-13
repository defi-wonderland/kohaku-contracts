// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {Ownable} from '@openzeppelin/contracts/access/Ownable.sol';
import {Test} from 'forge-std/Test.sol';
import {IPolicyMethodAdmin} from 'interfaces/IPolicyMethodAdmin.sol';
import {MethodRolesHarness} from 'test/mocks/MethodRolesHarness.sol';

/// @notice Shared setup for the roles base tests. It deploys one harness with two initial keys, where the
///         pause holder and the key admin are different addresses. It also offers small helpers.
abstract contract MethodRolesTestBase is Test {
  string internal constant _NAME = 'Harness Method';
  string internal constant _VERSION = '1.0.0';

  MethodRolesHarness internal _roles;

  address internal _pauseHolder = makeAddr('pauseHolder');
  address internal _keyAdmin = makeAddr('keyAdmin');
  address internal _nominee = makeAddr('nominee');
  address internal _secondNominee = makeAddr('secondNominee');
  address internal _stranger = makeAddr('stranger');

  bytes32[] internal _initialKeys;
  bytes32 internal _marker;

  /// @dev Stores the two initial keys, deploys the harness over them and reads its marker word.
  function setUp() public virtual {
    _initialKeys.push(keccak256('initial.key.0'));
    _initialKeys.push(keccak256('initial.key.1'));
    _roles = _deploy(_pauseHolder, _keyAdmin, _initialKeys);
    _marker = _roles.MARKER();
  }

  /// @dev Deploys a harness with the fixed name and version.
  function _deploy(address _owner, address _admin, bytes32[] memory _keys)
    internal
    returns (MethodRolesHarness _deployed)
  {
    _deployed = new MethodRolesHarness(_owner, _admin, _keys, _NAME, _VERSION);
  }

  /// @dev Builds a key list of one word.
  function _keyList(bytes32 _a) internal pure returns (bytes32[] memory _keys) {
    _keys = new bytes32[](1);
    _keys[0] = _a;
  }

  /// @dev Builds a key list of two words, in order.
  function _keyList(bytes32 _a, bytes32 _b) internal pure returns (bytes32[] memory _keys) {
    _keys = new bytes32[](2);
    _keys[0] = _a;
    _keys[1] = _b;
  }

  /// @dev Builds a key list of three words, in order.
  function _keyList(bytes32 _a, bytes32 _b, bytes32 _c) internal pure returns (bytes32[] memory _keys) {
    _keys = new bytes32[](3);
    _keys[0] = _a;
    _keys[1] = _b;
    _keys[2] = _c;
  }

  /// @dev The keys the method reports it trusts today.
  function _reportedKeys() internal view returns (bytes32[] memory _keys) {
    (,, _keys,,) = _roles.trustedParties();
  }

  /// @dev The key admin the method reports today.
  function _reportedAdmin() internal view returns (address _admin) {
    (_admin,,,,) = _roles.trustedParties();
  }

  /// @dev Asserts two key lists hold the same words in the same order.
  function _assertKeys(bytes32[] memory _actual, bytes32[] memory _expected) internal pure {
    assertEq(_actual.length, _expected.length, 'keys length');
    for (uint256 _i = 0; _i < _expected.length; _i++) {
      assertEq(_actual[_i], _expected[_i], 'key word');
    }
  }

  /// @dev The revert data OpenZeppelin's Ownable gives when a caller other than the owner calls.
  function _unauthorized(address _caller) internal pure returns (bytes memory _reason) {
    _reason = abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, _caller);
  }

  /// @dev The revert data the key admin surface gives when a caller may not act as the key admin,
  ///      or may not accept a transfer nobody offered it.
  function _adminUnauthorized(address _caller) internal pure returns (bytes memory _reason) {
    _reason = abi.encodeWithSelector(IPolicyMethodAdmin.PolicyMethodRoles_AdminUnauthorizedAccount.selector, _caller);
  }

  /// @dev The revert data the harness hook gives when it meets its marker at position `_index`.
  function _markerRefused(uint256 _index) internal view returns (bytes memory _reason) {
    _reason = abi.encodeWithSelector(MethodRolesHarness.MethodRolesHarness_MarkerKeyRefused.selector, _index, _marker);
  }

  /// @dev Maps a fuzzed seed to any address except `_excluded`. It adds a nonzero offset to `_excluded` and
  ///      lets the sum wrap around the address space. So every other address can come out, including the zero
  ///      address, and `_excluded` never does.
  function _anyAddressBut(address _excluded, uint256 _seed) internal pure returns (address _picked) {
    uint160 _offset = uint160(bound(_seed, 1, type(uint160).max));
    unchecked {
      _picked = address(uint160(_excluded) + _offset);
    }
  }

  /// @dev Maps a fuzzed seed to any 32-byte word except `_excluded`, the same way `_anyAddressBut`
  ///      maps addresses.
  function _anyWordBut(bytes32 _excluded, uint256 _seed) internal pure returns (bytes32 _picked) {
    uint256 _offset = bound(_seed, 1, type(uint256).max);
    unchecked {
      _picked = bytes32(uint256(_excluded) + _offset);
    }
  }
}
