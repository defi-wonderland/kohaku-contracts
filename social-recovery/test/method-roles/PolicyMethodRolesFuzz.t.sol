// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {IERC165} from '@openzeppelin/contracts/utils/introspection/IERC165.sol';
import {IPolicyMethod} from 'interfaces/IPolicyMethod.sol';
import {IPolicyMethodAdmin} from 'interfaces/IPolicyMethodAdmin.sol';
import {IPolicyMethodPause} from 'interfaces/IPolicyMethodPause.sol';
import {MethodRolesHarness} from 'test/mocks/MethodRolesHarness.sol';
import {MethodRolesTestBase} from 'test/utils/MethodRolesTestBase.sol';

/// @notice Stateless fuzz tests over the caller of each role function and over the key list the
///         validation hook receives. A `_callerSeed` parameter is a fuzzed number that
///         `_anyAddressBut` turns into any address except the one the test names.
contract PolicyMethodRolesFuzzTest is MethodRolesTestBase {
  /// @notice No caller other than the key admin can replace the keys, not even the zero address, and the keys
  ///         stay as they were. An address able to set the keys could forge every proof.
  function testFuzz_onlyTheKeyAdminSetsKeys(uint256 _callerSeed, uint256 _keySeed) external {
    address _caller = _anyAddressBut(_keyAdmin, _callerSeed);
    bytes32 _key = _anyWordBut(_marker, _keySeed);
    vm.expectRevert(_adminUnauthorized(_caller));
    vm.prank(_caller);
    _roles.setTrustedKeys(_keyList(_key));
    _assertKeys(_reportedKeys(), _initialKeys);
  }

  /// @notice No caller other than the key admin can offer the role to any address. Otherwise a stranger could
  ///         name a nominee who would only need to accept before setting keys.
  function testFuzz_onlyTheKeyAdminOffersTheRole(uint256 _callerSeed, address _target) external {
    address _caller = _anyAddressBut(_keyAdmin, _callerSeed);
    vm.expectRevert(_adminUnauthorized(_caller));
    vm.prank(_caller);
    _roles.transferAdmin(_target);
    assertEq(_roles.pendingAdmin(), address(0), 'pendingAdmin');
  }

  /// @notice With an offer open to one nominee, any other caller fails to accept it, and the admin
  ///         and the offer stay as they were.
  function testFuzz_onlyTheNomineeAccepts(uint256 _callerSeed) external {
    address _caller = _anyAddressBut(_nominee, _callerSeed);
    vm.prank(_keyAdmin);
    _roles.transferAdmin(_nominee);
    vm.expectRevert(_adminUnauthorized(_caller));
    vm.prank(_caller);
    _roles.acceptAdmin();
    assertEq(_reportedAdmin(), _keyAdmin, 'admin');
    assertEq(_roles.pendingAdmin(), _nominee, 'pendingAdmin');
  }

  /// @notice Any caller other than the key admin fails to renounce the role, so nobody else can
  ///         freeze the keys a method needs to follow an issuer's rotation.
  function testFuzz_onlyTheKeyAdminRenounces(uint256 _callerSeed) external {
    address _caller = _anyAddressBut(_keyAdmin, _callerSeed);
    vm.expectRevert(_adminUnauthorized(_caller));
    vm.prank(_caller);
    _roles.renounceAdmin();
    assertEq(_reportedAdmin(), _keyAdmin, 'admin');
  }

  /// @notice After the admin offers the role to any nonzero nominee and then renounces, that nominee
  ///         fails to accept. Renouncing clears the offer first, so the frozen keys cannot be captured.
  function testFuzz_noNomineeAcceptsAfterRenounce(uint256 _nomineeSeed) external {
    address _someNominee = _anyAddressBut(address(0), _nomineeSeed);
    vm.startPrank(_keyAdmin);
    _roles.transferAdmin(_someNominee);
    _roles.renounceAdmin();
    vm.stopPrank();
    vm.expectRevert(_adminUnauthorized(_someNominee));
    vm.prank(_someNominee);
    _roles.acceptAdmin();
    assertEq(_reportedAdmin(), address(0), 'admin');
    assertEq(_roles.pendingAdmin(), address(0), 'pendingAdmin');
  }

  /// @notice No caller other than the pause holder can stop the method, and the error names the caller.
  ///         Anyone able to stop it could block every recovery that relies on it.
  function testFuzz_onlyThePauseHolderPauses(uint256 _callerSeed) external {
    address _caller = _anyAddressBut(_pauseHolder, _callerSeed);
    vm.expectRevert(_unauthorized(_caller));
    vm.prank(_caller);
    _roles.pause();
    assertFalse(_roles.paused(), 'paused');
  }

  /// @notice No caller other than the pause holder can lift a stop, and the error names the caller. So a
  ///         method stopped over a suspected bug stays stopped until the pause holder lifts the stop.
  function testFuzz_onlyThePauseHolderUnpauses(uint256 _callerSeed) external {
    address _caller = _anyAddressBut(_pauseHolder, _callerSeed);
    vm.prank(_pauseHolder);
    _roles.pause();
    vm.expectRevert(_unauthorized(_caller));
    vm.prank(_caller);
    _roles.unpause();
    assertTrue(_roles.paused(), 'paused');
  }

  /// @notice After the pause holder pauses and renounces, no caller can lift the stop, including the former
  ///         holder and the zero address. The method stays paused forever.
  function testFuzz_nobodyLiftsAStopAfterRenounce(address _caller) external {
    vm.startPrank(_pauseHolder);
    _roles.pause();
    _roles.renounceOwnership();
    vm.stopPrank();
    vm.expectRevert(_unauthorized(_caller));
    vm.prank(_caller);
    _roles.unpause();
    assertTrue(_roles.paused(), 'paused');
  }

  /// @notice A key list of 1 to 16 words holding the hook's marker at any position is refused by
  ///         setTrustedKeys and by the constructor alike, with the position named. Both paths run
  ///         the same hook, so neither can install keys the method would refuse.
  function testFuzz_hookRefusesTheMarkerAtAnyPosition(uint256 _lengthSeed, uint256 _positionSeed) external {
    uint256 _length = bound(_lengthSeed, 1, 16);
    uint256 _position = bound(_positionSeed, 0, _length - 1);
    bytes32[] memory _keys = new bytes32[](_length);
    for (uint256 _i = 0; _i < _length; _i++) {
      _keys[_i] = _anyWordBut(_marker, uint256(keccak256(abi.encode('k', _i))));
    }
    _keys[_position] = _marker;

    vm.expectRevert(_markerRefused(_position));
    vm.prank(_keyAdmin);
    _roles.setTrustedKeys(_keys);
    _assertKeys(_reportedKeys(), _initialKeys);

    vm.expectRevert(_markerRefused(_position));
    new MethodRolesHarness(_pauseHolder, _keyAdmin, _keys, _NAME, _VERSION);
  }

  /// @notice Any key list of 0 to 32 words the hook accepts is stored exactly, in order, and the hook
  ///         runs while the old keys are still in storage. `_wordSeed` derives each word, never the marker.
  function testFuzz_setTrustedKeysStoresWhatTheHookAccepts(uint256 _lengthSeed, uint256 _wordSeed) external {
    uint256 _length = bound(_lengthSeed, 0, 32);
    bytes32[] memory _keys = new bytes32[](_length);
    for (uint256 _i = 0; _i < _length; _i++) {
      _keys[_i] = _anyWordBut(_marker, uint256(keccak256(abi.encode(_wordSeed, _i))));
    }
    _roles.armProbe(keccak256(abi.encodePacked(_initialKeys)));
    vm.prank(_keyAdmin);
    _roles.setTrustedKeys(_keys);
    _assertKeys(_reportedKeys(), _keys);
  }

  /// @notice supportsInterface answers false for any id other than the four the method implements.
  ///         `_idSeed` becomes an id that `_unknownInterfaceId` steps past those four.
  function testFuzz_supportsInterfaceIsFalseForUnknownIds(uint32 _idSeed) external view {
    assertFalse(_roles.supportsInterface(_unknownInterfaceId(_idSeed)), 'unknown id');
  }

  /// @dev Turns a seed into an interface id outside the four the specification says the method
  ///      supports, stepping the value up by one while it lands on one of them. The four are distinct,
  ///      so it ends.
  function _unknownInterfaceId(uint32 _idSeed) internal pure returns (bytes4 _id) {
    _id = bytes4(_idSeed);
    while (_isSupported(_id)) {
      unchecked {
        _id = bytes4(uint32(_id) + 1);
      }
    }
  }

  /// @dev Whether `_id` is one of the four interface ids that a policy method with both roles must answer
  ///      true for. The specification lists them as the method, the pause holder's surface, the key admin's
  ///      surface and ERC-165 itself. This list copies the specification, not the method.
  function _isSupported(bytes4 _id) internal pure returns (bool _supported) {
    _supported = _id == type(IPolicyMethod).interfaceId || _id == type(IPolicyMethodPause).interfaceId
      || _id == type(IPolicyMethodAdmin).interfaceId || _id == type(IERC165).interfaceId;
  }
}
