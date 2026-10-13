// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {Test} from 'forge-std/Test.sol';
import {IAmbireRecoveryAction} from 'contracts/actions/ambire/IAmbireRecoveryAction.sol';
import {ActionAmbireAccountMock} from 'test/mocks/ActionAmbireAccountMock.sol';

/// @notice Shared setup for the recovery action's tests. The action is deployed from its compiled
///         artifact, so the suite compiles against the action's interfaces alone.
/// @dev Assumed shapes: the contract `AmbireRecoveryAction` in a file of the same name, a
///      constructor taking the manager's address and then the Ambire implementation address, and
///      public getters `KIT_SLOT()`, `KEY_VALUE()`, `MANAGER()` and `AMBIRE_IMPLEMENTATION()`.
abstract contract ActionTestBase is Test {
  /// @notice The artifact the action is deployed from.
  string internal constant _ACTION_ARTIFACT = 'AmbireRecoveryAction.sol:AmbireRecoveryAction';
  /// @notice The value Ambire's account stores for the ERC-4337 entry point, code rather than a key.
  bytes32 internal constant _ENTRY_POINT_MARKER = bytes32(uint256(0x7171));
  /// @notice The ERC-165 interface id of ERC-165 itself.
  bytes4 internal constant _ERC165_ID = 0x01ffc9a7;

  address internal _manager;
  address internal _implementation;
  IAmbireRecoveryAction internal _action;
  ActionAmbireAccountMock internal _account;
  bytes internal _cachedCreationCode;

  function setUp() public virtual {
    _manager = makeAddr('policyManager');
    vm.etch(_manager, hex'00');
    _implementation = makeAddr('ambireImplementation');
    vm.etch(_implementation, hex'00');
    _action = _deployAction(_manager, _implementation);
    _account = new ActionAmbireAccountMock();
  }

  /*///////////////////////////////////////////////////////////////
                            DEPLOYMENT
  ///////////////////////////////////////////////////////////////*/

  /// @notice Deploys the action from its cached creation code with the assumed constructor order.
  function _deployAction(address _managerAddress, address _pinnedImplementation)
    internal
    returns (IAmbireRecoveryAction _deployed)
  {
    bytes memory _initCode = abi.encodePacked(_creationCode(), abi.encode(_managerAddress, _pinnedImplementation));
    address _addr;
    assembly {
      _addr := create(0, add(_initCode, 0x20), mload(_initCode))
    }
    assertTrue(_addr != address(0), 'action deployment');
    _deployed = IAmbireRecoveryAction(_addr);
  }

  /// @notice Deploys the action at a chosen address, so every value it derives from its own
  ///         address binds that one. The same steps as forge-std's deployCodeTo.
  function _deployActionAt(address _where, address _managerAddress, address _pinnedImplementation) internal {
    vm.etch(_where, abi.encodePacked(_creationCode(), abi.encode(_managerAddress, _pinnedImplementation)));
    (bool _ok, bytes memory _runtime) = _where.call('');
    assertTrue(_ok, 'action deployment at a chosen address');
    vm.etch(_where, _runtime);
  }

  /// @notice The action's creation code, read from its artifact once.
  function _creationCode() internal returns (bytes memory _code) {
    if (_cachedCreationCode.length == 0) _cachedCreationCode = vm.getCode(_ACTION_ARTIFACT);
    _code = _cachedCreationCode;
  }

  /*///////////////////////////////////////////////////////////////
                              GETTERS
  ///////////////////////////////////////////////////////////////*/

  /// @notice Reads the action's KIT_SLOT through its getter.
  function _kitSlotOf(address _actionAddress) internal view returns (address _slot) {
    _slot = _addressGetter(_actionAddress, 'KIT_SLOT()');
  }

  /// @notice Reads the action's KEY_VALUE through its getter, as one 32-byte word.
  function _keyValueOf(address _actionAddress) internal view returns (bytes32 _value) {
    (bool _ok, bytes memory _ret) = _actionAddress.staticcall(abi.encodeWithSignature('KEY_VALUE()'));
    assertTrue(_ok && _ret.length == 32, 'KEY_VALUE() getter missing');
    _value = abi.decode(_ret, (bytes32));
  }

  /// @notice Reads an address-valued getter of the action by its signature.
  function _addressGetter(address _actionAddress, string memory _signature) internal view returns (address _value) {
    (bool _ok, bytes memory _ret) = _actionAddress.staticcall(abi.encodeWithSignature(_signature));
    assertTrue(_ok && _ret.length == 32, string.concat(_signature, ' getter missing'));
    _value = abi.decode(_ret, (address));
  }

  /*///////////////////////////////////////////////////////////////
                            RENDERINGS
  ///////////////////////////////////////////////////////////////*/

  /// @notice The kit slot the specification defines for an action address: the low twenty bytes
  ///         of keccak256(abi.encode("kit", action)) with "kit" typed as a string. The vector test in
  ///         test/kat checks this rendering against the frozen vector.
  function _expectedKitSlot(address _actionAddress) internal pure returns (address _slot) {
    string memory _kit = 'kit';
    _slot = address(uint160(uint256(keccak256(abi.encode(_kit, _actionAddress)))));
  }

  /// @notice The binding value the account compares under the kit slot: keccak256 of the action
  ///         address and empty validator data. The vector test in test/kat checks it against the vector.
  function _expectedBinding(address _actionAddress) internal pure returns (bytes32 _binding) {
    _binding = keccak256(abi.encode(_actionAddress, bytes('')));
  }

  /// @notice The slot Ambire's own function `getSignerKey` derives for a validator and its data, in
  ///         kohaku-commons src/libs/dkim/recovery.ts lines 40-45: the low twenty bytes of
  ///         keccak256(abi.encode(validator, data)).
  function _ambireSignerKeySlot(address _validator, bytes memory _data) internal pure returns (address _slot) {
    _slot = address(uint160(uint256(keccak256(abi.encode(_validator, _data)))));
  }

  /*///////////////////////////////////////////////////////////////
                            FUZZ INPUTS
  ///////////////////////////////////////////////////////////////*/

  /// @notice Maps a fuzzed number onto an address that is never `_excluded` and never zero, by
  ///         skipping the excluded address rather than filtering the run.
  function _addressOtherThan(uint256 _raw, address _excluded) internal pure returns (address _other) {
    uint256 _r = bound(_raw, 1, type(uint160).max - 1);
    _r += _r < uint160(_excluded) ? 0 : 1;
    // casting to 'uint160' is safe because _r is bounded to the address range
    // forge-lint: disable-next-line(unsafe-typecast)
    _other = address(uint160(_r));
  }

  /// @notice Hashes a fuzzed number and a tag into an address no fixture uses. The fuzzer seeds its
  ///         inputs with addresses it reads from state, so a number mapped straight onto an address
  ///         can fall on a key the fixture already privileges. A hashed address matches a fixture
  ///         address, zero or another tag's address only through a keccak collision.
  function _freshAddress(string memory _tag, uint256 _seed) internal pure returns (address _fresh) {
    _fresh = address(uint160(uint256(keccak256(abi.encode(_tag, _seed)))));
  }
}
