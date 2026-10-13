// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {Test} from 'forge-std/Test.sol';

/// @notice The action's local ABI for Ambire's account, `IAmbireAccount`, against Ambire's own
///         source in kohaku-commons at commit 29227cc: contracts/deployless/IAmbireAccount.sol
///         lines 23, 25 and 29, contracts/AmbireAccount.sol lines 31, 85, 97 and 140, and
///         contracts/libs/Transaction.sol lines 7-11. A wrong selector or event layout would make
///         the action read or write the wrong thing on every Kohaku account. The test reads the
///         compiled ABI, so it binds the declaration without importing its file.
contract AmbireAccountLocalAbiTest is Test {
  string internal _json;

  function setUp() public {
    string[2] memory _candidates =
      ['out/IAmbireAccount.sol/IAmbireAccount.json', 'out/AmbireRecoveryAction.sol/IAmbireAccount.json'];
    for (uint256 _i; _i < _candidates.length; ++_i) {
      if (vm.isFile(_candidates[_i])) {
        _json = vm.readFile(_candidates[_i]);
        return;
      }
    }
    // forge coverage compiles without writing out/, so no artifact exists to read there
    vm.skip(true, 'no IAmbireAccount artifact under out/, run forge build first');
  }

  /// @notice The JSON path of the ABI entry at `_index`.
  function _entry(uint256 _index) internal pure returns (string memory _path) {
    _path = string.concat('.abi[', vm.toString(_index), ']');
  }

  /// @notice The path of the one ABI entry of `_kind` named `_name`, and how many such entries exist.
  function _find(string memory _kind, string memory _name) internal view returns (string memory _path, uint256 _count) {
    for (uint256 _i; vm.keyExistsJson(_json, _entry(_i)); ++_i) {
      string memory _entryPath = _entry(_i);
      if (!_eq(vm.parseJsonString(_json, string.concat(_entryPath, '.type')), _kind)) continue;
      if (!_eq(vm.parseJsonString(_json, string.concat(_entryPath, '.name')), _name)) continue;
      _path = _entryPath;
      ++_count;
    }
  }

  function _eq(string memory _a, string memory _b) internal pure returns (bool _equal) {
    _equal = keccak256(bytes(_a)) == keccak256(bytes(_b));
  }

  /// @notice Asserts the ABI maps `_signature` to the first four bytes of its keccak256.
  function _assertSelector(string memory _signature) internal view {
    string memory _selectorPath = string.concat('.methodIdentifiers[\'', _signature, '\']');
    assertTrue(vm.keyExistsJson(_json, _selectorPath), string.concat('missing ', _signature));
    assertEq(
      string.concat('0x', vm.parseJsonString(_json, _selectorPath)),
      vm.toString(abi.encodePacked(bytes4(keccak256(bytes(_signature))))),
      _signature
    );
  }

  /// @notice The three calls the action makes on the account carry Ambire's signatures, the batch
  ///         element included as the (address,uint256,bytes) tuple Ambire's Transaction encodes to.
  function test_WhenTheLocalAbisFunctionsAreRead() external view {
    // it should carry the three calls of Ambire's source with their selectors
    _assertSelector('privileges(address)');
    _assertSelector('setAddrPrivilege(address,bytes32)');
    _assertSelector('execute((address,uint256,bytes)[],bytes)');
  }

  /// @notice The privilege getter is a view that returns one bytes32 word, as Ambire's does.
  function test_WhenThePrivilegesGetterIsRead() external view {
    (string memory _path, uint256 _count) = _find('function', 'privileges');
    // it should be a view returning one word
    assertEq(_count, 1);
    assertEq(vm.parseJsonString(_json, string.concat(_path, '.stateMutability')), 'view');
    assertEq(vm.parseJsonString(_json, string.concat(_path, '.outputs[0].type')), 'bytes32');
    assertFalse(vm.keyExistsJson(_json, string.concat(_path, '.outputs[1]')));
  }

  /// @notice The privilege write and the batch execution are payable and return nothing, as
  ///         Ambire declares them.
  function test_WhenTheWriteAndExecuteCallsAreRead() external view {
    (string memory _setPath, uint256 _setCount) = _find('function', 'setAddrPrivilege');
    (string memory _executePath, uint256 _executeCount) = _find('function', 'execute');
    // it should be payable and return nothing as in Ambire's source
    assertEq(_setCount, 1);
    assertEq(_executeCount, 1);
    assertEq(vm.parseJsonString(_json, string.concat(_setPath, '.stateMutability')), 'payable');
    assertEq(vm.parseJsonString(_json, string.concat(_executePath, '.stateMutability')), 'payable');
    assertFalse(vm.keyExistsJson(_json, string.concat(_setPath, '.outputs[0]')));
    assertFalse(vm.keyExistsJson(_json, string.concat(_executePath, '.outputs[0]')));
  }

  /// @notice The privilege event is LogPrivilegeChanged with an indexed address and a bytes32 data
  ///         word, the layout the SDK's alerting decodes.
  function test_WhenThePrivilegeEventIsRead() external view {
    (string memory _path, uint256 _count) = _find('event', 'LogPrivilegeChanged');
    // it should be Ambire's event with an indexed address and a data word
    assertEq(_count, 1);
    assertFalse(vm.parseJsonBool(_json, string.concat(_path, '.anonymous')));
    assertEq(vm.parseJsonString(_json, string.concat(_path, '.inputs[0].type')), 'address');
    assertTrue(vm.parseJsonBool(_json, string.concat(_path, '.inputs[0].indexed')));
    assertEq(vm.parseJsonString(_json, string.concat(_path, '.inputs[1].type')), 'bytes32');
    assertFalse(vm.parseJsonBool(_json, string.concat(_path, '.inputs[1].indexed')));
    assertFalse(vm.keyExistsJson(_json, string.concat(_path, '.inputs[2]')));
  }
}
