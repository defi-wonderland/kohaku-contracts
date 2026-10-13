// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {Test} from 'forge-std/Test.sol';

/// @notice Test helpers for the six kit interfaces and the Ambire action's own interface. They read
///         the compiled artifacts forge writes under out/, so a test can check the whole ABI surface
///         of an interface, not only the members the compiler lets a test name.
/// @dev forge coverage compiles without writing out/, so a test that needs an artifact skips
///      where none exists. forge build and forge test always write it first, so a run that sets
///      ARTIFACTS_REQUIRED=true, as CI does on forge test, fails on a missing artifact instead:
///      a silent skip there would pass a suite that checked nothing.
abstract contract InterfacesArtifacts is Test {
  /// @notice Loads out/<name>.sol/<name>.json. When no artifact was written it fails the test if
  ///         ARTIFACTS_REQUIRED is true, and skips it otherwise.
  function _interfacesLoad(string memory _name) internal returns (string memory _json) {
    string memory _path = _interfacesArtifactPath(_name);
    if (!vm.exists(_path)) {
      string memory _reason = string.concat('no artifact at ', _path, ', run forge build first');
      if (vm.envOr('ARTIFACTS_REQUIRED', false)) fail(_reason);
      vm.skip(true, _reason);
    }
    _json = vm.readFile(_path);
  }

  /// @notice The artifact path forge writes for an interface declared in a file of its own name.
  function _interfacesArtifactPath(string memory _name) internal pure returns (string memory _path) {
    _path = string.concat('out/', _name, '.sol/', _name, '.json');
  }

  /// @notice Asserts the artifact's method identifiers are exactly the given signatures, each
  ///         mapped to the first four bytes of its keccak256, and nothing else.
  function _interfacesAssertMethodIdentifiers(string memory _json, string[] memory _signatures) internal view {
    string[] memory _keys = vm.parseJsonKeys(_json, '.methodIdentifiers');
    assertEq(_keys.length, _signatures.length, 'number of functions in the ABI');
    for (uint256 _i; _i < _signatures.length; ++_i) {
      string memory _path = string.concat('.methodIdentifiers[\'', _signatures[_i], '\']');
      assertTrue(vm.keyExistsJson(_json, _path), string.concat('missing function ', _signatures[_i]));
      assertEq(
        string.concat('0x', vm.parseJsonString(_json, _path)),
        vm.toString(abi.encodePacked(bytes4(keccak256(bytes(_signatures[_i]))))),
        _signatures[_i]
      );
    }
  }

  /// @notice The number of ABI entries of one kind: function, event or error.
  function _interfacesAbiCount(string memory _json, string memory _kind) internal view returns (uint256 _count) {
    for (uint256 _i; vm.keyExistsJson(_json, _interfacesEntry(_i, '')); ++_i) {
      if (_interfacesEq(vm.parseJsonString(_json, _interfacesEntry(_i, '.type')), _kind)) ++_count;
    }
  }

  /// @notice Asserts one function appears once, with the given mutability, parameters and
  ///         returns, each written as its internal type and name joined by commas.
  function _interfacesAssertFunction(
    string memory _json,
    string memory _name,
    string memory _mutability,
    string memory _inputs,
    string memory _outputs
  ) internal view {
    uint256 _index = _interfacesFind(_json, 'function', _name);
    assertEq(vm.parseJsonString(_json, _interfacesEntry(_index, '.stateMutability')), _mutability, _name);
    assertEq(_interfacesParams(_json, _index, '.inputs', false), _inputs, string.concat(_name, ' parameters'));
    assertEq(_interfacesParams(_json, _index, '.outputs', false), _outputs, string.concat(_name, ' returns'));
  }

  /// @notice Asserts one event appears once, with the given parameters and indexing.
  function _interfacesAssertEvent(string memory _json, string memory _name, string memory _inputs) internal view {
    uint256 _index = _interfacesFind(_json, 'event', _name);
    assertFalse(vm.parseJsonBool(_json, _interfacesEntry(_index, '.anonymous')), string.concat(_name, ' anonymous'));
    assertEq(_interfacesParams(_json, _index, '.inputs', true), _inputs, string.concat(_name, ' parameters'));
  }

  /// @notice Asserts one custom error appears once, with the given parameters, each written as its
  ///         internal type and name joined by commas.
  function _interfacesAssertError(string memory _json, string memory _name, string memory _inputs) internal view {
    uint256 _index = _interfacesFind(_json, 'error', _name);
    assertEq(_interfacesParams(_json, _index, '.inputs', false), _inputs, string.concat(_name, ' parameters'));
  }

  /// @notice Asserts the struct the artifact's contract declares under this name has exactly the
  ///         given members, each written as its type and name joined by commas, in declaration order.
  ///         Reads the AST, since the ABI lists a struct only where a function or event uses it.
  function _interfacesAssertStruct(string memory _json, string memory _name, string memory _members) internal view {
    string memory _struct = _interfacesFindNode(_json, 'StructDefinition', _name);
    string memory _joined;
    for (uint256 _k;; ++_k) {
      string memory _base = string.concat(_struct, '.members[', vm.toString(_k), ']');
      if (!vm.keyExistsJson(_json, _base)) break;
      string memory _item = string.concat(
        vm.parseJsonString(_json, string.concat(_base, '.typeDescriptions.typeString')),
        ' ',
        vm.parseJsonString(_json, string.concat(_base, '.name'))
      );
      _joined = _k == 0 ? _item : string.concat(_joined, ',', _item);
    }
    assertEq(_joined, _members, string.concat(_name, ' members'));
  }

  /// @notice The JSON path of the one AST node of this kind and name that a contract of the
  ///         artifact's source unit declares, failing on none or several.
  function _interfacesFindNode(string memory _json, string memory _kind, string memory _name)
    internal
    view
    returns (string memory _path)
  {
    uint256 _found;
    for (uint256 _i; vm.keyExistsJson(_json, string.concat('.ast.nodes[', vm.toString(_i), ']')); ++_i) {
      string memory _unit = string.concat('.ast.nodes[', vm.toString(_i), ']');
      if (!_interfacesEq(vm.parseJsonString(_json, string.concat(_unit, '.nodeType')), 'ContractDefinition')) continue;
      for (uint256 _j; vm.keyExistsJson(_json, string.concat(_unit, '.nodes[', vm.toString(_j), ']')); ++_j) {
        string memory _node = string.concat(_unit, '.nodes[', vm.toString(_j), ']');
        if (!_interfacesEq(vm.parseJsonString(_json, string.concat(_node, '.nodeType')), _kind)) continue;
        if (!_interfacesEq(vm.parseJsonString(_json, string.concat(_node, '.name')), _name)) continue;
        _path = _node;
        ++_found;
      }
    }
    assertEq(_found, 1, string.concat('occurrences of ', _kind, ' ', _name));
  }

  /// @notice The index of the one ABI entry of this kind and name, failing on none or several.
  function _interfacesFind(string memory _json, string memory _kind, string memory _name)
    internal
    view
    returns (uint256 _index)
  {
    uint256 _found;
    for (uint256 _i; vm.keyExistsJson(_json, _interfacesEntry(_i, '')); ++_i) {
      if (!_interfacesEq(vm.parseJsonString(_json, _interfacesEntry(_i, '.type')), _kind)) continue;
      if (!_interfacesEq(vm.parseJsonString(_json, _interfacesEntry(_i, '.name')), _name)) continue;
      _index = _i;
      ++_found;
    }
    assertEq(_found, 1, string.concat('occurrences of ', _kind, ' ', _name));
  }

  /// @notice Joins the parameters of one ABI entry as `internalType [indexed] name`, by commas.
  function _interfacesParams(string memory _json, uint256 _index, string memory _list, bool _withIndexed)
    internal
    view
    returns (string memory _joined)
  {
    for (uint256 _k;; ++_k) {
      string memory _base = _interfacesEntry(_index, string.concat(_list, '[', vm.toString(_k), ']'));
      if (!vm.keyExistsJson(_json, _base)) break;
      string memory _item = vm.parseJsonString(_json, string.concat(_base, '.internalType'));
      if (_withIndexed && vm.parseJsonBool(_json, string.concat(_base, '.indexed'))) {
        _item = string.concat(_item, ' indexed');
      }
      string memory _name = vm.parseJsonString(_json, string.concat(_base, '.name'));
      if (bytes(_name).length != 0) _item = string.concat(_item, ' ', _name);
      _joined = _k == 0 ? _item : string.concat(_joined, ',', _item);
    }
  }

  /// @notice The JSON path of one ABI entry, with an optional suffix.
  function _interfacesEntry(uint256 _index, string memory _suffix) internal pure returns (string memory _path) {
    _path = string.concat('.abi[', vm.toString(_index), ']', _suffix);
  }

  /// @notice Asserts a selector is the first four bytes of the keccak256 of its canonical signature.
  function _interfacesAssertSelector(bytes4 _actual, string memory _signature) internal pure {
    assertEq(_actual, bytes4(keccak256(bytes(_signature))), _signature);
  }

  /// @notice The canonical ABI tuple of AttemptRequest, its field types in declaration order, as a function
  ///         or event signature writes the struct.
  function _interfacesAttemptRequestTuple() internal pure returns (string memory _tuple) {
    _tuple = '(address,address,uint64,uint64,bytes,bytes,(address,uint256,address),uint48,(uint256,a'
      'ddress,bytes,bytes32,bytes)[])';
  }

  /// @notice The canonical ABI tuple of CancelRequest, its field types in declaration order, as a function
  ///         or event signature writes the struct.
  function _interfacesCancelRequestTuple() internal pure returns (string memory _tuple) {
    _tuple = '(address,address,uint64,uint64,bytes,uint48,(uint256,address,bytes,bytes32,bytes)[])';
  }

  /// @notice The canonical ABI tuple of Ambire's Transaction, its field types in declaration order, as a function
  ///         or event signature writes the struct.
  function _interfacesTransactionTuple() internal pure returns (string memory _tuple) {
    _tuple = '(address,uint256,bytes)';
  }

  /// @notice The canonical ABI tuple of PaymentOrder, its field types in declaration order, as a function
  ///         or event signature writes the struct.
  function _interfacesPaymentOrderTuple() internal pure returns (string memory _tuple) {
    _tuple = '(address,uint256,address)';
  }

  /// @notice Whether two strings are byte-equal.
  function _interfacesEq(string memory _a, string memory _b) internal pure returns (bool _equal) {
    _equal = keccak256(bytes(_a)) == keccak256(bytes(_b));
  }
}
