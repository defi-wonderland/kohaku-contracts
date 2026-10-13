// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {Test} from 'forge-std/Test.sol';
import {IPolicyMethod} from 'interfaces/IPolicyMethod.sol';

/// @notice Shared reading helpers for the replays of the method vector files. A vector file holds a `vectors` array,
///         and each row carries an `id`, an `input` object and an `expected` object.
abstract contract MethodKatBase is Test {
  string internal constant _VERDICT_FILE = 'test/fixtures/kats/method-verdict.json';
  string internal constant _ECDSA_CONFIG_FILE = 'test/fixtures/kats/method-ecdsa-config.json';
  string internal constant _ECDSA_PROOF_FILE = 'test/fixtures/kats/method-ecdsa-proof.json';
  string internal constant _PASSKEY_CONFIG_FILE = 'test/fixtures/kats/method-passkey-config.json';
  string internal constant _PASSKEY_PROOF_FILE = 'test/fixtures/kats/method-passkey-proof.json';

  /// @dev The id of the passkey config row whose key and relying party signed every passkey proof row.
  string internal constant _PASSKEY_CONFIG_ID = 'recover-example';

  /// @dev No row of the passkey config file carries the id the proof rows were signed under.
  error MethodKatBase_NoPasskeyConfig(string _id);

  /// @dev The JSON path of row `_i` of a vector file.
  function _rowPath(uint256 _i) internal pure returns (string memory _path) {
    _path = string.concat('.vectors[', vm.toString(_i), ']');
  }

  /// @dev The number of rows in a vector file.
  function _rowCount(string memory _json) internal view returns (uint256 _rows) {
    while (vm.keyExistsJson(_json, _rowPath(_rows))) ++_rows;
  }

  /// @dev The id of a row, used to name the row in every assertion message.
  function _rowId(string memory _json, string memory _row) internal pure returns (string memory _id) {
    _id = vm.parseJsonString(_json, string.concat(_row, '.id'));
  }

  /// @dev An assertion message naming the row and the field it checks.
  function _message(string memory _id, string memory _field) internal pure returns (string memory _text) {
    _text = string.concat(_id, ': ', _field);
  }

  /// @dev The ABI word the verdict vector freezes. The file must hold exactly one row, so no second row goes unread.
  function _vectorWord() internal view returns (bytes32 _word) {
    string memory _json = vm.readFile(_VERDICT_FILE);
    assertEq(_rowCount(_json), 1, 'the verdict file holds exactly one row');
    _word = vm.parseJsonBytes32(_json, '.vectors[0].expected.abiWord');
  }

  /// @dev The magic value the verdict vector freezes, as the selector of verify.
  function _vectorMagic() internal view returns (bytes4 _magic) {
    _magic = bytes4(_vectorWord());
  }

  /// @dev The encoded passkey config the proof rows were signed under, read from the config file by its id.
  function _passkeyConfig() internal view returns (bytes memory _config) {
    string memory _json = vm.readFile(_PASSKEY_CONFIG_FILE);
    uint256 _rows = _rowCount(_json);
    for (uint256 _i; _i < _rows; ++_i) {
      string memory _row = _rowPath(_i);
      if (keccak256(bytes(_rowId(_json, _row))) == keccak256(bytes(_PASSKEY_CONFIG_ID))) {
        return vm.parseJsonBytes(_json, string.concat(_row, '.expected.encoded'));
      }
    }
    revert MethodKatBase_NoPasskeyConfig(_PASSKEY_CONFIG_ID);
  }

  /// @dev Calls verify on `_method` as the manager does, with a static call, and returns the raw success flag and
  ///      returndata, so a replay can check the exact bytes the method answers.
  function _rawVerify(address _method, bytes memory _config, bytes32 _digest, bytes memory _proof)
    internal
    view
    returns (bool _success, bytes memory _returned)
  {
    (_success, _returned) = _method.staticcall(abi.encodeCall(IPolicyMethod.verify, (_config, _digest, _proof)));
  }
}
