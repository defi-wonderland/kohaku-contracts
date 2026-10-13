// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {Test} from 'forge-std/Test.sol';
import {Vm} from 'forge-std/Vm.sol';
import {IPolicyManager} from 'interfaces/IPolicyManager.sol';

/// @notice Shared readers for the vector replays of the manager's and the action's formats. Each helper reads a frozen
///         file under test/fixtures/kats and turns a row into the struct the kit takes, so the replays compare the
///         kit's bytes with the file's and embed no expected value. No helper computes an expected output.
abstract contract ManagerKatBase is Test {
  /// @notice A replay looked for a row the vector file does not carry.
  /// @param _file The vector file read.
  /// @param _id The row id looked for.
  error ManagerKatBase_NoRow(string _file, string _id);

  /// @notice A digest vector names a setup body hash that no setup-body or setup-commitment row hashes to.
  /// @param _bodyHash The hash looked for.
  error ManagerKatBase_NoVectorBody(bytes32 _bodyHash);

  string internal constant _APPROVAL_FILE = 'test/fixtures/kats/approval-digest.json';
  string internal constant _CANCELLATION_FILE = 'test/fixtures/kats/cancellation-digest.json';
  string internal constant _CREDENTIAL_COMMITMENT_FILE = 'test/fixtures/kats/credential-commitment.json';
  string internal constant _SETUP_COMMITMENT_FILE = 'test/fixtures/kats/setup-commitment.json';
  string internal constant _ATTEMPT_REQUEST_FILE = 'test/fixtures/kats/attempt-request.json';
  string internal constant _CANCEL_REQUEST_FILE = 'test/fixtures/kats/cancel-request.json';
  string internal constant _SETUP_BODY_FILE = 'test/fixtures/kats/setup-body.json';
  string internal constant _PAYMENT_ORDER_FILE = 'test/fixtures/kats/payment-order.json';
  string internal constant _PROOF_PLACE_FILE = 'test/fixtures/kats/proof-place.json';
  string internal constant _KIT_SLOT_FILE = 'test/fixtures/kats/ambire-kit-slot.json';
  string internal constant _HANDOVER_FILE = 'test/fixtures/kats/ambire-handover.json';
  string internal constant _MANAGER_EVENTS_FILE = 'test/fixtures/kats/manager-events.json';
  string internal constant _METHOD_EVENTS_FILE = 'test/fixtures/kats/method-events.json';

  /*///////////////////////////////////////////////////////////////
                               ROWS
  ///////////////////////////////////////////////////////////////*/

  /// @notice The JSON path of row `_i` of a vector file.
  function _rowPath(uint256 _i) internal pure returns (string memory _path) {
    _path = string.concat('.vectors[', vm.toString(_i), ']');
  }

  /// @notice The number of rows in a vector file.
  function _rowCount(string memory _json) internal view returns (uint256 _rows) {
    while (vm.keyExistsJson(_json, _rowPath(_rows))) ++_rows;
  }

  /// @notice The id of the row at `_row`, used to name the row in every assertion message.
  function _rowId(string memory _json, string memory _row) internal pure returns (string memory _id) {
    _id = vm.parseJsonString(_json, string.concat(_row, '.id'));
  }

  /// @notice An assertion message naming the field and the row it was read from.
  function _what(string memory _field, string memory _id) internal pure returns (string memory _message) {
    _message = string.concat(_field, ' of row ', _id);
  }

  /// @notice The path of the row whose id is `_id`, failing the test when the file carries none.
  function _rowWithId(string memory _file, string memory _json, string memory _id)
    internal
    view
    returns (string memory _row)
  {
    uint256 _i;
    while (vm.keyExistsJson(_json, _rowPath(_i))) {
      _row = _rowPath(_i);
      if (keccak256(bytes(_rowId(_json, _row))) == keccak256(bytes(_id))) return _row;
      ++_i;
    }
    revert ManagerKatBase_NoRow(_file, _id);
  }

  /*///////////////////////////////////////////////////////////////
                            FIELD READERS
  ///////////////////////////////////////////////////////////////*/

  /// @notice Reads a decimal string or number at `_key` as a uint64, failing when it is wider.
  function _uint64At(string memory _json, string memory _key) internal pure returns (uint64 _value) {
    uint256 _raw = vm.parseJsonUint(_json, _key);
    assertLe(_raw, type(uint64).max, string.concat(_key, ' wider than uint64'));
    // casting to 'uint64' is safe because the previous line bounds it
    // forge-lint: disable-next-line(unsafe-typecast)
    _value = uint64(_raw);
  }

  /// @notice Reads a decimal string or number at `_key` as a uint48, failing when it is wider.
  function _uint48At(string memory _json, string memory _key) internal pure returns (uint48 _value) {
    uint256 _raw = vm.parseJsonUint(_json, _key);
    assertLe(_raw, type(uint48).max, string.concat(_key, ' wider than uint48'));
    // casting to 'uint48' is safe because the previous line bounds it
    // forge-lint: disable-next-line(unsafe-typecast)
    _value = uint48(_raw);
  }

  /// @notice Reads the payment order object at `_path`.
  function _orderAt(string memory _json, string memory _path)
    internal
    pure
    returns (IPolicyManager.PaymentOrder memory _order)
  {
    _order = IPolicyManager.PaymentOrder({
      token: vm.parseJsonAddress(_json, string.concat(_path, '.token')),
      amount: vm.parseJsonUint(_json, string.concat(_path, '.amount')),
      payee: vm.parseJsonAddress(_json, string.concat(_path, '.payee'))
    });
  }

  /// @notice Reads the proof place object at `_path`.
  function _proofAt(string memory _json, string memory _path)
    internal
    pure
    returns (IPolicyManager.ProofPlace memory _proof)
  {
    _proof = IPolicyManager.ProofPlace({
      place: vm.parseJsonUint(_json, string.concat(_path, '.place')),
      method: vm.parseJsonAddress(_json, string.concat(_path, '.method')),
      config: vm.parseJsonBytes(_json, string.concat(_path, '.config')),
      salt: vm.parseJsonBytes32(_json, string.concat(_path, '.salt')),
      proof: vm.parseJsonBytes(_json, string.concat(_path, '.proof'))
    });
  }

  /// @notice Reads the array of proof place objects at `_path`, in file order.
  function _proofsAt(string memory _json, string memory _path)
    internal
    view
    returns (IPolicyManager.ProofPlace[] memory _proofs)
  {
    uint256 _n;
    while (vm.keyExistsJson(_json, string.concat(_path, '[', vm.toString(_n), ']'))) ++_n;
    _proofs = new IPolicyManager.ProofPlace[](_n);
    for (uint256 _i; _i < _n; ++_i) {
      _proofs[_i] = _proofAt(_json, string.concat(_path, '[', vm.toString(_i), ']'));
    }
  }

  /// @notice Reads the attempt request whose fields sit under `_input`, the shape attempt-request.json writes. A
  ///         field the file leaves out stays zero.
  function _attemptRequestAt(string memory _json, string memory _input)
    internal
    view
    returns (IPolicyManager.AttemptRequest memory _request)
  {
    _request.account = vm.parseJsonAddress(_json, string.concat(_input, '.account'));
    _request.action = vm.parseJsonAddress(_json, string.concat(_input, '.action'));
    _request.attemptId = _uint64At(_json, string.concat(_input, '.attemptId'));
    _request.setupNonce = _uint64At(_json, string.concat(_input, '.setupNonce'));
    _request.setupBody = vm.parseJsonBytes(_json, string.concat(_input, '.setupBody'));
    _request.payload = vm.parseJsonBytes(_json, string.concat(_input, '.payload'));
    _request.order = _orderAt(_json, string.concat(_input, '.order'));
    if (vm.keyExistsJson(_json, string.concat(_input, '.validUntil'))) {
      _request.validUntil = _uint48At(_json, string.concat(_input, '.validUntil'));
    }
    if (vm.keyExistsJson(_json, string.concat(_input, '.proofs'))) {
      _request.proofs = _proofsAt(_json, string.concat(_input, '.proofs'));
    }
  }

  /// @notice Reads the cancellation request whose fields sit under `_input`, the shape cancel-request.json writes.
  function _cancelRequestAt(string memory _json, string memory _input)
    internal
    view
    returns (IPolicyManager.CancelRequest memory _request)
  {
    _request.account = vm.parseJsonAddress(_json, string.concat(_input, '.account'));
    _request.action = vm.parseJsonAddress(_json, string.concat(_input, '.action'));
    _request.attemptId = _uint64At(_json, string.concat(_input, '.attemptId'));
    _request.setupNonce = _uint64At(_json, string.concat(_input, '.setupNonce'));
    _request.setupBody = vm.parseJsonBytes(_json, string.concat(_input, '.setupBody'));
    _request.validUntil = _uint48At(_json, string.concat(_input, '.validUntil'));
    _request.proofs = _proofsAt(_json, string.concat(_input, '.proofs'));
  }

  /// @notice The digest vectors freeze only the setup body's hash, while the manager takes the body and hashes it.
  ///         The corpus derives its digests from the same bodies as the setup-body and setup-commitment rows, so
  ///         this returns the body from those files whose keccak256 is `_bodyHash`.
  function _bodyHashingTo(bytes32 _bodyHash) internal view returns (bytes memory _body) {
    string[2] memory _files = [_SETUP_COMMITMENT_FILE, _SETUP_BODY_FILE];
    string[2] memory _keys = ['.input.setupBody', '.expected.encoded'];
    for (uint256 _f; _f < _files.length; ++_f) {
      string memory _json = vm.readFile(_files[_f]);
      uint256 _rows = _rowCount(_json);
      for (uint256 _i; _i < _rows; ++_i) {
        bytes memory _candidate = vm.parseJsonBytes(_json, string.concat(_rowPath(_i), _keys[_f]));
        if (keccak256(_candidate) == _bodyHash) return _candidate;
      }
    }
    revert ManagerKatBase_NoVectorBody(_bodyHash);
  }

  /// @notice The setup commitment row whose input is this account, action, nonce and body, read from
  ///         setup-commitment.json, so a replay that needs a stored commitment takes the frozen one.
  function _setupCommitmentOf(address _account, address _action, uint64 _nonce, bytes memory _body)
    internal
    view
    returns (bytes32 _commitment)
  {
    string memory _json = vm.readFile(_SETUP_COMMITMENT_FILE);
    uint256 _rows = _rowCount(_json);
    for (uint256 _i; _i < _rows; ++_i) {
      string memory _in = string.concat(_rowPath(_i), '.input');
      if (
        vm.parseJsonAddress(_json, string.concat(_in, '.account')) == _account
          && vm.parseJsonAddress(_json, string.concat(_in, '.action')) == _action
          && _uint64At(_json, string.concat(_in, '.nonce')) == _nonce
          && keccak256(vm.parseJsonBytes(_json, string.concat(_in, '.setupBody'))) == keccak256(_body)
      ) return vm.parseJsonBytes32(_json, string.concat(_rowPath(_i), '.expected.commitment'));
    }
    revert ManagerKatBase_NoRow(_SETUP_COMMITMENT_FILE, 'matching account, action, nonce and body');
  }

  /*///////////////////////////////////////////////////////////////
                               LOGS
  ///////////////////////////////////////////////////////////////*/

  /// @notice Takes the logs recorded since `vm.recordLogs`, requires exactly one, emitted by `_emitter`, and
  ///         compares its topics and data byte for byte with the row's `expected.topics` and `expected.data`.
  function _assertOnlyLogMatches(string memory _json, string memory _row, address _emitter) internal view {
    string memory _id = _rowId(_json, _row);
    Vm.Log[] memory _logs = vm.getRecordedLogs();
    assertEq(_logs.length, 1, _what('log count', _id));
    assertEq(_logs[0].emitter, _emitter, _what('emitter', _id));
    bytes32[] memory _topics = vm.parseJsonBytes32Array(_json, string.concat(_row, '.expected.topics'));
    assertEq(_logs[0].topics.length, _topics.length, _what('topic count', _id));
    for (uint256 _t; _t < _topics.length; ++_t) {
      assertEq(_logs[0].topics[_t], _topics[_t], _what(string.concat('topic ', vm.toString(_t)), _id));
    }
    assertEq(_logs[0].data, vm.parseJsonBytes(_json, string.concat(_row, '.expected.data')), _what('data', _id));
  }
}
