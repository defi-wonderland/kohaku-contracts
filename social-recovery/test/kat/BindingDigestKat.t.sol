// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {Test} from 'forge-std/Test.sol';
import {IPolicyManager} from 'interfaces/IPolicyManager.sol';
import {BindingDigestHarness} from 'test/utils/BindingDigestHarness.sol';

/// @notice Replays the frozen digest and commitment vectors through the binding digest library itself. Every expected
///         value is read from test/fixtures/kats and none is embedded. The vectors are what the SDK also replays, so a
///         byte the library encodes differently from the SDK fails here, whatever the property tests say. Each test
///         reads every row of its file. Tree: BindingDigestKat.tree.
contract BindingDigestKatTest is Test {
  /// @dev No setup-body or setup-commitment vector body hashes to a digest vector's setupBodyHash.
  error BindingDigestKatTest_NoVectorBody(bytes32 _bodyHash);

  string internal constant _APPROVAL_FILE = 'test/fixtures/kats/approval-digest.json';
  string internal constant _CANCELLATION_FILE = 'test/fixtures/kats/cancellation-digest.json';
  string internal constant _SETUP_COMMITMENT_FILE = 'test/fixtures/kats/setup-commitment.json';
  string internal constant _CREDENTIAL_COMMITMENT_FILE = 'test/fixtures/kats/credential-commitment.json';
  string internal constant _SETUP_BODY_FILE = 'test/fixtures/kats/setup-body.json';

  BindingDigestHarness internal _harness;

  /// @dev Deploys the harness that exposes the library as external calls.
  function setUp() external {
    _harness = new BindingDigestHarness();
  }

  /// Every approval digest vector is reproduced, under the library's own separator for the vector's chain and
  /// manager. The library reads the chain id of the chain running the call, so each row first moves the test to the
  /// vector's chain. This fixes the Approval and PaymentOrder type strings, the nested order hash and the domain byte
  /// for byte, including the empty and maximum rows.
  function test_WhenReplayingTheApprovalDigestVectors() external {
    // it should reproduce every expected digest.
    string memory _json = vm.readFile(_APPROVAL_FILE);
    uint256 _rows = _rowCount(_json);
    assertGt(_rows, 0, 'no approval vector');
    for (uint256 _i; _i < _rows; ++_i) {
      string memory _row = _rowPath(_i);
      bytes32 _separator = _domainOf(_json, _row);

      IPolicyManager.AttemptRequest memory _request;
      string memory _message = string.concat(_row, '.input.message');
      _request.account = vm.parseJsonAddress(_json, string.concat(_message, '.account'));
      _request.action = vm.parseJsonAddress(_json, string.concat(_message, '.action'));
      _request.attemptId = uint64(vm.parseJsonUint(_json, string.concat(_message, '.attemptId')));
      _request.setupNonce = uint64(vm.parseJsonUint(_json, string.concat(_message, '.setupNonce')));
      _request.setupBody = _bodyHashingTo(vm.parseJsonBytes32(_json, string.concat(_message, '.setupBodyHash')));
      _request.payload = vm.parseJsonBytes(_json, string.concat(_message, '.payload'));
      _request.order = IPolicyManager.PaymentOrder({
        token: vm.parseJsonAddress(_json, string.concat(_message, '.order.token')),
        amount: vm.parseJsonUint(_json, string.concat(_message, '.order.amount')),
        payee: vm.parseJsonAddress(_json, string.concat(_message, '.order.payee'))
      });
      _request.validUntil = uint48(vm.parseJsonUint(_json, string.concat(_message, '.validUntil')));
      uint256 _place = vm.parseJsonUint(_json, string.concat(_message, '.place'));
      bytes32 _expected = vm.parseJsonBytes32(_json, string.concat(_row, '.expected.digest'));

      // The library's digest under the library's own separator.
      assertEq(_harness.approvalDigest(_separator, _request, _place), _expected, 'approval digest vector');
    }
  }

  /// Every cancellation digest vector is reproduced, each under the vector's own chain, which fixes the Cancellation
  /// type string byte for byte, including the empty body and maximum rows.
  function test_WhenReplayingTheCancellationDigestVectors() external {
    // it should reproduce every expected digest.
    string memory _json = vm.readFile(_CANCELLATION_FILE);
    uint256 _rows = _rowCount(_json);
    assertGt(_rows, 0, 'no cancellation vector');
    for (uint256 _i; _i < _rows; ++_i) {
      string memory _row = _rowPath(_i);
      bytes32 _separator = _domainOf(_json, _row);

      IPolicyManager.CancelRequest memory _request;
      string memory _message = string.concat(_row, '.input.message');
      _request.account = vm.parseJsonAddress(_json, string.concat(_message, '.account'));
      _request.action = vm.parseJsonAddress(_json, string.concat(_message, '.action'));
      _request.attemptId = uint64(vm.parseJsonUint(_json, string.concat(_message, '.attemptId')));
      _request.setupNonce = uint64(vm.parseJsonUint(_json, string.concat(_message, '.setupNonce')));
      _request.setupBody = _bodyHashingTo(vm.parseJsonBytes32(_json, string.concat(_message, '.setupBodyHash')));
      _request.validUntil = uint48(vm.parseJsonUint(_json, string.concat(_message, '.validUntil')));
      uint256 _place = vm.parseJsonUint(_json, string.concat(_message, '.place'));
      bytes32 _expected = vm.parseJsonBytes32(_json, string.concat(_row, '.expected.digest'));

      assertEq(_harness.cancelDigest(_separator, _request, _place), _expected, 'cancellation digest vector');
    }
  }

  /// Every setup commitment vector is reproduced. The vectors freeze keccak256 over the abi.encode of account,
  /// action, nonce and body, so an encodePacked preimage fails here.
  function test_WhenReplayingTheSetupCommitmentVectors() external view {
    string memory _json = vm.readFile(_SETUP_COMMITMENT_FILE);
    uint256 _rows = _rowCount(_json);
    assertGt(_rows, 0, 'no setup commitment vector');
    for (uint256 _i; _i < _rows; ++_i) {
      string memory _row = _rowPath(_i);
      address _account = vm.parseJsonAddress(_json, string.concat(_row, '.input.account'));
      address _action = vm.parseJsonAddress(_json, string.concat(_row, '.input.action'));
      uint64 _nonce = uint64(vm.parseJsonUint(_json, string.concat(_row, '.input.nonce')));
      bytes memory _body = vm.parseJsonBytes(_json, string.concat(_row, '.input.setupBody'));

      // it should reproduce every expected commitment.
      assertEq(
        _harness.setupCommitment(_account, _action, _nonce, _body),
        vm.parseJsonBytes32(_json, string.concat(_row, '.expected.commitment')),
        'setup commitment vector'
      );
    }
  }

  /// Every credential commitment vector is reproduced, the zero method, empty config and zero salt row included. The
  /// vectors freeze keccak256 over the abi.encode of method, config and salt, and the zero row shows a zero salt is
  /// hashed as supplied, with no default put in.
  function test_WhenReplayingTheCredentialCommitmentVectors() external view {
    string memory _json = vm.readFile(_CREDENTIAL_COMMITMENT_FILE);
    uint256 _rows = _rowCount(_json);
    assertGt(_rows, 0, 'no credential commitment vector');
    for (uint256 _i; _i < _rows; ++_i) {
      string memory _row = _rowPath(_i);
      address _method = vm.parseJsonAddress(_json, string.concat(_row, '.input.method'));
      bytes memory _config = vm.parseJsonBytes(_json, string.concat(_row, '.input.config'));
      bytes32 _salt = vm.parseJsonBytes32(_json, string.concat(_row, '.input.salt'));

      // it should reproduce every expected commitment.
      assertEq(
        _harness.credentialCommitment(_method, _config, _salt),
        vm.parseJsonBytes32(_json, string.concat(_row, '.expected.commitment')),
        'credential commitment vector'
      );
    }
  }

  /*///////////////////////////////////////////////////////////////
                               HELPERS
  ///////////////////////////////////////////////////////////////*/

  /// @dev The JSON path of row `_i` of a vector file.
  function _rowPath(uint256 _i) internal pure returns (string memory _path) {
    _path = string.concat('.vectors[', vm.toString(_i), ']');
  }

  /// @dev The number of rows in a vector file.
  function _rowCount(string memory _json) internal view returns (uint256 _rows) {
    while (vm.keyExistsJson(_json, _rowPath(_rows))) ++_rows;
  }

  /// @dev Checks the vector's domain version is the library's DIGEST_VERSION, moves the test to the vector's chain
  ///      with `vm.chainId`, and returns the library's own separator on that chain for the vector's manager.
  function _domainOf(string memory _json, string memory _row) internal returns (bytes32 _separator) {
    string memory _domain = string.concat(_row, '.input.domain');
    assertEq(
      vm.parseJsonString(_json, string.concat(_domain, '.version')), _harness.digestVersion(), 'vector domain version'
    );
    vm.chainId(vm.parseJsonUint(_json, string.concat(_domain, '.chainId')));
    _separator = _harness.domainSeparator(vm.parseJsonAddress(_json, string.concat(_domain, '.verifyingContract')));
  }

  /// @dev The digest vectors freeze setupBodyHash, while the library takes the body and hashes it. The vector corpus
  ///      derives its digests from the same bodies as the setup-body and setup-commitment vectors, so this returns
  ///      the body from those files whose hash matches.
  function _bodyHashingTo(bytes32 _bodyHash) internal view returns (bytes memory _body) {
    string[2] memory _files = [_SETUP_COMMITMENT_FILE, _SETUP_BODY_FILE];
    string[2] memory _keys = ['.input.setupBody', '.expected.encoded'];
    for (uint256 _f; _f < _files.length; ++_f) {
      string memory _json = vm.readFile(_files[_f]);
      uint256 _rows = _rowCount(_json);
      for (uint256 _i; _i < _rows; ++_i) {
        string memory _key = string.concat(_rowPath(_i), _keys[_f]);
        if (!vm.keyExistsJson(_json, _key)) continue;
        bytes memory _candidate = vm.parseJsonBytes(_json, _key);
        if (keccak256(_candidate) == _bodyHash) return _candidate;
      }
    }
    revert BindingDigestKatTest_NoVectorBody(_bodyHash);
  }
}
