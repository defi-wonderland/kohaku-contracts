// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {IPolicyManager} from 'interfaces/IPolicyManager.sol';
import {SetupBodyTestBase, SetupBodyTestClause} from 'test/utils/SetupBodyTestBase.sol';

/// @notice Reads the frozen `test/fixtures/kats/setup-body.json` bytes with the setup body readers: every expected
///         encoding must read back as the vector's own input. The offchain SDK replays the same vectors, so this checks
///         that the contracts read a client's body the way the client meant it. Tree: SetupBodyKat.tree.
contract SetupBodyKatTest is SetupBodyTestBase {
  string internal constant _KAT_PATH = 'test/fixtures/kats/setup-body.json';

  string internal _json;

  /// Loads the frozen setup body vectors.
  function setUp() public override {
    super.setUp();
    _json = vm.readFile(string.concat(vm.projectRoot(), '/', _KAT_PATH));
  }

  /// Checks that every frozen body reads back its wait, its `ignoresPause` value and every credential at its
  /// place, and that the first place past the end reverts. A mismatch means a client's body and the contract disagree.
  function test_WhenReadingBackEveryVectorsEncoding() external {
    // it should return the vector's wait, pause choice and every credential at its place, and revert one place past
    // the end.
    uint256 _vectors = _vectorCount();
    assertGt(_vectors, 0, 'no vectors read');
    for (uint256 _v = 0; _v < _vectors; _v++) {
      string memory _vectorPath = _base(_v);
      bytes memory _encoded = vm.parseJsonBytes(_json, string.concat(_vectorPath, '.expected.encoded'));
      uint256 _wait = vm.parseUint(vm.parseJsonString(_json, string.concat(_vectorPath, '.input.wait')));
      bool _ignoresPause = vm.parseJsonBool(_json, string.concat(_vectorPath, '.input.ignoresPause'));
      SetupBodyTestClause[] memory _clauses = _clausesOf(_vectorPath);

      assertEq(uint256(_harness.waitOf(_encoded)), _wait, 'wait');
      assertEq(_harness.ignoresPauseOf(_encoded), _ignoresPause, 'ignoresPause');
      uint256 _place;
      for (uint256 _i = 0; _i < _clauses.length; _i++) {
        for (uint256 _j = 0; _j < _clauses[_i].credentials.length; _j++) {
          assertEq(_harness.credentialAt(_encoded, _place), _clauses[_i].credentials[_j], 'credential');
          _place++;
        }
      }
      vm.expectRevert(abi.encodeWithSelector(IPolicyManager.PolicyManager_PlaceOutOfRange.selector, _place, _place));
      _harness.credentialAt(_encoded, _place);
    }
  }

  /// Checks that `decode` reads every frozen body back as the vector's own input: its wait, its `ignoresPause` value
  /// and every clause with its threshold and credentials in order, and that reading each place from the decoded
  /// clauses returns the credential written there. A caller that decodes once must see the rule the client meant.
  function test_WhenDecodingEveryVectorsEncoding() external view {
    // it should return the vector's wait, pause choice and clauses, and every credential at its place from the decoded
    // clauses.
    uint256 _vectors = _vectorCount();
    assertGt(_vectors, 0, 'no vectors read');
    for (uint256 _v = 0; _v < _vectors; _v++) {
      string memory _vectorPath = _base(_v);
      bytes memory _encoded = vm.parseJsonBytes(_json, string.concat(_vectorPath, '.expected.encoded'));
      uint256 _wait = vm.parseUint(vm.parseJsonString(_json, string.concat(_vectorPath, '.input.wait')));
      bool _ignoresPause = vm.parseJsonBool(_json, string.concat(_vectorPath, '.input.ignoresPause'));
      SetupBodyTestClause[] memory _clauses = _clausesOf(_vectorPath);

      (uint48 _gotWait, bool _gotIgnoresPause, IPolicyManager.Clause[] memory _decoded) = _harness.decode(_encoded);
      assertEq(uint256(_gotWait), _wait, 'wait');
      assertEq(_gotIgnoresPause, _ignoresPause, 'ignoresPause');
      _assertSameClauses(_decoded, _clauses);
      uint256 _place;
      for (uint256 _i = 0; _i < _clauses.length; _i++) {
        for (uint256 _j = 0; _j < _clauses[_i].credentials.length; _j++) {
          assertEq(_harness.credentialAt(_decoded, _place), _clauses[_i].credentials[_j], 'credential');
          _place++;
        }
      }
    }
  }

  /// Checks that every frozen body fails naming clause zero when no place is filled. In each vector the first clause
  /// needs at least one place, or there is no clause, so a request with no proof must never open a recovery from a
  /// body a client produced.
  function test_WhenNoPlaceOfAnyVectorIsFilled() external view {
    // it should fail naming clause zero.
    uint256 _vectors = _vectorCount();
    assertGt(_vectors, 0, 'no vectors read');
    for (uint256 _v = 0; _v < _vectors; _v++) {
      (bool _satisfied, uint256 _failingClause) = _rule(_encodedOf(_v), _none());
      assertFalse(_satisfied, 'satisfied');
      assertEq(_failingClause, 0, 'failing clause');
    }
  }

  /// Checks that the frozen two clause body, a one of one clause and a two of three clause, is met when every place
  /// is filled, naming no failing clause. A client's ordinary rule must open a recovery once all its guardians prove.
  function test_WhenEveryPlaceOfTheTwoClauseVectorIsFilled() external view {
    // it should return true naming no failing clause.
    uint256 _v = _vectorIndex('two-clauses');
    (bool _satisfied, uint256 _failingClause) = _rule(_encodedOf(_v), _range(0, _placeCount(_clausesOf(_base(_v)))));
    assertTrue(_satisfied, 'satisfied');
    assertEq(_failingClause, 0, 'failing clause beside a satisfied rule');
  }

  /// Checks that the frozen body with no clauses fails naming clause zero even with a place filled past its end. An
  /// empty rule must never open a recovery.
  function test_WhenAPlaceIsFilledPastTheEndOfTheEmptyClausesVector() external view {
    // it should fail naming clause zero.
    (bool _satisfied, uint256 _failingClause) = _rule(_encodedOf(_vectorIndex('empty-clauses')), _places(0));
    assertFalse(_satisfied, 'satisfied');
    assertEq(_failingClause, 0, 'failing clause');
  }

  /// Checks that the test-side encoder every unit and fuzz test uses reproduces each frozen encoding. If it did not,
  /// the other tests would be feeding the library bodies no client ever produces.
  function test_WhenTheTestEncoderEncodesEveryVectorsInput() external view {
    // it should reproduce the expected encoding.
    uint256 _vectors = _vectorCount();
    assertGt(_vectors, 0, 'no vectors read');
    for (uint256 _v = 0; _v < _vectors; _v++) {
      string memory _vectorPath = _base(_v);
      bytes memory _encoded = vm.parseJsonBytes(_json, string.concat(_vectorPath, '.expected.encoded'));
      uint256 _wait = vm.parseUint(vm.parseJsonString(_json, string.concat(_vectorPath, '.input.wait')));
      bool _ignoresPause = vm.parseJsonBool(_json, string.concat(_vectorPath, '.input.ignoresPause'));
      assertLe(_wait, type(uint48).max, 'wait wider than uint48');
      // casting to 'uint48' is safe because the previous line bounds it
      // forge-lint: disable-next-line(unsafe-typecast)
      assertEq(_encode(uint48(_wait), _ignoresPause, _clausesOf(_vectorPath)), _encoded);
    }
  }

  /// Checks that the library's own encoder, `SetupBody.encode`, reproduces each frozen encoding from the vector's
  /// input. Tests and replays build bodies with it, so a drift would make them build bodies the readers and the SDK
  /// disagree on.
  function test_WhenTheLibraryEncoderEncodesEveryVectorsInput() external view {
    // it should reproduce the expected encoding.
    uint256 _vectors = _vectorCount();
    assertGt(_vectors, 0, 'no vectors read');
    for (uint256 _v = 0; _v < _vectors; _v++) {
      string memory _vectorPath = _base(_v);
      bytes memory _encoded = vm.parseJsonBytes(_json, string.concat(_vectorPath, '.expected.encoded'));
      uint256 _wait = vm.parseUint(vm.parseJsonString(_json, string.concat(_vectorPath, '.input.wait')));
      bool _ignoresPause = vm.parseJsonBool(_json, string.concat(_vectorPath, '.input.ignoresPause'));
      SetupBodyTestClause[] memory _testClauses = _clausesOf(_vectorPath);
      IPolicyManager.Clause[] memory _clauses = new IPolicyManager.Clause[](_testClauses.length);
      for (uint256 _i = 0; _i < _testClauses.length; _i++) {
        _clauses[_i] =
          IPolicyManager.Clause({threshold: _testClauses[_i].threshold, credentials: _testClauses[_i].credentials});
      }
      assertLe(_wait, type(uint48).max, 'wait wider than uint48');
      // casting to 'uint48' is safe because the previous line bounds it
      // forge-lint: disable-next-line(unsafe-typecast)
      assertEq(_harness.encode(uint48(_wait), _ignoresPause, _clauses), _encoded, 'library encoding');
    }
  }

  /*///////////////////////////////////////////////////////////////
                               HELPERS
  ///////////////////////////////////////////////////////////////*/

  /// Returns the JSON path of vector `_v`.
  function _base(uint256 _v) internal pure returns (string memory _vectorPath) {
    _vectorPath = string.concat('.vectors[', vm.toString(_v), ']');
  }

  /// Returns the number of vectors in the file.
  function _vectorCount() internal view returns (uint256 _n) {
    while (vm.keyExistsJson(_json, string.concat('.vectors[', vm.toString(_n), ']'))) _n++;
  }

  /// Returns the index of the vector whose `id` is `_id`, failing the test when no vector carries it.
  function _vectorIndex(string memory _id) internal view returns (uint256 _v) {
    uint256 _vectors = _vectorCount();
    for (_v = 0; _v < _vectors; _v++) {
      if (keccak256(bytes(vm.parseJsonString(_json, string.concat(_base(_v), '.id')))) == keccak256(bytes(_id))) {
        return _v;
      }
    }
    revert(string.concat('no vector ', _id));
  }

  /// Returns vector `_v`'s frozen encoding.
  function _encodedOf(uint256 _v) internal view returns (bytes memory _encoded) {
    _encoded = vm.parseJsonBytes(_json, string.concat(_base(_v), '.expected.encoded'));
  }

  /// Parses one vector's input clauses into test clauses.
  function _clausesOf(string memory _vectorPath) internal view returns (SetupBodyTestClause[] memory _clauses) {
    uint256 _n;
    while (vm.keyExistsJson(_json, string.concat(_vectorPath, '.input.clauses[', vm.toString(_n), ']'))) _n++;
    _clauses = new SetupBodyTestClause[](_n);
    for (uint256 _i = 0; _i < _n; _i++) {
      string memory _c = string.concat(_vectorPath, '.input.clauses[', vm.toString(_i), ']');
      uint256 _threshold = vm.parseJsonUint(_json, string.concat(_c, '.threshold'));
      assertLe(_threshold, type(uint8).max, 'threshold wider than uint8');
      // casting to 'uint8' is safe because the previous line bounds it
      // forge-lint: disable-next-line(unsafe-typecast)
      _clauses[_i].threshold = uint8(_threshold);
      _clauses[_i].credentials = vm.parseJsonBytes32Array(_json, string.concat(_c, '.credentials'));
    }
  }
}
