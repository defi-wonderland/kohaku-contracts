// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {Test} from 'forge-std/Test.sol';
import {IPolicyManager} from 'interfaces/IPolicyManager.sol';
import {SetupBodyHarness} from 'test/utils/SetupBodyHarness.sol';

/// @notice One clause of a setup body: `(uint8 threshold, bytes32[] credentials)`, meaning any `threshold` of these
///         credentials. Declared on the test side, so the tests encode bodies without the library's own types.
struct SetupBodyTestClause {
  uint8 threshold;
  bytes32[] credentials;
}

/// @notice Shared setup for the setup body tests. It holds an independent encoder for
///         `abi.encode(uint48 wait, bool ignoresPause, Clause[] clauses)` and the input builders the tests share.
///         Terms the tests use:
///         - a place is the flat index of a credential across all clauses in body order, so place 0 is the first
///           credential of the first clause and the numbering runs on into the next clause;
///         - a filled place is a place the caller hands `ruleSatisfied` as verified;
///         - a zero clause is a clause whose threshold is zero;
///         - a `_seed` is a fuzz parameter from which a builder derives a random body, so one number fixes every
///           clause count, threshold and credential of that body;
///         - `_randomClauses` builds up to a given number of clauses, possibly none, with thresholds up to one past
///           each clause's credential count; `_randomClausesWithAPlace` builds at least one clause and at least one
///           place; `_reachableClauses` builds clauses whose thresholds never exceed their credential counts, with
///           one named clause with a threshold greater than zero;
///         - `_placeCount` is the body's number of places, `_clauseStart` the first place of a clause, and
///           `_fillAllBut` fills every place except those of one clause, of which it fills a chosen number.
///         The builders only arrange inputs. No helper computes the answer a reader should give.
abstract contract SetupBodyTestBase is Test {
  SetupBodyHarness internal _harness;

  /// @dev Deploys the harness that exposes the library's readers as external calls.
  function setUp() public virtual {
    _harness = new SetupBodyHarness();
  }

  /*///////////////////////////////////////////////////////////////
                              ENCODING
  ///////////////////////////////////////////////////////////////*/

  /// @dev Encodes a body the way a client does, with plain `abi.encode`.
  function _encode(uint48 _wait, bool _ignoresPause, SetupBodyTestClause[] memory _clauses)
    internal
    pure
    returns (bytes memory _setupBody)
  {
    _setupBody = abi.encode(_wait, _ignoresPause, _clauses);
  }

  /// @dev Encodes a body with a two day wait and `ignoresPause` false, for tests that only care about the clauses.
  function _body(SetupBodyTestClause[] memory _clauses) internal pure returns (bytes memory _setupBody) {
    _setupBody = _encode(2 days, false, _clauses);
  }

  /// @dev An empty clause list.
  function _noClauses() internal pure returns (SetupBodyTestClause[] memory _clauses) {
    _clauses = new SetupBodyTestClause[](0);
  }

  /// @dev A clause whose credentials are distinct words tagged by `_tag`, so every place is recognizable.
  function _clause(uint8 _threshold, uint256 _count, uint256 _tag)
    internal
    pure
    returns (SetupBodyTestClause memory _newClause)
  {
    _newClause.threshold = _threshold;
    _newClause.credentials = new bytes32[](_count);
    for (uint256 _i = 0; _i < _count; _i++) {
      _newClause.credentials[_i] = keccak256(abi.encode('setup-body-credential', _tag, _i));
    }
  }

  /// @dev A clause list holding one clause.
  function _one(SetupBodyTestClause memory _a) internal pure returns (SetupBodyTestClause[] memory _clauses) {
    _clauses = new SetupBodyTestClause[](1);
    _clauses[0] = _a;
  }

  /// @dev A clause list holding two clauses, in the order given.
  function _two(SetupBodyTestClause memory _a, SetupBodyTestClause memory _b)
    internal
    pure
    returns (SetupBodyTestClause[] memory _clauses)
  {
    _clauses = new SetupBodyTestClause[](2);
    _clauses[0] = _a;
    _clauses[1] = _b;
  }

  /// @dev A clause list holding three clauses, in the order given.
  function _three(SetupBodyTestClause memory _a, SetupBodyTestClause memory _b, SetupBodyTestClause memory _c)
    internal
    pure
    returns (SetupBodyTestClause[] memory _clauses)
  {
    _clauses = new SetupBodyTestClause[](3);
    _clauses[0] = _a;
    _clauses[1] = _b;
    _clauses[2] = _c;
  }

  /// @dev The same clauses as the library's `Clause` type, member for member, so they can be handed to the library.
  function _asClauses(SetupBodyTestClause[] memory _testClauses)
    internal
    pure
    returns (IPolicyManager.Clause[] memory _clauses)
  {
    _clauses = new IPolicyManager.Clause[](_testClauses.length);
    for (uint256 _i = 0; _i < _testClauses.length; _i++) {
      _clauses[_i] =
        IPolicyManager.Clause({threshold: _testClauses[_i].threshold, credentials: _testClauses[_i].credentials});
    }
  }

  /// @dev Encodes a body with the library's own encoder, `SetupBody.encode`, reached through the harness.
  function _libraryBody(uint48 _wait, bool _ignoresPause, SetupBodyTestClause[] memory _clauses)
    internal
    view
    returns (bytes memory _setupBody)
  {
    _setupBody = _harness.encode(_wait, _ignoresPause, _asClauses(_clauses));
  }

  /// @dev Asserts that `_actual` holds the clauses of `_expected`: the same count and, clause by clause, the same
  ///      threshold and the same credentials in the same order.
  function _assertSameClauses(IPolicyManager.Clause[] memory _actual, SetupBodyTestClause[] memory _expected)
    internal
    pure
  {
    assertEq(_actual.length, _expected.length, 'clause count');
    for (uint256 _i = 0; _i < _expected.length; _i++) {
      assertEq(_actual[_i].threshold, _expected[_i].threshold, 'threshold');
      assertEq(_actual[_i].credentials, _expected[_i].credentials, 'credentials');
    }
  }

  /*///////////////////////////////////////////////////////////////
                               PLACES
  ///////////////////////////////////////////////////////////////*/

  /// @dev An empty list of filled places.
  function _none() internal pure returns (uint256[] memory _placeList) {
    _placeList = new uint256[](0);
  }

  /// @dev A list of one filled place.
  function _places(uint256 _a) internal pure returns (uint256[] memory _placeList) {
    _placeList = new uint256[](1);
    _placeList[0] = _a;
  }

  /// @dev A list of two filled places, in the order given.
  function _places(uint256 _a, uint256 _b) internal pure returns (uint256[] memory _placeList) {
    _placeList = new uint256[](2);
    _placeList[0] = _a;
    _placeList[1] = _b;
  }

  /// @dev A list of three filled places, in the order given.
  function _places(uint256 _a, uint256 _b, uint256 _c) internal pure returns (uint256[] memory _placeList) {
    _placeList = new uint256[](3);
    _placeList[0] = _a;
    _placeList[1] = _b;
    _placeList[2] = _c;
  }

  /// @dev Every place from `_from` up to but excluding `_to`, strictly increasing.
  function _range(uint256 _from, uint256 _to) internal pure returns (uint256[] memory _placeList) {
    _placeList = new uint256[](_to - _from);
    for (uint256 _i = _from; _i < _to; _i++) {
      _placeList[_i - _from] = _i;
    }
  }

  /*///////////////////////////////////////////////////////////////
                           THE RULE READER
  ///////////////////////////////////////////////////////////////*/

  /// @dev Wraps places into the `ProofPlace` entries that `ruleSatisfied(_body, _proofs)` takes. Only `place` matters
  ///      to the reader. The other members carry arbitrary values that differ per entry.
  function _proofs(uint256[] memory _placeList) internal pure returns (IPolicyManager.ProofPlace[] memory _proofList) {
    _proofList = new IPolicyManager.ProofPlace[](_placeList.length);
    for (uint256 _i = 0; _i < _placeList.length; _i++) {
      _proofList[_i] = IPolicyManager.ProofPlace({
        place: _placeList[_i],
        method: vm.addr(0xBEEF + _i),
        config: abi.encode('setup-body-config', _i),
        salt: keccak256(abi.encode('setup-body-salt', _i)),
        proof: abi.encode('setup-body-proof', _placeList[_i])
      });
    }
  }

  /// @dev Calls the library's `ruleSatisfied` through the harness with the given places.
  function _rule(bytes memory _setupBody, uint256[] memory _placeList)
    internal
    view
    returns (bool _satisfied, uint256 _failingClause)
  {
    (_satisfied, _failingClause) = _harness.ruleSatisfied(_setupBody, _proofs(_placeList));
  }

  /*///////////////////////////////////////////////////////////////
                           COUNTING PLACES
  ///////////////////////////////////////////////////////////////*/

  /// @dev The body's total credential count, which is also its number of places: place `_p` exists when `_p` is below
  ///      it.
  function _placeCount(SetupBodyTestClause[] memory _clauses) internal pure returns (uint256 _count) {
    for (uint256 _i = 0; _i < _clauses.length; _i++) {
      _count += _clauses[_i].credentials.length;
    }
  }

  /// @dev The first place of clause `_index`, which is the credential count of every clause before it, since places
  ///      number the credentials of all clauses in body order.
  function _clauseStart(SetupBodyTestClause[] memory _clauses, uint256 _index) internal pure returns (uint256 _start) {
    for (uint256 _i = 0; _i < _index; _i++) {
      _start += _clauses[_i].credentials.length;
    }
  }

  /// @dev Every place of every clause other than clause `_index`, plus the first `_k` places of clause `_index`, in
  ///      increasing order. With `_k` at zero it leaves clause `_index` entirely unfilled.
  function _fillAllBut(SetupBodyTestClause[] memory _clauses, uint256 _index, uint256 _k)
    internal
    pure
    returns (uint256[] memory _placeList)
  {
    uint256 _total = _placeCount(_clauses);
    uint256 _start = _clauseStart(_clauses, _index);
    uint256 _end = _start + _clauses[_index].credentials.length;
    _placeList = new uint256[](_total - (_end - _start) + _k);
    uint256 _n;
    for (uint256 _p = 0; _p < _total; _p++) {
      // solhint-disable-next-line gas-strict-inequalities
      if (_p < _start + _k || _p >= _end) _placeList[_n++] = _p;
    }
  }

  /// @dev `_placeList` followed by `_extra` consecutive places starting at `_from`, which the caller sets at or past
  ///      the end of the body, so the result stays strictly increasing when every entry of `_placeList` is below
  ///      `_from`.
  function _withPlacesPastTheEnd(uint256[] memory _placeList, uint256 _from, uint256 _extra)
    internal
    pure
    returns (uint256[] memory _widened)
  {
    _widened = new uint256[](_placeList.length + _extra);
    for (uint256 _i = 0; _i < _placeList.length; _i++) {
      _widened[_i] = _placeList[_i];
    }
    for (uint256 _i = 0; _i < _extra; _i++) {
      _widened[_placeList.length + _i] = _from + _i;
    }
  }

  /*///////////////////////////////////////////////////////////////
                      RANDOM BODIES FOR FUZZING
  ///////////////////////////////////////////////////////////////*/

  /// @dev Builds `_n` clauses from `_seed`. Each clause holds up to `_maxCredentials` credentials, except clause
  ///      `_withPlace`, which holds at least one (pass `type(uint256).max` for no such clause). A clause's threshold
  ///      runs up to one past its credential count, or, when `_reachable` is true, up to its credential count, with
  ///      clause `_withPlace` then at a threshold of at least one. Credentials may repeat, since a rule may name one
  ///      credential twice.
  function _clauseList(uint256 _seed, uint256 _n, uint256 _maxCredentials, uint256 _withPlace, bool _reachable)
    internal
    pure
    returns (SetupBodyTestClause[] memory _clauses)
  {
    _clauses = new SetupBodyTestClause[](_n);
    for (uint256 _i = 0; _i < _n; _i++) {
      uint256 _r = uint256(keccak256(abi.encode(_seed, _i)));
      uint256 _count = _i == _withPlace ? 1 + _r % _maxCredentials : _r % (_maxCredentials + 1);
      uint256 _threshold = (_r >> 8) % (_reachable ? _count + 1 : _count + 2);
      if (_reachable && _i == _withPlace) _threshold = 1 + (_r >> 8) % _count;
      // casting to 'uint8' is safe because the count, and so the threshold, stays far below 255 in every caller
      // forge-lint: disable-next-line(unsafe-typecast)
      _clauses[_i].threshold = uint8(_threshold);
      _clauses[_i].credentials = new bytes32[](_count);
      for (uint256 _j = 0; _j < _count; _j++) {
        // one in four credentials repeats a small fixed word, so repeated credentials occur
        uint256 _w = uint256(keccak256(abi.encode(_seed, _i, _j)));
        _clauses[_i].credentials[_j] = _w % 4 == 0 ? bytes32(_w % 3) : bytes32(_w);
      }
    }
  }

  /// @dev Up to `_maxClauses` random clauses, possibly none, each with thresholds up to one past its credential count.
  function _randomClauses(uint256 _seed, uint256 _maxClauses, uint256 _maxCredentials)
    internal
    pure
    returns (SetupBodyTestClause[] memory _clauses)
  {
    uint256 _n = uint256(keccak256(abi.encode(_seed, 'clauses'))) % (_maxClauses + 1);
    _clauses = _clauseList(_seed, _n, _maxCredentials, type(uint256).max, false);
  }

  /// @dev One to `_maxClauses` random clauses of which at least one, picked by `_seed`, holds a credential, so the body
  ///      has at least one place. `_maxClauses` and `_maxCredentials` must be at least one.
  function _randomClausesWithAPlace(uint256 _seed, uint256 _maxClauses, uint256 _maxCredentials)
    internal
    pure
    returns (SetupBodyTestClause[] memory _clauses)
  {
    uint256 _h = uint256(keccak256(abi.encode(_seed, 'clauses')));
    uint256 _n = 1 + _h % _maxClauses;
    _clauses = _clauseList(_seed, _n, _maxCredentials, (_h >> 128) % _n, false);
  }

  /// @dev `n` random clauses that every filled place can meet: each threshold is at most its credential count, and
  ///      clause `_positive` holds at least one credential and a threshold of at least one, so the rule is not the
  ///      all zero shape. `_maxCredentials` must be at least one.
  function _reachableClauses(uint256 _seed, uint256 _n, uint256 _positive, uint256 _maxCredentials)
    internal
    pure
    returns (SetupBodyTestClause[] memory _clauses)
  {
    _clauses = _clauseList(_seed, _n, _maxCredentials, _positive, true);
  }

  /// @dev A strictly increasing subset of `[0, _count)` picked by the bits of `_mask`.
  function _maskedPlaces(uint256 _count, uint256 _mask) internal pure returns (uint256[] memory _placeList) {
    uint256 _n;
    for (uint256 _i = 0; _i < _count && _i < 256; _i++) {
      if ((_mask >> _i) & 1 == 1) _n++;
    }
    _placeList = new uint256[](_n);
    uint256 _k;
    for (uint256 _i = 0; _i < _count && _i < 256; _i++) {
      if ((_mask >> _i) & 1 == 1) _placeList[_k++] = _i;
    }
  }
}
