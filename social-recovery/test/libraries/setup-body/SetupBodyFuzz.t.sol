// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {IPolicyManager} from 'interfaces/IPolicyManager.sol';
import {SetupBodyTestBase, SetupBodyTestClause} from 'test/utils/SetupBodyTestBase.sol';

/// @notice Property fuzzing of the four setup body readers. Each test builds a random body from a `_seed`, a fuzz
///         parameter from which a builder in `SetupBodyTestBase` derives every clause count, threshold and credential,
///         and checks one property that must hold for any such body. Every test covers one outcome: its inputs are
///         built so that outcome is the only one the readers may give, and no test recomputes the readers' answer.
///         A place, a filled place, a zero clause and the builders are defined in `SetupBodyTestBase`.
contract SetupBodyFuzzTest is SetupBodyTestBase {
  /// Checks that any wait and any `ignoresPause` value read back unchanged, beside up to four random clauses.
  /// If the wait read back wrong, an accepted recovery could release earlier or later than the holder chose.
  /// If `ignoresPause` read back wrong, a method's stop could reach a holder who opted out of it, or miss a holder
  /// who did not.
  function testFuzz_ScalarsReadBack(uint48 _wait, bool _ignoresPause, uint256 _seed) external view {
    bytes memory _setupBody = _encode(_wait, _ignoresPause, _randomClauses(_seed, 4, 4));
    assertEq(_harness.waitOf(_setupBody), _wait);
    assertEq(_harness.ignoresPauseOf(_setupBody), _ignoresPause);
  }

  /// Checks every place of a random body of at least one place in order: place 0 is the first credential of the
  /// first clause, and the numbering runs on into each next clause, so each place returns its clause's credential at
  /// its index. A gap or overlap at a clause boundary would make a place name the wrong credential, so the manager
  /// would compare a proof against the wrong hash and a guardian's proof would count toward a clause the holder did not
  /// put them in.
  function testFuzz_CredentialAtReadsEveryPlace(uint256 _seed) external view {
    SetupBodyTestClause[] memory _clauses = _randomClausesWithAPlace(_seed, 4, 4);
    bytes memory _setupBody = _body(_clauses);
    uint256 _place;
    for (uint256 _i = 0; _i < _clauses.length; _i++) {
      for (uint256 _j = 0; _j < _clauses[_i].credentials.length; _j++) {
        assertEq(_harness.credentialAt(_setupBody, _place), _clauses[_i].credentials[_j]);
        _place++;
      }
    }
  }

  /// Checks that any place at or past the total credential count reverts with `PolicyManager_PlaceOutOfRange` naming
  /// the place and the count. The place is fuzzed over every value from the count up. Without this revert, a proof
  /// could name a place the rule does not have and reach a method anyway.
  function testFuzz_CredentialAtRevertsPastTheEnd(uint256 _seed, uint256 _place) external {
    SetupBodyTestClause[] memory _clauses = _randomClauses(_seed, 5, 5);
    uint256 _count = _placeCount(_clauses);
    _place = bound(_place, _count, type(uint256).max);
    bytes memory _setupBody = _body(_clauses);
    vm.expectRevert(abi.encodeWithSelector(IPolicyManager.PolicyManager_PlaceOutOfRange.selector, _place, _count));
    _harness.credentialAt(_setupBody, _place);
  }

  /// Checks the first place past the end, which equals the total count, reverts with `PolicyManager_PlaceOutOfRange`.
  /// This is where an off by one error would sit, reading one word beyond the last credential as if it were a
  /// credential.
  function testFuzz_CredentialAtRevertsAtTheCount(uint256 _seed) external {
    SetupBodyTestClause[] memory _clauses = _randomClauses(_seed, 5, 5);
    uint256 _count = _placeCount(_clauses);
    bytes memory _setupBody = _body(_clauses);
    vm.expectRevert(abi.encodeWithSelector(IPolicyManager.PolicyManager_PlaceOutOfRange.selector, _count, _count));
    _harness.credentialAt(_setupBody, _count);
  }

  /// Checks that filling every place meets any rule whose thresholds never exceed their clauses' credential counts
  /// and whose thresholds are not all zero. Every guardian the holder named has proved, so refusing here would lock
  /// the holder out of a recovery their own rule allows.
  function testFuzz_EveryPlaceFilledMeetsAReachableRule(uint256 _seed, uint256 _clauseCount, uint256 _positive)
    external
    view
  {
    uint256 _n = bound(_clauseCount, 1, 5);
    SetupBodyTestClause[] memory _clauses = _reachableClauses(_seed, _n, bound(_positive, 0, _n - 1), 5);
    (bool _satisfied, uint256 _failingClause) = _rule(_body(_clauses), _range(0, _placeCount(_clauses)));
    assertTrue(_satisfied, 'satisfied');
    assertEq(_failingClause, 0, 'failing clause beside a satisfied rule');
  }

  /// Checks that places past the end of the body, from any starting place at or above the count, leave a rule met by
  /// its own places met, naming no failing clause. Such places belong to no clause and the reader ignores them, since
  /// `credentialAt` refuses them before a proof reaches the count. A reader that failed here would turn a stray place
  /// into a lost recovery.
  function testFuzz_PlacesPastTheEndKeepAMetRuleMet(
    uint256 _seed,
    uint256 _clauseCount,
    uint256 _positive,
    uint256 _from,
    uint256 _extra
  ) external view {
    uint256 _n = bound(_clauseCount, 1, 5);
    SetupBodyTestClause[] memory _clauses = _reachableClauses(_seed, _n, bound(_positive, 0, _n - 1), 5);
    uint256 _count = _placeCount(_clauses);
    _extra = bound(_extra, 1, 8);
    // the places past the end run from `_from` upward, strictly increasing and without overflow
    _from = bound(_from, _count, type(uint256).max - _extra + 1);
    uint256[] memory _filled = _withPlacesPastTheEnd(_range(0, _count), _from, _extra);
    (bool _satisfied, uint256 _failingClause) = _rule(_body(_clauses), _filled);
    assertTrue(_satisfied, 'satisfied');
    assertEq(_failingClause, 0, 'failing clause beside a satisfied rule');
  }

  /// Checks that when every other clause is filled and a random clause `_i`, with a threshold of at least one, has one
  /// filled place fewer than its threshold, the rule fails naming clause `_i`. The clauses before `_i` are met, so `_i`
  /// is the first failing clause. A reader that let a recovery open here would accept one guardian fewer than the
  /// holder chose, and one that named another clause would point the caller at the wrong group of guardians.
  function testFuzz_OneShortClauseIsNamed(uint256 _seed, uint256 _clauseCount, uint256 _at) external view {
    uint256 _n = bound(_clauseCount, 1, 5);
    uint256 _i = bound(_at, 0, _n - 1);
    SetupBodyTestClause[] memory _clauses = _reachableClauses(_seed, _n, _i, 5);
    uint256[] memory _filled = _fillAllBut(_clauses, _i, _clauses[_i].threshold - 1);
    (bool _satisfied, uint256 _failingClause) = _rule(_body(_clauses), _filled);
    assertFalse(_satisfied, 'satisfied');
    assertEq(_failingClause, _i, 'failing clause');
  }

  /// Checks that a rule whose every threshold is zero, including a body with no clauses, is never satisfied, whatever
  /// places are filled, and names clause zero. Such a rule would otherwise be met by a request with no proof at all,
  /// so anyone could open a recovery.
  function testFuzz_AllZeroRuleNeverSatisfied(uint256 _seed, uint256 _mask) external view {
    SetupBodyTestClause[] memory _clauses = _randomClauses(_seed, 5, 5);
    for (uint256 _i = 0; _i < _clauses.length; _i++) {
      _clauses[_i].threshold = 0;
    }
    uint256[] memory _filled = _maskedPlaces(_placeCount(_clauses), _mask);
    (bool _satisfied, uint256 _failingClause) = _rule(_body(_clauses), _filled);
    assertFalse(_satisfied, 'satisfied');
    assertEq(_failingClause, 0, 'failing clause');
  }

  /// Checks that a zero clause with none of its places filled does not block a rule whose other clauses are all filled
  /// and include one clause whose threshold is greater than zero. A holder may park a retired credential in a zero
  /// clause, and the rest of their rule must still work.
  function testFuzz_UnfilledZeroClauseKeepsTheRuleMet(
    uint256 _seed,
    uint256 _clauseCount,
    uint256 _positive,
    uint256 _zeroSeed
  ) external view {
    uint256 _n = bound(_clauseCount, 2, 5);
    uint256 _p = bound(_positive, 0, _n - 1);
    // any clause other than the positive one
    uint256 _z = (_p + 1 + bound(_zeroSeed, 0, _n - 2)) % _n;
    SetupBodyTestClause[] memory _clauses = _reachableClauses(_seed, _n, _p, 5);
    _clauses[_z].threshold = 0;
    (bool _satisfied, uint256 _failingClause) = _rule(_body(_clauses), _fillAllBut(_clauses, _z, 0));
    assertTrue(_satisfied, 'satisfied');
    assertEq(_failingClause, 0, 'failing clause beside a satisfied rule');
  }

  /// Checks that a fully filled zero clause does not stand in for a clause with a threshold greater than zero that is
  /// one place short: the rule fails naming the short clause. Every other clause is filled too. Otherwise a parked
  /// credential could count as a guardian the rule requires.
  function testFuzz_FilledZeroClauseDoesNotCoverAShortClause(
    uint256 _seed,
    uint256 _clauseCount,
    uint256 _at,
    uint256 _zeroSeed
  ) external view {
    uint256 _n = bound(_clauseCount, 2, 5);
    uint256 _i = bound(_at, 0, _n - 1);
    // any clause other than the short one
    uint256 _z = (_i + 1 + bound(_zeroSeed, 0, _n - 2)) % _n;
    SetupBodyTestClause[] memory _clauses = _reachableClauses(_seed, _n, _i, 5);
    _clauses[_z].threshold = 0;
    uint256[] memory _filled = _fillAllBut(_clauses, _i, _clauses[_i].threshold - 1);
    (bool _satisfied, uint256 _failingClause) = _rule(_body(_clauses), _filled);
    assertFalse(_satisfied, 'satisfied');
    assertEq(_failingClause, _i, 'failing clause');
  }

  /// Checks that filled places past the end of the body count for no clause. The last clause is left one place short,
  /// every other place is filled, and a random number of places past the end are added; the rule still fails naming
  /// the last clause. A reader that counted those places toward the last clause would open a recovery with a place
  /// the rule does not have.
  function testFuzz_PlacesPastTheEndCountForNoClause(uint256 _seed, uint256 _clauseCount, uint256 _extra)
    external
    view
  {
    uint256 _n = bound(_clauseCount, 1, 5);
    uint256 _last = _n - 1;
    SetupBodyTestClause[] memory _clauses = _reachableClauses(_seed, _n, _last, 5);
    uint256[] memory _filled = _withPlacesPastTheEnd(
      _fillAllBut(_clauses, _last, _clauses[_last].threshold - 1), _placeCount(_clauses), bound(_extra, 1, 8)
    );
    (bool _satisfied, uint256 _failingClause) = _rule(_body(_clauses), _filled);
    assertFalse(_satisfied, 'satisfied');
    assertEq(_failingClause, _last, 'failing clause');
  }

  /// Checks that a list of places with one entry not greater than its predecessor, equal to it or below it, reverts
  /// with `PolicyManager_PlacesNotStrictlyIncreasing` naming that entry. A place counted twice would let one guardian
  /// fill two seats of a clause, so the library refuses the order on its own, whatever its caller checked first.
  function testFuzz_NonIncreasingPlacesRevert(uint256 _seed, uint256 _mask, uint256 _bit, uint256 _at, uint256 _drop)
    external
  {
    SetupBodyTestClause[] memory _clauses = _randomClausesWithAPlace(_seed, 5, 5);
    uint256 _count = _placeCount(_clauses);
    // a strictly increasing set of places that holds at least the place picked by `_bit`
    _mask |= 2 ** bound(_bit, 0, _count - 1);
    uint256[] memory _increasing = _maskedPlaces(_count, _mask);
    // insert, after entry `_at - 1`, an entry equal to it or below it: the first entry not greater than its predecessor
    _at = bound(_at, 1, _increasing.length);
    uint256 _offending = bound(_drop, 0, _increasing[_at - 1]);

    uint256[] memory _placeList = new uint256[](_increasing.length + 1);
    for (uint256 _i = 0; _i < _placeList.length; _i++) {
      if (_i < _at) _placeList[_i] = _increasing[_i];
      else if (_i == _at) _placeList[_i] = _offending;
      else _placeList[_i] = _increasing[_i - 1];
    }
    IPolicyManager.ProofPlace[] memory _proofList = _proofs(_placeList);
    bytes memory _setupBody = _body(_clauses);
    vm.expectRevert(
      abi.encodeWithSelector(IPolicyManager.PolicyManager_PlacesNotStrictlyIncreasing.selector, _offending)
    );
    _harness.ruleSatisfied(_setupBody, _proofList);
  }
}
