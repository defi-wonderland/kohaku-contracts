// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {IPolicyManager} from 'interfaces/IPolicyManager.sol';
import {SetupBodyTestBase, SetupBodyTestClause} from 'test/utils/SetupBodyTestBase.sol';

/// @notice Unit tests for `ruleSatisfied(_body, _proofs)`. The rule is the AND of its clauses, and each clause is an
///         any N of M group of credentials. The reader counts the filled places inside each clause against its
///         threshold, answers whether every clause meets its own, and names the first failing clause. It returns false
///         naming clause zero for a body with no clauses and for a rule whose every threshold is zero, since those
///         would open a recovery with no proof. A zero clause beside a positive one is allowed. The reader takes the
///         proofs, reads each entry's place and reverts with `PolicyManager_PlacesNotStrictlyIncreasing` at the first
///         place not greater than the previous one, so no place is filled twice. Tree: SetupBodyRuleSatisfied.tree.
contract SetupBodyRuleSatisfiedTest is SetupBodyTestBase {
  /// Asserts the rule is unsatisfied and names `_expectedClause` as the first failing clause.
  function _assertFails(bytes memory _setupBody, uint256[] memory _filled, uint256 _expectedClause) internal view {
    (bool _satisfied, uint256 _failingClause) = _rule(_setupBody, _filled);
    assertFalse(_satisfied, 'rule should be unsatisfied');
    assertEq(_failingClause, _expectedClause, 'wrong failing clause');
  }

  /// Asserts the rule is satisfied and names no failing clause, which the reader reports as clause zero. A caller
  /// that reads the clause beside a satisfied rule must not find a stale or invented one.
  function _assertMet(bytes memory _setupBody, uint256[] memory _filled) internal view {
    (bool _satisfied, uint256 _failingClause) = _rule(_setupBody, _filled);
    assertTrue(_satisfied, 'rule should be satisfied');
    assertEq(_failingClause, 0, 'failing clause beside a satisfied rule');
  }

  /// Checks that an empty rule is never satisfied, whatever the scalars. Otherwise a holder with an empty rule
  /// would let anyone open a recovery with no proof.
  function test_WhenTheBodyHasNoClauses() external view {
    // it should return false naming clause zero
    _assertFails(_body(_noClauses()), _none(), 0);
    // also when the body carries the other scalar values
    _assertFails(_encode(0, true, _noClauses()), _none(), 0);
    _assertFails(_encode(type(uint48).max, false, _noClauses()), _none(), 0);
  }

  modifier whenEveryClauseHasAThresholdOfZero() {
    _;
  }

  /// Checks that a rule whose every threshold is zero fails with no proofs. That rule is the one shape a request with
  /// no proof at all would meet, so accepting it would let anyone open a recovery.
  function test_WhenNoPlaceIsFilled() external view whenEveryClauseHasAThresholdOfZero {
    // it should return false naming clause zero
    // the body whose only clause sits at zero
    _assertFails(_body(_one(_clause(0, 3, 1))), _none(), 0);
    // a zero clause with no credentials at all
    _assertFails(_body(_one(_clause(0, 0, 1))), _none(), 0);
    // several clauses, all at zero
    _assertFails(_body(_three(_clause(0, 1, 1), _clause(0, 2, 2), _clause(0, 0, 3))), _none(), 0);
  }

  /// Checks that an all zero rule still fails when places are filled, so filling places cannot rescue it.
  function test_WhenPlacesAreFilled() external view whenEveryClauseHasAThresholdOfZero {
    // it should return false naming clause zero
    _assertFails(_body(_one(_clause(0, 3, 1))), _range(0, 3), 0);
    _assertFails(_body(_two(_clause(0, 2, 1), _clause(0, 2, 2))), _places(1, 3), 0);
  }

  modifier whenAZeroClauseSitsBesideAPositiveClause() {
    _;
  }

  /// Checks that a zero clause beside a positive clause is allowed, and the rule passes once the positive clause
  /// is met. A holder may park a retired credential in a zero clause and must keep a working rule.
  function test_WhenThePositiveClauseMeetsItsThreshold() external view whenAZeroClauseSitsBesideAPositiveClause {
    // it should return true
    // zero clause first (places 0-1), positive 1-of-2 second (places 2-3)
    bytes memory _zeroFirst = _body(_two(_clause(0, 2, 1), _clause(1, 2, 2)));
    _assertMet(_zeroFirst, _places(2));
    _assertMet(_zeroFirst, _places(3));
    // positive 2-of-2 first (places 0-1), zero clause second (places 2-4)
    bytes memory _zeroLast = _body(_two(_clause(2, 2, 1), _clause(0, 3, 2)));
    _assertMet(_zeroLast, _places(0, 1));
    // filling the zero clause's places too changes nothing
    _assertMet(_zeroLast, _places(0, 1, 4));
    // a zero clause with no credentials beside a positive clause
    _assertMet(_body(_two(_clause(0, 0, 1), _clause(1, 1, 2))), _places(0));
  }

  /// Checks that a zero clause does not excuse the positive clause beside it, which is named when it misses.
  function test_WhenThePositiveClauseMissesItsThreshold() external view whenAZeroClauseSitsBesideAPositiveClause {
    // it should return false naming the positive clause
    _assertFails(_body(_two(_clause(0, 2, 1), _clause(2, 2, 2))), _none(), 1);
    _assertFails(_body(_two(_clause(0, 2, 1), _clause(2, 2, 2))), _places(3), 1);
    _assertFails(_body(_two(_clause(2, 2, 1), _clause(0, 3, 2))), _places(0), 0);
  }

  /// Checks that places filled in a zero clause do not count toward the positive clause, so a parked credential
  /// cannot stand in for a guardian the rule requires.
  function test_WhenOnlyTheZeroClausesPlacesAreFilled() external view whenAZeroClauseSitsBesideAPositiveClause {
    // it should return false naming the positive clause
    // zero clause (places 0-2) then positive 1-of-2 (places 3-4)
    _assertFails(_body(_two(_clause(0, 3, 1), _clause(1, 2, 2))), _range(0, 3), 1);
    // positive 1-of-1 (place 0) then zero clause (places 1-2)
    _assertFails(_body(_two(_clause(1, 1, 1), _clause(0, 2, 2))), _places(1, 2), 0);
  }

  /// Checks that exactly N filled places meet an N of M clause. An off by one here would demand one guardian more
  /// than the holder chose.
  function test_WhenTheFilledCountEqualsTheThreshold() external view {
    // it should return true
    _assertMet(_body(_one(_clause(2, 3, 1))), _places(0, 2));
    // one clause, one credential, threshold one
    _assertMet(_body(_one(_clause(1, 1, 1))), _places(0));
    // threshold equal to the credential count, every place filled
    _assertMet(_body(_one(_clause(3, 3, 1))), _range(0, 3));
  }

  /// Checks that one place short of the threshold fails and names that clause. An off by one here would let a
  /// recovery open with one guardian fewer than the holder chose.
  function test_WhenTheFilledCountIsOneBelowTheThreshold() external view {
    // it should return false naming that clause
    _assertFails(_body(_one(_clause(2, 3, 1))), _places(1), 0);
    _assertFails(_body(_one(_clause(1, 1, 1))), _none(), 0);
    _assertFails(_body(_two(_clause(1, 1, 1), _clause(3, 4, 2))), _places(0, 1, 4), 1);
  }

  /// Checks that more filled places than the threshold still meet the clause.
  function test_WhenTheFilledCountExceedsTheThreshold() external view {
    // it should return true
    _assertMet(_body(_one(_clause(1, 3, 1))), _range(0, 3));
    _assertMet(_body(_two(_clause(1, 2, 1), _clause(1, 2, 2))), _range(0, 4));
  }

  /// Checks that a clause that can never be met is named rather than refused, even with every place filled. The
  /// name tells the caller which clause is impossible.
  function test_WhenAClausesThresholdExceedsItsCredentialCount() external view {
    // it should return false naming that clause even with every place filled
    _assertFails(_body(_one(_clause(4, 3, 1))), _range(0, 3), 0);
    _assertFails(_body(_two(_clause(1, 1, 1), _clause(3, 2, 2))), _range(0, 3), 1);
    // the widest threshold over no credentials
    _assertFails(_body(_one(_clause(type(uint8).max, 0, 1))), _none(), 0);
    _assertFails(_body(_two(_clause(1, 1, 1), _clause(type(uint8).max, 2, 2))), _range(0, 3), 1);
  }

  /// Checks that places filled past the end of the body leave a met rule met. Such places belong to no clause, and
  /// the reader ignores them rather than refusing them, since `credentialAt` refuses any place past the end before a
  /// proof ever reaches the count. A reader that failed here would turn a stray place into a lost recovery.
  function test_WhenTheRuleIsMetAndPlacesPastTheEndAreFilled() external view {
    // it should return true ignoring the places past the end
    // clause 0 is 1-of-2 (places 0-1), clause 1 is 2-of-3 (places 2-4), so place 5 is the first past the end
    SetupBodyTestClause[] memory _clauses = _two(_clause(1, 2, 1), _clause(2, 3, 2));
    _assertMet(_body(_clauses), _withPlacesPastTheEnd(_places(0, 2, 3), 5, 2));
    // the widest place too
    uint256[] memory _widest = new uint256[](4);
    _widest[0] = 1;
    _widest[1] = 3;
    _widest[2] = 4;
    _widest[3] = type(uint256).max;
    _assertMet(_body(_clauses), _widest);
  }

  modifier whenASingleClauseAtTheWidestThresholdListsOneCredentialMore() {
    _;
  }

  /// Checks that a clause of 256 credentials at a threshold of 255, the widest a threshold can be, is met by 255
  /// filled places that include the last one. The threshold is a uint8 while the list is not, so a count or a place
  /// kept in the threshold's width would wrap here and refuse a rule the holder is allowed to write.
  function test_WhenAsManyPlacesAsTheWidestThresholdAreFilled()
    external
    view
    whenASingleClauseAtTheWidestThresholdListsOneCredentialMore
  {
    // it should return true
    _assertMet(_body(_one(_clause(type(uint8).max, 256, 1))), _range(1, 256));
  }

  /// Checks that the same clause with 254 filled places fails and names it. A count that wrapped past the uint8
  /// width could read 254 as enough and open a recovery with one guardian fewer than the holder chose.
  function test_WhenOnePlaceFewerThanTheWidestThresholdIsFilled()
    external
    view
    whenASingleClauseAtTheWidestThresholdListsOneCredentialMore
  {
    // it should return false naming that clause
    _assertFails(_body(_one(_clause(type(uint8).max, 256, 1))), _range(2, 256), 0);
  }

  /// Checks that the reader names the first failing clause in body order, whichever clauses miss.
  function test_WhenSeveralClausesMissTheirThresholds() external view {
    // it should name the first failing clause in body order
    bytes memory _setupBody = _body(_three(_clause(1, 1, 1), _clause(1, 2, 2), _clause(2, 2, 3)));
    // clause 0 met, clauses 1 and 2 missed
    _assertFails(_setupBody, _places(0), 1);
    // all three missed
    _assertFails(_setupBody, _none(), 0);
    // clause 0 missed, clause 1 met, clause 2 missed
    _assertFails(_setupBody, _places(2, 3), 0);
    // only the last clause missed
    _assertFails(_setupBody, _places(0, 1, 3), 2);
  }

  /// Checks that meeting an earlier clause does not hide a later clause that misses. The rule needs every clause.
  function test_WhenAnEarlierClauseIsMetAndALaterClauseMisses() external view {
    // it should name the later clause
    _assertFails(_body(_two(_clause(1, 2, 1), _clause(2, 3, 2))), _places(0, 1, 2), 1);
  }

  /// Checks that the rule passes when every clause meets its threshold, whatever the scalars are.
  function test_WhenEveryClauseMeetsItsThreshold() external view {
    // it should return true
    // clause 0 is 1-of-2 (places 0-1), clause 1 is 2-of-3 (places 2-4), clause 2 is 1-of-1 (place 5)
    SetupBodyTestClause[] memory _clauses = _three(_clause(1, 2, 1), _clause(2, 3, 2), _clause(1, 1, 3));
    uint256[] memory _filled = new uint256[](4);
    _filled[0] = 1;
    _filled[1] = 2;
    _filled[2] = 4;
    _filled[3] = 5;
    _assertMet(_body(_clauses), _filled);
    // and whatever the scalars are
    _assertMet(_encode(0, true, _clauses), _filled);
    _assertMet(_encode(type(uint48).max, false, _clauses), _filled);
  }

  /// Checks that one credential named at two places counts at both, within a clause and across clauses. The
  /// rule counts places, not distinct credentials, since each place carries its own salt and proof.
  function test_WhenOneCredentialRepeatsAtTwoPlaces() external view {
    // it should count both places
    SetupBodyTestClause[] memory _clauses = _one(_clause(2, 3, 1));
    _clauses[0].credentials[2] = _clauses[0].credentials[0];
    _assertMet(_body(_clauses), _places(0, 2));

    // the same credential in two clauses fills each clause separately
    SetupBodyTestClause[] memory _across = _two(_clause(1, 1, 1), _clause(1, 1, 2));
    _across[1].credentials[0] = _across[0].credentials[0];
    _assertMet(_body(_across), _places(0, 1));
    _assertFails(_body(_across), _places(0), 1);
  }

  /// Checks that a filled place counts only toward the clause that holds it. Otherwise guardians from one group
  /// could satisfy another group the holder set apart.
  function test_WhenTheFilledPlacesSitInAnotherClause() external view {
    // it should not count them toward this clause
    // clause 0 is 1-of-1 (place 0), clause 1 is 2-of-3 (places 1-3)
    bytes memory _setupBody = _body(_two(_clause(1, 1, 1), _clause(2, 3, 2)));
    // the places of clause 1 do not fill clause 0
    _assertFails(_setupBody, _places(1, 2, 3), 0);
    // one place in clause 0 does not count as a second fill of clause 1
    _assertFails(_setupBody, _places(0, 3), 1);
  }

  /// Expects `ruleSatisfied` to revert with `PolicyManager_PlacesNotStrictlyIncreasing` naming `_offending`.
  function _expectNotIncreasing(bytes memory _setupBody, uint256[] memory _placeList, uint256 _offending) internal {
    IPolicyManager.ProofPlace[] memory _proofList = _proofs(_placeList);
    vm.expectRevert(
      abi.encodeWithSelector(IPolicyManager.PolicyManager_PlacesNotStrictlyIncreasing.selector, _offending)
    );
    _harness.ruleSatisfied(_setupBody, _proofList);
  }

  /// Checks that a repeated place reverts and names the first repeat. A repeated place would let one guardian fill
  /// two seats of a clause.
  function test_WhenAPlaceRepeatsThePreviousPlace() external {
    // it should revert with PolicyManager_PlacesNotStrictlyIncreasing naming the repeated place
    // one credential, threshold two: a repeated place must not fill it twice
    _expectNotIncreasing(_body(_one(_clause(2, 1, 1))), _places(0, 0), 0);
    // a repeat after a valid prefix, in a 2-of-3 clause
    _expectNotIncreasing(_body(_one(_clause(2, 3, 1))), _places(0, 1, 1), 1);
    // a repeat even where the distinct places already meet the rule
    _expectNotIncreasing(_body(_one(_clause(1, 2, 1))), _places(1, 1), 1);
    // the first offending entry is named: in [2, 2, 1] it is the second entry, place 2
    _expectNotIncreasing(_body(_one(_clause(1, 3, 1))), _places(2, 2, 1), 2);
  }

  /// Checks that the order check runs before the count, so a bad order reverts even when the rule would fail
  /// anyway. The caller learns the real fault, not a missed threshold.
  function test_WhenAPlaceRepeatsInASetThatMissesItsThreshold() external {
    // it should revert with PolicyManager_PlacesNotStrictlyIncreasing rather than report the missed clause
    // a 3-of-1 clause misses its threshold whatever is filled, so a reader that counted before checking the order
    // would return (false, 0); the order is refused first, regardless of the count
    _expectNotIncreasing(_body(_one(_clause(3, 1, 1))), _places(0, 0), 0);
    // a decreasing pair in a set that misses its threshold: 3-of-3 with two places filled
    _expectNotIncreasing(_body(_one(_clause(3, 3, 1))), _places(2, 1), 1);
  }

  /// Checks that a place below the previous one reverts and names the lower place, within a clause and across
  /// clauses. Allowing any order would let a list revisit a place it already counted.
  function test_WhenAPlaceIsBelowThePreviousPlace() external {
    // it should revert with PolicyManager_PlacesNotStrictlyIncreasing naming the lower place
    _expectNotIncreasing(_body(_one(_clause(2, 3, 1))), _places(2, 1), 1);
    _expectNotIncreasing(_body(_one(_clause(1, 4, 1))), _places(0, 3, 2), 2);
    // across clauses: clause 1's place before clause 0's
    _expectNotIncreasing(_body(_two(_clause(1, 1, 1), _clause(1, 3, 2))), _places(3, 0), 0);
  }

  /// Checks that consecutive places are accepted and all counted, including across a clause boundary.
  function test_WhenEachPlaceIsExactlyOneAboveThePreviousPlace() external view {
    // it should count every place
    _assertMet(_body(_one(_clause(2, 2, 1))), _places(0, 1));
    _assertMet(_body(_one(_clause(3, 3, 1))), _places(0, 1, 2));
    // across the clause boundary: place 1 closes clause 0, place 2 opens clause 1
    _assertMet(_body(_two(_clause(2, 2, 1), _clause(1, 1, 2))), _places(0, 1, 2));
  }
}
