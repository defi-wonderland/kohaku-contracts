// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {IPolicyManager} from 'interfaces/IPolicyManager.sol';
import {SetupBodyTestBase, SetupBodyTestClause} from 'test/utils/SetupBodyTestBase.sol';

/// @notice Unit tests for `ruleSatisfied(_clauses, _proofs)`, the form that checks the rule against clauses already
///         decoded from a body. The rule is the AND of its clauses, each an any N of M group of credentials. It counts
///         the filled places, the places of the proofs the caller hands it, inside each clause against its threshold
///         and names the first failing clause. It returns false naming clause zero for no clauses and for a rule
///         whose every threshold is zero, and reverts with `PolicyManager_PlacesNotStrictlyIncreasing` at the first
///         place not above the one before it, exactly as the form that reads the body bytes does.
///         Tree: SetupBodyRuleSatisfiedClauses.tree.
contract SetupBodyRuleSatisfiedClausesTest is SetupBodyTestBase {
  /// Checks the rule of `_clauses` through the clauses form with `_filled` as the filled places.
  function _ruleOf(SetupBodyTestClause[] memory _clauses, uint256[] memory _filled)
    internal
    view
    returns (bool _satisfied, uint256 _failingClause)
  {
    (_satisfied, _failingClause) = _harness.ruleSatisfied(_asClauses(_clauses), _proofs(_filled));
  }

  /// Asserts the rule is unsatisfied and names `_expectedClause` as the first failing clause.
  function _assertFails(SetupBodyTestClause[] memory _clauses, uint256[] memory _filled, uint256 _expectedClause)
    internal
    view
  {
    (bool _satisfied, uint256 _failingClause) = _ruleOf(_clauses, _filled);
    assertFalse(_satisfied, 'rule should be unsatisfied');
    assertEq(_failingClause, _expectedClause, 'wrong failing clause');
  }

  /// Asserts the rule is satisfied.
  function _assertMet(SetupBodyTestClause[] memory _clauses, uint256[] memory _filled) internal view {
    (bool _satisfied,) = _ruleOf(_clauses, _filled);
    assertTrue(_satisfied, 'rule should be satisfied');
  }

  /// Checks that an empty clause list is never satisfied, even with a place filled. Otherwise an empty rule would let
  /// anyone open a recovery with no proof.
  function test_WhenThereAreNoClauses() external view {
    // it should return false naming clause zero
    _assertFails(_noClauses(), _none(), 0);
    _assertFails(_noClauses(), _places(0), 0);
  }

  /// Checks that a rule whose every threshold is zero fails naming clause zero, with no place filled and with every
  /// place filled. That rule is the one shape a request with no proof would meet.
  function test_WhenEveryClauseHasAThresholdOfZero() external view {
    // it should return false naming clause zero even with places filled
    SetupBodyTestClause[] memory _clauses = _two(_clause(0, 2, 1), _clause(0, 1, 2));
    _assertFails(_clauses, _none(), 0);
    _assertFails(_clauses, _range(0, 3), 0);
  }

  modifier whenAZeroClauseSitsBesideAPositiveClause() {
    _;
  }

  /// Checks that a zero clause, one whose threshold is zero, left unfilled does not block a positive clause that meets
  /// its threshold. A holder who parks a retired credential in a zero clause keeps a rule that works.
  function test_WhenThePositiveClauseMeetsItsThreshold() external view whenAZeroClauseSitsBesideAPositiveClause {
    // it should return true
    _assertMet(_two(_clause(0, 2, 1), _clause(1, 2, 2)), _places(3));
  }

  /// Checks that filling only the zero clause's places does not meet the rule, and the positive clause is named. A
  /// parked credential must never count as a guardian the rule requires.
  function test_WhenOnlyTheZeroClausesPlacesAreFilled() external view whenAZeroClauseSitsBesideAPositiveClause {
    // it should return false naming the positive clause
    _assertFails(_two(_clause(0, 2, 1), _clause(1, 2, 2)), _places(0, 1), 1);
  }

  /// Checks that a clause whose filled count equals its threshold is met, the exact equality case of the count.
  function test_WhenTheFilledCountEqualsTheThreshold() external view {
    // it should return true
    _assertMet(_one(_clause(2, 3, 1)), _places(0, 2));
  }

  /// Checks that one filled place short of the threshold fails naming that clause, so a recovery never opens with one
  /// guardian fewer than the holder chose.
  function test_WhenTheFilledCountIsOneBelowTheThreshold() external view {
    // it should return false naming that clause
    _assertFails(_two(_clause(1, 1, 1), _clause(2, 3, 2)), _places(0, 2), 1);
  }

  /// Checks that a clause whose threshold exceeds its credential count fails naming it, even with every place filled,
  /// so the caller learns which clause cannot be met.
  function test_WhenAClausesThresholdExceedsItsCredentialCount() external view {
    // it should return false naming that clause even with every place filled
    _assertFails(_two(_clause(1, 1, 1), _clause(3, 2, 2)), _range(0, 3), 1);
  }

  /// Checks that with several clauses short, the first of them in order is named, so the caller reports the first
  /// group of guardians still missing.
  function test_WhenSeveralClausesMissTheirThresholds() external view {
    // it should name the first failing clause in order
    _assertFails(_three(_clause(1, 1, 1), _clause(1, 1, 2), _clause(1, 1, 3)), _places(0), 1);
  }

  /// Checks that one credential written at two places counts once per filled place. Each place carries its own proof,
  /// so both verify and both count.
  function test_WhenOneCredentialRepeatsAtTwoPlaces() external view {
    // it should count both places
    SetupBodyTestClause[] memory _clauses = _one(_clause(2, 2, 1));
    _clauses[0].credentials[1] = _clauses[0].credentials[0];
    _assertMet(_clauses, _places(0, 1));
  }

  /// Checks that a filled place past the last credential counts for no clause, so a place the rule does not have
  /// cannot complete the last clause.
  function test_WhenAPlaceLiesPastTheLastCredential() external view {
    // it should count it for no clause
    _assertFails(_two(_clause(1, 1, 1), _clause(2, 2, 2)), _places(0, 1, 3), 1);
  }

  /// Checks that a place equal to the one before it reverts naming it, so one guardian cannot fill two seats of a
  /// clause.
  function test_WhenAPlaceRepeatsThePreviousPlace() external {
    // it should revert with PolicyManager_PlacesNotStrictlyIncreasing naming the repeated place
    IPolicyManager.Clause[] memory _clauses = _asClauses(_one(_clause(2, 3, 1)));
    IPolicyManager.ProofPlace[] memory _proofList = _proofs(_places(0, 1, 1));
    vm.expectRevert(abi.encodeWithSelector(IPolicyManager.PolicyManager_PlacesNotStrictlyIncreasing.selector, 1));
    _harness.ruleSatisfied(_clauses, _proofList);
  }

  /// Checks that a place below the one before it reverts naming the lower place, so the places always walk the
  /// clauses in order and none is counted twice.
  function test_WhenAPlaceIsBelowThePreviousPlace() external {
    // it should revert with PolicyManager_PlacesNotStrictlyIncreasing naming the lower place
    IPolicyManager.Clause[] memory _clauses = _asClauses(_one(_clause(2, 3, 1)));
    IPolicyManager.ProofPlace[] memory _proofList = _proofs(_places(2, 0));
    vm.expectRevert(abi.encodeWithSelector(IPolicyManager.PolicyManager_PlacesNotStrictlyIncreasing.selector, 0));
    _harness.ruleSatisfied(_clauses, _proofList);
  }
}
