// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {IPolicyManager} from 'interfaces/IPolicyManager.sol';
import {SetupBodyTestBase, SetupBodyTestClause} from 'test/utils/SetupBodyTestBase.sol';

/// @notice Unit tests for `credentialAt(_clauses, _place)`, the form that reads a place from clauses already decoded
///         from a body. A place is the flat index of a credential across all clauses in order, so place 0 is the
///         first credential of the first clause and the numbering runs on into the next clause. It must return the
///         credential at that index and revert with `PolicyManager_PlaceOutOfRange` past the end, exactly as the form
///         that reads the body bytes does. Tree: SetupBodyCredentialAtClauses.tree.
contract SetupBodyCredentialAtClausesTest is SetupBodyTestBase {
  /// Reads place `_place` of `_clauses` through the clauses form.
  function _at(SetupBodyTestClause[] memory _clauses, uint256 _place) internal view returns (bytes32 _credential) {
    _credential = _harness.credentialAt(_asClauses(_clauses), _place);
  }

  /// Checks that an empty clause list has no place 0, so no proof can name a credential in an empty rule.
  function test_WhenThereAreNoClauses() external {
    // it should revert with PolicyManager_PlaceOutOfRange naming the place and a count of zero
    IPolicyManager.Clause[] memory _clauses = _asClauses(_noClauses());
    vm.expectRevert(abi.encodeWithSelector(IPolicyManager.PolicyManager_PlaceOutOfRange.selector, 0, 0));
    _harness.credentialAt(_clauses, 0);
  }

  /// Checks that place 0 is the first credential of the first clause, the start of the numbering.
  function test_WhenThePlaceIsTheFirstPlace() external view {
    // it should return the first credential of the first clause
    SetupBodyTestClause[] memory _clauses = _two(_clause(1, 2, 1), _clause(1, 3, 2));
    assertEq(_at(_clauses, 0), _clauses[0].credentials[0]);
  }

  /// Checks that the place after the first clause's last credential is the next clause's first credential, with no
  /// gap and no overlap at the boundary, so a guardian's proof counts in the clause the holder put them in.
  function test_WhenThePlaceRunsPastTheFirstClause() external view {
    // it should return the credential of the next clause in order
    SetupBodyTestClause[] memory _clauses = _two(_clause(1, 2, 1), _clause(1, 3, 2));
    assertEq(_at(_clauses, 1), _clauses[0].credentials[1], 'last of the first clause');
    assertEq(_at(_clauses, 2), _clauses[1].credentials[0], 'first of the second clause');
    assertEq(_at(_clauses, 4), _clauses[1].credentials[2], 'last of the second clause');
  }

  /// Checks that a clause with no credentials takes no place, so the clause after it starts right where the clause
  /// before it ended.
  function test_WhenAnEarlierClauseListsNoCredentials() external view {
    // it should give that clause no place in the flat numbering
    SetupBodyTestClause[] memory _clauses = _three(_clause(1, 1, 1), _clause(0, 0, 2), _clause(1, 2, 3));
    assertEq(_at(_clauses, 0), _clauses[0].credentials[0], 'first clause');
    assertEq(_at(_clauses, 1), _clauses[2].credentials[0], 'third clause, first credential');
    assertEq(_at(_clauses, 2), _clauses[2].credentials[1], 'third clause, second credential');
  }

  /// Checks that the last place, one below the total credential count, still returns the last credential of the last
  /// clause, so the last guardian the holder named can prove.
  function test_WhenThePlaceIsTheLastCredential() external view {
    // it should return the last credential of the last clause
    SetupBodyTestClause[] memory _clauses = _two(_clause(1, 2, 1), _clause(2, 3, 2));
    assertEq(_at(_clauses, 4), _clauses[1].credentials[2]);
  }

  /// Checks that the first place past the end, equal to the total credential count, reverts naming the place and the
  /// count. This is where an off by one error would read a word beyond the last credential as a credential.
  function test_WhenThePlaceEqualsTheTotalCredentialCount() external {
    // it should revert with PolicyManager_PlaceOutOfRange naming the place and the total count
    IPolicyManager.Clause[] memory _clauses = _asClauses(_two(_clause(1, 2, 1), _clause(2, 3, 2)));
    vm.expectRevert(abi.encodeWithSelector(IPolicyManager.PolicyManager_PlaceOutOfRange.selector, 5, 5));
    _harness.credentialAt(_clauses, 5);
  }

  /// Checks that the widest `uint256` place reverts naming itself and the count, with no overflow in the walk that
  /// could wrap it back onto a real credential.
  function test_WhenThePlaceIsTheWidestUint256() external {
    // it should revert with PolicyManager_PlaceOutOfRange naming the place and the total count
    IPolicyManager.Clause[] memory _clauses = _asClauses(_two(_clause(1, 2, 1), _clause(2, 3, 2)));
    uint256 _place = type(uint256).max;
    vm.expectRevert(abi.encodeWithSelector(IPolicyManager.PolicyManager_PlaceOutOfRange.selector, _place, 5));
    _harness.credentialAt(_clauses, _place);
  }

  /// Checks that clauses which all list no credentials have no place at all, so even place 0 reverts.
  function test_WhenEveryClauseListsNoCredentials() external {
    // it should revert at place zero with a count of zero
    IPolicyManager.Clause[] memory _clauses = _asClauses(_two(_clause(1, 0, 1), _clause(0, 0, 2)));
    vm.expectRevert(abi.encodeWithSelector(IPolicyManager.PolicyManager_PlaceOutOfRange.selector, 0, 0));
    _harness.credentialAt(_clauses, 0);
  }
}
