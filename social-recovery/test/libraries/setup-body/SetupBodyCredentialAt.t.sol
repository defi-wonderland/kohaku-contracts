// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {IPolicyManager} from 'interfaces/IPolicyManager.sol';
import {SetupBodyTestBase, SetupBodyTestClause} from 'test/utils/SetupBodyTestBase.sol';

/// @notice Unit tests for `credentialAt(_body, _place)`. A place is the flat index of a credential across all clauses
///         in body order, so place 0 is the first credential of the first clause and the numbering runs on into the
///         next clause. The reader returns the credential at that index and reverts with
///         `PolicyManager_PlaceOutOfRange` past the end, so a place the rule does not have fails before any method sees
///         it. Tree: SetupBodyCredentialAt.tree.
contract SetupBodyCredentialAtTest is SetupBodyTestBase {
  /// Checks that a body with no clauses has no place 0, so no proof can name a credential in an empty rule.
  function test_WhenTheBodyHasNoClauses() external {
    // it should revert with PolicyManager_PlaceOutOfRange naming the place and a count of zero
    bytes memory _setupBody = _body(_noClauses());
    vm.expectRevert(abi.encodeWithSelector(IPolicyManager.PolicyManager_PlaceOutOfRange.selector, 0, 0));
    _harness.credentialAt(_setupBody, 0);
  }

  /// Checks that place 0 is the first credential of the first clause, the start of the numbering.
  function test_WhenThePlaceIsTheFirstPlace() external view {
    // it should return the first credential of the first clause
    SetupBodyTestClause[] memory _clauses = _two(_clause(1, 2, 1), _clause(1, 3, 2));
    assertEq(_harness.credentialAt(_body(_clauses), 0), _clauses[0].credentials[0]);
  }

  /// Checks that places inside the first clause map to that clause's credentials by index.
  function test_WhenThePlaceIsInsideTheFirstClause() external view {
    // it should return that clause's credential at that index
    SetupBodyTestClause[] memory _clauses = _two(_clause(1, 3, 1), _clause(1, 2, 2));
    bytes memory _setupBody = _body(_clauses);
    assertEq(_harness.credentialAt(_setupBody, 1), _clauses[0].credentials[1]);
    assertEq(_harness.credentialAt(_setupBody, 2), _clauses[0].credentials[2]);
  }

  /// Checks that the numbering runs on across clause boundaries with no gap and no reset. A wrong boundary would
  /// make a place name the wrong credential, so a proof could count in a clause the holder did not put it in.
  function test_WhenThePlaceRunsPastTheFirstClause() external view {
    // it should return the credential of the next clause in body order
    SetupBodyTestClause[] memory _clauses = _three(_clause(1, 2, 1), _clause(2, 3, 2), _clause(1, 1, 3));
    bytes memory _setupBody = _body(_clauses);
    // places 0-1 are clause 0, places 2-4 are clause 1, place 5 is clause 2
    assertEq(_harness.credentialAt(_setupBody, 2), _clauses[1].credentials[0]);
    assertEq(_harness.credentialAt(_setupBody, 3), _clauses[1].credentials[1]);
    assertEq(_harness.credentialAt(_setupBody, 4), _clauses[1].credentials[2]);
    assertEq(_harness.credentialAt(_setupBody, 5), _clauses[2].credentials[0]);
  }

  /// Checks that a clause with no credentials takes no place, so the next clause still starts at place 0.
  function test_WhenAnEarlierClauseListsNoCredentials() external view {
    // it should give that clause no place in the flat numbering
    SetupBodyTestClause[] memory _clauses = _three(_clause(0, 0, 1), _clause(1, 2, 2), _clause(1, 1, 3));
    bytes memory _setupBody = _body(_clauses);
    assertEq(_harness.credentialAt(_setupBody, 0), _clauses[1].credentials[0]);
    assertEq(_harness.credentialAt(_setupBody, 1), _clauses[1].credentials[1]);
    assertEq(_harness.credentialAt(_setupBody, 2), _clauses[2].credentials[0]);
  }

  /// Checks that the last place reads the last credential of the last clause, in a two clause body and in a body
  /// of one credential.
  function test_WhenThePlaceIsTheLastCredential() external view {
    // it should return the last credential of the last clause
    SetupBodyTestClause[] memory _clauses = _two(_clause(1, 2, 1), _clause(2, 3, 2));
    assertEq(_harness.credentialAt(_body(_clauses), 4), _clauses[1].credentials[2]);

    SetupBodyTestClause[] memory _single = _one(_clause(1, 1, 9));
    assertEq(_harness.credentialAt(_body(_single), 0), _single[0].credentials[0]);
  }

  modifier whenASingleClauseListsOneCredentialMoreThanTheWidestThreshold() {
    _;
  }

  /// Checks that place 255 of a clause of 256 credentials reads the last credential. A threshold is a uint8 but a
  /// clause's list is not, so a place kept in the threshold's width would stop one credential short here.
  function test_WhenThePlaceIsTheLastCredentialOfThatClause()
    external
    view
    whenASingleClauseListsOneCredentialMoreThanTheWidestThreshold
  {
    // it should return the last credential
    SetupBodyTestClause[] memory _clauses = _one(_clause(type(uint8).max, 256, 1));
    assertEq(_harness.credentialAt(_body(_clauses), 255), _clauses[0].credentials[255]);
  }

  /// Checks that place 256 of a clause of 256 credentials reverts naming the place and a count of 256. A place or a
  /// count kept in a uint8 would wrap to zero here and read the first credential instead.
  function test_WhenThePlaceIsOnePastThatLastCredential()
    external
    whenASingleClauseListsOneCredentialMoreThanTheWidestThreshold
  {
    // it should revert with PolicyManager_PlaceOutOfRange naming the place and the count
    bytes memory _setupBody = _body(_one(_clause(type(uint8).max, 256, 1)));
    vm.expectRevert(abi.encodeWithSelector(IPolicyManager.PolicyManager_PlaceOutOfRange.selector, 256, 256));
    _harness.credentialAt(_setupBody, 256);
  }

  /// Checks that the first place past the end reverts, and that the bound is the credential count rather than the
  /// clause count. Bounding by the clause count would reject real places or accept missing ones.
  function test_WhenThePlaceEqualsTheTotalCredentialCount() external {
    // it should revert with PolicyManager_PlaceOutOfRange naming the place and the total count
    // five credentials over two clauses: the first place past the end is five, not two (the clause count)
    bytes memory _setupBody = _body(_two(_clause(1, 2, 1), _clause(2, 3, 2)));
    vm.expectRevert(abi.encodeWithSelector(IPolicyManager.PolicyManager_PlaceOutOfRange.selector, 5, 5));
    _harness.credentialAt(_setupBody, 5);
  }

  /// Checks that the largest possible place reverts cleanly rather than wrapping around to a real place.
  function test_WhenThePlaceIsTheWidestUint256() external {
    // it should revert with PolicyManager_PlaceOutOfRange naming the place and the total count
    bytes memory _setupBody = _body(_two(_clause(1, 2, 1), _clause(2, 3, 2)));
    uint256 _place = type(uint256).max;
    vm.expectRevert(abi.encodeWithSelector(IPolicyManager.PolicyManager_PlaceOutOfRange.selector, _place, 5));
    _harness.credentialAt(_setupBody, _place);
  }

  /// Checks that clauses with no credentials, even one with the largest threshold, give the body no places at all.
  function test_WhenEveryClauseListsNoCredentials() external {
    // it should revert at place zero with a count of zero
    bytes memory _setupBody = _body(_two(_clause(0, 0, 1), _clause(255, 0, 2)));
    vm.expectRevert(abi.encodeWithSelector(IPolicyManager.PolicyManager_PlaceOutOfRange.selector, 0, 0));
    _harness.credentialAt(_setupBody, 0);
  }
}
