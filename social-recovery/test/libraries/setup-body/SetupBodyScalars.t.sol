// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {SetupBodyTestBase, SetupBodyTestClause} from 'test/utils/SetupBodyTestBase.sol';

/// @notice Unit tests for the two scalar readers. `waitOf(_body)` reads the wait, the time an accepted recovery must
///         wait before it can run, as a `uint48` with no floor and no ceiling. `ignoresPauseOf(_body)` reads the
///         holder's choice of whether a method's stop reaches their accepted recoveries. Tree: SetupBodyScalars.tree.
contract SetupBodyScalarsTest is SetupBodyTestBase {
  /// Checks that a wait of zero reads back as zero, since the library sets no floor on the holder's choice.
  function test_WhenTheWaitIsZero() external view {
    // it should read a wait of zero
    assertEq(_harness.waitOf(_encode(0, false, _one(_clause(1, 1, 1)))), 0);
    assertEq(_harness.waitOf(_encode(0, true, _one(_clause(1, 1, 1)))), 0);
  }

  /// Checks that the largest `uint48` wait reads back whole, with no truncation to a shorter delay.
  function test_WhenTheWaitIsTheWidestUint48() external view {
    // it should read the widest uint48
    assertEq(_harness.waitOf(_encode(type(uint48).max, false, _one(_clause(1, 1, 1)))), type(uint48).max);
    assertEq(_harness.waitOf(_encode(type(uint48).max, true, _one(_clause(1, 1, 1)))), type(uint48).max);
  }

  /// Checks that `ignoresPause` true reads back true and leaves the wait intact. A flag read as false would let a
  /// method's stop reach a holder who opted out of it.
  function test_WhenIgnoresPauseIsTrue() external view {
    // it should read true
    SetupBodyTestClause[] memory _clauses = _two(_clause(1, 2, 1), _clause(0, 1, 2));
    assertTrue(_harness.ignoresPauseOf(_encode(2 days, true, _clauses)));
    assertTrue(_harness.ignoresPauseOf(_encode(0, true, _clauses)));
    assertEq(_harness.waitOf(_encode(2 days, true, _clauses)), 2 days);
  }

  /// Checks that `ignoresPause` false reads back false and leaves the wait intact. A flag read as true would stop a
  /// method's pause from protecting a holder who chose to honor it.
  function test_WhenIgnoresPauseIsFalse() external view {
    // it should read false
    SetupBodyTestClause[] memory _clauses = _two(_clause(1, 2, 1), _clause(0, 1, 2));
    assertFalse(_harness.ignoresPauseOf(_encode(2 days, false, _clauses)));
    assertFalse(_harness.ignoresPauseOf(_encode(type(uint48).max, false, _clauses)));
    assertEq(_harness.waitOf(_encode(2 days, false, _clauses)), 2 days);
  }

  /// Checks that both scalars read back even when the body has no clauses.
  function test_WhenTheBodyHasNoClauses() external view {
    // it should still read both scalars
    bytes memory _setupBody = _encode(7 days, true, _noClauses());
    assertEq(_harness.waitOf(_setupBody), 7 days);
    assertTrue(_harness.ignoresPauseOf(_setupBody));
    bytes memory _other = _encode(1, false, _noClauses());
    assertEq(_harness.waitOf(_other), 1);
    assertFalse(_harness.ignoresPauseOf(_other));
  }
}
