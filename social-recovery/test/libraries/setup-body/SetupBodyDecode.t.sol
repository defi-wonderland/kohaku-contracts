// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {IPolicyManager} from 'interfaces/IPolicyManager.sol';
import {SetupBodyTestBase, SetupBodyTestClause} from 'test/utils/SetupBodyTestBase.sol';

/// @notice Unit tests for `decode(_body)`, which reads the whole setup body once and returns its wait, its
///         `ignoresPause` flag and its clauses. Every body here is built with the library's own encoder, so each test
///         checks that the decoder gives back exactly what the encoder was handed. A caller that decodes once and
///         then reads places and the rule from the result must see the same rule the holder committed.
///         Tree: SetupBodyDecode.tree.
contract SetupBodyDecodeTest is SetupBodyTestBase {
  /// Decodes `_setupBody` and asserts it returns `_wait`, `_ignoresPause` and `_clauses`.
  function _assertDecodes(
    bytes memory _setupBody,
    uint48 _wait,
    bool _ignoresPause,
    SetupBodyTestClause[] memory _clauses
  ) internal view {
    (uint48 _gotWait, bool _gotIgnoresPause, IPolicyManager.Clause[] memory _gotClauses) = _harness.decode(_setupBody);
    assertEq(_gotWait, _wait, 'wait');
    assertEq(_gotIgnoresPause, _ignoresPause, 'ignoresPause');
    _assertSameClauses(_gotClauses, _clauses);
  }

  /// Checks that a body with no clauses decodes to its two scalars and an empty clause list. An empty list read as
  /// anything else would give a caller clauses the holder never wrote.
  function test_WhenTheBodyHasNoClauses() external view {
    // it should return the wait, the flag and no clauses
    _assertDecodes(_libraryBody(7 days, true, _noClauses()), 7 days, true, _noClauses());
  }

  /// Checks that a single clause decodes to its own threshold and credentials in order, so the caller counts the
  /// guardians the holder named against the number the holder chose.
  function test_WhenTheBodyHasOneClause() external view {
    // it should return that clause's threshold and credentials
    SetupBodyTestClause[] memory _clauses = _one(_clause(2, 3, 1));
    _assertDecodes(_libraryBody(2 days, false, _clauses), 2 days, false, _clauses);
  }

  /// Checks that several clauses decode in the order they were encoded. A reordering would move every place of the
  /// flat numbering, so a proof would count toward a clause the holder did not put that guardian in.
  function test_WhenTheBodyHasSeveralClauses() external view {
    // it should return every clause in body order
    SetupBodyTestClause[] memory _clauses = _three(_clause(1, 1, 1), _clause(2, 3, 2), _clause(1, 2, 3));
    _assertDecodes(_libraryBody(1 days, true, _clauses), 1 days, true, _clauses);
  }

  /// Checks that a clause with no credentials decodes as an empty list between its neighbours, so it takes no place
  /// and the clauses after it keep their own credentials.
  function test_WhenAClauseListsNoCredentials() external view {
    // it should return that clause with an empty credential list
    SetupBodyTestClause[] memory _clauses = _three(_clause(1, 2, 1), _clause(0, 0, 2), _clause(1, 1, 3));
    _assertDecodes(_libraryBody(2 days, false, _clauses), 2 days, false, _clauses);
  }

  /// Checks that a zero clause, one whose threshold is zero, decodes with its threshold still zero beside a positive
  /// clause. A holder may park a retired credential there, and reading any other threshold would change the rule.
  function test_WhenAClauseHasAThresholdOfZero() external view {
    // it should return that clause with a threshold of zero
    SetupBodyTestClause[] memory _clauses = _two(_clause(0, 2, 1), _clause(1, 1, 2));
    _assertDecodes(_libraryBody(2 days, false, _clauses), 2 days, false, _clauses);
  }

  /// Checks that a threshold above its clause's credential count, here the widest `uint8`, decodes unchanged rather
  /// than clamped, so that clause stays impossible to meet as the holder wrote it.
  function test_WhenAThresholdExceedsItsClausesCredentialCount() external view {
    // it should return the threshold unchanged
    SetupBodyTestClause[] memory _clauses = _two(_clause(type(uint8).max, 0, 1), _clause(3, 2, 2));
    _assertDecodes(_libraryBody(2 days, false, _clauses), 2 days, false, _clauses);
  }

  /// Checks that one credential written at two places decodes as two copies. A rule may name one credential twice,
  /// and each place carries its own proof, so dropping a copy would lose a place.
  function test_WhenOneCredentialRepeatsAtTwoPlaces() external view {
    // it should return both copies
    SetupBodyTestClause[] memory _clauses = _two(_clause(2, 2, 1), _clause(1, 1, 2));
    _clauses[1].credentials[0] = _clauses[0].credentials[1];
    _clauses[0].credentials[0] = _clauses[0].credentials[1];
    _assertDecodes(_libraryBody(2 days, false, _clauses), 2 days, false, _clauses);
  }

  /// Checks that the widest `uint48` wait and `ignoresPause` true decode whole, so no wait is truncated into a
  /// shorter delay and the holder's opt out of a method's stop is kept.
  function test_WhenTheScalarsAreAtTheirWidest() external view {
    // it should return the widest uint48 wait and true
    SetupBodyTestClause[] memory _clauses = _one(_clause(1, 1, 1));
    _assertDecodes(_libraryBody(type(uint48).max, true, _clauses), type(uint48).max, true, _clauses);
  }

  /// Checks that a zero wait and `ignoresPause` false decode as such, since the library sets no floor on the wait
  /// and a false flag read as true would stop a method's pause from protecting the holder.
  function test_WhenTheScalarsAreAtTheirSmallest() external view {
    // it should return a zero wait and false
    SetupBodyTestClause[] memory _clauses = _one(_clause(1, 1, 1));
    _assertDecodes(_libraryBody(0, false, _clauses), 0, false, _clauses);
  }
}
