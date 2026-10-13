// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {IPolicyManager} from 'interfaces/IPolicyManager.sol';

/// @title SetupBody
/// @author defi-wonderland
/// @notice This library encodes and reads the setup body. The setup body holds the rule, the
///         wait and the holder's pause choice, and the account commits to it by hash. The body
///         is abi.encode(uint48 wait, bool ignoresPause, IPolicyManager.Clause[] clauses).
/// @dev A place is the index of a credential when all clauses are read as one list in body
///      order. Place 0 is the first credential of the first clause, and the numbering continues
///      into the next clause. The library holds no storage. It sets no numeric limit other than
///      the widths of its types. It does not treat a position in the proofs array as filled.
///      The caller passes the places whose proofs verified, and the library counts those.
library SetupBody {
  /*///////////////////////////////////////////////////////////////
                          INTERNAL FUNCTIONS
  ///////////////////////////////////////////////////////////////*/

  /// @notice Encodes a setup body. The setup commitment and the digest both hash these bytes.
  /// @param _wait The number of seconds from acceptance to consumableAfter. It has no minimum
  ///        and no maximum.
  /// @param _ignoresPause Whether a method's stop reaches this holder's accepted attempts.
  /// @param _clauses The clauses of the rule in body order.
  /// @return _body The bytes abi.encode(_wait, _ignoresPause, _clauses).
  function encode(uint48 _wait, bool _ignoresPause, IPolicyManager.Clause[] memory _clauses)
    internal
    pure
    returns (bytes memory _body)
  {
    _body = abi.encode(_wait, _ignoresPause, _clauses);
  }

  /// @notice Decodes a setup body once, so a caller that reads it several times pays for one decode.
  /// @dev It reverts when the bytes do not decode as (uint48, bool, IPolicyManager.Clause[]). It does not
  ///      require the canonical encoding, so bytes with trailing data or moved offsets can decode. The
  ///      setup commitment and the digest hash the body's exact bytes, so only the bytes the account
  ///      committed can open an attempt, and a client that re-encodes the rule gets another hash. Every
  ///      other reader of this library decodes the body through this function.
  /// @param _body The setup body.
  /// @return _wait The wait of the body in seconds.
  /// @return _ignoresPause The ignoresPause flag of the body.
  /// @return _clauses The clauses of the rule in body order.
  function decode(bytes calldata _body)
    internal
    pure
    returns (uint48 _wait, bool _ignoresPause, IPolicyManager.Clause[] memory _clauses)
  {
    (_wait, _ignoresPause, _clauses) = abi.decode(_body, (uint48, bool, IPolicyManager.Clause[]));
  }

  /// @notice Returns the credential hash at a place of a setup body.
  /// @dev It decodes the body and reads the place from the decoded clauses. It reverts with
  ///      PolicyManager_PlaceOutOfRange when the place is equal to or greater than the body's total
  ///      credential count. A place the rule does not have therefore fails before any method receives it.
  /// @param _body The setup body.
  /// @param _place The flat index of the credential.
  /// @return _credential The credential hash at that place.
  function credentialAt(bytes calldata _body, uint256 _place) internal pure returns (bytes32 _credential) {
    (,, IPolicyManager.Clause[] memory _clauses) = decode(_body);
    _credential = credentialAt(_clauses, _place);
  }

  /// @notice Returns the credential hash at a place of clauses already decoded from a setup body.
  /// @dev A place is the index of a credential when all clauses are read as one list in order. It
  ///      reverts with PolicyManager_PlaceOutOfRange, carrying the place and the total credential
  ///      count, when the place is equal to or greater than that count.
  /// @param _clauses The clauses of the rule in body order.
  /// @param _place The flat index of the credential.
  /// @return _credential The credential hash at that place.
  function credentialAt(IPolicyManager.Clause[] memory _clauses, uint256 _place)
    internal
    pure
    returns (bytes32 _credential)
  {
    uint256 _offset = 0;
    for (uint256 _i; _i < _clauses.length; ++_i) {
      bytes32[] memory _credentials = _clauses[_i].credentials;
      if (_place < _offset + _credentials.length) return _credentials[_place - _offset];
      _offset += _credentials.length;
    }
    revert IPolicyManager.PolicyManager_PlaceOutOfRange(_place, _offset);
  }

  /// @notice Counts the filled places in each clause of a setup body and checks whether every clause
  ///         meets its threshold.
  /// @dev It decodes the body and answers as the overload that takes decoded clauses.
  /// @param _body The setup body.
  /// @param _proofs The proofs whose places verified, in strictly increasing order of place.
  /// @return _satisfied True when every clause meets its threshold and at least one threshold is
  ///         greater than zero.
  /// @return _failingClause The index of the first clause that misses its threshold. It is zero
  ///         for a body with no clauses, for a rule whose thresholds are all zero, and for a
  ///         satisfied rule.
  function ruleSatisfied(bytes calldata _body, IPolicyManager.ProofPlace[] calldata _proofs)
    internal
    pure
    returns (bool _satisfied, uint256 _failingClause)
  {
    (,, IPolicyManager.Clause[] memory _clauses) = decode(_body);
    (_satisfied, _failingClause) = ruleSatisfied(_clauses, _proofs);
  }

  /// @notice Counts the filled places in each of the clauses already decoded from a setup body and
  ///         checks whether every clause meets its threshold.
  /// @dev Returns false naming clause zero when there are no clauses or every threshold is zero, since
  ///      anyone could meet those rules with no proof at all. A clause with a threshold of zero requires
  ///      nothing, so the result then depends on the other clauses. Reverts with
  ///      PolicyManager_PlacesNotStrictlyIncreasing when a place is not greater than the one before it,
  ///      so no place counts twice. It reads only the places: the caller passes proofs that already
  ///      verified, and credentialAt has already refused any place the rule does not have.
  /// @param _clauses The clauses of the rule in body order.
  /// @param _proofs The proofs whose places verified, in strictly increasing order of place.
  /// @return _satisfied True when every clause meets its threshold and at least one threshold is
  ///         greater than zero.
  /// @return _failingClause The index of the first clause that misses its threshold. It is zero
  ///         when there are no clauses, for a rule whose thresholds are all zero, and for a
  ///         satisfied rule.
  function ruleSatisfied(IPolicyManager.Clause[] memory _clauses, IPolicyManager.ProofPlace[] calldata _proofs)
    internal
    pure
    returns (bool _satisfied, uint256 _failingClause)
  {
    _requireStrictlyIncreasing(_proofs);
    (_satisfied, _failingClause) = _countClauses(_clauses, _proofs);
  }

  /// @notice Reads the holder's choice about whether a method's stop reaches their accepted
  ///         attempts.
  /// @param _body The setup body.
  /// @return _ignoresPause The ignoresPause flag of the body.
  function ignoresPauseOf(bytes calldata _body) internal pure returns (bool _ignoresPause) {
    (, _ignoresPause,) = decode(_body);
  }

  /// @notice Reads the wait from acceptance to consumableAfter.
  /// @param _body The setup body.
  /// @return _wait The wait of the body in seconds.
  function waitOf(bytes calldata _body) internal pure returns (uint48 _wait) {
    (_wait,,) = decode(_body);
  }

  /*///////////////////////////////////////////////////////////////
                          PRIVATE FUNCTIONS
  ///////////////////////////////////////////////////////////////*/

  /// @notice Checks that every place is strictly greater than the one before it.
  /// @dev Reverts with PolicyManager_PlacesNotStrictlyIncreasing, carrying the first place that is not
  ///      greater than its predecessor.
  /// @param _proofs The proofs whose places are checked.
  function _requireStrictlyIncreasing(IPolicyManager.ProofPlace[] calldata _proofs) private pure {
    for (uint256 _j = 1; _j < _proofs.length; ++_j) {
      require(
        _proofs[_j].place > _proofs[_j - 1].place,
        IPolicyManager.PolicyManager_PlacesNotStrictlyIncreasing(_proofs[_j].place)
      );
    }
  }

  /// @notice Counts the filled places in each clause against its threshold.
  /// @dev It assumes the places are strictly increasing. It walks the clauses and the places together,
  ///      giving each place to the clause whose flat range holds it. A clause with a threshold of zero
  ///      requires nothing. _satisfied turns true at the first clause that requires something, so it
  ///      stays false, naming clause zero, when there are no clauses or every threshold is zero.
  /// @param _clauses The clauses of the rule in body order.
  /// @param _proofs The proofs whose places verified, in strictly increasing order of place.
  /// @return _satisfied True when every clause meets its threshold and at least one threshold is
  ///         greater than zero.
  /// @return _failingClause The index of the first clause that misses its threshold, or zero.
  function _countClauses(IPolicyManager.Clause[] memory _clauses, IPolicyManager.ProofPlace[] calldata _proofs)
    private
    pure
    returns (bool _satisfied, uint256 _failingClause)
  {
    uint256 _clauseEnd = 0;
    uint256 _cursor = 0;
    for (uint256 _i; _i < _clauses.length; ++_i) {
      _clauseEnd += _clauses[_i].credentials.length;
      uint256 _filled;
      (_filled, _cursor) = _countPlacesBelow(_proofs, _cursor, _clauseEnd);
      uint256 _threshold = _clauses[_i].threshold;
      if (_threshold != 0) {
        _satisfied = true;
        if (_filled < _threshold) return (false, _i);
      }
    }
  }

  /// @notice Counts the places from a cursor that fall below the end of a clause's flat range.
  /// @dev It assumes the places are strictly increasing, so it stops at the first place at or past
  ///      the end, which belongs to a later clause.
  /// @param _proofs The proofs whose places verified, in strictly increasing order of place.
  /// @param _cursor The index in _proofs of the first place not yet given to a clause.
  /// @param _clauseEnd The flat index one past the clause's last credential.
  /// @return _filled The number of places that fall in the clause.
  /// @return _nextCursor The index in _proofs of the first place past the clause.
  function _countPlacesBelow(IPolicyManager.ProofPlace[] calldata _proofs, uint256 _cursor, uint256 _clauseEnd)
    private
    pure
    returns (uint256 _filled, uint256 _nextCursor)
  {
    _nextCursor = _cursor;
    while (_nextCursor < _proofs.length && _proofs[_nextCursor].place < _clauseEnd) {
      ++_nextCursor;
    }
    _filled = _nextCursor - _cursor;
  }
}
