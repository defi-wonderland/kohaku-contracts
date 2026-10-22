// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {IPolicyManager} from 'interfaces/IPolicyManager.sol';
import {SetupBodyTestBase, SetupBodyTestClause} from 'test/utils/SetupBodyTestBase.sol';

/// @notice Property fuzzing of the decoder and of the two readers that take already decoded clauses. Each test builds
///         a random body from a `_seed`, a fuzz parameter from which a builder in `SetupBodyTestBase` derives every
///         clause count, threshold and credential, encodes it with the library's own encoder, and checks one property
///         for any such body. The equivalence tests hold the clauses readers to the readers that take the body bytes:
///         a caller that decodes a body once must get the same answer, or the same revert, as one that reads the bytes.
///         A place, a filled place and the builders are defined in `SetupBodyTestBase`.
contract SetupBodyDecodeFuzzTest is SetupBodyTestBase {
  /// Returns the clauses `decode` reads from `_setupBody`.
  function _decodedClauses(bytes memory _setupBody) internal view returns (IPolicyManager.Clause[] memory _clauses) {
    (,, _clauses) = _harness.decode(_setupBody);
  }

  /// Checks that decoding a body the library's encoder built from any wait, any `ignoresPause` value and up to five
  /// random clauses gives back exactly those inputs. A decoder that drifted from the encoder would run a recovery
  /// against a rule, a wait or a pause choice other than the one the holder committed.
  function testFuzz_DecodeReturnsTheEncodedInputs(uint48 _wait, bool _ignoresPause, uint256 _seed) external view {
    SetupBodyTestClause[] memory _clauses = _randomClauses(_seed, 5, 5);
    (uint48 _gotWait, bool _gotIgnoresPause, IPolicyManager.Clause[] memory _gotClauses) =
      _harness.decode(_libraryBody(_wait, _ignoresPause, _clauses));
    assertEq(_gotWait, _wait, 'wait');
    assertEq(_gotIgnoresPause, _ignoresPause, 'ignoresPause');
    _assertSameClauses(_gotClauses, _clauses);
  }

  /// Checks that the scalars `decode` returns are the ones `waitOf` and `ignoresPauseOf` read from the same body. A
  /// caller that decodes once must see the same wait and pause choice as one that reads each scalar on its own.
  function testFuzz_DecodeScalarsMatchTheScalarReaders(uint48 _wait, bool _ignoresPause, uint256 _seed) external view {
    bytes memory _setupBody = _libraryBody(_wait, _ignoresPause, _randomClauses(_seed, 5, 5));
    (uint48 _gotWait, bool _gotIgnoresPause,) = _harness.decode(_setupBody);
    assertEq(_gotWait, _harness.waitOf(_setupBody), 'wait');
    assertEq(_gotIgnoresPause, _harness.ignoresPauseOf(_setupBody), 'ignoresPause');
  }

  /// Checks that for any place inside a random body, reading it from the decoded clauses returns the same credential
  /// as reading it from the body bytes, and that this is the credential encoded at that place. A mismatch would
  /// compare a proof against a different hash depending on how the caller read the body.
  function testFuzz_CredentialAtClausesMatchesTheBodyForm(uint256 _seed, uint256 _place) external view {
    SetupBodyTestClause[] memory _clauses = _randomClausesWithAPlace(_seed, 5, 5);
    bytes memory _setupBody = _libraryBody(2 days, false, _clauses);
    _place = bound(_place, 0, _placeCount(_clauses) - 1);
    bytes32 _fromClauses = _harness.credentialAt(_decodedClauses(_setupBody), _place);
    assertEq(_fromClauses, _harness.credentialAt(_setupBody, _place), 'body form');
    assertEq(_fromClauses, _harness.credentialAt(_asClauses(_clauses), _place), 'encoded clauses');
  }

  /// Checks that for any place at or past the total credential count, both forms revert with
  /// `PolicyManager_PlaceOutOfRange` naming the same place and the same count. A form that returned a word instead
  /// would let a proof name a place the rule does not have.
  function testFuzz_CredentialAtClausesRevertsLikeTheBodyForm(uint256 _seed, uint256 _place) external {
    SetupBodyTestClause[] memory _clauses = _randomClauses(_seed, 5, 5);
    uint256 _count = _placeCount(_clauses);
    _place = bound(_place, _count, type(uint256).max);
    bytes memory _setupBody = _libraryBody(2 days, false, _clauses);
    IPolicyManager.Clause[] memory _decoded = _decodedClauses(_setupBody);
    bytes memory _expected =
      abi.encodeWithSelector(IPolicyManager.PolicyManager_PlaceOutOfRange.selector, _place, _count);

    vm.expectRevert(_expected);
    _harness.credentialAt(_setupBody, _place);
    vm.expectRevert(_expected);
    _harness.credentialAt(_decoded, _place);
  }

  /// Checks that for any random body and any strictly increasing filled places, some possibly past the end, checking
  /// the rule on the decoded clauses returns the same verdict and the same failing clause as checking it on the body
  /// bytes. `_mask` picks the filled places inside the body and `_extra` adds up to three past its end. A mismatch
  /// would let the same proofs open a recovery through one caller and not the other.
  function testFuzz_RuleSatisfiedClausesMatchesTheBodyForm(uint256 _seed, uint256 _mask, uint256 _extra) external view {
    SetupBodyTestClause[] memory _clauses = _randomClauses(_seed, 5, 5);
    uint256 _count = _placeCount(_clauses);
    bytes memory _setupBody = _libraryBody(2 days, false, _clauses);
    IPolicyManager.ProofPlace[] memory _proofList =
      _proofs(_withPlacesPastTheEnd(_maskedPlaces(_count, _mask), _count, bound(_extra, 0, 3)));

    (bool _bodySatisfied, uint256 _bodyFailing) = _harness.ruleSatisfied(_setupBody, _proofList);
    (bool _clausesSatisfied, uint256 _clausesFailing) = _harness.ruleSatisfied(_decodedClauses(_setupBody), _proofList);
    assertEq(_clausesSatisfied, _bodySatisfied, 'satisfied');
    assertEq(_clausesFailing, _bodyFailing, 'failing clause');
  }

  /// Checks that for any random body and a list of places with one entry not above its predecessor, both forms revert
  /// with `PolicyManager_PlacesNotStrictlyIncreasing` naming that entry. `_mask` and `_bit` pick a strictly increasing
  /// set, `_at` where the offending entry goes and `_drop` its value, at or below the entry before it. A form that
  /// counted instead would let one guardian fill two seats of a clause.
  function testFuzz_RuleSatisfiedClausesRevertsLikeTheBodyForm(
    uint256 _seed,
    uint256 _mask,
    uint256 _bit,
    uint256 _at,
    uint256 _drop
  ) external {
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
    bytes memory _setupBody = _libraryBody(2 days, false, _clauses);
    IPolicyManager.Clause[] memory _decoded = _decodedClauses(_setupBody);
    bytes memory _expected =
      abi.encodeWithSelector(IPolicyManager.PolicyManager_PlacesNotStrictlyIncreasing.selector, _offending);

    vm.expectRevert(_expected);
    _harness.ruleSatisfied(_setupBody, _proofList);
    vm.expectRevert(_expected);
    _harness.ruleSatisfied(_decoded, _proofList);
  }
}
