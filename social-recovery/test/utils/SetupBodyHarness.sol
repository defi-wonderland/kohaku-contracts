// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {SetupBody} from 'libraries/SetupBody.sol';
import {IPolicyManager} from 'interfaces/IPolicyManager.sol';

/// @notice Exposes the setup body readers as external calls. A test can then expect their reverts, and the body and
///         the proofs arrive as calldata, the way the policy manager hands them over. It also exposes the library's
///         own encoder, so the vector replay can hold it to the frozen bytes, and the decoder with the two readers that
///         take already decoded clauses, so a test can compare them with the readers that take the body bytes.
contract SetupBodyHarness {
  /// @dev Calls `SetupBody.credentialAt` with calldata arguments.
  function credentialAt(bytes calldata _body, uint256 _place) external pure returns (bytes32 _credential) {
    _credential = SetupBody.credentialAt(_body, _place);
  }

  /// @dev Calls `SetupBody.ruleSatisfied` with calldata arguments.
  function ruleSatisfied(bytes calldata _body, IPolicyManager.ProofPlace[] calldata _proofs)
    external
    pure
    returns (bool _satisfied, uint256 _failingClause)
  {
    (_satisfied, _failingClause) = SetupBody.ruleSatisfied(_body, _proofs);
  }

  /// @dev Calls `SetupBody.ignoresPauseOf` with a calldata body.
  function ignoresPauseOf(bytes calldata _body) external pure returns (bool _ignoresPause) {
    _ignoresPause = SetupBody.ignoresPauseOf(_body);
  }

  /// @dev Calls `SetupBody.encode`, the library's own encoder.
  function encode(uint48 _wait, bool _ignoresPause, IPolicyManager.Clause[] calldata _clauses)
    external
    pure
    returns (bytes memory _body)
  {
    _body = SetupBody.encode(_wait, _ignoresPause, _clauses);
  }

  /// @dev Calls `SetupBody.waitOf` with a calldata body.
  function waitOf(bytes calldata _body) external pure returns (uint48 _wait) {
    _wait = SetupBody.waitOf(_body);
  }

  /// @dev Calls `SetupBody.decode` with a calldata body.
  function decode(bytes calldata _body)
    external
    pure
    returns (uint48 _wait, bool _ignoresPause, IPolicyManager.Clause[] memory _clauses)
  {
    (_wait, _ignoresPause, _clauses) = SetupBody.decode(_body);
  }

  /// @dev Calls `SetupBody.credentialAt` with already decoded clauses, copied into memory as the library takes them.
  function credentialAt(IPolicyManager.Clause[] calldata _clauses, uint256 _place)
    external
    pure
    returns (bytes32 _credential)
  {
    _credential = SetupBody.credentialAt(_clauses, _place);
  }

  /// @dev Calls `SetupBody.ruleSatisfied` with already decoded clauses, copied into memory as the library takes them,
  ///      and calldata proofs.
  function ruleSatisfied(IPolicyManager.Clause[] calldata _clauses, IPolicyManager.ProofPlace[] calldata _proofs)
    external
    pure
    returns (bool _satisfied, uint256 _failingClause)
  {
    (_satisfied, _failingClause) = SetupBody.ruleSatisfied(_clauses, _proofs);
  }
}
