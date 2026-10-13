// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {IRecoveryAction} from 'interfaces/IRecoveryAction.sol';
import {InterfacesArtifacts} from 'test/utils/InterfacesArtifacts.sol';

/// @notice Checks the field types, field names and encoding order of the struct every recovery action shares.
contract RecoveryActionTypesTest is InterfacesArtifacts {
  /// Builds a Handover with named fields and distinct values. Each _exactly helper compiles only when
  /// the field has exactly that type, and the encoding must equal the fields encoded in order.
  /// Clients and the manager exchange these bytes, so a moved or resized field breaks every request.
  function test_WhenTheHandoverStructIsEncoded() external pure {
    // it should hold the specified fields types and order
    IRecoveryAction.Handover memory _subject =
      IRecoveryAction.Handover({newAuthority: address(0x1001), removedAuthority: address(0x1002)});
    _subject.newAuthority = _exactlyAddress(_subject.newAuthority);
    _subject.removedAuthority = _exactlyAddress(_subject.removedAuthority);
    assertEq(abi.encode(_subject), abi.encode(_subject.newAuthority, _subject.removedAuthority));
  }

  /// @notice Compiles only when the field is exactly address: the argument converts implicitly
  ///         from the field, and the result converts implicitly back into it.
  function _exactlyAddress(address _input) private pure returns (address _output) {
    _output = _input;
  }
}
