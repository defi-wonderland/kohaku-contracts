// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {IRecoveryAction} from 'interfaces/IRecoveryAction.sol';
import {InterfacesArtifacts} from 'test/utils/InterfacesArtifacts.sol';

/// @notice Checks the call surface of IRecoveryAction: its selectors, the exact set of its functions including
///         those of its base interface, and each function's parameters, returns and mutability in the compiled ABI.
contract IRecoveryActionTest is InterfacesArtifacts {
  /// Checks each selector of IRecoveryAction is the first four bytes of keccak256 of the function's
  /// canonical signature. Every caller encodes calls from that signature, so a drift breaks the call.
  function test_WhenTheSelectorsAreDerived() external pure {
    // it should match each function's canonical signature
    _interfacesAssertSelector(IRecoveryAction.holdsAnyPrivilege.selector, 'holdsAnyPrivilege(address,address)');
    _interfacesAssertSelector(IRecoveryAction.executeHandover.selector, 'executeHandover(address,bytes)');
  }

  /// Reads the compiled ABI of IRecoveryAction and checks it lists exactly the specified functions, events
  /// and errors. An extra or missing entry changes the surface every other contract compiles against, and
  /// an account-specific callback here would make every recovery action for another account declare it.
  function test_WhenTheCompiledAbiIsRead() external {
    // it should list exactly the specified functions events and errors
    string memory _json = _interfacesLoad('IRecoveryAction');
    string[] memory _signatures = new string[](8);
    _signatures[0] = 'supportsAccount(address)';
    _signatures[1] = 'isAuthority(address,address)';
    _signatures[2] = 'isAuthorized(address)';
    _signatures[3] = 'supportsInterface(bytes4)';
    _signatures[4] = 'name()';
    _signatures[5] = 'version()';
    _signatures[6] = 'holdsAnyPrivilege(address,address)';
    _signatures[7] = 'executeHandover(address,bytes)';
    _interfacesAssertMethodIdentifiers(_json, _signatures);
    assertEq(_interfacesAbiCount(_json, 'function'), 8, 'functions');
    assertEq(_interfacesAbiCount(_json, 'event'), 0, 'events');
    assertEq(_interfacesAbiCount(_json, 'error'), 6, 'errors');
  }

  /// Checks that holdsAnyPrivilege in the compiled ABI of IRecoveryAction has the specified parameter and return types
  /// and names and is view. A view is what lets a caller reach it with a static call, which can write nothing.
  function test_WhenHoldsAnyPrivilegeIsReadFromTheAbi() external {
    // it should declare the specified parameters returns and mutability
    string memory _json = _interfacesLoad('IRecoveryAction');
    _interfacesAssertFunction(
      _json, 'holdsAnyPrivilege', 'view', 'address _account,address _candidate', 'bool _reserved'
    );
  }

  /// Checks that executeHandover in the compiled ABI of IRecoveryAction has the specified parameter and return types
  /// and names and is nonpayable. Clients encode their calls from these types and names.
  function test_WhenExecuteHandoverIsReadFromTheAbi() external {
    // it should declare the specified parameters returns and mutability
    string memory _json = _interfacesLoad('IRecoveryAction');
    _interfacesAssertFunction(_json, 'executeHandover', 'nonpayable', 'address _account,bytes _payload', '');
  }
}
