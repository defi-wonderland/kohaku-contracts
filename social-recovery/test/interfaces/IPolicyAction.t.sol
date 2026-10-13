// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {IPolicyAction} from 'interfaces/IPolicyAction.sol';
import {InterfacesArtifacts} from 'test/utils/InterfacesArtifacts.sol';

/// @notice Checks the call surface of IPolicyAction: its selectors, the exact set of its functions, and each
///         function's parameters, returns and mutability in the compiled ABI.
contract IPolicyActionTest is InterfacesArtifacts {
  /// Checks each selector of IPolicyAction is the first four bytes of keccak256 of the function's
  /// canonical signature. Every caller encodes calls from that signature, so a drift breaks the call.
  function test_WhenTheSelectorsAreDerived() external pure {
    // it should match each function's canonical signature
    _interfacesAssertSelector(IPolicyAction.supportsAccount.selector, 'supportsAccount(address)');
    _interfacesAssertSelector(IPolicyAction.isAuthority.selector, 'isAuthority(address,address)');
    _interfacesAssertSelector(IPolicyAction.isAuthorized.selector, 'isAuthorized(address)');
    _interfacesAssertSelector(IPolicyAction.supportsInterface.selector, 'supportsInterface(bytes4)');
    _interfacesAssertSelector(IPolicyAction.name.selector, 'name()');
    _interfacesAssertSelector(IPolicyAction.version.selector, 'version()');
  }

  /// Reads the compiled ABI of IPolicyAction and checks it lists exactly the specified functions, events
  /// and errors. An extra or missing entry changes the surface every other contract compiles against.
  function test_WhenTheCompiledAbiIsRead() external {
    // it should list exactly the specified functions events and errors
    string memory _json = _interfacesLoad('IPolicyAction');
    string[] memory _signatures = new string[](6);
    _signatures[0] = 'supportsAccount(address)';
    _signatures[1] = 'isAuthority(address,address)';
    _signatures[2] = 'isAuthorized(address)';
    _signatures[3] = 'supportsInterface(bytes4)';
    _signatures[4] = 'name()';
    _signatures[5] = 'version()';
    _interfacesAssertMethodIdentifiers(_json, _signatures);
    assertEq(_interfacesAbiCount(_json, 'function'), 6, 'functions');
    assertEq(_interfacesAbiCount(_json, 'event'), 0, 'events');
    assertEq(_interfacesAbiCount(_json, 'error'), 0, 'errors');
  }

  /// Checks that supportsAccount in the compiled ABI of IPolicyAction has the specified parameter and return types
  /// and names and is view. A view is what lets a caller reach it with a static call, which can write nothing.
  function test_WhenSupportsAccountIsReadFromTheAbi() external {
    // it should declare the specified parameters returns and mutability
    string memory _json = _interfacesLoad('IPolicyAction');
    _interfacesAssertFunction(_json, 'supportsAccount', 'view', 'address _account', 'bool _supported');
  }

  /// Checks that isAuthority in the compiled ABI of IPolicyAction has the specified parameter and return types
  /// and names and is view. A view is what lets a caller reach it with a static call, which can write nothing.
  function test_WhenIsAuthorityIsReadFromTheAbi() external {
    // it should declare the specified parameters returns and mutability
    string memory _json = _interfacesLoad('IPolicyAction');
    _interfacesAssertFunction(_json, 'isAuthority', 'view', 'address _account,address _authority', 'bool _holds');
  }

  /// Checks that isAuthorized in the compiled ABI of IPolicyAction has the specified parameter and return types
  /// and names and is view. A view is what lets a caller reach it with a static call, which can write nothing.
  function test_WhenIsAuthorizedIsReadFromTheAbi() external {
    // it should declare the specified parameters returns and mutability
    string memory _json = _interfacesLoad('IPolicyAction');
    _interfacesAssertFunction(_json, 'isAuthorized', 'view', 'address _account', 'bool _authorized');
  }

  /// Checks that supportsInterface in the compiled ABI of IPolicyAction has the specified parameter and return types
  /// and names and is view. A view is what lets a caller reach it with a static call, which can write nothing.
  function test_WhenSupportsInterfaceIsReadFromTheAbi() external {
    // it should declare the specified parameters returns and mutability
    string memory _json = _interfacesLoad('IPolicyAction');
    _interfacesAssertFunction(_json, 'supportsInterface', 'view', 'bytes4 _interfaceId', 'bool _supported');
  }

  /// Checks that name in the compiled ABI of IPolicyAction has the specified parameter and return types
  /// and names and is view. A view is what lets a caller reach it with a static call, which can write nothing.
  function test_WhenNameIsReadFromTheAbi() external {
    // it should declare the specified parameters returns and mutability
    string memory _json = _interfacesLoad('IPolicyAction');
    _interfacesAssertFunction(_json, 'name', 'view', '', 'string _actionName');
  }

  /// Checks that version in the compiled ABI of IPolicyAction has the specified parameter and return types
  /// and names and is view. A view is what lets a caller reach it with a static call, which can write nothing.
  function test_WhenVersionIsReadFromTheAbi() external {
    // it should declare the specified parameters returns and mutability
    string memory _json = _interfacesLoad('IPolicyAction');
    _interfacesAssertFunction(_json, 'version', 'view', '', 'string _actionVersion');
  }
}
