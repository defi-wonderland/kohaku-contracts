// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {IPolicyMethod} from 'interfaces/IPolicyMethod.sol';
import {InterfacesArtifacts} from 'test/utils/InterfacesArtifacts.sol';

/// @notice Checks the call surface of IPolicyMethod: its selectors, the verify magic value, the exact set of its
///         functions, and each function's parameters, returns and mutability in the compiled ABI.
contract IPolicyMethodTest is InterfacesArtifacts {
  /// Checks each selector of IPolicyMethod is the first four bytes of keccak256 of the function's
  /// canonical signature. Every caller encodes calls from that signature, so a drift breaks the call.
  function test_WhenTheSelectorsAreDerived() external pure {
    // it should match each function's canonical signature
    _interfacesAssertSelector(IPolicyMethod.verify.selector, 'verify(bytes,bytes32,bytes)');
    _interfacesAssertSelector(IPolicyMethod.trustedParties.selector, 'trustedParties()');
    _interfacesAssertSelector(IPolicyMethod.supportsInterface.selector, 'supportsInterface(bytes4)');
    _interfacesAssertSelector(IPolicyMethod.name.selector, 'name()');
    _interfacesAssertSelector(IPolicyMethod.version.selector, 'version()');
  }

  /// Checks the verify selector is 0x024ad318, the one word the manager accepts as a passing verdict.
  /// It is also the ERC-7913 magic value, so a verifier built to that standard works as a method.
  function test_WhenTheVerifySelectorIsComputed() external pure {
    // it should equal the magic value 0x024ad318
    assertEq(IPolicyMethod.verify.selector, bytes4(0x024ad318));
  }

  /// Reads the compiled ABI of IPolicyMethod and checks it lists exactly the specified functions, events
  /// and errors. An extra or missing entry changes the surface every other contract compiles against.
  function test_WhenTheCompiledAbiIsRead() external {
    // it should list exactly the specified functions events and errors
    string memory _json = _interfacesLoad('IPolicyMethod');
    string[] memory _signatures = new string[](5);
    _signatures[0] = 'verify(bytes,bytes32,bytes)';
    _signatures[1] = 'trustedParties()';
    _signatures[2] = 'supportsInterface(bytes4)';
    _signatures[3] = 'name()';
    _signatures[4] = 'version()';
    _interfacesAssertMethodIdentifiers(_json, _signatures);
    assertEq(_interfacesAbiCount(_json, 'function'), 5, 'functions');
    assertEq(_interfacesAbiCount(_json, 'event'), 0, 'events');
    assertEq(_interfacesAbiCount(_json, 'error'), 0, 'errors');
  }

  /// Checks that verify in the compiled ABI of IPolicyMethod has the specified parameter and return types
  /// and names and is view. A view is what lets a caller reach it with a static call, which can write nothing.
  function test_WhenVerifyIsReadFromTheAbi() external {
    // it should declare the specified parameters returns and mutability
    string memory _json = _interfacesLoad('IPolicyMethod');
    _interfacesAssertFunction(
      _json, 'verify', 'view', 'bytes _config,bytes32 _digest,bytes _proof', 'bytes4 _magicValue'
    );
  }

  /// Checks that trustedParties in the compiled ABI of IPolicyMethod has the specified parameter and return types
  /// and names and is view. A view is what lets a caller reach it with a static call, which can write nothing.
  function test_WhenTrustedPartiesIsReadFromTheAbi() external {
    // it should declare the specified parameters returns and mutability
    string memory _json = _interfacesLoad('IPolicyMethod');
    _interfacesAssertFunction(
      _json,
      'trustedParties',
      'view',
      '',
      'address _admin,address _pendingAdmin,bytes32[] _trustedKeys,address _pauseHolder,address ' '_pendingPauseHolder'
    );
  }

  /// Checks that supportsInterface in the compiled ABI of IPolicyMethod has the specified parameter and return types
  /// and names and is view. A view is what lets a caller reach it with a static call, which can write nothing.
  function test_WhenSupportsInterfaceIsReadFromTheAbi() external {
    // it should declare the specified parameters returns and mutability
    string memory _json = _interfacesLoad('IPolicyMethod');
    _interfacesAssertFunction(_json, 'supportsInterface', 'view', 'bytes4 _interfaceId', 'bool _supported');
  }

  /// Checks that name in the compiled ABI of IPolicyMethod has the specified parameter and return types
  /// and names and is view. A view is what lets a caller reach it with a static call, which can write nothing.
  function test_WhenNameIsReadFromTheAbi() external {
    // it should declare the specified parameters returns and mutability
    string memory _json = _interfacesLoad('IPolicyMethod');
    _interfacesAssertFunction(_json, 'name', 'view', '', 'string _moduleName');
  }

  /// Checks that version in the compiled ABI of IPolicyMethod has the specified parameter and return types
  /// and names and is view. A view is what lets a caller reach it with a static call, which can write nothing.
  function test_WhenVersionIsReadFromTheAbi() external {
    // it should declare the specified parameters returns and mutability
    string memory _json = _interfacesLoad('IPolicyMethod');
    _interfacesAssertFunction(_json, 'version', 'view', '', 'string _moduleVersion');
  }
}
