// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {IPolicyManager} from 'interfaces/IPolicyManager.sol';
import {InterfacesArtifacts} from 'test/utils/InterfacesArtifacts.sol';

/// @notice Checks the call surface of IPolicyManager: its selectors, the exact set of its functions, events and
///         errors, and each function's parameters, returns and mutability in the compiled ABI.
contract IPolicyManagerTest is InterfacesArtifacts {
  /// Checks each selector of IPolicyManager is the first four bytes of keccak256 of the function's
  /// canonical signature. Every caller encodes calls from that signature, so a drift breaks the call.
  function test_WhenTheSelectorsAreDerived() external pure {
    // it should match each function's canonical signature
    _interfacesAssertSelector(IPolicyManager.commitSetup.selector, 'commitSetup(address,bytes32,uint64,bytes,bytes)');
    _interfacesAssertSelector(IPolicyManager.clearSetup.selector, 'clearSetup(address,uint64)');
    _interfacesAssertSelector(IPolicyManager.cancelByOwner.selector, 'cancelByOwner(address,uint64)');
    _interfacesAssertSelector(
      IPolicyManager.startAttempt.selector, string.concat('startAttempt(', _interfacesAttemptRequestTuple(), ')')
    );
    _interfacesAssertSelector(
      IPolicyManager.cancelByProofs.selector, string.concat('cancelByProofs(', _interfacesCancelRequestTuple(), ')')
    );
    _interfacesAssertSelector(IPolicyManager.cancelByVeto.selector, 'cancelByVeto(address,address,uint64,address)');
    _interfacesAssertSelector(IPolicyManager.consume.selector, 'consume(address,uint64,bytes32)');
    _interfacesAssertSelector(IPolicyManager.stateOf.selector, 'stateOf(address,address)');
    _interfacesAssertSelector(
      IPolicyManager.hashApproval.selector,
      string.concat('hashApproval(', _interfacesAttemptRequestTuple(), ',uint256)')
    );
    _interfacesAssertSelector(
      IPolicyManager.hashCancel.selector, string.concat('hashCancel(', _interfacesCancelRequestTuple(), ',uint256)')
    );
    _interfacesAssertSelector(IPolicyManager.eip712Domain.selector, 'eip712Domain()');
    _interfacesAssertSelector(IPolicyManager.supportsInterface.selector, 'supportsInterface(bytes4)');
    _interfacesAssertSelector(IPolicyManager.name.selector, 'name()');
    _interfacesAssertSelector(IPolicyManager.version.selector, 'version()');
  }

  /// Reads the compiled ABI of IPolicyManager and checks it lists exactly the specified functions, events
  /// and errors. An extra or missing entry changes the surface every other contract compiles against.
  function test_WhenTheCompiledAbiIsRead() external {
    // it should list exactly the specified functions events and errors
    string memory _json = _interfacesLoad('IPolicyManager');
    string[] memory _signatures = new string[](14);
    _signatures[0] = 'commitSetup(address,bytes32,uint64,bytes,bytes)';
    _signatures[1] = 'clearSetup(address,uint64)';
    _signatures[2] = 'cancelByOwner(address,uint64)';
    _signatures[3] = string.concat('startAttempt(', _interfacesAttemptRequestTuple(), ')');
    _signatures[4] = string.concat('cancelByProofs(', _interfacesCancelRequestTuple(), ')');
    _signatures[5] = 'cancelByVeto(address,address,uint64,address)';
    _signatures[6] = 'consume(address,uint64,bytes32)';
    _signatures[7] = 'stateOf(address,address)';
    _signatures[8] = string.concat('hashApproval(', _interfacesAttemptRequestTuple(), ',uint256)');
    _signatures[9] = string.concat('hashCancel(', _interfacesCancelRequestTuple(), ',uint256)');
    _signatures[10] = 'eip712Domain()';
    _signatures[11] = 'supportsInterface(bytes4)';
    _signatures[12] = 'name()';
    _signatures[13] = 'version()';
    _interfacesAssertMethodIdentifiers(_json, _signatures);
    assertEq(_interfacesAbiCount(_json, 'function'), 14, 'functions');
    assertEq(_interfacesAbiCount(_json, 'event'), 5, 'events');
    assertEq(_interfacesAbiCount(_json, 'error'), 22, 'errors');
  }

  /// Checks that commitSetup in the compiled ABI of IPolicyManager has the specified parameter and return types
  /// and names and is nonpayable. Clients encode their calls from these types and names.
  function test_WhenCommitSetupIsReadFromTheAbi() external {
    // it should declare the specified parameters returns and mutability
    string memory _json = _interfacesLoad('IPolicyManager');
    _interfacesAssertFunction(
      _json,
      'commitSetup',
      'nonpayable',
      'address _action,bytes32 _setupCommitment,uint64 _nonce,bytes _publicMetadata,bytes ' '_privateMetadata',
      ''
    );
  }

  /// Checks that clearSetup in the compiled ABI of IPolicyManager has the specified parameter and return types
  /// and names and is nonpayable. Clients encode their calls from these types and names.
  function test_WhenClearSetupIsReadFromTheAbi() external {
    // it should declare the specified parameters returns and mutability
    string memory _json = _interfacesLoad('IPolicyManager');
    _interfacesAssertFunction(_json, 'clearSetup', 'nonpayable', 'address _action,uint64 _nonce', '');
  }

  /// Checks that cancelByOwner in the compiled ABI of IPolicyManager has the specified parameter and return types
  /// and names and is nonpayable. Clients encode their calls from these types and names.
  function test_WhenCancelByOwnerIsReadFromTheAbi() external {
    // it should declare the specified parameters returns and mutability
    string memory _json = _interfacesLoad('IPolicyManager');
    _interfacesAssertFunction(_json, 'cancelByOwner', 'nonpayable', 'address _action,uint64 _attemptId', '');
  }

  /// Checks that startAttempt in the compiled ABI of IPolicyManager has the specified parameter and return types
  /// and names and is nonpayable. Clients encode their calls from these types and names.
  function test_WhenStartAttemptIsReadFromTheAbi() external {
    // it should declare the specified parameters returns and mutability
    string memory _json = _interfacesLoad('IPolicyManager');
    _interfacesAssertFunction(_json, 'startAttempt', 'nonpayable', 'struct IPolicyManager.AttemptRequest _request', '');
  }

  /// Checks that cancelByProofs in the compiled ABI of IPolicyManager has the specified parameter and return types
  /// and names and is nonpayable. Clients encode their calls from these types and names.
  function test_WhenCancelByProofsIsReadFromTheAbi() external {
    // it should declare the specified parameters returns and mutability
    string memory _json = _interfacesLoad('IPolicyManager');
    string memory _request = 'struct IPolicyManager.CancelRequest _request';
    _interfacesAssertFunction(_json, 'cancelByProofs', 'nonpayable', _request, '');
  }

  /// Checks that cancelByVeto in the compiled ABI of IPolicyManager has the specified parameter and return types
  /// and names and is nonpayable. Clients encode their calls from these types and names.
  function test_WhenCancelByVetoIsReadFromTheAbi() external {
    // it should declare the specified parameters returns and mutability
    string memory _json = _interfacesLoad('IPolicyManager');
    _interfacesAssertFunction(
      _json, 'cancelByVeto', 'nonpayable', 'address _account,address _action,uint64 _attemptId,address _method', ''
    );
  }

  /// Checks that consume in the compiled ABI of IPolicyManager has the specified parameter and return types
  /// and names and is nonpayable. Clients encode their calls from these types and names.
  function test_WhenConsumeIsReadFromTheAbi() external {
    // it should declare the specified parameters returns and mutability
    string memory _json = _interfacesLoad('IPolicyManager');
    _interfacesAssertFunction(
      _json, 'consume', 'nonpayable', 'address _action,uint64 _attemptId,bytes32 _payloadHash', ''
    );
  }

  /// Checks that stateOf in the compiled ABI of IPolicyManager has the specified parameter and return types
  /// and names and is view. A view is what lets a caller reach it with a static call, which can write nothing.
  function test_WhenStateOfIsReadFromTheAbi() external {
    // it should declare the specified parameters returns and mutability
    string memory _json = _interfacesLoad('IPolicyManager');
    _interfacesAssertFunction(
      _json, 'stateOf', 'view', 'address _account,address _action', 'struct IPolicyManager.ActionState _state'
    );
  }

  /// Checks that hashApproval in the compiled ABI of IPolicyManager has the specified parameter and return types
  /// and names and is view. A view is what lets a caller reach it with a static call, which can write nothing.
  function test_WhenHashApprovalIsReadFromTheAbi() external {
    // it should declare the specified parameters returns and mutability
    string memory _json = _interfacesLoad('IPolicyManager');
    _interfacesAssertFunction(
      _json, 'hashApproval', 'view', 'struct IPolicyManager.AttemptRequest _request,uint256 _place', 'bytes32 _digest'
    );
  }

  /// Checks that hashCancel in the compiled ABI of IPolicyManager has the specified parameter and return types
  /// and names and is view. A view is what lets a caller reach it with a static call, which can write nothing.
  function test_WhenHashCancelIsReadFromTheAbi() external {
    // it should declare the specified parameters returns and mutability
    string memory _json = _interfacesLoad('IPolicyManager');
    _interfacesAssertFunction(
      _json, 'hashCancel', 'view', 'struct IPolicyManager.CancelRequest _request,uint256 _place', 'bytes32 _digest'
    );
  }

  /// Checks that eip712Domain in the compiled ABI of IPolicyManager has the specified parameter and return types
  /// and names and is view. A view is what lets a caller reach it with a static call, which can write nothing.
  function test_WhenEip712DomainIsReadFromTheAbi() external {
    // it should declare the specified parameters returns and mutability
    string memory _json = _interfacesLoad('IPolicyManager');
    _interfacesAssertFunction(
      _json,
      'eip712Domain',
      'view',
      '',
      'bytes1 _fields,string _name,string _version,uint256 _chainId,address '
      '_verifyingContract,bytes32 _salt,uint256[] _extensions'
    );
  }

  /// Checks that supportsInterface in the compiled ABI of IPolicyManager has the specified parameter and return types
  /// and names and is view. A view is what lets a caller reach it with a static call, which can write nothing.
  function test_WhenSupportsInterfaceIsReadFromTheAbi() external {
    // it should declare the specified parameters returns and mutability
    string memory _json = _interfacesLoad('IPolicyManager');
    _interfacesAssertFunction(_json, 'supportsInterface', 'view', 'bytes4 _interfaceId', 'bool _supported');
  }

  /// Checks that name in the compiled ABI of IPolicyManager has the specified parameter and return types
  /// and names and is view. A view is what lets a caller reach it with a static call, which can write nothing.
  function test_WhenNameIsReadFromTheAbi() external {
    // it should declare the specified parameters returns and mutability
    string memory _json = _interfacesLoad('IPolicyManager');
    _interfacesAssertFunction(_json, 'name', 'view', '', 'string _managerName');
  }

  /// Checks that version in the compiled ABI of IPolicyManager has the specified parameter and return types
  /// and names and is view. A view is what lets a caller reach it with a static call, which can write nothing.
  function test_WhenVersionIsReadFromTheAbi() external {
    // it should declare the specified parameters returns and mutability
    string memory _json = _interfacesLoad('IPolicyManager');
    _interfacesAssertFunction(_json, 'version', 'view', '', 'string _managerVersion');
  }
}
