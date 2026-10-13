// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {Vm} from 'forge-std/Vm.sol';
import {IPolicyMethodPause} from 'interfaces/IPolicyMethodPause.sol';
import {InterfacesArtifacts} from 'test/utils/InterfacesArtifacts.sol';

/// @notice Checks the call surface of IPolicyMethodPause: its selectors, its events' topics, indexing and data
///         order, and each declaration in the compiled ABI.
contract IPolicyMethodPauseTest is InterfacesArtifacts {
  /// Checks each selector of IPolicyMethodPause is the first four bytes of keccak256 of the function's
  /// canonical signature. Every caller encodes calls from that signature, so a drift breaks the call.
  function test_WhenTheSelectorsAreDerived() external pure {
    // it should match each function's canonical signature
    _interfacesAssertSelector(IPolicyMethodPause.pause.selector, 'pause()');
    _interfacesAssertSelector(IPolicyMethodPause.unpause.selector, 'unpause()');
    _interfacesAssertSelector(IPolicyMethodPause.paused.selector, 'paused()');
  }

  /// Emits Paused with distinct sample values and checks which parameters become log topics and
  /// the order of the rest in the log data. A watcher that follows a recovery decodes the log this way.
  function test_WhenPausedIsEmitted() external {
    // it should index and order its fields as specified
    address _account = address(0x1001);
    vm.recordLogs();
    emit IPolicyMethodPause.Paused(_account);
    Vm.Log[] memory _logs = vm.getRecordedLogs();
    assertEq(_logs.length, 1);
    assertEq(_logs[0].topics.length, 1, 'topics');
    assertEq(_logs[0].topics[0], keccak256(bytes('Paused(address)')), 'topic0');
    assertEq(_logs[0].data, abi.encode(_account), 'data');
  }

  /// Emits Unpaused with distinct sample values and checks which parameters become log topics and
  /// the order of the rest in the log data. A watcher that follows a recovery decodes the log this way.
  function test_WhenUnpausedIsEmitted() external {
    // it should index and order its fields as specified
    address _account = address(0x1001);
    vm.recordLogs();
    emit IPolicyMethodPause.Unpaused(_account);
    Vm.Log[] memory _logs = vm.getRecordedLogs();
    assertEq(_logs.length, 1);
    assertEq(_logs[0].topics.length, 1, 'topics');
    assertEq(_logs[0].topics[0], keccak256(bytes('Unpaused(address)')), 'topic0');
    assertEq(_logs[0].data, abi.encode(_account), 'data');
  }

  /// Reads the compiled ABI of IPolicyMethodPause and checks it lists exactly the specified functions, events
  /// and errors. An extra or missing entry changes the surface every other contract compiles against.
  function test_WhenTheCompiledAbiIsRead() external {
    // it should list exactly the specified functions events and errors
    string memory _json = _interfacesLoad('IPolicyMethodPause');
    string[] memory _signatures = new string[](3);
    _signatures[0] = 'pause()';
    _signatures[1] = 'unpause()';
    _signatures[2] = 'paused()';
    _interfacesAssertMethodIdentifiers(_json, _signatures);
    assertEq(_interfacesAbiCount(_json, 'function'), 3, 'functions');
    assertEq(_interfacesAbiCount(_json, 'event'), 2, 'events');
    assertEq(_interfacesAbiCount(_json, 'error'), 0, 'errors');
  }

  /// Checks that pause in the compiled ABI of IPolicyMethodPause has the specified parameter and return types
  /// and names and is nonpayable. Clients encode their calls from these types and names.
  function test_WhenPauseIsReadFromTheAbi() external {
    // it should declare the specified parameters returns and mutability
    string memory _json = _interfacesLoad('IPolicyMethodPause');
    _interfacesAssertFunction(_json, 'pause', 'nonpayable', '', '');
  }

  /// Checks that unpause in the compiled ABI of IPolicyMethodPause has the specified parameter and return types
  /// and names and is nonpayable. Clients encode their calls from these types and names.
  function test_WhenUnpauseIsReadFromTheAbi() external {
    // it should declare the specified parameters returns and mutability
    string memory _json = _interfacesLoad('IPolicyMethodPause');
    _interfacesAssertFunction(_json, 'unpause', 'nonpayable', '', '');
  }

  /// Checks that paused in the compiled ABI of IPolicyMethodPause has the specified parameter and return types
  /// and names and is view. A view is what lets a caller reach it with a static call, which can write nothing.
  function test_WhenPausedIsReadFromTheAbi() external {
    // it should declare the specified parameters returns and mutability
    string memory _json = _interfacesLoad('IPolicyMethodPause');
    _interfacesAssertFunction(_json, 'paused', 'view', '', 'bool _isPaused');
  }

  /// Checks that the event Paused in the compiled ABI has the specified parameter types, names
  /// and indexed flags and is not anonymous. Watchers decode the log from exactly this layout.
  function test_WhenTheEventPausedIsReadFromTheAbi() external {
    // it should declare the specified parameters
    string memory _json = _interfacesLoad('IPolicyMethodPause');
    _interfacesAssertEvent(_json, 'Paused', 'address account');
  }

  /// Checks that the event Unpaused in the compiled ABI has the specified parameter types, names
  /// and indexed flags and is not anonymous. Watchers decode the log from exactly this layout.
  function test_WhenTheEventUnpausedIsReadFromTheAbi() external {
    // it should declare the specified parameters
    string memory _json = _interfacesLoad('IPolicyMethodPause');
    _interfacesAssertEvent(_json, 'Unpaused', 'address account');
  }
}
