// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {Vm} from 'forge-std/Vm.sol';
import {IPolicyManager} from 'interfaces/IPolicyManager.sol';
import {InterfacesArtifacts} from 'test/utils/InterfacesArtifacts.sol';

/// @notice Checks the topics, the indexed parameters and the data layout of the policy manager's events, and each
///         event's parameter types, names and indexing in the compiled ABI.
contract PolicyManagerEventsTest is InterfacesArtifacts {
  /// Emits SetupCommitted with distinct sample values and checks which parameters become log topics and
  /// the order of the rest in the log data. A watcher that follows a recovery decodes the log this way.
  function test_WhenSetupCommittedIsEmitted() external {
    // it should index the account and the action and put the rest in order as data
    address _account = address(0x1001);
    address _action = address(0x1002);
    uint64 _nonce = uint64(3);
    bytes32 _setupCommitment = bytes32(uint256(0xb004));
    bytes memory _publicMetadata = bytes('publicMetadata-5');
    bytes memory _privateMetadata = bytes('privateMetadata-6');
    vm.recordLogs();
    emit IPolicyManager.SetupCommitted(_account, _action, _nonce, _setupCommitment, _publicMetadata, _privateMetadata);
    Vm.Log[] memory _logs = vm.getRecordedLogs();
    assertEq(_logs.length, 1);
    assertEq(_logs[0].topics.length, 3, 'topics');
    assertEq(
      _logs[0].topics[0], keccak256(bytes('SetupCommitted(address,address,uint64,bytes32,bytes,bytes)')), 'topic0'
    );
    assertEq(_logs[0].topics[1], bytes32(uint256(uint160(_account))), 'account');
    assertEq(_logs[0].topics[2], bytes32(uint256(uint160(_action))), 'action');
    assertEq(_logs[0].data, abi.encode(_nonce, _setupCommitment, _publicMetadata, _privateMetadata), 'data');
  }

  /// Emits SetupCleared with distinct sample values and checks which parameters become log topics and
  /// the order of the rest in the log data. A watcher that follows a recovery decodes the log this way.
  function test_WhenSetupClearedIsEmitted() external {
    // it should index the account and the action and put the rest in order as data
    address _account = address(0x1001);
    address _action = address(0x1002);
    uint64 _nonce = uint64(3);
    vm.recordLogs();
    emit IPolicyManager.SetupCleared(_account, _action, _nonce);
    Vm.Log[] memory _logs = vm.getRecordedLogs();
    assertEq(_logs.length, 1);
    assertEq(_logs[0].topics.length, 3, 'topics');
    assertEq(_logs[0].topics[0], keccak256(bytes('SetupCleared(address,address,uint64)')), 'topic0');
    assertEq(_logs[0].topics[1], bytes32(uint256(uint160(_account))), 'account');
    assertEq(_logs[0].topics[2], bytes32(uint256(uint160(_action))), 'action');
    assertEq(_logs[0].data, abi.encode(_nonce), 'data');
  }

  /// Emits AttemptStarted with distinct sample values and checks which parameters become log topics and
  /// the order of the rest in the log data. A watcher that follows a recovery decodes the log this way.
  function test_WhenAttemptStartedIsEmitted() external {
    // it should index the account and the action and put the rest in order as data
    uint256[] memory _usedPlaces = new uint256[](1);
    _usedPlaces[0] = uint256(7);
    address[] memory _usedMethods = new address[](1);
    _usedMethods[0] = address(0x1009);
    address _account = address(0x1001);
    address _action = address(0x1002);
    uint64 _attemptId = uint64(3);
    uint64 _setupNonce = uint64(4);
    bytes memory _setupBody = bytes('setupBody-5');
    bytes memory _payload = bytes('payload-10');
    IPolicyManager.PaymentOrder memory _order =
      IPolicyManager.PaymentOrder({token: address(0x100c), amount: uint256(13), payee: address(0x100e)});
    uint48 _consumableAfter = uint48(15);
    vm.recordLogs();
    emit IPolicyManager.AttemptStarted(
      _account,
      _action,
      _attemptId,
      _setupNonce,
      _setupBody,
      _usedPlaces,
      _usedMethods,
      _payload,
      _order,
      _consumableAfter
    );
    Vm.Log[] memory _logs = vm.getRecordedLogs();
    assertEq(_logs.length, 1);
    assertEq(_logs[0].topics.length, 3, 'topics');
    assertEq(
      _logs[0].topics[0],
      keccak256(
        bytes(
          string.concat(
            'AttemptStarted(address,address,uint64,uint64,bytes,uint256[],address[],bytes,',
            _interfacesPaymentOrderTuple(),
            ',uint48)'
          )
        )
      ),
      'topic0'
    );
    assertEq(_logs[0].topics[1], bytes32(uint256(uint160(_account))), 'account');
    assertEq(_logs[0].topics[2], bytes32(uint256(uint160(_action))), 'action');
    assertEq(
      _logs[0].data,
      abi.encode(_attemptId, _setupNonce, _setupBody, _usedPlaces, _usedMethods, _payload, _order, _consumableAfter),
      'data'
    );
  }

  /// Emits AttemptCancelled with distinct sample values and checks which parameters become log topics and
  /// the order of the rest in the log data. A watcher that follows a recovery decodes the log this way.
  function test_WhenAttemptCancelledIsEmitted() external {
    // it should index the account and the action and put the rest in order as data
    uint256[] memory _usedPlaces = new uint256[](1);
    _usedPlaces[0] = uint256(8);
    address _account = address(0x1001);
    address _action = address(0x1002);
    uint64 _attemptId = uint64(3);
    address _canceller = address(0x1004);
    address _stoppedMethod = address(0x1005);
    uint64 _setupNonce = uint64(6);
    vm.recordLogs();
    emit IPolicyManager.AttemptCancelled(
      _account, _action, _attemptId, _canceller, _stoppedMethod, _setupNonce, _usedPlaces
    );
    Vm.Log[] memory _logs = vm.getRecordedLogs();
    assertEq(_logs.length, 1);
    assertEq(_logs[0].topics.length, 3, 'topics');
    assertEq(
      _logs[0].topics[0],
      keccak256(bytes('AttemptCancelled(address,address,uint64,address,address,uint64,uint256[])')),
      'topic0'
    );
    assertEq(_logs[0].topics[1], bytes32(uint256(uint160(_account))), 'account');
    assertEq(_logs[0].topics[2], bytes32(uint256(uint160(_action))), 'action');
    assertEq(_logs[0].data, abi.encode(_attemptId, _canceller, _stoppedMethod, _setupNonce, _usedPlaces), 'data');
  }

  /// Emits AttemptConsumed with distinct sample values and checks which parameters become log topics and
  /// the order of the rest in the log data. A watcher that follows a recovery decodes the log this way.
  function test_WhenAttemptConsumedIsEmitted() external {
    // it should index the account and the action and put the rest in order as data
    address _account = address(0x1001);
    address _action = address(0x1002);
    uint64 _attemptId = uint64(3);
    vm.recordLogs();
    emit IPolicyManager.AttemptConsumed(_account, _action, _attemptId);
    Vm.Log[] memory _logs = vm.getRecordedLogs();
    assertEq(_logs.length, 1);
    assertEq(_logs[0].topics.length, 3, 'topics');
    assertEq(_logs[0].topics[0], keccak256(bytes('AttemptConsumed(address,address,uint64)')), 'topic0');
    assertEq(_logs[0].topics[1], bytes32(uint256(uint160(_account))), 'account');
    assertEq(_logs[0].topics[2], bytes32(uint256(uint160(_action))), 'action');
    assertEq(_logs[0].data, abi.encode(_attemptId), 'data');
  }

  /// Checks that the event SetupCommitted in the compiled ABI of IPolicyManager has the specified parameter types,
  /// names and indexed flags and is not anonymous. Watchers decode the log from exactly this layout.
  function test_WhenTheEventSetupCommittedIsReadFromTheAbi() external {
    // it should declare the specified parameters
    string memory _json = _interfacesLoad('IPolicyManager');
    _interfacesAssertEvent(
      _json,
      'SetupCommitted',
      'address indexed _account,address indexed _action,uint64 _nonce,bytes32 _setupCommitment,bytes '
      '_publicMetadata,bytes _privateMetadata'
    );
  }

  /// Checks that the event SetupCleared in the compiled ABI of IPolicyManager has the specified parameter types,
  /// names and indexed flags and is not anonymous. Watchers decode the log from exactly this layout.
  function test_WhenTheEventSetupClearedIsReadFromTheAbi() external {
    // it should declare the specified parameters
    string memory _json = _interfacesLoad('IPolicyManager');
    _interfacesAssertEvent(_json, 'SetupCleared', 'address indexed _account,address indexed _action,uint64 _nonce');
  }

  /// Checks that the event AttemptStarted in the compiled ABI of IPolicyManager has the specified parameter types,
  /// names and indexed flags and is not anonymous. Watchers decode the log from exactly this layout.
  function test_WhenTheEventAttemptStartedIsReadFromTheAbi() external {
    // it should declare the specified parameters
    string memory _json = _interfacesLoad('IPolicyManager');
    _interfacesAssertEvent(
      _json,
      'AttemptStarted',
      'address indexed _account,address indexed _action,uint64 _attemptId,uint64 _setupNonce,bytes _setupBody,'
      'uint256[] _usedPlaces,address[] _usedMethods,bytes _payload,struct IPolicyManager.PaymentOrder _order,'
      'uint48 _consumableAfter'
    );
  }

  /// Checks that the event AttemptCancelled in the compiled ABI of IPolicyManager has the specified parameter types,
  /// names and indexed flags and is not anonymous. Watchers decode the log from exactly this layout.
  function test_WhenTheEventAttemptCancelledIsReadFromTheAbi() external {
    // it should declare the specified parameters
    string memory _json = _interfacesLoad('IPolicyManager');
    _interfacesAssertEvent(
      _json,
      'AttemptCancelled',
      'address indexed _account,address indexed _action,uint64 _attemptId,address _canceller,address '
      '_stoppedMethod,uint64 _setupNonce,uint256[] _usedPlaces'
    );
  }

  /// Checks that the event AttemptConsumed in the compiled ABI of IPolicyManager has the specified parameter types,
  /// names and indexed flags and is not anonymous. Watchers decode the log from exactly this layout.
  function test_WhenTheEventAttemptConsumedIsReadFromTheAbi() external {
    // it should declare the specified parameters
    string memory _json = _interfacesLoad('IPolicyManager');
    _interfacesAssertEvent(
      _json, 'AttemptConsumed', 'address indexed _account,address indexed _action,uint64 _attemptId'
    );
  }
}
