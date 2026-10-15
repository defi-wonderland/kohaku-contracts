// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {IPolicyManager} from 'interfaces/IPolicyManager.sol';
import {ManagerKatBase} from 'test/kat/ManagerKatBase.sol';
import {ManagerKatEventHarness} from 'test/kat/ManagerKatEventHarness.sol';
import {PolicyManagerMockAction} from 'test/mocks/PolicyManagerMockAction.sol';
import {PolicyManagerMockMethod} from 'test/mocks/PolicyManagerMockMethod.sol';

/// @notice Replays manager-events.json, the five events a watcher and a rebuild client decode. Each row's event is
///         emitted by the manager itself, through the call that emits it in production wherever the row's values
///         can be reached that way, and its topics and data are compared byte for byte with the row, so the split
///         between indexed and data fields is frozen too. Tree: PolicyManagerEventsKat.tree.
contract PolicyManagerEventsKatTest is ManagerKatBase {
  /// @notice The manager under replay, with the harness doors that plant a setup or an attempt.
  ManagerKatEventHarness internal _manager;
  /// @notice The frozen event rows.
  string internal _json;

  /// @dev Deploys the manager harness and loads the event rows.
  function setUp() external {
    _manager = new ManagerKatEventHarness();
    _json = vm.readFile(_MANAGER_EVENTS_FILE);
  }

  /// The file holds exactly five rows with five distinct ids, one per manager event, so every row is one of the
  /// five replays below and no extra or duplicated row goes unreplayed. A watcher decodes exactly these five events.
  function test_WhenCountingTheManagerEventRows() external view {
    // it should find five rows with distinct ids.
    uint256 _rows = _rowCount(_json);
    assertEq(_rows, 5, 'five manager event rows');
    for (uint256 _i; _i < _rows; ++_i) {
      for (uint256 _j = _i + 1; _j < _rows; ++_j) {
        assertTrue(
          keccak256(bytes(_rowId(_json, _rowPath(_i)))) != keccak256(bytes(_rowId(_json, _rowPath(_j)))),
          _what('distinct id', _rowId(_json, _rowPath(_i)))
        );
      }
    }
  }

  /// The row's account commits the row's commitment at the row's nonce with the row's two metadata fields, and the
  /// SetupCommitted log matches the row. A rebuild client finds the holder's backup in this event, so a layout
  /// drift loses the backup for every holder. The row's action carries the mock action's code, which answers true
  /// to supportsAccount for every account, since commitSetup refuses an action that does not serve the caller.
  function test_WhenTheAccountCommitsTheSetupCommittedRow() external {
    // it should emit the row's topics and data.
    string memory _row = _rowWithId(_MANAGER_EVENTS_FILE, _json, 'SetupCommitted');
    string memory _in = string.concat(_row, '.input');
    address _account = vm.parseJsonAddress(_json, string.concat(_in, '.account'));
    address _action = vm.parseJsonAddress(_json, string.concat(_in, '.action'));
    uint64 _nonce = _uint64At(_json, string.concat(_in, '.nonce'));
    _plantSetup(_account, _action, bytes32(0), _nonce - 1, 0);
    vm.etch(_action, address(new PolicyManagerMockAction()).code);

    vm.recordLogs();
    vm.prank(_account);
    _manager.commitSetup(
      _action,
      vm.parseJsonBytes32(_json, string.concat(_in, '.setupCommitment')),
      _nonce,
      vm.parseJsonBytes(_json, string.concat(_in, '.publicMetadata')),
      vm.parseJsonBytes(_json, string.concat(_in, '.privateMetadata'))
    );
    _assertOnlyLogMatches(_json, _row, address(_manager));
  }

  /// The row's account clears a setup whose nonce is one below the row's, and the SetupCleared log matches the row.
  /// A watcher reads this event to learn the holder removed recovery, so a drift hides the removal.
  function test_WhenTheAccountClearsTheSetupClearedRow() external {
    // it should emit the row's topics and data.
    string memory _row = _rowWithId(_MANAGER_EVENTS_FILE, _json, 'SetupCleared');
    string memory _in = string.concat(_row, '.input');
    address _account = vm.parseJsonAddress(_json, string.concat(_in, '.account'));
    address _action = vm.parseJsonAddress(_json, string.concat(_in, '.action'));
    uint64 _nonce = _uint64At(_json, string.concat(_in, '.nonce'));
    _plantSetup(_account, _action, keccak256('ManagerKat setup'), _nonce - 1, 0);

    vm.recordLogs();
    vm.prank(_account);
    _manager.clearSetup(_action, _nonce - 1);
    _assertOnlyLogMatches(_json, _row, address(_manager));
  }

  /// The manager's own emit of AttemptStarted, run with the row's request fields, places, methods and wait end,
  /// matches the row. The opening event carries the body, the payload and the order in the clear, and it is the
  /// only place a holder's watcher learns an attempt is running, so a drift blinds the watcher.
  function test_WhenTheManagerEmitsTheAttemptStartedRow() external {
    // it should emit the row's topics and data.
    string memory _row = _rowWithId(_MANAGER_EVENTS_FILE, _json, 'AttemptStarted');
    string memory _in = string.concat(_row, '.input');
    IPolicyManager.AttemptRequest memory _request = _attemptRequestAt(_json, _in);

    vm.recordLogs();
    _manager.harnessEmitAttemptStarted(
      _request,
      vm.parseJsonUintArray(_json, string.concat(_in, '.usedPlaces')),
      vm.parseJsonAddressArray(_json, string.concat(_in, '.usedMethods')),
      _uint48At(_json, string.concat(_in, '.consumableAfter'))
    );
    _assertOnlyLogMatches(_json, _row, address(_manager));
  }

  /// The row names a stopped method and no places, which is a cancel by veto: the row's canceller cancels the row's
  /// attempt, whose accepted set used that stopped method, and the AttemptCancelled log matches the row. A holder
  /// tells an administrative stop from their guardians withdrawing by these fields, so a drift misleads them.
  function test_WhenTheCancellerVetoesTheAttemptCancelledRow() external {
    // it should emit the row's topics and data.
    string memory _row = _rowWithId(_MANAGER_EVENTS_FILE, _json, 'AttemptCancelled');
    string memory _in = string.concat(_row, '.input');
    address _account = vm.parseJsonAddress(_json, string.concat(_in, '.account'));
    address _action = vm.parseJsonAddress(_json, string.concat(_in, '.action'));
    uint64 _attemptId = _uint64At(_json, string.concat(_in, '.attemptId'));
    uint64 _setupNonce = _uint64At(_json, string.concat(_in, '.setupNonce'));
    address _stoppedMethod = vm.parseJsonAddress(_json, string.concat(_in, '.stoppedMethod'));
    assertTrue(_stoppedMethod != address(0), 'the row names a stopped method');
    assertEq(vm.parseJsonUintArray(_json, string.concat(_in, '.usedPlaces')).length, 0, 'the row fills no place');

    vm.etch(_stoppedMethod, address(new PolicyManagerMockMethod()).code);
    address[] memory _usedMethods = new address[](1);
    _usedMethods[0] = _stoppedMethod;
    _plantSetup(_account, _action, keccak256('ManagerKat setup'), _setupNonce, _attemptId);
    _plantWaitingAttempt(_account, _action, _attemptId, _setupNonce, _usedMethods);

    vm.recordLogs();
    vm.prank(vm.parseJsonAddress(_json, string.concat(_in, '.canceller')));
    _manager.cancelByVeto(_account, _action, _attemptId, _stoppedMethod);
    _assertOnlyLogMatches(_json, _row, address(_manager));
  }

  /// The row's account spends the row's waiting attempt, its wait over, and the AttemptConsumed log matches the
  /// row. This event is how a watcher learns the recovery executed, so a drift hides a completed recovery.
  function test_WhenTheAccountConsumesTheAttemptConsumedRow() external {
    // it should emit the row's topics and data.
    string memory _row = _rowWithId(_MANAGER_EVENTS_FILE, _json, 'AttemptConsumed');
    string memory _in = string.concat(_row, '.input');
    address _account = vm.parseJsonAddress(_json, string.concat(_in, '.account'));
    address _action = vm.parseJsonAddress(_json, string.concat(_in, '.action'));
    uint64 _attemptId = _uint64At(_json, string.concat(_in, '.attemptId'));
    _plantSetup(_account, _action, keccak256('ManagerKat setup'), 1, _attemptId);
    _plantWaitingAttempt(_account, _action, _attemptId, 1, new address[](0));

    vm.recordLogs();
    vm.prank(_account);
    _manager.consume(_action, _attemptId, keccak256('ManagerKat payload'));
    _assertOnlyLogMatches(_json, _row, address(_manager));
  }

  /*///////////////////////////////////////////////////////////////
                               HELPERS
  ///////////////////////////////////////////////////////////////*/

  /// @dev Writes a setup for the pair with this commitment, nonce and last allocated attempt id.
  function _plantSetup(address _account, address _action, bytes32 _commitment, uint64 _nonce, uint64 _attemptCounter)
    internal
  {
    _manager.harnessWriteSetup(
      _account,
      _action,
      IPolicyManager.Setup({
        commitment: _commitment,
        nonce: _nonce,
        attemptCounter: _attemptCounter,
        setupCommittedAtBlock: uint48(block.number)
      })
    );
  }

  /// @dev Writes a waiting attempt for the pair whose wait has ended, committed to the hash of
  ///      'ManagerKat payload' and to an empty order, judged under `_setupNonce` and using `_usedMethods`.
  function _plantWaitingAttempt(
    address _account,
    address _action,
    uint64 _attemptId,
    uint64 _setupNonce,
    address[] memory _usedMethods
  ) internal {
    _manager.harnessWriteAttempt(
      _account,
      _action,
      IPolicyManager.Attempt({
        attemptId: _attemptId,
        setupNonce: _setupNonce,
        consumableAfter: uint48(block.timestamp),
        state: IPolicyManager.AttemptState.Waiting,
        ignoresPause: false,
        payloadHash: keccak256('ManagerKat payload'),
        order: IPolicyManager.PaymentOrder({token: address(0), amount: 0, payee: address(0)}),
        usedMethods: _usedMethods
      })
    );
  }
}
