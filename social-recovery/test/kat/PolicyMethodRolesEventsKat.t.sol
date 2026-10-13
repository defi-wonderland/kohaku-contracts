// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {ManagerKatBase} from 'test/kat/ManagerKatBase.sol';
import {MethodRolesHarness} from 'test/mocks/MethodRolesHarness.sol';

/// @notice Replays method-events.json through the roles base every identity method ships with. Each row's event is
///         left by the call that emits it in production, run on the roles contract by the role the row names, and
///         its topics and data are compared byte for byte with the row, so the split between indexed and data
///         fields is frozen on the shipped code and not only on the interface declarations. The roles contract is
///         reached through MethodRolesHarness, which adds only a key check and a verifier that approves nothing.
///         Tree: PolicyMethodRolesEventsKat.tree.
contract PolicyMethodRolesEventsKatTest is ManagerKatBase {
  /// @notice The method name every replayed roles contract carries.
  string internal constant _NAME = 'MethodKat roles';
  /// @notice The method version every replayed roles contract carries.
  string internal constant _VERSION = '1.0.0';

  /// @notice The frozen event rows.
  string internal _json;

  /// @dev Loads the event rows.
  function setUp() external {
    _json = vm.readFile(_METHOD_EVENTS_FILE);
  }

  /// The file holds exactly six rows with six distinct ids, one per roles event, so every row is one of the six
  /// replays below and no extra or duplicated row goes unreplayed. A monitor decodes exactly these six events.
  function test_WhenCountingTheMethodEventRows() external view {
    // it should find six rows with distinct ids.
    uint256 _rows = _rowCount(_json);
    assertEq(_rows, 6, 'six method event rows');
    for (uint256 _i; _i < _rows; ++_i) {
      for (uint256 _j = _i + 1; _j < _rows; ++_j) {
        assertTrue(
          keccak256(bytes(_rowId(_json, _rowPath(_i)))) != keccak256(bytes(_rowId(_json, _rowPath(_j)))),
          _what('distinct id', _rowId(_json, _rowPath(_i)))
        );
      }
    }
  }

  /// The row's account, the pause holder, stops the method with pause, and the Paused log matches the row. A monitor
  /// reads this event to learn a stop is blocking recoveries through the method, so a drift hides the stop.
  function test_WhenThePauseHolderPausesThePausedRow() external {
    // it should emit the row's topics and data.
    string memory _row = _rowWithId(_METHOD_EVENTS_FILE, _json, 'Paused');
    address _holder = vm.parseJsonAddress(_json, string.concat(_row, '.input.account'));
    MethodRolesHarness _roles = _deploy(_holder, makeAddr('MethodKat key admin'), _oneKey());

    vm.recordLogs();
    vm.prank(_holder);
    _roles.pause();
    _assertOnlyLogMatches(_json, _row, address(_roles));
  }

  /// The row's account, the pause holder, lifts its own stop with unpause, and the Unpaused log matches the row. A
  /// monitor reads this event to learn the method serves recoveries again, so a drift leaves the stop looking live.
  function test_WhenThePauseHolderUnpausesTheUnpausedRow() external {
    // it should emit the row's topics and data.
    string memory _row = _rowWithId(_METHOD_EVENTS_FILE, _json, 'Unpaused');
    address _holder = vm.parseJsonAddress(_json, string.concat(_row, '.input.account'));
    MethodRolesHarness _roles = _deploy(_holder, makeAddr('MethodKat key admin'), _oneKey());
    vm.prank(_holder);
    _roles.pause();

    vm.recordLogs();
    vm.prank(_holder);
    _roles.unpause();
    _assertOnlyLogMatches(_json, _row, address(_roles));
  }

  /// A roles contract deployed with the row's previous keys has them replaced by the row's current keys through the
  /// key admin's setTrustedKeys, and the TrustedKeysUpdated log matches the row. A monitor reads both lists here to
  /// see a key rotation, which changes whose identity proofs the method accepts.
  function test_WhenTheKeyAdminSetsTheTrustedKeysUpdatedRow() external {
    // it should emit the row's topics and data.
    string memory _row = _rowWithId(_METHOD_EVENTS_FILE, _json, 'TrustedKeysUpdated');
    string memory _in = string.concat(_row, '.input');
    address _admin = makeAddr('MethodKat key admin');
    MethodRolesHarness _roles = _deploy(
      makeAddr('MethodKat pause holder'), _admin, vm.parseJsonBytes32Array(_json, string.concat(_in, '.previous'))
    );

    vm.recordLogs();
    vm.prank(_admin);
    _roles.setTrustedKeys(vm.parseJsonBytes32Array(_json, string.concat(_in, '.current')));
    _assertOnlyLogMatches(_json, _row, address(_roles));
  }

  /// The row's current key admin offers the role to the row's pending address with transferAdmin, and the
  /// AdminTransferOffered log matches the row. A monitor reads this event to see a handover of the key admin role
  /// begin, so a drift hides who may soon rotate the keys.
  function test_WhenTheKeyAdminOffersTheAdminTransferOfferedRow() external {
    // it should emit the row's topics and data.
    string memory _row = _rowWithId(_METHOD_EVENTS_FILE, _json, 'AdminTransferOffered');
    string memory _in = string.concat(_row, '.input');
    address _current = vm.parseJsonAddress(_json, string.concat(_in, '.current'));
    MethodRolesHarness _roles = _deploy(makeAddr('MethodKat pause holder'), _current, _oneKey());

    vm.recordLogs();
    vm.prank(_current);
    _roles.transferAdmin(vm.parseJsonAddress(_json, string.concat(_in, '.pending')));
    _assertOnlyLogMatches(_json, _row, address(_roles));
  }

  /// The row's previous key admin offers the role to the row's current address, which takes it with acceptAdmin,
  /// and the AdminTransferred log matches the row. A monitor reads this event to learn who now rotates the keys.
  function test_WhenTheNomineeAcceptsTheAdminTransferredRow() external {
    // it should emit the row's topics and data.
    string memory _row = _rowWithId(_METHOD_EVENTS_FILE, _json, 'AdminTransferred');
    string memory _in = string.concat(_row, '.input');
    address _previous = vm.parseJsonAddress(_json, string.concat(_in, '.previous'));
    address _current = vm.parseJsonAddress(_json, string.concat(_in, '.current'));
    MethodRolesHarness _roles = _deploy(makeAddr('MethodKat pause holder'), _previous, _oneKey());
    vm.prank(_previous);
    _roles.transferAdmin(_current);

    vm.recordLogs();
    vm.prank(_current);
    _roles.acceptAdmin();
    _assertOnlyLogMatches(_json, _row, address(_roles));
  }

  /// The row's previous key admin gives the role up with renounceAdmin, and the AdminRenounced log matches the row,
  /// two topics and empty data. A monitor reads this event to learn the method's keys can never change again.
  function test_WhenTheKeyAdminRenouncesTheAdminRenouncedRow() external {
    // it should emit the row's topics and data.
    string memory _row = _rowWithId(_METHOD_EVENTS_FILE, _json, 'AdminRenounced');
    address _previous = vm.parseJsonAddress(_json, string.concat(_row, '.input.previous'));
    MethodRolesHarness _roles = _deploy(makeAddr('MethodKat pause holder'), _previous, _oneKey());

    vm.recordLogs();
    vm.prank(_previous);
    _roles.renounceAdmin();
    _assertOnlyLogMatches(_json, _row, address(_roles));
  }

  /*///////////////////////////////////////////////////////////////
                               HELPERS
  ///////////////////////////////////////////////////////////////*/

  /// @dev Deploys a roles contract whose pause holder is `_pauseHolder`, whose key admin is `_admin` and whose
  ///      trusted keys are `_keys`.
  function _deploy(address _pauseHolder, address _admin, bytes32[] memory _keys)
    internal
    returns (MethodRolesHarness _roles)
  {
    _roles = new MethodRolesHarness(_pauseHolder, _admin, _keys, _NAME, _VERSION);
  }

  /// @dev A key list of one word, the hash of 'MethodKat key', for the rows that do not name keys.
  function _oneKey() internal pure returns (bytes32[] memory _keys) {
    _keys = new bytes32[](1);
    _keys[0] = keccak256('MethodKat key');
  }
}
