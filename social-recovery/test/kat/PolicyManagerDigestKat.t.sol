// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {IPolicyManager} from 'interfaces/IPolicyManager.sol';
import {ManagerKatBase} from 'test/kat/ManagerKatBase.sol';

/// @notice Replays approval-digest.json and cancellation-digest.json through the deployed manager's own views,
///         hashApproval and hashCancel, rather than through the library alone. Each row moves the test to the
///         row's chain and places the manager at the row's verifying contract, so the domain the deployed views
///         sign under is the one the SDK signs under. Tree: PolicyManagerDigestKat.tree.
contract PolicyManagerDigestKatTest is ManagerKatBase {
  /// The manager's hashApproval reproduces every approval digest row, the place-two, maximum place, empty
  /// payload and body, width maxima and zero order rows included. A guardian whose wallet signs the SDK's digest
  /// must sign exactly what the manager will check, or no recovery ever opens.
  function test_WhenReplayingTheApprovalDigestVectorsThroughTheManager() external {
    // it should reproduce every expected digest from the manager's view.
    string memory _json = vm.readFile(_APPROVAL_FILE);
    uint256 _rows = _rowCount(_json);
    assertGt(_rows, 0, 'no approval vector');
    for (uint256 _i; _i < _rows; ++_i) {
      string memory _row = _rowPath(_i);
      string memory _id = _rowId(_json, _row);
      IPolicyManager _manager = _managerAtDomain(_json, _row, _id);

      string memory _message = string.concat(_row, '.input.message');
      IPolicyManager.AttemptRequest memory _request;
      _request.account = vm.parseJsonAddress(_json, string.concat(_message, '.account'));
      _request.action = vm.parseJsonAddress(_json, string.concat(_message, '.action'));
      _request.attemptId = _uint64At(_json, string.concat(_message, '.attemptId'));
      _request.setupNonce = _uint64At(_json, string.concat(_message, '.setupNonce'));
      _request.setupBody = _bodyHashingTo(vm.parseJsonBytes32(_json, string.concat(_message, '.setupBodyHash')));
      _request.payload = vm.parseJsonBytes(_json, string.concat(_message, '.payload'));
      _request.order = _orderAt(_json, string.concat(_message, '.order'));
      _request.validUntil = _uint48At(_json, string.concat(_message, '.validUntil'));
      uint256 _place = vm.parseJsonUint(_json, string.concat(_message, '.place'));

      assertEq(
        _manager.hashApproval(_request, _place),
        vm.parseJsonBytes32(_json, string.concat(_row, '.expected.digest')),
        _what('approval digest', _id)
      );
    }
  }

  /// The manager's hashCancel reproduces every cancellation digest row, the empty body, maximum place and width
  /// maxima rows included. A cancel a guardian signs off chain must match the digest the manager checks, or the
  /// holder's guardians cannot stop a hostile attempt.
  function test_WhenReplayingTheCancellationDigestVectorsThroughTheManager() external {
    // it should reproduce every expected digest from the manager's view.
    string memory _json = vm.readFile(_CANCELLATION_FILE);
    uint256 _rows = _rowCount(_json);
    assertGt(_rows, 0, 'no cancellation vector');
    for (uint256 _i; _i < _rows; ++_i) {
      string memory _row = _rowPath(_i);
      string memory _id = _rowId(_json, _row);
      IPolicyManager _manager = _managerAtDomain(_json, _row, _id);

      string memory _message = string.concat(_row, '.input.message');
      IPolicyManager.CancelRequest memory _request;
      _request.account = vm.parseJsonAddress(_json, string.concat(_message, '.account'));
      _request.action = vm.parseJsonAddress(_json, string.concat(_message, '.action'));
      _request.attemptId = _uint64At(_json, string.concat(_message, '.attemptId'));
      _request.setupNonce = _uint64At(_json, string.concat(_message, '.setupNonce'));
      _request.setupBody = _bodyHashingTo(vm.parseJsonBytes32(_json, string.concat(_message, '.setupBodyHash')));
      _request.validUntil = _uint48At(_json, string.concat(_message, '.validUntil'));
      uint256 _place = vm.parseJsonUint(_json, string.concat(_message, '.place'));

      assertEq(
        _manager.hashCancel(_request, _place),
        vm.parseJsonBytes32(_json, string.concat(_row, '.expected.digest')),
        _what('cancellation digest', _id)
      );
    }
  }

  /*///////////////////////////////////////////////////////////////
                               HELPERS
  ///////////////////////////////////////////////////////////////*/

  /// @dev Moves the test to the row's chain id, deploys the manager at the row's verifying contract, and checks
  ///      that the manager's ERC-5267 domain reports the row's name, version, chain id and address, with the bitmap
  ///      0x0f of those four fields and no salt or extensions, so the digest comparison that follows runs under the
  ///      row's own domain and an SDK reading the domain builds no other.
  function _managerAtDomain(string memory _json, string memory _row, string memory _id)
    internal
    returns (IPolicyManager _manager)
  {
    string memory _domain = string.concat(_row, '.input.domain');
    uint256 _chainId = vm.parseJsonUint(_json, string.concat(_domain, '.chainId'));
    address _at = vm.parseJsonAddress(_json, string.concat(_domain, '.verifyingContract'));
    vm.chainId(_chainId);
    deployCodeTo('PolicyManager.sol:PolicyManager', _at);
    _manager = IPolicyManager(_at);

    (, string memory _name, string memory _version, uint256 _reportedChainId, address _verifyingContract,,) =
      _manager.eip712Domain();
    assertEq(_name, vm.parseJsonString(_json, string.concat(_domain, '.name')), _what('domain name', _id));
    assertEq(_version, vm.parseJsonString(_json, string.concat(_domain, '.version')), _what('domain version', _id));
    assertEq(_reportedChainId, _chainId, _what('domain chain id', _id));
    assertEq(_verifyingContract, _at, _what('domain verifying contract', _id));
    _assertNoSaltOrExtensions(_manager, _id);
  }

  /// @dev Checks that the manager's ERC-5267 domain sets the bitmap 0x0f of name, version, chain id and verifying
  ///      contract, a zero salt and no extensions, the domain shape the row's four fields describe.
  function _assertNoSaltOrExtensions(IPolicyManager _manager, string memory _id) internal view {
    (bytes1 _fields,,,,, bytes32 _salt, uint256[] memory _extensions) = _manager.eip712Domain();
    assertEq(_fields, bytes1(0x0f), _what('domain fields bitmap', _id));
    assertEq(_salt, bytes32(0), _what('domain salt', _id));
    assertEq(_extensions.length, 0, _what('domain extensions', _id));
  }
}
