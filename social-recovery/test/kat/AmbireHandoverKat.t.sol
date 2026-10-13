// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {BindingDigest} from 'libraries/BindingDigest.sol';
import {SetupBody} from 'libraries/SetupBody.sol';
import {IPolicyManager} from 'interfaces/IPolicyManager.sol';
import {IRecoveryAction} from 'interfaces/IRecoveryAction.sol';
import {ManagerKatApprovingMethod} from 'test/kat/ManagerKatApprovingMethod.sol';
import {ManagerKatBase} from 'test/kat/ManagerKatBase.sol';
import {ActionSpendTestBase} from 'test/utils/ActionSpendTestBase.sol';

/// @notice Replays ambire-handover.json, the recovery action's payload: the two addresses the guardians approve as
///         opaque bytes and the action decodes at the spend. Each row runs through the live world: a real manager
///         holds a waiting attempt committed to the row's bytes, planted or opened through startAttempt, an account
///         is built as Ambire's factory builds it, and the action is asked to carry out the handover.
///         Tree: AmbireHandoverKat.tree.
contract AmbireHandoverKatTest is ActionSpendTestBase, ManagerKatBase {
  /// @notice The frozen handover rows.
  string internal _json;
  /// @notice Who submits the handover.
  address internal _executor;

  /// @dev Builds the action's shared fixture, loads the rows and names the submitter.
  function setUp() public override {
    super.setUp();
    _json = vm.readFile(_HANDOVER_FILE);
    _executor = makeAddr('executor');
  }

  /// Every row the action accepts is the abi.encode of the Handover struct over the row's two addresses, hashes
  /// to the row's payload hash, and, committed in an attempt, makes the action install the new key and remove the
  /// old one while the manager spends the attempt. A payload the SDK encodes this way is one the action can carry
  /// out, so the guardians' approval ends in a recovered account.
  function test_WhenReplayingTheHandoverRowsTheActionAccepts() external {
    // it should encode and hash as the row says, and hand the account over to the new key.
    uint256 _rows = _rowCount(_json);
    uint256 _replayed;
    for (uint256 _i; _i < _rows; ++_i) {
      string memory _row = _rowPath(_i);
      if (!vm.parseJsonBool(_json, string.concat(_row, '.expected.actionAcceptance'))) continue;
      string memory _id = _rowId(_json, _row);
      _newKey = vm.parseJsonAddress(_json, string.concat(_row, '.input.newAuthority'));
      _removedKey = vm.parseJsonAddress(_json, string.concat(_row, '.input.removedAuthority'));
      bytes memory _encoded = vm.parseJsonBytes(_json, string.concat(_row, '.expected.encoded'));

      assertEq(
        abi.encode(IRecoveryAction.Handover({newAuthority: _newKey, removedAuthority: _removedKey})),
        _encoded,
        _what('encoding', _id)
      );
      assertEq(
        keccak256(_encoded),
        vm.parseJsonBytes32(_json, string.concat(_row, '.expected.payloadHash')),
        _what('hash', _id)
      );

      _buildLiveWorld();
      _plantLive(_encoded, _noPayment(), 0);
      vm.prank(_executor);
      _liveAction.executeHandover(_live, _encoded);

      assertEq(_livePrivilege(_newKey), _KEY_VALUE, _what('new key installed', _id));
      assertEq(_livePrivilege(_removedKey), bytes32(0), _what('old key removed', _id));
      assertEq(uint8(_liveState()), uint8(IPolicyManager.AttemptState.Consumed), _what('attempt spent', _id));
      ++_replayed;
    }
    assertGt(_replayed, 0, 'no accepted handover row');
  }

  /// Every row the manager treats as opaque opens a real attempt through startAttempt with the row's bytes as the
  /// payload, under a committed one place setup whose method approves any proof, and the attempt stores the row's
  /// payload hash. The action then carries the handover out from that attempt. The manager never decodes a payload,
  /// so it must accept the action's frozen layout as it is, or no recovery could ever open.
  function test_WhenOpeningTheOpaqueHandoverRowsThroughTheManager() external {
    // it should store the row's payload hash and let the action hand the account over.
    uint256 _rows = _rowCount(_json);
    uint256 _replayed;
    for (uint256 _i; _i < _rows; ++_i) {
      string memory _row = _rowPath(_i);
      string memory _acceptance = string.concat(_row, '.expected.managerAcceptance');
      if (!vm.keyExistsJson(_json, _acceptance)) continue;
      string memory _id = _rowId(_json, _row);
      assertEq(vm.parseJsonString(_json, _acceptance), 'opaque', _what('manager acceptance', _id));
      _newKey = vm.parseJsonAddress(_json, string.concat(_row, '.input.newAuthority'));
      _removedKey = vm.parseJsonAddress(_json, string.concat(_row, '.input.removedAuthority'));
      bytes memory _encoded = vm.parseJsonBytes(_json, string.concat(_row, '.expected.encoded'));

      _buildLiveWorld();
      IPolicyManager.AttemptRequest memory _request = _openingRequest(_encoded);
      _liveManager.startAttempt(_request);

      IPolicyManager.Attempt memory _attempt = _liveManager.stateOf(_live, address(_liveAction)).attempt;
      assertEq(uint8(_attempt.state), uint8(IPolicyManager.AttemptState.Waiting), _what('attempt opened', _id));
      assertEq(
        _attempt.payloadHash,
        vm.parseJsonBytes32(_json, string.concat(_row, '.expected.payloadHash')),
        _what('stored payload hash', _id)
      );

      vm.prank(_executor);
      _liveAction.executeHandover(_live, _encoded);
      assertEq(_livePrivilege(_newKey), _KEY_VALUE, _what('new key installed', _id));
      assertEq(_livePrivilege(_removedKey), bytes32(0), _what('old key removed', _id));
      assertEq(uint8(_liveState()), uint8(IPolicyManager.AttemptState.Consumed), _what('attempt spent', _id));
      ++_replayed;
    }
    assertGt(_replayed, 0, 'no opaque handover row');
  }

  /// Every row the action refuses, the trailing-byte row among them, is refused when committed in an attempt. It
  /// decodes cleanly, so the refusal is a batch the account's check does not approve, since the grant and revoke
  /// rebuild a canonical payload whose hash differs from the committed one, and the attempt keeps waiting with both
  /// keys untouched. A payload signed in a non canonical form must never move a key.
  function test_WhenReplayingTheHandoverRowsTheActionRefuses() external {
    // it should refuse the batch as not approved and leave the keys and the attempt as they were.
    uint256 _rows = _rowCount(_json);
    uint256 _replayed;
    for (uint256 _i; _i < _rows; ++_i) {
      string memory _row = _rowPath(_i);
      if (vm.parseJsonBool(_json, string.concat(_row, '.expected.actionAcceptance'))) continue;
      string memory _id = _rowId(_json, _row);
      bytes memory _encoded = vm.parseJsonBytes(_json, string.concat(_row, '.input.encoded'));
      IRecoveryAction.Handover memory _handover = abi.decode(_encoded, (IRecoveryAction.Handover));
      _newKey = _handover.newAuthority;
      _removedKey = _handover.removedAuthority;

      _buildLiveWorld();
      _plantLive(_encoded, _noPayment(), 0);
      bytes32 _removedBefore = _livePrivilege(_removedKey);
      vm.expectPartialRevert(IRecoveryAction.RecoveryAction_BatchNotApproved.selector);
      vm.prank(_executor);
      _liveAction.executeHandover(_live, _encoded);

      assertEq(_livePrivilege(_newKey), bytes32(0), _what('new key not installed', _id));
      assertEq(_livePrivilege(_removedKey), _removedBefore, _what('old key kept', _id));
      assertEq(uint8(_liveState()), uint8(IPolicyManager.AttemptState.Waiting), _what('attempt still waiting', _id));
      ++_replayed;
    }
    assertGt(_replayed, 0, 'no refused handover row');
  }

  /*///////////////////////////////////////////////////////////////
                               HELPERS
  ///////////////////////////////////////////////////////////////*/

  /// @dev Has the live account commit, through the real commitSetup, a setup with no wait whose one clause needs its
  ///      one credential, a method that approves any proof, and returns the opening request for `_payload` that
  ///      fills that place, built with the kit's own body encoder and commitment hashes.
  function _openingRequest(bytes memory _payload) internal returns (IPolicyManager.AttemptRequest memory _request) {
    address _method = address(new ManagerKatApprovingMethod());
    bytes memory _config = hex'01';
    bytes32 _salt = keccak256('ManagerKat salt');
    IPolicyManager.Clause[] memory _clauses = new IPolicyManager.Clause[](1);
    _clauses[0].threshold = 1;
    _clauses[0].credentials = new bytes32[](1);
    _clauses[0].credentials[0] = BindingDigest.credentialCommitment(_method, _config, _salt);
    bytes memory _body = SetupBody.encode(0, false, _clauses);

    IPolicyManager.ActionState memory _state = _liveManager.stateOf(_live, address(_liveAction));
    uint64 _nonce = _state.setupNonce + 1;
    vm.prank(_live);
    _liveManager.commitSetup(
      address(_liveAction), BindingDigest.setupCommitment(_live, address(_liveAction), _nonce, _body), _nonce, '', ''
    );

    _request.account = _live;
    _request.action = address(_liveAction);
    _request.attemptId = _state.nextAttemptId;
    _request.setupNonce = _nonce;
    _request.setupBody = _body;
    _request.payload = _payload;
    _request.order = _noPayment();
    _request.validUntil = uint48(block.timestamp);
    _request.proofs = new IPolicyManager.ProofPlace[](1);
    IPolicyManager.ProofPlace memory _proof;
    (_proof.method, _proof.config, _proof.salt) = (_method, _config, _salt);
    _request.proofs[0] = _proof;
  }
}
