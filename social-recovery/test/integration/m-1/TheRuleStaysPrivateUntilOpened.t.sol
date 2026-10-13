// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {Vm} from 'forge-std/Vm.sol';
import {SetupBody} from 'libraries/SetupBody.sol';
import {IPolicyManager} from 'interfaces/IPolicyManager.sol';
import {IRecoveryAction} from 'interfaces/IRecoveryAction.sol';
import {IntegrationDemoKitTestBase} from 'test/utils/IntegrationDemoKitTestBase.sol';

/// @notice The holder commits a rule. The chain sees only its commitment and the metadata the holder chose to publish.
///         Nobody can read the guardians from the chain until an attempt opens. The opening event then shows the rule
///         and the handover in the clear.
contract TheRuleStaysPrivateUntilOpenedTest is IntegrationDemoKitTestBase {
  /// @notice The fields of a setup event's data, decoded in the event's order.
  struct CommittedLog {
    uint64 nonce;
    bytes32 setupCommitment;
    bytes publicMetadata;
    bytes privateMetadata;
  }

  /// @notice Builds `_length` bytes from `_seed` to stand in for the holder's encrypted backup. The manager never reads
  ///         the backup, so its content does not matter.
  function _opaqueBackup(uint256 _seed, uint256 _length) internal pure returns (bytes memory _backup) {
    _backup = new bytes(_length);
    for (uint256 _i; _i < _length; ++_i) {
      _backup[_i] = bytes1(uint8(uint256(keccak256(abi.encode('backup', _seed, _i)))));
    }
  }

  /// @notice Whether `_haystack` holds `_needle` as a run of bytes.
  function _contains(bytes memory _haystack, bytes memory _needle) internal pure returns (bool _found) {
    for (uint256 _at; _at + _needle.length < _haystack.length + 1; ++_at) {
      uint256 _j;
      while (_j < _needle.length && _haystack[_at + _j] == _needle[_j]) ++_j;
      if (_j == _needle.length) return true;
    }
  }

  /// @notice Builds a salt from the account and the place alone, so any reader can recompute it. The kit's default salt
  ///         has this shape.
  function _guessableSalt(uint256 _place) internal view returns (bytes32 _salt) {
    _salt = keccak256(abi.encode(_account, _place));
  }

  /// @notice The credential hash a wallet guardian at `_address` gets at `_place` under the guessable salt.
  function _guessableWalletHash(address _address, uint256 _place) internal view returns (bytes32 _hash) {
    _hash = keccak256(abi.encode(address(_ecdsa), abi.encode(_address), _guessableSalt(_place)));
  }

  /// @notice Builds the holder's rule with each wallet guardian under the guessable salt. The phone and the third-party
  ///         credential stay as in the default rule.
  function _guessableRule() internal view returns (bytes memory _setupBody) {
    IPolicyManager.Clause[] memory _clauses = new IPolicyManager.Clause[](2);
    _clauses[0].threshold = 2;
    _clauses[0].credentials = new bytes32[](3);
    for (uint256 _place; _place < _PHONE; ++_place) {
      _clauses[0].credentials[_place] = _guessableWalletHash(_guardians[_place], _place);
    }
    _clauses[1].threshold = 1;
    _clauses[1].credentials = new bytes32[](2);
    _clauses[1].credentials[0] = _credentialHash(_PHONE);
    _clauses[1].credentials[1] = _credentialHash(_THIRD_PARTY);
    _setupBody = SetupBody.encode(_WAIT, false, _clauses);
  }

  /// @notice Authorizes the action and commits the default rule in one batch. The holder passes the public note and the
  ///         backup.
  function _authorizeAndCommitWith(bytes memory _publicNote, bytes memory _backup) internal {
    _asHolder(
      _two(
        _authorizeCall(),
        _managerCall(
          abi.encodeCall(
            IPolicyManager.commitSetup, (address(_action), _commitmentOf(1, _body()), 1, _publicNote, _backup)
          )
        )
      )
    );
  }

  /// @notice Committing the rule stores only its commitment, nonce and block. The event shows the commitment, the nonce
  ///         and the holder's two metadata fields as passed. No log contains the rule or any guardian's credential
  ///         hash, so watchers cannot learn who the guardians are. `_seed` and `_length` build the backup.
  function test_WhenTheHolderCommitsTheRule(uint256 _seed, uint256 _length) external {
    // it should publish the commitment and the metadata but no part of the rule
    bytes memory _backup = _opaqueBackup(_seed, bound(_length, 0, 512));
    vm.roll(block.number + 1000);
    vm.recordLogs();
    _authorizeAndCommitWith(_PUBLIC_METADATA, _backup);
    Vm.Log[] memory _logs = vm.getRecordedLogs();

    assertEq(_countLogs(_logs, IPolicyManager.SetupCommitted.selector), 1, 'not one setup event');
    Vm.Log memory _log = _logs[_indexOfLog(_logs, IPolicyManager.SetupCommitted.selector)];
    assertEq(address(uint160(uint256(_log.topics[1]))), _account, 'the setup event names another account');
    assertEq(address(uint160(uint256(_log.topics[2]))), address(_action), 'the setup event names another action');
    CommittedLog memory _committed = abi.decode(abi.encodePacked(uint256(32), _log.data), (CommittedLog));
    assertEq(_committed.nonce, 1, 'the setup event carries another nonce');
    assertEq(_committed.setupCommitment, _commitmentOf(1, _body()), 'the setup event carries another commitment');
    assertEq(_committed.publicMetadata, _PUBLIC_METADATA, 'the public note changed on the way');
    assertEq(_committed.privateMetadata, _backup, 'the backup changed on the way');
    IPolicyManager.ActionState memory _stored = _state();
    assertEq(_stored.setupCommitment, _committed.setupCommitment, 'the stored commitment differs from the event');
    assertEq(_stored.setupNonce, 1, 'the manager stores another nonce');
    assertEq(_stored.setupCommittedAtBlock, block.number, 'the manager stores another block for the commit');

    assertFalse(_anyLogCarries(_logs, _body()), 'a log carries the rule');
    for (uint256 _place; _place < _THIRD_PARTY + 1; ++_place) {
      assertFalse(_anyLogCarries(_logs, abi.encode(_credentialHash(_place))), 'a log carries a credential hash');
    }
  }

  /// @notice Opening an attempt publishes the rule, the handover, the places used and the methods that checked them.
  ///         Anyone can check the rule against the commitment and read both keys from the handover. The log search that
  ///         found no rule at the commit finds it here.
  function test_WhenAnAttemptOpens() external {
    // it should publish the rule and the payload in the clear
    _authorizeAndCommit();
    bytes32 _committed = _state().setupCommitment;

    vm.recordLogs();
    _open(_openingSet());
    Vm.Log[] memory _logs = vm.getRecordedLogs();
    StartedLog memory _started = _startedLog(_logs);
    assertTrue(_anyLogCarries(_logs, _body()), 'the search does not find the rule where the event shows it');

    assertEq(_started.setupBody, _body(), 'the opening event does not carry the rule');
    assertEq(_started.payload, _payload(), 'the opening event does not carry the handover');
    assertEq(_started.setupNonce, 1, 'the opening event carries another nonce');
    assertEq(_started.usedPlaces, _openingSet(), 'the opening event names other places');
    assertEq(_started.usedMethods.length, 2, 'the opening event names another number of methods');
    assertEq(_started.usedMethods[0], address(_ecdsa), 'the first method used is not the wallet method');
    assertEq(_started.usedMethods[1], address(_passkey), 'the second method used is not the passkey method');
    assertEq(
      keccak256(abi.encode(_account, address(_action), _started.setupNonce, _started.setupBody)),
      _committed,
      'the revealed rule does not open the commitment'
    );
    IRecoveryAction.Handover memory _handover = abi.decode(_started.payload, (IRecoveryAction.Handover));
    assertEq(_handover.newAuthority, _newKey, 'the payload names another new key');
    assertEq(_handover.removedAuthority, _holderKey, 'the payload names another removed key');
  }

  /// @notice A holder who writes no public note gets an empty note in the setup event. Only the commitment, the nonce
  ///         and the backup then reach the chain. `_seed` and `_length` build the backup.
  function test_WhenTheHolderWritesNoNote(uint256 _seed, uint256 _length) external {
    // it should publish an empty note
    bytes memory _backup = _opaqueBackup(_seed, bound(_length, 0, 512));
    vm.recordLogs();
    _authorizeAndCommitWith('', _backup);
    Vm.Log[] memory _logs = vm.getRecordedLogs();

    Vm.Log memory _log = _logs[_indexOfLog(_logs, IPolicyManager.SetupCommitted.selector)];
    CommittedLog memory _committed = abi.decode(abi.encodePacked(uint256(32), _log.data), (CommittedLog));
    assertEq(_committed.publicMetadata.length, 0, 'the setup event carries a note the holder did not write');
    assertEq(_committed.privateMetadata, _backup, 'the backup changed on the way');
  }

  /// @notice No setup or opening log contains the address of Carol, the guardian who did not approve. No log contains
  ///         any guardian's config either. The opening names each guardian only by a credential hash, so Carol stays
  ///         hidden even after the recovery opens.
  function test_WhenAGuardianDoesNotApprove() external {
    // it should keep that guardian's address and every config out of the logs
    vm.recordLogs();
    _authorizeAndCommit();
    Vm.Log[] memory _commitLogs = vm.getRecordedLogs();
    _open(_openingSet());
    Vm.Log[] memory _openingLogs = vm.getRecordedLogs();
    assertEq(_countLogs(_openingLogs, IPolicyManager.AttemptStarted.selector), 1, 'not one opening event');

    bytes memory _carol = abi.encodePacked(_guardians[_CAROL]);
    assertFalse(_anyLogCarries(_commitLogs, _carol), 'a setup log carries the guardian who did not approve');
    assertFalse(_anyLogCarries(_openingLogs, _carol), 'an opening log carries the guardian who did not approve');
    for (uint256 _place; _place < _THIRD_PARTY + 1; ++_place) {
      (, bytes memory _config,) = _credential(_place);
      assertFalse(_anyLogCarries(_commitLogs, _config), 'a setup log carries a guardian config');
      assertFalse(_anyLogCarries(_openingLogs, _config), 'an opening log carries a guardian config');
    }
  }

  /// @notice The manager refuses this request on its nonce, before it asks any method. The refused request still
  ///         carries the rule and each filled place's config in its calldata. So the first request anyone sends reveals
  ///         the rule, even when no attempt opens.
  function test_RevertWhen_ARefusedRequestCarriesTheRule() external {
    // it should revert
    _authorizeAndCommit();
    IPolicyManager.AttemptRequest memory _req = _request(_openingSet(), 1, 2, _window());
    bytes memory _calldata = abi.encodeCall(IPolicyManager.startAttempt, (_req));
    _sendRefusedBeforeAnyMethod(_req, _wrongNonce(2, 1));

    assertTrue(_contains(_calldata, _body()), 'the refused request does not carry the rule');
    for (uint256 _i; _i < _req.proofs.length; ++_i) {
      (, bytes memory _config,) = _credential(_req.proofs[_i].place);
      assertTrue(_contains(_calldata, _config), 'the refused request does not carry a filled place config');
    }
  }

  /// @notice Here the holder's backup is the rule and each place's config, unencrypted. The setup event then shows the
  ///         rule from the commit on. A reader rebuilds the stored commitment from it, so an unencrypted backup gives
  ///         up the privacy.
  function test_WhenTheHolderSendsTheBackupInTheClear() external {
    // it should show the rule from the commit on
    bytes[] memory _configs = new bytes[](_THIRD_PARTY + 1);
    for (uint256 _place; _place < _THIRD_PARTY + 1; ++_place) {
      (, _configs[_place],) = _credential(_place);
    }
    bytes memory _clearBackup = abi.encode(_body(), _configs);
    vm.recordLogs();
    _authorizeAndCommitWith(_PUBLIC_METADATA, _clearBackup);
    Vm.Log[] memory _logs = vm.getRecordedLogs();

    assertTrue(_anyLogCarries(_logs, _body()), 'the setup event does not show the rule');
    Vm.Log memory _log = _logs[_indexOfLog(_logs, IPolicyManager.SetupCommitted.selector)];
    CommittedLog memory _committed = abi.decode(abi.encodePacked(uint256(32), _log.data), (CommittedLog));
    (bytes memory _readBody,) = abi.decode(_committed.privateMetadata, (bytes, bytes[]));
    assertEq(
      keccak256(abi.encode(_account, address(_action), _committed.nonce, _readBody)),
      _state().setupCommitment,
      'the rule read from the backup does not open the stored commitment'
    );
  }

  /// @notice Here each wallet guardian's salt comes from the account and the place, so any reader can recompute it. A
  ///         reader who guesses Carol's address rebuilds the hash the opening published at her place. A wrong guess
  ///         does not. So a guessable salt exposes a guardian who did not approve. `_seed` builds the wrong guess's
  ///         address.
  function test_WhenAWalletGuardianHasAGuessableSalt(uint256 _seed) external {
    // it should let a reader who guesses the guardian find their place
    bytes memory _setupBody = _guessableRule();
    _asHolder(
      _two(
        _authorizeCall(),
        _managerCall(
          abi.encodeCall(
            IPolicyManager.commitSetup,
            (address(_action), _commitmentOf(1, _setupBody), 1, _PUBLIC_METADATA, _PRIVATE_METADATA)
          )
        )
      )
    );
    IPolicyManager.AttemptRequest memory _req = _requestOver(_setupBody, _openingSet(), 1, 1, _window());
    for (uint256 _i; _i < _req.proofs.length; ++_i) {
      if (_req.proofs[_i].place < _PHONE) _req.proofs[_i].salt = _guessableSalt(_req.proofs[_i].place);
    }
    _resign(_req);
    vm.recordLogs();
    _send(_req);
    bytes memory _published = _startedLog(vm.getRecordedLogs()).setupBody;

    (,, IPolicyManager.Clause[] memory _clauses) = abi.decode(_published, (uint48, bool, IPolicyManager.Clause[]));
    bytes32 _atCarol = _clauses[0].credentials[_CAROL];
    assertEq(_guessableWalletHash(_guardians[_CAROL], _CAROL), _atCarol, 'the right guess does not find Carol');
    assertNotEq(
      _guessableWalletHash(_fresh('wrongGuess', _seed), _CAROL), _atCarol, 'a wrong guess matches Carol\'s place'
    );
  }
}
