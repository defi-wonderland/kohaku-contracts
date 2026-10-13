// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {Vm} from 'forge-std/Vm.sol';
import {SetupBody} from 'libraries/SetupBody.sol';
import {IPolicyManager} from 'interfaces/IPolicyManager.sol';
import {ActionBatch} from 'test/utils/ActionBatch.sol';
import {IntegrationDemoKitTestBase} from 'test/utils/IntegrationDemoKitTestBase.sol';

/// @notice A recovery published the holder's rule. The new key commits the same guardians and methods again under fresh
///         salts. The published rule then opens nothing. The new rule stays private until its own first attempt.
contract RotateTheRuleAfterARecoveryTest is IntegrationDemoKitTestBase {
  /// @notice The fields of a setup event's data, decoded in the event's order.
  struct CommittedLog {
    uint64 nonce;
    bytes32 setupCommitment;
    bytes publicMetadata;
    bytes privateMetadata;
  }

  /// @notice The holder's new backup for the rotated rule. The manager never reads it.
  bytes internal constant _ROTATED_BACKUP = hex'5ea1ed0b';

  /// @notice The rule the first recovery published.
  bytes internal _revealed;

  function setUp() public override {
    super.setUp();
    _authorizeAndCommit();
    vm.recordLogs();
    _open(_openingSet());
    _revealed = _startedLog(vm.getRecordedLogs()).setupBody;
    vm.warp(_state().attempt.consumableAfter);
    _executeHandover();
    assertEq(_privilege(_newKey), _KEY_VALUE, 'given: the recovery installed the new key');
    assertEq(_revealed, _body(), 'given: the opening event published the rule');
  }

  /// @notice The salt the rotated rule gives `_place`, built from `_seed`.
  function _freshSalt(uint256 _seed, uint256 _place) internal pure returns (bytes32 _salt) {
    _salt = keccak256(abi.encode('fresh salt', _seed, _place));
  }

  /// @notice The credential at `_place` under the same method and config as before, with a fresh salt.
  function _rotatedCredentialHash(uint256 _seed, uint256 _place) internal view returns (bytes32 _hash) {
    (address _method, bytes memory _config,) = _credential(_place);
    _hash = keccak256(abi.encode(_method, _config, _freshSalt(_seed, _place)));
  }

  /// @notice Builds the holder's rule again under fresh salts. The clauses, thresholds, wait and guardians stay the
  ///         same. Places count across the clauses in order, so places 0 to 2 sit in clause zero.
  function _rotatedRule(uint256 _seed) internal view returns (bytes memory _setupBody) {
    IPolicyManager.Clause[] memory _clauses = new IPolicyManager.Clause[](2);
    _clauses[0].threshold = 2;
    _clauses[0].credentials = new bytes32[](3);
    _clauses[1].threshold = 1;
    _clauses[1].credentials = new bytes32[](2);
    for (uint256 _place; _place < _PHONE; ++_place) {
      _clauses[0].credentials[_place] = _rotatedCredentialHash(_seed, _place);
    }
    _clauses[1].credentials[0] = _rotatedCredentialHash(_seed, _PHONE);
    _clauses[1].credentials[1] = _rotatedCredentialHash(_seed, _THIRD_PARTY);
    _setupBody = SetupBody.encode(_WAIT, false, _clauses);
  }

  /// @notice Builds a request for attempt two under nonce two over the rotated rule. Each place names its fresh salt
  ///         and signs its approval digest. The request hands the account from the new key to `_newerKey`.
  function _rotatedRequest(uint256 _seed, address _newerKey)
    internal
    view
    returns (IPolicyManager.AttemptRequest memory _req)
  {
    _req = _requestOver(_rotatedRule(_seed), _openingSet(), 2, 2, _window());
    _req.payload = ActionBatch.payload(_newerKey, _newKey);
    for (uint256 _i; _i < _req.proofs.length; ++_i) {
      _req.proofs[_i].salt = _freshSalt(_seed, _req.proofs[_i].place);
    }
    _resign(_req);
  }

  /// @notice Lists the credential hashes of `_setupBody` by place. A body is abi.encode(wait, ignoresPause, clauses).
  ///         Places count across the clauses in order.
  function _credentialsOf(bytes memory _setupBody) internal pure returns (bytes32[] memory _hashes) {
    (,, IPolicyManager.Clause[] memory _clauses) = abi.decode(_setupBody, (uint48, bool, IPolicyManager.Clause[]));
    uint256 _count;
    for (uint256 _c; _c < _clauses.length; ++_c) {
      _count += _clauses[_c].credentials.length;
    }
    _hashes = new bytes32[](_count);
    uint256 _place;
    for (uint256 _c; _c < _clauses.length; ++_c) {
      for (uint256 _k; _k < _clauses[_c].credentials.length; ++_k) {
        _hashes[_place++] = _clauses[_c].credentials[_k];
      }
    }
  }

  /// @notice The new key commits the rotated rule under nonce two with the new backup. Returns the commit's logs.
  function _rotate(uint256 _seed) internal returns (Vm.Log[] memory _logs) {
    vm.recordLogs();
    _asKey(
      _newKey,
      _one(
        _managerCall(
          abi.encodeCall(
            IPolicyManager.commitSetup,
            (address(_action), _commitmentOf(2, _rotatedRule(_seed)), 2, _PUBLIC_METADATA, _ROTATED_BACKUP)
          )
        )
      )
    );
    _logs = vm.getRecordedLogs();
    assertEq(_state().setupNonce, 2, 'given: the new key did not commit the rotated rule');
  }

  /// @notice After the rotation, the manager refuses the published rule before it asks any method. A request at nonce
  ///         one fails on the nonce. A request at nonce two, freshly signed over the old credentials, fails on the
  ///         commitment. So a rule anyone read from a past recovery no longer opens an attempt. `_seed` builds the
  ///         fresh salts.
  function test_RevertWhen_ThePublishedRuleIsReplayed(uint256 _seed) external {
    // it should revert
    _rotate(_seed);
    IPolicyManager.ActionState memory _rotated = _state();
    _sendRefusedBeforeAnyMethod(_requestOver(_revealed, _openingSet(), 2, 1, _window()), _wrongNonce(1, 2));
    _assertSameState(_rotated, _state(), 'the refused request at nonce one wrote state');
    IPolicyManager.AttemptRequest memory _replay = _requestOver(_revealed, _openingSet(), 2, 2, _window());
    _sendRefusedBeforeAnyMethod(
      _replay,
      abi.encodeWithSelector(
        IPolicyManager.PolicyManager_SetupCommitmentMismatch.selector,
        _commitmentOf(2, _revealed),
        _commitmentOf(2, _rotatedRule(_seed))
      )
    );
    _assertSameState(_rotated, _state(), 'the refused replay wrote state');
  }

  /// @notice Committing the rotated rule publishes its commitment and the new backup, not the old one. No log contains
  ///         the new rule or any new credential hash, so a reader of the old rule cannot learn the new credentials. The
  ///         action stays authorized, so the account can still be recovered. `_seed` builds the fresh salts.
  function test_WhenTheNewKeyCommitsTheRotatedRule(uint256 _seed) external {
    // it should publish the new commitment and backup but no part of the new rule
    // it should keep the authorization
    Vm.Log[] memory _logs = _rotate(_seed);
    bytes memory _rotatedBody = _rotatedRule(_seed);
    assertEq(_state().setupCommitment, _commitmentOf(2, _rotatedBody), 'the stored commitment is not the rotated one');
    Vm.Log memory _log = _logs[_indexOfLog(_logs, IPolicyManager.SetupCommitted.selector)];
    CommittedLog memory _committed = abi.decode(abi.encodePacked(uint256(32), _log.data), (CommittedLog));
    assertEq(_committed.nonce, 2, 'the setup event carries another nonce');
    assertEq(_committed.privateMetadata, _ROTATED_BACKUP, 'the setup event does not carry the new backup');
    assertNotEq(
      _committed.privateMetadata, _PRIVATE_METADATA, 'the setup event carries the backup of the published rule'
    );
    assertTrue(_action.isAuthorized(_account), 'the rotation removed the action\'s authorization');
    assertEq(
      _privilege(ActionBatch.kitSlot(address(_action))),
      ActionBatch.binding(address(_action)),
      'the rotation changed the kit slot'
    );
    assertTrue(_anyLogCarries(_logs, abi.encode(_commitmentOf(2, _rotatedBody))), 'no log carries the commitment');
    assertFalse(_anyLogCarries(_logs, _rotatedBody), 'a log carries the rotated rule');
    for (uint256 _place; _place < _THIRD_PARTY + 1; ++_place) {
      assertFalse(
        _anyLogCarries(_logs, abi.encode(_rotatedCredentialHash(_seed, _place))), 'a log carries a new credential'
      );
    }
  }

  /// @notice Signing with their fresh salts, the same guardians open attempt two over the rotated rule. After the full
  ///         wait, the account passes to a newer key. Every credential hash in the second opening differs from the
  ///         first opening's hash at the same place. So new salts retire every published hash, and the holder can still
  ///         recover. `_seed` builds the fresh salts and the newer key's address.
  function test_WhenTheGuardiansSignForTheRotatedRule(uint256 _seed) external {
    // it should open the attempt and hand the account over after the wait
    _rotate(_seed);
    address _newerKey = _fresh('newerKey', _seed);
    IPolicyManager.AttemptRequest memory _req = _rotatedRequest(_seed, _newerKey);
    vm.recordLogs();
    _send(_req);
    bytes memory _published = _startedLog(vm.getRecordedLogs()).setupBody;
    assertEq(_published, _rotatedRule(_seed), 'the attempt opened another rule');
    bytes32[] memory _before = _credentialsOf(_revealed);
    bytes32[] memory _after = _credentialsOf(_published);
    assertEq(_after.length, _before.length, 'the rotated rule has another number of places');
    for (uint256 _place; _place < _before.length; ++_place) {
      assertNotEq(_after[_place], _before[_place], 'a credential hash did not change with its salt');
    }

    IPolicyManager.Attempt memory _waiting = _state().attempt;
    assertEq(uint256(_waiting.state), uint256(IPolicyManager.AttemptState.Waiting), 'the attempt is not waiting');
    assertEq(_waiting.attemptId, 2, 'the attempt took another id');
    assertEq(_waiting.setupNonce, 2, 'the attempt was judged under another setup');
    assertEq(_waiting.consumableAfter, block.timestamp + _WAIT, 'the attempt skipped part of the wait');

    vm.warp(_waiting.consumableAfter);
    _executeHandoverOf(_req.payload);
    assertEq(_privilege(_newerKey), _KEY_VALUE, 'the newer key holds no key value');
    assertEq(_privilege(_newKey), bytes32(0), 'the key the first recovery installed still holds a privilege');
  }

  /// @notice Here the new key commits the published rule again, unchanged. The manager refuses an approval signed under
  ///         nonce one on its nonce. A fresh request over the same rule at nonce two still opens attempt two. Only
  ///         fresh salts retire a published rule. `_seed` builds the address of the key the fresh request installs.
  function test_WhenTheNewKeyCommitsThePublishedRuleAgain(uint256 _seed) external {
    // it should refuse the old approvals and open a fresh attempt over the published rule
    _asKey(_newKey, _one(_commitCall(2, _commitmentOf(2, _revealed))));
    IPolicyManager.ActionState memory _recommitted = _state();
    assertEq(_recommitted.setupNonce, 2, 'the commit did not move the nonce');
    assertEq(_recommitted.setupCommitment, _commitmentOf(2, _revealed), 'the stored commitment is not the recommit');

    _sendRefusedBeforeAnyMethod(_requestOver(_revealed, _openingSet(), 2, 1, _window()), _wrongNonce(1, 2));
    _assertSameState(_recommitted, _state(), 'the refused old approvals wrote state');

    IPolicyManager.AttemptRequest memory _req = _requestOver(_revealed, _openingSet(), 2, 2, _window());
    _req.payload = ActionBatch.payload(_fresh('newerKey', _seed), _newKey);
    _resign(_req);
    vm.recordLogs();
    _send(_req);
    assertEq(_startedLog(vm.getRecordedLogs()).setupBody, _revealed, 'the opening event carries another rule');
    IPolicyManager.Attempt memory _waiting = _state().attempt;
    assertEq(uint256(_waiting.state), uint256(IPolicyManager.AttemptState.Waiting), 'the attempt is not waiting');
    assertEq(_waiting.attemptId, 2, 'the attempt took another id');
    assertEq(_waiting.setupNonce, 2, 'the attempt was judged under another setup');
  }
}
