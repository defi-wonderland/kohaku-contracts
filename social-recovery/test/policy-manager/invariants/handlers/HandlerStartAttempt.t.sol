// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {Vm} from 'forge-std/Vm.sol';
import {IPolicyManager} from 'interfaces/IPolicyManager.sol';
import {PolicyManagerBaseHandler} from 'test/policy-manager/invariants/handlers/BaseHandler.t.sol';

/// @notice The handler for startAttempt, sent by anyone for any entry, with proof sets built over
///         the entry's committed rule and, now and then, one corruption the manager must refuse. It
///         also keeps a bank of requests, sent or only prepared, and replays them after the state
///         moved on.
abstract contract PolicyManagerHandlerStartAttempt is PolicyManagerBaseHandler {
  /// @notice One opening the handler builds and sends, with what it knows about it.
  // solhint-disable-next-line gas-struct-packing
  struct Opening {
    uint256 entry;
    uint256 mode;
    address submitter;
    ProofSet set;
    IPolicyManager.ActionState before;
    IPolicyManager.AttemptRequest request;
    bytes32[] digests;
    bool expectAccepted;
  }

  /// @notice A request that expired one second ago.
  uint256 internal constant _OPEN_EXPIRED = 4;
  /// @notice A request naming the stored nonce plus one.
  uint256 internal constant _OPEN_WRONG_NONCE = 5;
  /// @notice A request naming the next attempt id plus one.
  uint256 internal constant _OPEN_WRONG_ID = 6;
  /// @notice A request whose last proof seals the digest of another payload.
  uint256 internal constant _OPEN_WRONG_SEAL = 7;
  /// @notice A request whose last proof names the stranger method instead of the committed one.
  uint256 internal constant _OPEN_STRANGER_METHOD = 8;
  /// @notice A request whose last proof carries another place's config, sealed for that config.
  uint256 internal constant _OPEN_OTHER_CONFIG = 9;
  /// @notice A request prepared and banked but not sent.
  uint256 internal constant _OPEN_PREPARE_ONLY = 10;
  /// @notice A set seed that keeps every clause's threshold of honest places, drops none, adds no
  ///         hostile place and steers to an entry whose rule the handler holds. Bit 0, surplus, is
  ///         left for the caller.
  uint256 internal constant _CLEAN_STEERED_SET = 0x01010100;

  /// @notice Requests sent or prepared, each as abi.encode(request, entry, sent).
  bytes[] internal _bankedApprovals;
  /// @notice The next bank slot to overwrite once the bank is full.
  uint256 internal _nextApprovalSlot;

  /*///////////////////////////////////////////////////////////////
                                HANDLERS
  ///////////////////////////////////////////////////////////////*/

  /// @notice startAttempt for the entry `_accountSeed` and `_actionSeed` pick, usually steered to an
  ///         entry whose rule the handler holds, sent by a caller `_submitterSeed` picks. `_modeSeed`
  ///         picks a valid request eight times in fifteen and one corruption otherwise. `_setSeed`
  ///         builds the proof set. `_payload` and `_amount` are the outcome and the price, paid to
  ///         the submitter.
  function handler_startAttempt(
    uint256 _accountSeed,
    uint256 _actionSeed,
    uint256 _modeSeed,
    uint256 _setSeed,
    bytes calldata _payload,
    uint256 _amount,
    uint256 _submitterSeed
  ) external {
    Opening memory _opening = _buildOpening(_accountSeed, _actionSeed, _modeSeed, _setSeed, _payload, _amount);
    (_opening.submitter,,) = _pick(_submitterSeed, 0);
    _opening.request.order.payee = _opening.submitter;
    _sealProofs(_opening);
    if (_opening.mode == _OPEN_PREPARE_ONLY) {
      _bankApproval(_opening.request, _opening.entry, false);
      return;
    }
    _sendOpening(_opening);
  }

  /// @notice Sends again a banked request, as it was or moved to the entry's current nonce and next
  ///         id, or to another entry, as `_modeSeed` picks. The proofs were sealed for the request as
  ///         first built, so no such replay may ever open an attempt. A replay that would be the very
  ///         request first built is skipped, since sending it is no replay.
  function handler_replayApproval(uint256 _bankSeed, uint256 _modeSeed, uint256 _accountSeed, uint256 _actionSeed)
    external
  {
    if (_bankedApprovals.length == 0) return;
    (IPolicyManager.AttemptRequest memory _request, uint256 _origin, bool _sent) = abi.decode(
      _bankedApprovals[bound(_bankSeed, 0, _bankedApprovals.length - 1)], (IPolicyManager.AttemptRequest, uint256, bool)
    );
    uint64 _signedNonce = _request.setupNonce;
    uint256 _mode = bound(_modeSeed, 0, 2);
    if (_mode == 0 && !_sent) return;
    if (_mode == 2) {
      (address _account, address _action, uint256 _target) = _pick(_accountSeed, _actionSeed);
      if (_target == _origin) return;
      _request.account = _account;
      _request.action = _action;
    }
    IPolicyManager.ActionState memory _now = manager.stateOf(_request.account, _request.action);
    if (_mode != 0) {
      if (_mode == 1 && _request.setupNonce == _now.setupNonce && _request.attemptId == _now.nextAttemptId) return;
      _request.setupNonce = _now.setupNonce;
      _request.attemptId = _now.nextAttemptId;
    }
    vm.recordLogs();
    try manager.startAttempt(_request) {
      _observe();
      if (_mode == 1 && _signedNonce != _now.setupNonce) ghost_retiredProofAccepted = true;
      else ghost_replayAccepted = true;
      _checkEntries(type(uint256).max);
    } catch {
      vm.getRecordedLogs();
      ++ghost_replaysRefused;
    }
  }

  /// @inheritdoc PolicyManagerBaseHandler
  function _openAValidAttempt(uint256 _seed) internal override {
    uint256 _setSeed = _CLEAN_STEERED_SET | (_seed & 1);
    Opening memory _opening = _buildOpening(_seed >> 8, _seed >> 64, 0, _setSeed, 'an outcome to spend', 0);
    (_opening.submitter,,) = _pick(_seed >> 128, 0);
    _opening.request.order.payee = _opening.submitter;
    _sealProofs(_opening);
    _sendOpening(_opening);
  }

  /*///////////////////////////////////////////////////////////////
                                 BUILD
  ///////////////////////////////////////////////////////////////*/

  /// @notice Builds the request for the picked entry: the stored nonce, the next id, the entry's
  ///         rule, a window of one hour, and a proof set over the rule, then applies the corruption
  ///         the mode names to the request's fields. Proofs are sealed afterwards.
  function _buildOpening(
    uint256 _accountSeed,
    uint256 _actionSeed,
    uint256 _modeSeed,
    uint256 _setSeed,
    bytes memory _payload,
    uint256 _amount
  ) private view returns (Opening memory _opening) {
    (,, uint256 _picked) = _pick(_accountSeed, _actionSeed);
    (address _account, address _action, uint256 _entry) = _steer(_picked, _setSeed >> 24, false);
    _opening.entry = _entry;
    _opening.mode = bound(_modeSeed, 0, 14);
    if (_opening.mode > _OPEN_PREPARE_ONLY) _opening.mode = 0;
    _opening.before = manager.stateOf(_account, _action);
    Rule memory _rule = _rules[_entry];
    IPolicyManager.AttemptRequest memory _request = _opening.request;
    _request.account = _account;
    _request.action = _action;
    _request.attemptId = _opening.before.nextAttemptId;
    _request.setupNonce = _opening.before.setupNonce;
    _request.setupBody = _rule.body;
    _request.payload = _payload;
    _request.order.amount = bound(_amount, 0, type(uint128).max);
    _request.validUntil = uint48(block.timestamp + 1 hours);
    if (_opening.mode == _OPEN_EXPIRED) _request.validUntil = uint48(block.timestamp - 1);
    if (_opening.mode == _OPEN_WRONG_NONCE) _request.setupNonce = _opening.before.setupNonce + 1;
    if (_opening.mode == _OPEN_WRONG_ID) _request.attemptId = _opening.before.nextAttemptId + 1;
    if (_ruleCredentials[_entry].length > 0) _opening.set = _chooseSet(_entry, _setSeed);
    _opening.expectAccepted = _rule.live && _rule.nonce == _opening.before.setupNonce
      && _opening.before.attempt.state != IPolicyManager.AttemptState.Waiting && _opening.mode < _OPEN_EXPIRED
      && _opening.set.complete && !_opening.set.hostile && !_opening.set.stopped;
  }

  /// @notice Seals a proof for each place of the set over the request's own digest at that place,
  ///         then applies the corruption the mode names to the last proof. The other config is the
  ///         config of the next place, or a config no place holds when the rule has one place.
  function _sealProofs(Opening memory _opening) private view {
    IPolicyManager.AttemptRequest memory _request = _opening.request;
    uint256[] memory _places = _opening.set.places;
    _opening.digests = new bytes32[](_places.length);
    for (uint256 _i; _i < _places.length; ++_i) {
      _opening.digests[_i] = manager.hashApproval(_request, _places[_i]);
    }
    _request.proofs = _proofsFor(_opening.entry, _places, _opening.digests);
    if (_places.length == 0) return;
    uint256 _last = _places.length - 1;
    IPolicyManager.ProofPlace memory _proof = _request.proofs[_last];
    if (_opening.mode == _OPEN_WRONG_SEAL) {
      IPolicyManager.AttemptRequest memory _other = _copy(_request);
      _other.payload = bytes.concat(_request.payload, 'another outcome');
      _proof.proof = _seal(_proof.config, manager.hashApproval(_other, _proof.place));
    } else if (_opening.mode == _OPEN_STRANGER_METHOD) {
      _proof.method = strangerMethod;
    } else if (_opening.mode == _OPEN_OTHER_CONFIG) {
      Credential[] storage _credentials = _ruleCredentials[_opening.entry];
      _proof.config = _credentials.length > 1
        ? _credentials[(_proof.place + 1) % _credentials.length].config
        : bytes.concat(_proof.config, 'another config');
      _proof.proof = _seal(_proof.config, _opening.digests[_last]);
    }
  }

  /// @notice A copy of `_request` whose top-level fields can change without touching the original.
  function _copy(IPolicyManager.AttemptRequest memory _request)
    private
    pure
    returns (IPolicyManager.AttemptRequest memory _copied)
  {
    _copied = abi.decode(abi.encode(_request), (IPolicyManager.AttemptRequest));
  }

  /*///////////////////////////////////////////////////////////////
                              SEND AND CHECK
  ///////////////////////////////////////////////////////////////*/

  /// @notice Sends the opening and checks what it did, whether it was accepted or refused.
  function _sendOpening(Opening memory _opening) private {
    vm.recordLogs();
    vm.startStateDiffRecording();
    vm.prank(_opening.submitter);
    try manager.startAttempt(_opening.request) {
      Vm.AccountAccess[] memory _accesses = vm.stopAndReturnStateDiff();
      _checkMethodCalls(_accesses, _opening.request.proofs, _opening.digests);
      _checkStorageHidesRule(_accesses, _opening.entry);
      _checkAccepted(_opening, _observe());
      _bankApproval(_opening.request, _opening.entry, true);
    } catch (bytes memory _reason) {
      _checkMethodCalls(vm.stopAndReturnStateDiff(), _opening.request.proofs, _opening.digests);
      vm.getRecordedLogs();
      _checkRefused(_opening, _reason);
    }
  }

  /// @notice Checks an accepted opening. It must be one the handler built to be accepted; each
  ///         flag names the corruption that let an opening through. The record must hold what the
  ///         request and the rule define, the counter must move to the request's id, the setup must
  ///         stay, and one AttemptStarted must carry the request in the clear.
  function _checkAccepted(Opening memory _opening, Vm.Log[] memory _logs) private {
    IPolicyManager.AttemptRequest memory _request = _opening.request;
    if (!_opening.expectAccepted) {
      if (_opening.mode == _OPEN_EXPIRED) ghost_expiredAccepted = true;
      if (!_opening.set.complete || _opening.set.hostile) ghost_incompleteSetAccepted = true;
      if (_opening.mode == _OPEN_STRANGER_METHOD) ghost_unnamedMethodCounted = true;
      if (_opening.mode == _OPEN_OTHER_CONFIG) ghost_swappedCredentialAccepted = true;
      if (_opening.mode == _OPEN_WRONG_SEAL) ghost_replayAccepted = true;
      if (_opening.set.stopped) ghost_stopIgnored = true;
      ghost_acceptedCallWrong = true;
    }
    IPolicyManager.ActionState memory _after = _checkEntries(_opening.entry);
    Rule memory _rule = _rules[_opening.entry];
    uint48 _consumableAfter = uint48(block.timestamp) + _rule.wait;
    address[] memory _usedMethods = _distinctMethods(_request.proofs);
    IPolicyManager.Attempt memory _expected = IPolicyManager.Attempt({
      attemptId: _request.attemptId,
      setupNonce: _request.setupNonce,
      consumableAfter: _consumableAfter,
      state: IPolicyManager.AttemptState.Waiting,
      ignoresPause: _rule.ignoresPause,
      payloadHash: keccak256(_request.payload),
      order: _request.order,
      usedMethods: _usedMethods
    });
    if (_hash(_after.attempt) != _hash(_expected)) ghost_acceptedCallWrong = true;
    if (
      _after.setupCommitment != _opening.before.setupCommitment || _after.setupNonce != _opening.before.setupNonce
        || _after.setupCommittedAtBlock != _opening.before.setupCommittedAtBlock
    ) ghost_acceptedCallWrong = true;
    if (_request.attemptId != _opening.before.nextAttemptId || _after.nextAttemptId != _request.attemptId + 1) {
      ghost_counterMovedWrongly = true;
    }
    _checkUsedMethodsNamed(_after.attempt.usedMethods, _opening.entry);
    if (_opening.expectAccepted) _recordAcceptedOpening(_opening, _usedMethods);
    bytes memory _data = abi.encode(
      _request.attemptId,
      _request.setupNonce,
      _request.setupBody,
      _placesOf(_request.proofs),
      _usedMethods,
      _request.payload,
      _request.order,
      _consumableAfter
    );
    if (
      _logs.length != 1
        || !_isLog(_logs[0], IPolicyManager.AttemptStarted.selector, _request.account, _request.action, _data)
    ) ghost_wrongEvents = true;
  }

  /// @notice Checks a refused opening. An opening built to be accepted must not be refused, and an
  ///         expired one whose earlier checks held must be refused on its window.
  function _checkRefused(Opening memory _opening, bytes memory _reason) private {
    if (_opening.expectAccepted) ghost_honestRequestRefused = true;
    bool _earlierChecksHold = _opening.before.setupCommitment != bytes32(0)
      && _opening.before.attempt.state != IPolicyManager.AttemptState.Waiting;
    if (_opening.mode == _OPEN_EXPIRED && _earlierChecksHold) {
      bytes memory _expired = abi.encodeWithSelector(
        IPolicyManager.PolicyManager_RequestExpired.selector, uint48(block.timestamp), _opening.request.validUntil
      );
      if (!_eq(_reason, _expired)) ghost_windowNotCheckedFirst = true;
    }
  }

  /// @notice Records an opening the handler built to be accepted and saw accepted, as it built it,
  ///         so the spend and the cancel by veto can be judged against the handler's own record.
  function _recordAcceptedOpening(Opening memory _opening, address[] memory _usedMethods) private {
    Rule memory _rule = _rules[_opening.entry];
    ghost_acceptedOpening[_opening.entry] = AcceptedOpening({
      known: true,
      attemptId: _opening.request.attemptId,
      setupNonce: _opening.request.setupNonce,
      acceptedAt: block.timestamp,
      wait: _rule.wait,
      ignoresPause: _rule.ignoresPause,
      payloadHash: keccak256(_opening.request.payload)
    });
    ghost_acceptedUsedMethods[_opening.entry] = _usedMethods;
  }

  /// @notice Keeps `_request` in the bank, overwriting the oldest once the bank is full.
  function _bankApproval(IPolicyManager.AttemptRequest memory _request, uint256 _entry, bool _sent) private {
    bytes memory _banked = abi.encode(_request, _entry, _sent);
    if (_bankedApprovals.length < _MAX_BANKED) {
      _bankedApprovals.push(_banked);
    } else {
      _bankedApprovals[_nextApprovalSlot] = _banked;
      _nextApprovalSlot = (_nextApprovalSlot + 1) % _MAX_BANKED;
    }
  }
}
