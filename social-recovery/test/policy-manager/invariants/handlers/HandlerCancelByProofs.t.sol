// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {Vm} from 'forge-std/Vm.sol';
import {IPolicyManager} from 'interfaces/IPolicyManager.sol';
import {PolicyManagerBaseHandler} from 'test/policy-manager/invariants/handlers/BaseHandler.t.sol';

/// @notice The handler for cancelByProofs, sent by anyone for any entry, with proof sets built over
///         the entry's committed rule independently of the set that opened the attempt and, now and
///         then, one corruption the manager must refuse. It also replays accepted cancellations.
abstract contract PolicyManagerHandlerCancelByProofs is PolicyManagerBaseHandler {
  /// @notice One cancellation the handler builds and sends, with what it knows about it.
  // solhint-disable-next-line gas-struct-packing
  struct Cancellation {
    uint256 entry;
    uint256 mode;
    address submitter;
    ProofSet set;
    IPolicyManager.ActionState before;
    IPolicyManager.CancelRequest request;
    bytes32[] digests;
    bool expectAccepted;
  }

  /// @notice A cancellation that expired one second ago.
  uint256 internal constant _CANCEL_EXPIRED = 4;
  /// @notice A cancellation naming the stored nonce plus one.
  uint256 internal constant _CANCEL_WRONG_NONCE = 5;
  /// @notice A cancellation naming the next attempt id, the one an opening would name.
  uint256 internal constant _CANCEL_NEXT_ID = 6;
  /// @notice A cancellation whose proofs seal the approval digest of the same attempt.
  uint256 internal constant _CANCEL_APPROVAL_SEALED = 7;
  /// @notice A cancellation whose last proof names the stranger method instead of the committed one.
  uint256 internal constant _CANCEL_STRANGER_METHOD = 8;
  /// @notice A cancellation whose last proof carries a config not committed at its place.
  uint256 internal constant _CANCEL_OTHER_CONFIG = 9;

  /// @notice Accepted cancellations, each as abi.encode(request, entry).
  bytes[] internal _bankedCancels;
  /// @notice The next bank slot to overwrite once the bank is full.
  uint256 internal _nextCancelSlot;

  /*///////////////////////////////////////////////////////////////
                                HANDLERS
  ///////////////////////////////////////////////////////////////*/

  /// @notice cancelByProofs for the entry `_accountSeed` and `_actionSeed` pick, usually steered to
  ///         an entry whose attempt waits under a rule the handler holds, sent by a caller
  ///         `_submitterSeed` picks. `_modeSeed` picks a valid cancellation eight times in fourteen
  ///         and one corruption otherwise. `_setSeed` builds the proof set.
  function handler_cancelByProofs(
    uint256 _accountSeed,
    uint256 _actionSeed,
    uint256 _modeSeed,
    uint256 _setSeed,
    uint256 _submitterSeed
  ) external {
    Cancellation memory _cancellation = _buildCancellation(_accountSeed, _actionSeed, _modeSeed, _setSeed);
    (_cancellation.submitter,,) = _pick(_submitterSeed, 0);
    _sealCancelProofs(_cancellation);
    _sendCancellation(_cancellation);
  }

  /// @notice Sends again an accepted cancellation, as it was, moved to the entry's live attempt and
  ///         current nonce, or moved to another entry, as `_modeSeed` picks. The proofs were sealed
  ///         for the attempt they cancelled, so no such replay may ever cancel anything.
  function handler_replayCancel(uint256 _bankSeed, uint256 _modeSeed, uint256 _accountSeed, uint256 _actionSeed)
    external
  {
    if (_bankedCancels.length == 0) return;
    (IPolicyManager.CancelRequest memory _request, uint256 _origin) = abi.decode(
      _bankedCancels[bound(_bankSeed, 0, _bankedCancels.length - 1)], (IPolicyManager.CancelRequest, uint256)
    );
    uint64 _signedNonce = _request.setupNonce;
    uint256 _mode = bound(_modeSeed, 0, 2);
    if (_mode == 2) {
      (address _account, address _action, uint256 _target) = _pick(_accountSeed, _actionSeed);
      if (_target == _origin) return;
      _request.account = _account;
      _request.action = _action;
    }
    IPolicyManager.ActionState memory _now = manager.stateOf(_request.account, _request.action);
    if (_mode != 0) {
      _request.setupNonce = _now.setupNonce;
      _request.attemptId = _now.attempt.attemptId;
    }
    vm.recordLogs();
    try manager.cancelByProofs(_request) {
      _observe();
      if (_mode == 1 && _signedNonce != _now.setupNonce) ghost_retiredProofAccepted = true;
      else ghost_replayAccepted = true;
      _checkEntries(type(uint256).max);
    } catch {
      vm.getRecordedLogs();
      ++ghost_replaysRefused;
    }
  }

  /*///////////////////////////////////////////////////////////////
                                 BUILD
  ///////////////////////////////////////////////////////////////*/

  /// @notice Builds the cancellation for the picked entry: the stored nonce, the live attempt's id,
  ///         the entry's rule, a window of one hour and a proof set over the rule, then applies the
  ///         corruption the mode names to the cancellation's fields. Proofs are sealed afterwards.
  function _buildCancellation(uint256 _accountSeed, uint256 _actionSeed, uint256 _modeSeed, uint256 _setSeed)
    private
    view
    returns (Cancellation memory _cancellation)
  {
    (,, uint256 _picked) = _pick(_accountSeed, _actionSeed);
    (address _account, address _action, uint256 _entry) = _steer(_picked, _setSeed >> 24, true);
    _cancellation.entry = _entry;
    _cancellation.mode = bound(_modeSeed, 0, 13);
    if (_cancellation.mode > _CANCEL_OTHER_CONFIG) _cancellation.mode = 0;
    _cancellation.before = manager.stateOf(_account, _action);
    Rule memory _rule = _rules[_entry];
    IPolicyManager.CancelRequest memory _request = _cancellation.request;
    _request.account = _account;
    _request.action = _action;
    _request.attemptId = _cancellation.before.attempt.attemptId;
    _request.setupNonce = _cancellation.before.setupNonce;
    _request.setupBody = _rule.body;
    _request.validUntil = uint48(block.timestamp + 1 hours);
    if (_cancellation.mode == _CANCEL_EXPIRED) _request.validUntil = uint48(block.timestamp - 1);
    if (_cancellation.mode == _CANCEL_WRONG_NONCE) _request.setupNonce = _cancellation.before.setupNonce + 1;
    if (_cancellation.mode == _CANCEL_NEXT_ID) _request.attemptId = _cancellation.before.nextAttemptId;
    if (_ruleCredentials[_entry].length > 0) _cancellation.set = _chooseSet(_entry, _setSeed);
    _cancellation.expectAccepted = _rule.live && _rule.nonce == _cancellation.before.setupNonce
      && _cancellation.before.attempt.state == IPolicyManager.AttemptState.Waiting
      && _cancellation.before.attempt.setupNonce == _cancellation.before.setupNonce
      && _cancellation.mode < _CANCEL_EXPIRED && _cancellation.set.complete && !_cancellation.set.hostile
      && !_cancellation.set.stopped;
  }

  /// @notice Seals a proof for each place of the set over the cancellation's own digest at that
  ///         place, or over the approval digest of the same attempt in the mode that asks for it,
  ///         then applies the corruption the mode names to the last proof.
  function _sealCancelProofs(Cancellation memory _cancellation) private view {
    IPolicyManager.CancelRequest memory _request = _cancellation.request;
    uint256[] memory _places = _cancellation.set.places;
    _cancellation.digests = new bytes32[](_places.length);
    bytes32[] memory _sealed = new bytes32[](_places.length);
    for (uint256 _i; _i < _places.length; ++_i) {
      _cancellation.digests[_i] = manager.hashCancel(_request, _places[_i]);
      _sealed[_i] = _cancellation.mode == _CANCEL_APPROVAL_SEALED
        ? manager.hashApproval(_approvalOf(_request), _places[_i])
        : _cancellation.digests[_i];
    }
    _request.proofs = _proofsFor(_cancellation.entry, _places, _sealed);
    if (_places.length == 0) return;
    IPolicyManager.ProofPlace memory _proof = _request.proofs[_places.length - 1];
    if (_cancellation.mode == _CANCEL_STRANGER_METHOD) {
      _proof.method = strangerMethod;
    } else if (_cancellation.mode == _CANCEL_OTHER_CONFIG) {
      _proof.config = bytes.concat(_proof.config, 'another config');
      _proof.proof = _seal(_proof.config, _cancellation.digests[_places.length - 1]);
    }
  }

  /// @notice The opening request of the same account, action, attempt id, nonce, body and window,
  ///         with no payload and no order.
  function _approvalOf(IPolicyManager.CancelRequest memory _request)
    private
    pure
    returns (IPolicyManager.AttemptRequest memory _approval)
  {
    _approval.account = _request.account;
    _approval.action = _request.action;
    _approval.attemptId = _request.attemptId;
    _approval.setupNonce = _request.setupNonce;
    _approval.setupBody = _request.setupBody;
    _approval.validUntil = _request.validUntil;
  }

  /*///////////////////////////////////////////////////////////////
                              SEND AND CHECK
  ///////////////////////////////////////////////////////////////*/

  /// @notice Sends the cancellation and checks what it did, whether it was accepted or refused.
  function _sendCancellation(Cancellation memory _cancellation) private {
    vm.recordLogs();
    vm.startStateDiffRecording();
    vm.prank(_cancellation.submitter);
    try manager.cancelByProofs(_cancellation.request) {
      _checkMethodCalls(vm.stopAndReturnStateDiff(), _cancellation.request.proofs, _cancellation.digests);
      _checkCancelled(_cancellation, _observe());
      _bankCancel(_cancellation.request, _cancellation.entry);
    } catch (bytes memory _reason) {
      _checkMethodCalls(vm.stopAndReturnStateDiff(), _cancellation.request.proofs, _cancellation.digests);
      vm.getRecordedLogs();
      if (_cancellation.expectAccepted) ghost_honestRequestRefused = true;
      bool _earlierChecksHold = _cancellation.before.attempt.state == IPolicyManager.AttemptState.Waiting
        && _cancellation.before.attempt.setupNonce == _cancellation.before.setupNonce;
      if (_cancellation.mode == _CANCEL_EXPIRED && _earlierChecksHold) {
        bytes memory _expired = abi.encodeWithSelector(
          IPolicyManager.PolicyManager_RequestExpired.selector,
          uint48(block.timestamp),
          _cancellation.request.validUntil
        );
        if (!_eq(_reason, _expired)) ghost_windowNotCheckedFirst = true;
      }
    }
  }

  /// @notice Checks an accepted cancellation. It must be one the handler built to be accepted; each
  ///         flag names the corruption that let a cancellation through. The record must turn
  ///         Cancelled and keep every other field, the setup and the counter must stay, and one
  ///         AttemptCancelled must name the sender and the places filled.
  function _checkCancelled(Cancellation memory _cancellation, Vm.Log[] memory _logs) private {
    IPolicyManager.CancelRequest memory _request = _cancellation.request;
    if (!_cancellation.expectAccepted) {
      if (_cancellation.mode == _CANCEL_EXPIRED) ghost_expiredAccepted = true;
      if (!_cancellation.set.complete || _cancellation.set.hostile) ghost_incompleteSetAccepted = true;
      if (_cancellation.mode == _CANCEL_STRANGER_METHOD) ghost_unnamedMethodCounted = true;
      if (_cancellation.mode == _CANCEL_OTHER_CONFIG) ghost_swappedCredentialAccepted = true;
      if (_cancellation.mode == _CANCEL_APPROVAL_SEALED) ghost_replayAccepted = true;
      if (_cancellation.set.stopped) ghost_stopIgnored = true;
      ghost_acceptedCallWrong = true;
    }
    IPolicyManager.ActionState memory _after = _checkEntries(_cancellation.entry);
    IPolicyManager.Attempt memory _expected = _cancellation.before.attempt;
    _expected.state = IPolicyManager.AttemptState.Cancelled;
    if (_hash(_after.attempt) != _hash(_expected)) ghost_acceptedCallWrong = true;
    if (
      _after.setupCommitment != _cancellation.before.setupCommitment
        || _after.setupNonce != _cancellation.before.setupNonce
        || _after.setupCommittedAtBlock != _cancellation.before.setupCommittedAtBlock
    ) ghost_acceptedCallWrong = true;
    _checkCounterKept(_cancellation.before, _after);
    bytes memory _data = abi.encode(
      _request.attemptId,
      _cancellation.submitter,
      address(0),
      _cancellation.before.attempt.setupNonce,
      _placesOf(_request.proofs)
    );
    if (
      _logs.length != 1
        || !_isLog(_logs[0], IPolicyManager.AttemptCancelled.selector, _request.account, _request.action, _data)
    ) ghost_wrongEvents = true;
  }

  /// @notice Keeps `_request` in the bank, overwriting the oldest once the bank is full.
  function _bankCancel(IPolicyManager.CancelRequest memory _request, uint256 _entry) private {
    bytes memory _banked = abi.encode(_request, _entry);
    if (_bankedCancels.length < _MAX_BANKED) {
      _bankedCancels.push(_banked);
    } else {
      _bankedCancels[_nextCancelSlot] = _banked;
      _nextCancelSlot = (_nextCancelSlot + 1) % _MAX_BANKED;
    }
  }
}
