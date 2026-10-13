// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {Vm} from 'forge-std/Vm.sol';
import {IPolicyManager} from 'interfaces/IPolicyManager.sol';
import {BindingDigest} from 'libraries/BindingDigest.sol';
import {PolicyManagerBaseHandler} from 'test/policy-manager/invariants/handlers/BaseHandler.t.sol';

/// @notice The handler for commitSetup, sent from several callers over several actions with fuzzed
///         nonces and commitments.
abstract contract PolicyManagerHandlerCommitSetup is PolicyManagerBaseHandler {
  /// @notice The arguments of one fuzzed commitSetup, and the rule it commits when the handler
  ///         built one.
  struct Write {
    bytes32 commitment;
    address caller;
    uint64 nonce;
    address action;
    bool builtRule;
    Rule rule;
    Credential[] credentials;
    uint8[] thresholds;
    uint256[] sizes;
  }

  /*///////////////////////////////////////////////////////////////
                                HANDLER
  ///////////////////////////////////////////////////////////////*/

  /// @notice commitSetup from a caller picked by `_callerSeed`, for an action picked by
  ///         `_actionSeed`. As `_nonceMode` picks, the nonce is the stored nonce plus one three
  ///         times in four, and otherwise the stored nonce itself or `_rawNonce`, as the parity of
  ///         `_rawNonce` picks. As
  ///         `_commitmentMode` picks, the commitment is over a new rule built from `_rawCommitment`
  ///         three times in seven, over the entry's last built rule again once in seven, so the
  ///         identical rule returns under a new nonce, a hash of `_rawCommitment` once in seven, zero
  ///         once in seven and the commitment of an empty body once in seven.
  function handler_commitSetup(
    uint256 _callerSeed,
    uint256 _actionSeed,
    uint256 _nonceMode,
    uint64 _rawNonce,
    uint256 _commitmentMode,
    bytes32 _rawCommitment,
    bytes calldata _publicMetadata,
    bytes calldata _privateMetadata
  ) external {
    Write memory _write;
    uint256 _entry;
    (_write.caller, _write.action, _entry) = _pick(_callerSeed, _actionSeed);
    IPolicyManager.ActionState memory _own = manager.stateOf(_write.caller, _write.action);
    uint64 _next = _own.setupNonce + 1;
    _nonceMode = bound(_nonceMode, 0, 3);
    _write.nonce = _nonceMode < 3 ? _next : (_rawNonce % 2 == 0 ? _own.setupNonce : _rawNonce);
    _commitmentMode = bound(_commitmentMode, 0, 6);
    if (_commitmentMode == 3 && _ruleCredentials[_entry].length == 0) _commitmentMode = 0;
    if (_commitmentMode < 3) {
      _write.builtRule = true;
      (_write.rule, _write.credentials, _write.thresholds, _write.sizes) = _buildRule(_entry, uint256(_rawCommitment));
    } else if (_commitmentMode == 3) {
      _write.builtRule = true;
      (_write.rule, _write.credentials, _write.thresholds, _write.sizes) = _loadRule(_entry);
    }
    if (_write.builtRule) {
      _write.commitment = BindingDigest.setupCommitment(_write.caller, _write.action, _next, _write.rule.body);
    } else if (_commitmentMode == 4) {
      _write.commitment = keccak256(abi.encode(_rawCommitment, 'handler commitment'));
    } else if (_commitmentMode == 6) {
      _write.commitment = BindingDigest.setupCommitment(_write.caller, _write.action, _next, '');
    }
    _commit(_write, _entry, _own, _publicMetadata, _privateMetadata);
  }

  /*///////////////////////////////////////////////////////////////
                                CHECKS
  ///////////////////////////////////////////////////////////////*/

  /// @notice Sends one commitSetup and checks it against `_own`, the entry's state before the call.
  ///         An accepted write must reach no contract other than the manager, except its own action
  ///         asked supportsAccount by a static call, and must leave the attempt counter where it was.
  ///         An accepted write records the rule it committed, or records that the entry's rule is no
  ///         longer one the handler built.
  function _commit(
    Write memory _write,
    uint256 _entry,
    IPolicyManager.ActionState memory _own,
    bytes calldata _publicMetadata,
    bytes calldata _privateMetadata
  ) private {
    uint64 _next = _own.setupNonce + 1;
    bytes32 _dead = BindingDigest.setupCommitment(_write.caller, _write.action, _next, '');

    vm.recordLogs();
    vm.startStateDiffRecording();
    vm.prank(_write.caller);
    try manager.commitSetup(_write.action, _write.commitment, _write.nonce, _publicMetadata, _privateMetadata) {
      _checkOnlyServingProbe(vm.stopAndReturnStateDiff(), _write.caller, _write.action);
      Vm.Log[] memory _logs = _observe();
      IPolicyManager.ActionState memory _after = _checkEntries(_entry);
      // An accepted write named the stored nonce plus one, stored a live commitment and this block.
      if (
        _write.nonce != _next || _after.setupNonce != _next || _after.setupCommitment != _write.commitment
          || _write.commitment == bytes32(0) || _write.commitment == _dead
          || _after.setupCommittedAtBlock != block.number
      ) ghost_acceptedCallWrong = true;
      _checkCounterKept(_own, _after);
      bytes memory _data = abi.encode(_next, _write.commitment, _publicMetadata, _privateMetadata);
      _checkWriteEvents(
        _logs, _write.caller, _write.action, _own.attempt, _after.attempt, IPolicyManager.SetupCommitted.selector, _data
      );
      _recordRule(_write, _entry, _next);
    } catch (bytes memory _reason) {
      vm.stopAndReturnStateDiff();
      vm.getRecordedLogs();
      // A write is refused for a nonce other than the stored one plus one, or for a commitment that
      // is zero or the empty-body one. Neither check is fixed to run first, so when both hold
      // either error explains the refusal. Both actions serve every account, so a refusal for an
      // action that does not serve the caller is unexplained.
      bool _nonceWrong = _write.nonce != _next;
      bool _commitmentInvalid = _write.commitment == bytes32(0) || _write.commitment == _dead;
      bool _explained =
        (_nonceWrong
            && _eq(
              _reason,
              abi.encodeWithSelector(IPolicyManager.PolicyManager_WrongSetupNonce.selector, _write.nonce, _next)
            ))
          || (_commitmentInvalid
            && _eq(
              _reason,
              abi.encodeWithSelector(IPolicyManager.PolicyManager_InvalidCommitment.selector, _write.commitment)
            ));
      if (!_explained) ghost_unexplainedRevert = true;
    }
  }

  /// @notice Records the rule an accepted write committed under `_next`, or that the entry's rule is
  ///         no longer one the handler built.
  function _recordRule(Write memory _write, uint256 _entry, uint64 _next) private {
    if (_write.builtRule) {
      _storeRule(_entry, _write.rule, _write.credentials, _write.thresholds, _write.sizes, _next);
    } else {
      _rules[_entry].live = false;
    }
  }
}
