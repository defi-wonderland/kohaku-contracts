// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {SetupBody} from 'libraries/SetupBody.sol';
import {IPolicyManager} from 'interfaces/IPolicyManager.sol';
import {IntegrationDemoKitTestBase} from 'test/utils/IntegrationDemoKitTestBase.sol';

/// @notice Measures the gas of an opening, a cancel by proofs and a handover with real proofs. It uses
///         the demo rule with every place filled, and a wider rule of thirteen places. The contracts set
///         no limit on a rule's size, so the setup screen needs these numbers to refuse a rule too big
///         for a block. Each test logs its figure and asserts it stays far below a block. The figures
///         are what forge measures under the evm_version foundry.toml pins; a chain on a later hard fork
///         that reprices storage or code charges differently.
contract TheCostOfAWideRuleTest is IntegrationDemoKitTestBase {
  /// @notice The ceiling each call of the demo rule must stay under: one thirtieth of a 30 million
  ///         gas block.
  uint256 internal constant _DEMO_BUDGET = 1_000_000;
  /// @notice The ceiling each call of the wide rule must stay under: one tenth of a 30 million gas block.
  uint256 internal constant _WIDE_BUDGET = 3_000_000;
  /// @notice How many wallet guardians the wide rule names, all required.
  uint256 internal constant _WIDE_WALLETS = 9;
  /// @notice How many passkeys the wide rule names, all required.
  uint256 internal constant _WIDE_PASSKEYS = 3;

  /// @notice The wide rule's wallet guardian keys, by place.
  uint256[_WIDE_WALLETS] internal _wideWalletKeys;

  /// @notice Every place of the demo rule: the three friends, the phone and the third-party credential.
  function _everyPlace() internal pure returns (uint256[] memory _list) {
    _list = new uint256[](5);
    (_list[0], _list[1], _list[2], _list[3], _list[4]) = (_ALICE, _BOB, _CAROL, _PHONE, _THIRD_PARTY);
  }

  /// @notice Opening the demo rule with all five places filled costs well under a block. The places are
  ///         three wallet guardians, the passkey and the third-party credential.
  function test_WhenTheDemoRuleOpensAtEveryPlace() external {
    // it should open for less than the demo budget
    _authorizeAndCommit();
    _open(_everyPlace());
    _assertUnder('demo rule, startAttempt, five places', _DEMO_BUDGET);
  }

  /// @notice Cancelling by proofs with all five places of the demo rule filled costs well under a block.
  function test_WhenTheDemoRuleCancelsAtEveryPlace() external {
    // it should cancel for less than the demo budget
    _authorizeAndCommit();
    _open(_everyPlace());
    IPolicyManager.CancelRequest memory _cancel = _cancelRequest(_everyPlace(), 1, 1, _window());
    vm.prank(_executor);
    _manager.cancelByProofs(_cancel);
    _assertUnder('demo rule, cancelByProofs, five places', _DEMO_BUDGET);
  }

  /// @notice A handover with a token payment, for an attempt that used all three methods of the demo
  ///         rule, costs well under a block. This includes the account's check with the action and the
  ///         pause reads.
  function test_WhenTheDemoRuleIsSpent() external {
    // it should hand over for less than the demo budget
    _authorizeAndCommit();
    _open(_everyPlace());
    vm.warp(_state().attempt.consumableAfter);
    _executeHandover();
    _assertUnder('demo rule, executeHandover, three methods, token payment', _DEMO_BUDGET);
  }

  /// @notice Opening a wide rule costs well under a block. The rule has nine wallet guardians, three
  ///         passkeys and the third-party credential, and each clause needs all of its credentials.
  function test_WhenAWideRuleOpensAtEveryPlace() external {
    // it should open for less than the wide budget
    bytes memory _wide = _commitTheWideRule();
    _send(_wideRequest(_wide));
    _assertUnder('wide rule, startAttempt, thirteen places', _WIDE_BUDGET);
  }

  /// @notice Cancelling the wide rule's attempt by proofs at all thirteen places costs well under a block.
  function test_WhenAWideRuleCancelsAtEveryPlace() external {
    // it should cancel for less than the wide budget
    bytes memory _wide = _commitTheWideRule();
    _send(_wideRequest(_wide));
    IPolicyManager.CancelRequest memory _cancel = _wideCancel(_wide);
    vm.prank(_executor);
    _manager.cancelByProofs(_cancel);
    _assertUnder('wide rule, cancelByProofs, thirteen places', _WIDE_BUDGET);
  }

  /// @notice A handover for the wide rule's attempt, which used three methods, costs about the same as
  ///         for the demo rule. The spend reads one pause per method and no proof.
  function test_WhenAWideRuleIsSpent() external {
    // it should hand over for less than the demo budget
    bytes memory _wide = _commitTheWideRule();
    _send(_wideRequest(_wide));
    vm.warp(_state().attempt.consumableAfter);
    _executeHandover();
    _assertUnder('wide rule, executeHandover, three methods, token payment', _DEMO_BUDGET);
  }

  /// @notice Logs the gas of the last call under `_label` and asserts it is below `_budget`.
  function _assertUnder(string memory _label, uint256 _budget) internal {
    uint256 _used = vm.lastCallGas().gasTotalUsed;
    emit log_named_uint(_label, _used);
    assertLt(_used, _budget, _label);
  }

  /// @notice The wide rule's credential at `_place`: wallet guardians first, then passkeys, then the
  ///         third-party credential.
  function _wideCredential(uint256 _place)
    internal
    view
    returns (address _method, bytes memory _config, bytes32 _salt)
  {
    _salt = keccak256(abi.encode('wide salt', _place));
    if (_place < _WIDE_WALLETS) {
      _method = address(_ecdsa);
      _config = abi.encode(vm.addr(_wideWalletKeys[_place]));
    } else if (_place < _WIDE_WALLETS + _WIDE_PASSKEYS) {
      _method = address(_passkey);
      _config = _buildConfig(_widePasskeyKey(_place), _rpIdHash);
    } else {
      _method = address(_thirdParty);
      _config = abi.encode('third party credential');
    }
  }

  /// @notice The P-256 private key of the wide rule's passkey at `_place`.
  function _widePasskeyKey(uint256 _place) internal pure returns (uint256 _key) {
    _key = 0xB0B0 + _place;
  }

  /// @notice How many places the wide rule has.
  function _wideCount() internal pure returns (uint256 _count) {
    _count = _WIDE_WALLETS + _WIDE_PASSKEYS + 1;
  }

  /// @notice Authorizes the action and commits the wide rule in one batch, and returns the rule.
  function _commitTheWideRule() internal returns (bytes memory _wide) {
    for (uint256 _i; _i < _WIDE_WALLETS; ++_i) {
      (, _wideWalletKeys[_i]) = makeAddrAndKey(string.concat('wideGuardian', vm.toString(_i)));
    }
    IPolicyManager.Clause[] memory _clauses = new IPolicyManager.Clause[](3);
    uint256[3] memory _sizes = [_WIDE_WALLETS, _WIDE_PASSKEYS, uint256(1)];
    uint256 _place;
    for (uint256 _c; _c < 3; ++_c) {
      _clauses[_c].threshold = uint8(_sizes[_c]);
      _clauses[_c].credentials = new bytes32[](_sizes[_c]);
      for (uint256 _k; _k < _sizes[_c]; ++_k) {
        (address _method, bytes memory _config, bytes32 _salt) = _wideCredential(_place++);
        _clauses[_c].credentials[_k] = keccak256(abi.encode(_method, _config, _salt));
      }
    }
    _wide = SetupBody.encode(_WAIT, false, _clauses);
    _asHolder(_two(_authorizeCall(), _commitCall(1, _commitmentOf(1, _wide))));
  }

  /// @notice The wide rule's places, filled with their committed credential and no proof yet.
  function _wideUnsigned() internal view returns (IPolicyManager.ProofPlace[] memory _proofs) {
    _proofs = new IPolicyManager.ProofPlace[](_wideCount());
    for (uint256 _i; _i < _proofs.length; ++_i) {
      (address _method, bytes memory _config, bytes32 _salt) = _wideCredential(_i);
      _proofs[_i] = IPolicyManager.ProofPlace({place: _i, method: _method, config: _config, salt: _salt, proof: ''});
    }
  }

  /// @notice The proof the wide rule's credential at `_place` gives for `_digest`.
  function _wideProve(uint256 _place, bytes32 _digest) internal view returns (bytes memory _proof) {
    if (_place < _WIDE_WALLETS) {
      (uint8 _v, bytes32 _r, bytes32 _s) = vm.sign(_wideWalletKeys[_place], _digest);
      _proof = abi.encodePacked(_r, _s, _v);
    } else if (_place < _WIDE_WALLETS + _WIDE_PASSKEYS) {
      _proof = _signedProof(
        _widePasskeyKey(_place), _buildAuthenticatorData(_rpIdHash, _FLAGS_UP_UV), _standardClientData(_digest)
      );
    } else {
      (, bytes memory _config,) = _wideCredential(_place);
      _proof = abi.encode(_config, _digest);
    }
  }

  /// @notice The first opening request over the wide rule, every place signed.
  function _wideRequest(bytes memory _wide) internal view returns (IPolicyManager.AttemptRequest memory _req) {
    _req = _requestOver(_wide, new uint256[](0), 1, 1, _window());
    _req.proofs = _wideUnsigned();
    for (uint256 _i; _i < _req.proofs.length; ++_i) {
      _req.proofs[_i].proof = _wideProve(_i, _manager.hashApproval(_req, _i));
    }
  }

  /// @notice A cancellation of the wide rule's first attempt, every place signed.
  function _wideCancel(bytes memory _wide) internal view returns (IPolicyManager.CancelRequest memory _req) {
    _req = IPolicyManager.CancelRequest({
      account: _account,
      action: address(_action),
      attemptId: 1,
      setupNonce: 1,
      setupBody: _wide,
      validUntil: _window(),
      proofs: _wideUnsigned()
    });
    for (uint256 _i; _i < _req.proofs.length; ++_i) {
      _req.proofs[_i].proof = _wideProve(_i, _manager.hashCancel(_req, _i));
    }
  }
}
