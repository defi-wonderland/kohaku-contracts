// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {IPolicyManager} from 'interfaces/IPolicyManager.sol';
import {ManagerKatBase} from 'test/kat/ManagerKatBase.sol';
import {PolicyManagerHarness} from 'test/utils/PolicyManagerHarness.sol';

/// @notice Replays attempt-request.json and cancel-request.json, the calldata a submitter sends, and their two
///         component fixtures, payment-order.json and proof-place.json. The encodings are the ABI encoding of the
///         structs IPolicyManager declares, and the deployed manager is then handed each frozen calldata to show it
///         reads every field the SDK wrote where the SDK wrote it. Tree: PolicyManagerRequestKat.tree.
contract PolicyManagerRequestKatTest is ManagerKatBase {
  /// The ABI encoding of IPolicyManager.PaymentOrder reproduces every payment order row, the open zero order
  /// included. The order sits inside the request, the digest and the attempt, so a drift would make the payment
  /// the guardians approved differ from the one the account pays.
  function test_WhenEncodingThePaymentOrderVectors() external view {
    // it should reproduce every expected encoding.
    string memory _json = vm.readFile(_PAYMENT_ORDER_FILE);
    uint256 _rows = _rowCount(_json);
    assertGt(_rows, 0, 'no payment order vector');
    for (uint256 _i; _i < _rows; ++_i) {
      string memory _row = _rowPath(_i);
      assertEq(
        abi.encode(_orderAt(_json, string.concat(_row, '.input'))),
        vm.parseJsonBytes(_json, string.concat(_row, '.expected.encoded')),
        _what('payment order encoding', _rowId(_json, _row))
      );
    }
  }

  /// The ABI encoding of IPolicyManager.ProofPlace reproduces every proof place row, the empty config and empty
  /// proof row included. Each filled place travels in this layout, so a drift would hand the manager a method,
  /// config or salt other than the one the guardian committed.
  function test_WhenEncodingTheProofPlaceVectors() external view {
    // it should reproduce every expected encoding.
    string memory _json = vm.readFile(_PROOF_PLACE_FILE);
    uint256 _rows = _rowCount(_json);
    assertGt(_rows, 0, 'no proof place vector');
    for (uint256 _i; _i < _rows; ++_i) {
      string memory _row = _rowPath(_i);
      assertEq(
        abi.encode(_proofAt(_json, string.concat(_row, '.input'))),
        vm.parseJsonBytes(_json, string.concat(_row, '.expected.encoded')),
        _what('proof place encoding', _rowId(_json, _row))
      );
    }
  }

  /// The startAttempt call built from each attempt request row's fields, through IPolicyManager's own selector and
  /// AttemptRequest struct, reproduces the row's calldata byte for byte. A submitter that builds the opening
  /// request another way sends bytes the manager decodes into a different request.
  function test_WhenEncodingTheAttemptRequestVectors() external view {
    // it should reproduce every expected calldata.
    string memory _json = vm.readFile(_ATTEMPT_REQUEST_FILE);
    uint256 _rows = _rowCount(_json);
    assertGt(_rows, 0, 'no attempt request vector');
    for (uint256 _i; _i < _rows; ++_i) {
      string memory _row = _rowPath(_i);
      IPolicyManager.AttemptRequest memory _request = _attemptRequestAt(_json, string.concat(_row, '.input'));
      assertEq(
        abi.encodeCall(IPolicyManager.startAttempt, (_request)),
        vm.parseJsonBytes(_json, string.concat(_row, '.expected.calldata')),
        _what('startAttempt calldata', _rowId(_json, _row))
      );
    }
  }

  /// The cancelByProofs call built from each cancellation request row's fields reproduces the row's calldata byte
  /// for byte. A cancel built another way never reaches the manager as the cancel the guardians signed.
  function test_WhenEncodingTheCancelRequestVectors() external view {
    // it should reproduce every expected calldata.
    string memory _json = vm.readFile(_CANCEL_REQUEST_FILE);
    uint256 _rows = _rowCount(_json);
    assertGt(_rows, 0, 'no cancel request vector');
    for (uint256 _i; _i < _rows; ++_i) {
      string memory _row = _rowPath(_i);
      IPolicyManager.CancelRequest memory _request = _cancelRequestAt(_json, string.concat(_row, '.input'));
      assertEq(
        abi.encodeCall(IPolicyManager.cancelByProofs, (_request)),
        vm.parseJsonBytes(_json, string.concat(_row, '.expected.calldata')),
        _what('cancelByProofs calldata', _rowId(_json, _row))
      );
    }
  }

  /// The deployed manager, holding the row's setup at the row's nonce with the row's attempt id next, reads each
  /// frozen opening calldata field by field: it passes the setup, nonce, attempt id, deadline and commitment checks
  /// and the credential check at the first proof's place, and stops at that proof's method, which has no code and
  /// so never approves. Every one of those checks reads a field the SDK placed, so the bytes decode as the SDK meant.
  function test_WhenTheManagerReadsTheAttemptRequestVectors() external {
    // it should refuse the first proof's method, after reading every field before it.
    string memory _json = vm.readFile(_ATTEMPT_REQUEST_FILE);
    uint256 _rows = _rowCount(_json);
    assertGt(_rows, 0, 'no attempt request vector');
    for (uint256 _i; _i < _rows; ++_i) {
      string memory _row = _rowPath(_i);
      IPolicyManager.AttemptRequest memory _request = _attemptRequestAt(_json, string.concat(_row, '.input'));
      assertGt(_request.proofs.length, 0, _what('proofs', _rowId(_json, _row)));
      assertEq(_request.proofs[0].method.code.length, 0, _what('first method has no code', _rowId(_json, _row)));

      PolicyManagerHarness _manager = new PolicyManagerHarness();
      _manager.harnessWriteSetup(
        _request.account,
        _request.action,
        IPolicyManager.Setup({
          commitment: _setupCommitmentOf(_request.account, _request.action, _request.setupNonce, _request.setupBody),
          nonce: _request.setupNonce,
          attemptCounter: _request.attemptId - 1,
          setupCommittedAtBlock: uint48(block.number)
        })
      );
      vm.warp(_request.validUntil);

      (bool _ok, bytes memory _revert) =
        address(_manager).call(vm.parseJsonBytes(_json, string.concat(_row, '.expected.calldata')));
      assertFalse(_ok, _what('opening accepted', _rowId(_json, _row)));
      assertEq(
        _revert,
        abi.encodeWithSelector(
          IPolicyManager.PolicyManager_ProofRejected.selector, _request.proofs[0].place, _request.proofs[0].method
        ),
        _what('opening refusal', _rowId(_json, _row))
      );
    }
  }

  /// The deployed manager, holding the row's setup and the row's attempt waiting under it, reads each frozen
  /// cancellation calldata field by field and stops at the first proof's method, which has no code and so never
  /// approves. The checks it passes on the way read every field the SDK placed before that proof.
  function test_WhenTheManagerReadsTheCancelRequestVectors() external {
    // it should refuse the first proof's method, after reading every field before it.
    string memory _json = vm.readFile(_CANCEL_REQUEST_FILE);
    uint256 _rows = _rowCount(_json);
    assertGt(_rows, 0, 'no cancel request vector');
    for (uint256 _i; _i < _rows; ++_i) {
      string memory _row = _rowPath(_i);
      IPolicyManager.CancelRequest memory _request = _cancelRequestAt(_json, string.concat(_row, '.input'));
      assertGt(_request.proofs.length, 0, _what('proofs', _rowId(_json, _row)));
      assertEq(_request.proofs[0].method.code.length, 0, _what('first method has no code', _rowId(_json, _row)));

      PolicyManagerHarness _manager = new PolicyManagerHarness();
      _manager.harnessWriteSetup(
        _request.account,
        _request.action,
        IPolicyManager.Setup({
          commitment: _setupCommitmentOf(_request.account, _request.action, _request.setupNonce, _request.setupBody),
          nonce: _request.setupNonce,
          attemptCounter: _request.attemptId,
          setupCommittedAtBlock: uint48(block.number)
        })
      );
      _manager.harnessWriteAttempt(
        _request.account,
        _request.action,
        IPolicyManager.Attempt({
          attemptId: _request.attemptId,
          setupNonce: _request.setupNonce,
          consumableAfter: _request.validUntil,
          state: IPolicyManager.AttemptState.Waiting,
          ignoresPause: false,
          payloadHash: keccak256('ManagerKat payload'),
          order: IPolicyManager.PaymentOrder({token: address(0), amount: 0, payee: address(0)}),
          usedMethods: new address[](0)
        })
      );
      vm.warp(_request.validUntil);

      (bool _ok, bytes memory _revert) =
        address(_manager).call(vm.parseJsonBytes(_json, string.concat(_row, '.expected.calldata')));
      assertFalse(_ok, _what('cancellation accepted', _rowId(_json, _row)));
      assertEq(
        _revert,
        abi.encodeWithSelector(
          IPolicyManager.PolicyManager_ProofRejected.selector, _request.proofs[0].place, _request.proofs[0].method
        ),
        _what('cancellation refusal', _rowId(_json, _row))
      );
    }
  }
}
