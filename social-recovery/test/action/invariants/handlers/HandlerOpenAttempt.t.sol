// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {IPolicyManager} from 'interfaces/IPolicyManager.sol';
import {ActionBaseHandler} from 'test/action/invariants/handlers/BaseHandler.t.sol';
import {ActionBatch} from 'test/utils/ActionBatch.sol';

/// @notice Writes a new waiting attempt for the account when none is waiting, the state an accepted
///         opening leaves in the manager.
abstract contract ActionHandlerOpenAttempt is ActionBaseHandler {
  /// @notice Writes the next attempt under the stored setup nonce. `_newSeed` and `_removedSeed`
  ///         pick the two keys, mostly a key that holds nothing and a key that holds a key value, and
  ///         otherwise any address of the pool, zero and the kit slot included. `_shapeSeed` makes one
  ///         payload in eight carry a trailing byte. `_orderSeed` picks no payment, a token or the
  ///         native asset, each for a fixed payee or open, and the payee. `_amountSeed` sets an amount
  ///         that the account sometimes cannot cover. `_waitSeed` sets no wait in three draws of
  ///         four, so the spend is often possible at once, and otherwise a wait of up to one day,
  ///         which one move of time usually ends.
  function handler_openAttempt(
    uint256 _newSeed,
    uint256 _removedSeed,
    uint256 _shapeSeed,
    uint256 _orderSeed,
    uint256 _amountSeed,
    uint256 _waitSeed
  ) external {
    Snapshot memory _before = _snapshot();
    if (_before.state == IPolicyManager.AttemptState.Waiting) return;

    address _new = _pickNewKey(_newSeed);
    address _removed = _pickRemovedKey(_removedSeed);
    bool _canonical = _shapeSeed % 8 != 0;
    bytes memory _payload = ActionBatch.payload(_new, _removed);
    if (!_canonical) _payload = abi.encodePacked(_payload, bytes1(0x00));
    IPolicyManager.PaymentOrder memory _order = _buildOrder(_orderSeed, _amountSeed);

    IPolicyManager.ActionState memory _state = manager.stateOf(account, address(action));
    uint64 _id = _state.nextAttemptId;
    manager.harnessWriteSetup(
      account,
      address(action),
      IPolicyManager.Setup({
        commitment: _state.setupCommitment,
        nonce: _state.setupNonce,
        attemptCounter: _id,
        setupCommittedAtBlock: _state.setupCommittedAtBlock
      })
    );
    IPolicyManager.Attempt memory _record = IPolicyManager.Attempt({
      attemptId: _id,
      setupNonce: _state.setupNonce,
      consumableAfter: uint48(block.timestamp + (_waitSeed % 4 != 0 ? 0 : bound(_waitSeed, 1, 1 days))),
      state: IPolicyManager.AttemptState.Waiting,
      ignoresPause: false,
      payloadHash: keccak256(_payload),
      order: _order,
      usedMethods: new address[](0)
    });
    manager.harnessWriteAttempt(account, address(action), _record);
    _committed.newKey = _new;
    _committed.exists = true;
    _committed.canonical = _canonical;
    _committed.removedKey = _removed;
    _committed.payload = _payload;
    if (_order.payee == address(callbackPayee)) {
      callbackPayee.load(account, _renderApproved(_record, _order.payee), ActionBatch.kitSignature(address(action)));
    }
    _checkNothingSpent(_before);
  }

  /// @notice The order `_orderSeed` picks, with an amount from `_amountSeed`.
  function _buildOrder(uint256 _orderSeed, uint256 _amountSeed)
    internal
    view
    returns (IPolicyManager.PaymentOrder memory _order)
  {
    uint256 _kind = _orderSeed % 5;
    address _payee = _payees[(_orderSeed / 5) % _payees.length];
    if (_kind == 0) return _order;
    bool _native = _kind > 2;
    bool _open = _kind % 2 == 0;
    _order.token = _native ? address(0) : address(token);
    _order.amount = _native ? bound(_amountSeed, 1, 60 ether) : bound(_amountSeed, 1, 1.2e21);
    _order.payee = _open ? address(0) : _payee;
  }
}
