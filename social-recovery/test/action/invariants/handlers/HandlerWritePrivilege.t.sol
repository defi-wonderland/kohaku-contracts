// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {IAmbireAccount} from 'contracts/actions/ambire/IAmbireAccount.sol';
import {ActionBaseHandler} from 'test/action/invariants/handlers/BaseHandler.t.sol';
import {ActionBatch} from 'test/utils/ActionBatch.sol';

/// @notice The account writes one of its own privilege entries, as its holder or a second
///         authority can during a wait.
abstract contract ActionHandlerWritePrivilege is ActionBaseHandler {
  /// @notice Writes one entry as the account. `_addrSeed` picks the kit slot in one draw of
  ///         thirty-two while the account authorizes the action, and in one draw of four while it
  ///         does not. There `_valueSeed` removes the binding once in four and restores it otherwise,
  ///         so the account soon authorizes the action again. When the kit slot is not picked, a
  ///         write happens only in one draw of three as `_valueSeed` picks, so most handovers meet the
  ///         entries they were opened against. `_addrSeed` then picks a pool key or the entry point,
  ///         and `_valueSeed` picks nothing, either key value, the entry point's marker, the action's
  ///         binding or another validator's binding. A write can move keys and can stop the account
  ///         authorizing the action, but it never spends the attempt.
  function handler_writePrivilege(uint256 _addrSeed, uint256 _valueSeed) external {
    bool _authorizes = _privilege(ActionBatch.kitSlot(address(action))) == ActionBatch.binding(address(action));
    if (_addrSeed % (_authorizes ? 32 : 4) == 0) {
      Snapshot memory _beforeSlot = _snapshot();
      vm.prank(account);
      IAmbireAccount(account)
        .setAddrPrivilege(
          ActionBatch.kitSlot(address(action)), _valueSeed % 4 == 0 ? bytes32(0) : ActionBatch.binding(address(action))
        );
      _checkNothingSpent(_beforeSlot);
      return;
    }
    if ((_valueSeed >> 128) % 3 != 0) return;
    uint256 _pick = (_addrSeed / 32) % (_keys.length + 1);
    address _target = _pick == _keys.length ? entryPoint : _keys[_pick];
    bytes32[6] memory _values = [
      bytes32(0),
      bytes32(uint256(1)),
      bytes32(uint256(2)),
      _ENTRY_POINT_MARKER,
      ActionBatch.binding(address(action)),
      keccak256(abi.encode(address(0xDEAD), bytes('')))
    ];
    Snapshot memory _before = _snapshot();
    vm.prank(account);
    IAmbireAccount(account).setAddrPrivilege(_target, _values[_valueSeed % 6]);
    _checkNothingSpent(_before);
  }
}
