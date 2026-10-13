// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {StdInvariant} from 'forge-std/StdInvariant.sol';
import {Test} from 'forge-std/Test.sol';
import {IPolicyManager} from 'interfaces/IPolicyManager.sol';
import {IRecoveryAction} from 'interfaces/IRecoveryAction.sol';
import {IAmbireAccount} from 'contracts/actions/ambire/IAmbireAccount.sol';
import {ActionHandlersTarget} from 'test/action/invariants/HandlersTarget.t.sol';
import {ActionAmbireAccountFixture, ActionPaymentToken} from 'test/mocks/ActionAmbireAccountFixture.sol';
import {ActionAmbireProxy, ActionAmbireProxyDeployer} from 'test/utils/ActionAmbireProxy.sol';
import {ActionBatch} from 'test/utils/ActionBatch.sol';
import {PolicyManagerHarness} from 'test/utils/PolicyManagerHarness.sol';

/// @notice Deploys what the recovery action's invariant suite runs against: a real policy manager,
///         the action bound to it, and one account built the way Ambire's factory builds it. The
///         account is a proxy over a copy of Ambire's account code. Its creation code gives the first
///         key the key value 2. The account then gives the second key the value 1 and stores the
///         entry point's marker. It stores the action's binding under the kit slot, so it authorizes
///         the action. It holds a setup at the manager, the native asset and two tokens.
contract ActionInvariantSetup is StdInvariant, Test {
  string internal constant _ACTION_ARTIFACT = 'AmbireRecoveryAction.sol:AmbireRecoveryAction';

  PolicyManagerHarness internal _manager;
  IRecoveryAction internal _action;
  address internal _account;
  ActionHandlersTarget internal _handler;

  /// @dev Builds the world and targets the handler's eight calls.
  function setUp() public {
    vm.warp(1_000_000);
    _manager = new PolicyManagerHarness();
    address _impl = address(new ActionAmbireAccountFixture());
    _action = IRecoveryAction(deployCode(_ACTION_ARTIFACT, abi.encode(address(_manager), _impl)));

    address[] memory _keyList = new address[](5);
    for (uint256 _i; _i < _keyList.length; ++_i) {
      _keyList[_i] = makeAddr(string.concat('key', vm.toString(_i)));
    }
    ActionAmbireProxyDeployer _factory = new ActionAmbireProxyDeployer();
    _account = _factory.deploy(ActionAmbireProxy.creationCode(_impl, _keyList[0], bytes32(uint256(2))), 0);
    assertTrue(_action.supportsAccount(_account), 'the account is the proxy the action serves');

    vm.startPrank(_account);
    IAmbireAccount(_account).setAddrPrivilege(_keyList[1], bytes32(uint256(1)));
    IAmbireAccount(_account).setAddrPrivilege(address(0xE4747), bytes32(uint256(0x7171)));
    IAmbireAccount(_account)
      .setAddrPrivilege(ActionBatch.kitSlot(address(_action)), ActionBatch.binding(address(_action)));
    vm.stopPrank();
    assertTrue(_action.isAuthorized(_account), 'authorizes the action');
    _manager.harnessWriteSetup(
      _account,
      address(_action),
      IPolicyManager.Setup({
        commitment: keccak256('invariant setup'), nonce: 1, attemptCounter: 0, setupCommittedAtBlock: 1
      })
    );

    ActionPaymentToken _token = new ActionPaymentToken();
    _token.mint(_account, 1e22);
    vm.deal(_account, 500 ether);

    address[] memory _senderList = new address[](3);
    _senderList[0] = makeAddr('sender0');
    _senderList[1] = makeAddr('sender1');
    _senderList[2] = makeAddr('sender2');
    _handler = new ActionHandlersTarget(_manager, _action, _account, _token, _keyList, _senderList);

    bytes4[] memory _selectors = new bytes4[](8);
    _selectors[0] = _handler.handler_openAttempt.selector;
    _selectors[1] = _handler.handler_executeHandover.selector;
    _selectors[2] = _handler.handler_executeBatch.selector;
    _selectors[3] = _handler.handler_sendAgain.selector;
    _selectors[4] = _handler.handler_writePrivilege.selector;
    _selectors[5] = _handler.handler_cancelByOwner.selector;
    _selectors[6] = _handler.handler_setTokenAnswer.selector;
    _selectors[7] = _handler.handler_warp.selector;
    targetSelector(FuzzSelector({addr: address(_handler), selectors: _selectors}));
    targetContract(address(_handler));
  }
}
