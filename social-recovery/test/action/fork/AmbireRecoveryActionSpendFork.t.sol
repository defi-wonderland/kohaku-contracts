// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {Test} from 'forge-std/Test.sol';
import {IPolicyManager} from 'interfaces/IPolicyManager.sol';
import {IRecoveryAction} from 'interfaces/IRecoveryAction.sol';
import {IAmbireAccount} from 'contracts/actions/ambire/IAmbireAccount.sol';
import {IAmbireRecoveryAction} from 'contracts/actions/ambire/IAmbireRecoveryAction.sol';
import {IActionAmbireFactory, IActionAmbireSender} from 'test/utils/ActionAmbireForkAbi.sol';
import {ActionAmbireProxy} from 'test/utils/ActionAmbireProxy.sol';
import {ActionForkBlocks} from 'test/utils/ActionForkBlocks.sol';
import {ActionBatch} from 'test/utils/ActionBatch.sol';
import {PolicyManagerHarness} from 'test/utils/PolicyManagerHarness.sol';

/// @notice Runs the whole spend on a fork of mainnet and of Sepolia against Ambire's deployed
///         implementation: an account built by the deployed factory, holding the action's
///         binding, spends a waiting attempt through executeHandover. The deployed account decodes
///         the action's signature, calls the action's validateSig with the batch as its own
///         Transaction tuple, and runs the batch, so a signature laid out in the wrong order, a
///         wrong callback ABI or a wrong call layout makes the handover fail here.
/// @dev Each test skips cleanly when its endpoint is unset. The manager is the real manager with a
///      harness door that writes the attempt, deployed on the fork.
contract AmbireRecoveryActionSpendForkTest is Test, ActionForkBlocks {
  string internal constant _ACTION_ARTIFACT = 'AmbireRecoveryAction.sol:AmbireRecoveryAction';
  /// @notice The pinned implementation, kohaku-commons src/consts/deploy.ts line 1.
  address internal constant _AMBIRE_IMPLEMENTATION = 0x0F2AA7bcda3d9D210dF69a394b6965CB2566c828;
  /// @notice Ambire's account factory, kohaku-commons src/consts/deploy.ts line 2.
  address internal constant _AMBIRE_FACTORY = 0x26cE6745A633030A6faC5e64e41D21fb6246dc2d;

  PolicyManagerHarness internal _manager;
  IRecoveryAction internal _action;
  address internal _account;
  address internal _signer;
  address internal _newKey;
  address internal _payee;

  /// @notice Forks, deploys the manager and the action, builds the account through the deployed
  ///         factory with its signer at 2, and has the signer write the action's binding into the kit
  ///         slot. Forks at `_block`, a fixed block, so the test does not depend on later chain
  ///         state. Skips when the endpoint is unset.
  function _fork(string memory _envName, uint256 _block) internal returns (bool _ran) {
    string memory _url = vm.envOr(_envName, string(''));
    if (bytes(_url).length == 0) {
      vm.skip(true);
      return false;
    }
    vm.createSelectFork(_url, _block);
    _manager = new PolicyManagerHarness();
    _action = IRecoveryAction(deployCode(_ACTION_ARTIFACT, abi.encode(address(_manager), _AMBIRE_IMPLEMENTATION)));
    _signer = makeAddr('forkSigner');
    _newKey = makeAddr('forkNewKey');
    _payee = makeAddr('forkPayee');
    _account = IActionAmbireFactory(_AMBIRE_FACTORY)
      .deploy(ActionAmbireProxy.creationCode(_AMBIRE_IMPLEMENTATION, _signer, bytes32(uint256(2))), 0);
    IAmbireRecoveryAction.Transaction[] memory _arm = new IAmbireRecoveryAction.Transaction[](1);
    _arm[0] = IAmbireRecoveryAction.Transaction({
      to: _account,
      value: 0,
      data: abi.encodeCall(
        IAmbireAccount.setAddrPrivilege, (ActionBatch.kitSlot(address(_action)), ActionBatch.binding(address(_action)))
      )
    });
    vm.prank(_signer);
    IActionAmbireSender(_account).executeBySender(_arm);
    assertTrue(_action.isAuthorized(_account), 'authorizes the action');
    vm.deal(_account, 1 ether);
    _ran = true;
  }

  /// @notice Writes a waiting attempt, its wait already over, handing the signer's key to a new key
  ///         and paying the payee 0.1 ether.
  function _plant() internal returns (IPolicyManager.Attempt memory _attempt) {
    _manager.harnessWriteSetup(
      _account,
      address(_action),
      IPolicyManager.Setup({
        commitment: keccak256('fork setup'), nonce: 1, attemptCounter: 1, setupCommittedAtBlock: uint48(block.number)
      })
    );
    _attempt = IPolicyManager.Attempt({
      attemptId: 1,
      setupNonce: 1,
      consumableAfter: uint48(block.timestamp),
      state: IPolicyManager.AttemptState.Waiting,
      ignoresPause: false,
      payloadHash: keccak256(ActionBatch.payload(_newKey, _signer)),
      order: IPolicyManager.PaymentOrder({token: address(0), amount: 0.1 ether, payee: _payee}),
      usedMethods: new address[](0)
    });
    _manager.harnessWriteAttempt(_account, address(_action), _attempt);
  }

  /// @notice Spends the attempt through executeHandover and checks what the deployed account did,
  ///         then checks that the same batch sent again is refused as a consumed attempt.
  function _checkSpend() internal {
    IPolicyManager.Attempt memory _attempt = _plant();
    vm.prank(makeAddr('forkExecutor'));
    _action.executeHandover(_account, ActionBatch.payload(_newKey, _signer));
    assertEq(
      uint8(_manager.stateOf(_account, address(_action)).attempt.state),
      uint8(IPolicyManager.AttemptState.Consumed),
      'consumed'
    );
    assertEq(IAmbireAccount(_account).privileges(_newKey), bytes32(uint256(1)), 'new key at 1');
    assertEq(IAmbireAccount(_account).privileges(_signer), bytes32(0), 'lost key zeroed');
    assertEq(_payee.balance, 0.1 ether, 'payee paid');
    assertTrue(_action.isAuthorized(_account), 'still authorizes the action');

    _attempt.state = IPolicyManager.AttemptState.Consumed;
    vm.expectRevert(
      abi.encodeWithSelector(
        IRecoveryAction.RecoveryAction_NotConsumable.selector,
        _account,
        _attempt.state,
        _attempt.consumableAfter,
        _attempt.payloadHash
      )
    );
    IAmbireAccount(_account)
      .execute(
        ActionBatch.approvedBatch(address(_manager), address(_action), _account, _attempt, _newKey, _signer, _payee),
        ActionBatch.kitSignature(address(_action))
      );
  }

  /// @notice On mainnet the deployed account runs the handover the action hands it: the attempt is
  ///         spent, the new key holds 1, the lost key holds nothing, the payee is paid, and the same
  ///         batch sent again is refused.
  function test_WhenAMainnetAccountSpendsAnAttempt() external {
    if (!_fork('MAINNET_RPC_URL', _MAINNET_BLOCK)) return;
    // it should run the handover once and refuse it a second time
    _checkSpend();
  }

  /// @notice The same spend on Sepolia.
  function test_WhenASepoliaAccountSpendsAnAttempt() external {
    if (!_fork('SEPOLIA_RPC_URL', _SEPOLIA_BLOCK)) return;
    // it should run the handover once and refuse it a second time
    _checkSpend();
  }
}
