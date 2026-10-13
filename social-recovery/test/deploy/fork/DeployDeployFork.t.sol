// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {VmSafe} from 'forge-std/Vm.sol';
import {IPolicyAction} from 'interfaces/IPolicyAction.sol';
import {IPolicyManager} from 'interfaces/IPolicyManager.sol';
import {IPolicyMethod} from 'interfaces/IPolicyMethod.sol';
import {IRecoveryAction} from 'interfaces/IRecoveryAction.sol';
import {IDeploy} from 'script/IDeploy.sol';
import {IAmbireRecoveryAction} from 'contracts/actions/ambire/IAmbireRecoveryAction.sol';
import {EcdsaMethod} from 'contracts/methods/ecdsa/EcdsaMethod.sol';
import {PasskeyMethod} from 'contracts/methods/passkey/PasskeyMethod.sol';
import {PolicyManager} from 'contracts/manager/PolicyManager.sol';
import {DeployForkTestBase} from 'test/utils/DeployForkTestBase.sol';

/// @notice deploy on a mainnet fork, where the probe has a node to ask and the pinned
///         implementation exists. It runs the probe and the implementation check, creates the
///         manager, the wallet and passkey methods and the recovery action, then runs the remaining
///         assertions. forge script simulates the whole run before it sends a transaction, so a
///         check that fails before the first creation keeps a bad pin from ever reaching the chain.
///         The tests record every account access, reverted ones included, so a contract created and
///         then undone by a revert still counts. Each test skips cleanly when MAINNET_RPC_URL is unset.
contract DeployDeployForkTest is DeployForkTestBase {
  /// deploy reverts naming the pin, having created nothing, when the pinned implementation has no
  /// code. The pin is an address hashed from a label, which holds no code on mainnet.
  function test_RevertWhen_ThePinnedImplementationHasNoCode() external {
    if (!_forkMainnet()) return;
    address _pin = _freshAddress('implementationWithoutCode', 0);
    // it should revert
    // it should name the pin in the error
    // it should create no contract
    uint256 _created = _deployExpectingRevert(
      IDeploy.Pins({ambireImplementation: _pin, ambireImplementationCodehash: _PINNED_CODEHASH}),
      abi.encodeWithSelector(IDeploy.Deploy_ImplementationHasNoCode.selector, _pin)
    );
    assertEq(_created, 0, 'contracts created before the implementation check');
  }

  /// deploy reverts naming the pin and both codehashes, having created nothing, when the pin is
  /// the real implementation but the pinned codehash is another one, so a table whose codehash
  /// does not match the code on chain never deploys.
  function test_RevertWhen_ThePinnedCodehashDiffers() external {
    if (!_forkMainnet()) return;
    bytes32 _wrong = keccak256('wrongCodehash');
    // it should revert
    // it should name the pin and both codehashes in the error
    // it should create no contract
    uint256 _created = _deployExpectingRevert(
      IDeploy.Pins({ambireImplementation: _PINNED_IMPLEMENTATION, ambireImplementationCodehash: _wrong}),
      abi.encodeWithSelector(
        IDeploy.Deploy_ImplementationCodehashMismatch.selector, _PINNED_IMPLEMENTATION, _wrong, _PINNED_CODEHASH
      )
    );
    assertEq(_created, 0, 'contracts created before the implementation check');
  }

  /// deploy with mainnet's pins returns an action whose MANAGER is the manager it deployed and
  /// whose AMBIRE_IMPLEMENTATION is the pin, the two constructor arguments a recovery depends on.
  function test_WhenThePinsAreGood() external {
    if (!_forkMainnet()) return;
    IDeploy.Deployment memory _deployment = _script.deploy(_script.pinsFor(block.chainid));
    // it should return an action naming the deployed manager and the pin
    assertEq(address(_deployment.action.MANAGER()), address(_deployment.manager), 'manager');
    assertEq(_deployment.action.AMBIRE_IMPLEMENTATION(), _PINNED_IMPLEMENTATION, 'implementation');
  }

  /// deploy creates exactly four contracts, at the four addresses it returns. A proxy or any other
  /// extra contract would add a creation, and every kit contract deploys directly.
  function test_WhenTheCreationsAreRecorded() external {
    if (!_forkMainnet()) return;
    vm.startStateDiffRecording();
    IDeploy.Deployment memory _deployment = _script.deploy(_script.pinsFor(block.chainid));
    VmSafe.AccountAccess[] memory _accesses = vm.stopAndReturnStateDiff();
    // it should create exactly the four returned contracts
    assertEq(_creations(_accesses), 4, 'creations');
    for (uint256 _i; _i < _accesses.length; ++_i) {
      if (_accesses[_i].kind != VmSafe.AccountAccessKind.Create) continue;
      address _created = _accesses[_i].account;
      assertTrue(
        _created == address(_deployment.manager) || _created == address(_deployment.ecdsaMethod)
          || _created == address(_deployment.passkeyMethod) || _created == address(_deployment.action),
        'a creation the deployment does not return'
      );
    }
  }

  /// deploy itself reads, on the contracts it returns, everything assertions two to five check:
  /// MANAGER, AMBIRE_IMPLEMENTATION and KIT_SLOT on the action, trustedParties on both methods, and
  /// supportsInterface for every interface id of every contract. A deploy that skipped a check
  /// would leave its read missing from the recorded calls.
  function test_WhenTheChecksDeployMakesAreRecorded() external {
    if (!_forkMainnet()) return;
    vm.startStateDiffRecording();
    IDeploy.Deployment memory _d = _script.deploy(_script.pinsFor(block.chainid));
    VmSafe.AccountAccess[] memory _accesses = vm.stopAndReturnStateDiff();
    address _action = address(_d.action);
    // it should read the action's manager, implementation and kit slot
    assertTrue(_called(_accesses, _action, abi.encodeCall(IAmbireRecoveryAction.MANAGER, ())), 'MANAGER');
    assertTrue(
      _called(_accesses, _action, abi.encodeCall(IAmbireRecoveryAction.AMBIRE_IMPLEMENTATION, ())),
      'AMBIRE_IMPLEMENTATION'
    );
    assertTrue(_called(_accesses, _action, abi.encodeCall(IAmbireRecoveryAction.KIT_SLOT, ())), 'KIT_SLOT');
    // it should read both methods' trusted parties
    bytes memory _parties = abi.encodeCall(IPolicyMethod.trustedParties, ());
    assertTrue(_called(_accesses, address(_d.ecdsaMethod), _parties), 'wallet trustedParties');
    assertTrue(_called(_accesses, address(_d.passkeyMethod), _parties), 'passkey trustedParties');
    // it should ask every contract for each of its interface ids
    _assertAsked(_accesses, address(_d.manager), type(IPolicyManager).interfaceId, 'manager');
    _assertAsked(_accesses, address(_d.ecdsaMethod), type(IPolicyMethod).interfaceId, 'wallet method');
    _assertAsked(_accesses, address(_d.passkeyMethod), type(IPolicyMethod).interfaceId, 'passkey method');
    _assertAsked(_accesses, _action, type(IPolicyAction).interfaceId, 'IPolicyAction');
    _assertAsked(_accesses, _action, type(IRecoveryAction).interfaceId, 'IRecoveryAction');
    _assertAsked(_accesses, _action, type(IAmbireRecoveryAction).interfaceId, 'IAmbireRecoveryAction');
  }

  function _assertAsked(
    VmSafe.AccountAccess[] memory _accesses,
    address _target,
    bytes4 _interfaceId,
    string memory _label
  ) internal pure {
    assertTrue(
      _called(_accesses, _target, abi.encodeWithSelector(IPolicyManager.supportsInterface.selector, _interfaceId)),
      _label
    );
  }

  /// deploy places the kit's own manager, wallet method and passkey method at the returned
  /// addresses, byte for byte, and the wallet and passkey methods in their own fields.
  /// A swapped or substituted contract would hand a holder's credentials to the wrong verifier.
  function test_WhenTheDeployedCodeIsComparedWithTheKitsContracts() external {
    if (!_forkMainnet()) return;
    IDeploy.Deployment memory _deployment = _script.deploy(_script.pinsFor(block.chainid));
    // it should hold the kit's manager and methods
    assertEq(address(_deployment.manager).code, type(PolicyManager).runtimeCode, 'manager');
    assertEq(address(_deployment.ecdsaMethod).code, type(EcdsaMethod).runtimeCode, 'wallet method');
    assertEq(address(_deployment.passkeyMethod).code, type(PasskeyMethod).runtimeCode, 'passkey method');
  }

  /// deploy places at the returned action address exactly the code the kit's action has when
  /// built there with the deployed manager and the pin. The test redeploys the kit's action at
  /// that address with those arguments and compares the code before and after.
  function test_WhenTheDeployedActionIsRebuiltInPlace() external {
    if (!_forkMainnet()) return;
    IDeploy.Deployment memory _deployment = _script.deploy(_script.pinsFor(block.chainid));
    address _action = address(_deployment.action);
    bytes memory _deployed = _action.code;
    deployCodeTo(
      'AmbireRecoveryAction.sol:AmbireRecoveryAction',
      abi.encode(address(_deployment.manager), _PINNED_IMPLEMENTATION),
      _action
    );
    // it should hold the kit's action built with the manager and the pin
    assertEq(_deployed, _action.code);
  }
}
