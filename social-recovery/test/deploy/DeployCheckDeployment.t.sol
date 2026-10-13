// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {IPolicyManager} from 'interfaces/IPolicyManager.sol';
import {IPolicyMethod} from 'interfaces/IPolicyMethod.sol';
import {IDeploy} from 'script/IDeploy.sol';
import {IAmbireRecoveryAction} from 'contracts/actions/ambire/IAmbireRecoveryAction.sol';
import {DeployMockAction} from 'test/mocks/DeployMockAction.sol';
import {DeployMockLookAlike} from 'test/mocks/DeployMockLookAlike.sol';
import {DeployMockMethod} from 'test/mocks/DeployMockMethod.sol';
import {DeployTestBase} from 'test/utils/DeployTestBase.sol';

/// @notice checkDeployment runs the action, kit slot, method role, interface and method name assertions, in
///         that order, over one deployment. Each test breaks one deployment in one place and
///         expects that assertion's error, so a check the function skips fails here. The ordering
///         tests break two places at once and expect the earlier assertion's error.
contract DeployCheckDeploymentTest is DeployTestBase {
  /// checkDeployment passes for a deployment of the kit's real contracts that names its manager
  /// and its pin, so a good deployment is never blocked.
  function test_WhenEveryAssertionHolds() external view {
    // it should pass
    _script.checkDeployment(_good, _pins);
  }

  /// checkDeployment reverts with the manager mismatch when the action names another manager.
  /// `_seed` is hashed into that manager's address, one no fixture uses.
  function test_RevertWhen_TheActionNamesAnotherManager(uint256 _seed) external {
    address _otherManager = _freshAddress('otherManager', _seed);
    _good.action = _newAction(_otherManager, _implementation);
    // it should revert
    // it should raise the manager mismatch
    vm.expectRevert(
      abi.encodeWithSelector(IDeploy.Deploy_ActionManagerMismatch.selector, address(_good.manager), _otherManager)
    );
    _script.checkDeployment(_good, _pins);
  }

  /// checkDeployment reverts with the implementation mismatch when the pins name another
  /// implementation than the action holds. `_seed` is hashed into that pin.
  function test_RevertWhen_ThePinsNameAnotherImplementation(uint256 _seed) external {
    address _otherPin = _freshAddress('otherPin', _seed);
    // it should revert
    // it should raise the implementation mismatch
    vm.expectRevert(
      abi.encodeWithSelector(IDeploy.Deploy_ActionImplementationMismatch.selector, _otherPin, _implementation)
    );
    _script.checkDeployment(
      _good, IDeploy.Pins({ambireImplementation: _otherPin, ambireImplementationCodehash: _otherPin.codehash})
    );
  }

  /// checkDeployment reverts with the kit slot collision when the action's slot equals the one
  /// Ambire's helper derives for it. The mock action names the right manager and pin.
  function test_RevertWhen_TheKitSlotCollides() external {
    DeployMockAction _action = new DeployMockAction(address(_good.manager), _implementation, true);
    _good.action = IAmbireRecoveryAction(address(_action));
    // it should revert
    // it should raise the kit slot collision
    vm.expectRevert(
      abi.encodeWithSelector(
        IDeploy.Deploy_KitSlotCollides.selector, address(_action), _ambireHelperSlot(address(_action))
      )
    );
    _script.checkDeployment(_good, _pins);
  }

  /// checkDeployment reverts naming the passkey method, the name method-ecdsa and the name it
  /// answered, when the wallet method's place holds the kit's passkey method. A record with the
  /// two swapped would send wallet guardians to the passkey method, and no recovery would verify.
  function test_RevertWhen_TheWalletPlaceHoldsThePasskeyMethod() external {
    address _passkeyMethod = address(_good.passkeyMethod);
    _good.ecdsaMethod = _good.passkeyMethod;
    // it should revert
    // it should name the method, the expected name and the answered name
    vm.expectRevert(
      abi.encodeWithSelector(IDeploy.Deploy_MethodMismatch.selector, _passkeyMethod, 'method-ecdsa', 'method-passkey')
    );
    _script.checkDeployment(_good, _pins);
  }

  /// checkDeployment reverts naming the wallet method, the name method-passkey and the name it
  /// answered, when the passkey method's place holds the kit's wallet method.
  function test_RevertWhen_ThePasskeyPlaceHoldsTheWalletMethod() external {
    address _walletMethod = address(_good.ecdsaMethod);
    _good.passkeyMethod = _good.ecdsaMethod;
    // it should revert
    // it should name the method, the expected name and the answered name
    vm.expectRevert(
      abi.encodeWithSelector(IDeploy.Deploy_MethodMismatch.selector, _walletMethod, 'method-passkey', 'method-ecdsa')
    );
    _script.checkDeployment(_good, _pins);
  }

  /// checkDeployment raises the method mismatch for the wallet method's place first when the two
  /// methods are swapped, since the wallet method is checked before the passkey method.
  function test_RevertWhen_TheTwoMethodsAreSwapped() external {
    (_good.ecdsaMethod, _good.passkeyMethod) = (_good.passkeyMethod, _good.ecdsaMethod);
    // it should revert
    // it should name the wallet place first
    vm.expectRevert(
      abi.encodeWithSelector(
        IDeploy.Deploy_MethodMismatch.selector, address(_good.ecdsaMethod), 'method-ecdsa', 'method-passkey'
      )
    );
    _script.checkDeployment(_good, _pins);
  }

  /// checkDeployment reverts naming ecdsaMethod and the method's address in the read failure when
  /// the wallet method's name call reverts, so a contract with no name never passes as one. A
  /// reverted read is reported as a read that failed, not as a method that answered an empty name,
  /// so the operator learns the address does not hold a method at all.
  function test_RevertWhen_AMethodNameCallReverts() external {
    DeployMockMethod _method = new DeployMockMethod();
    _method.revertName();
    _good.ecdsaMethod = IPolicyMethod(address(_method));
    // it should revert
    // it should name ecdsaMethod and the address in the read failure
    vm.expectRevert(abi.encodeWithSelector(IDeploy.Deploy_ReadFailed.selector, 'ecdsaMethod', address(_method)));
    _script.checkDeployment(_good, _pins);
  }

  /// checkDeployment reverts naming passkeyMethod and the method's address in the read failure when
  /// the passkey method's name call reverts, so the failure names the place that holds the bad
  /// contract.
  function test_RevertWhen_ThePasskeyMethodNameCallReverts() external {
    DeployMockMethod _method = new DeployMockMethod();
    _method.revertName();
    _good.passkeyMethod = IPolicyMethod(address(_method));
    // it should revert
    // it should name passkeyMethod and the address in the read failure
    vm.expectRevert(abi.encodeWithSelector(IDeploy.Deploy_ReadFailed.selector, 'passkeyMethod', address(_method)));
    _script.checkDeployment(_good, _pins);
  }

  /// checkDeployment reverts with the read failure when the wallet method answers name with no
  /// bytes, an answer that encodes no string. The method is a look-alike of the kit's wallet method
  /// that passes every other call on to it, so the role and interface checks pass and the name read
  /// is the one that fails.
  function test_RevertWhen_AMethodNameAnswerIsEmpty() external {
    DeployMockLookAlike _lookAlike = new DeployMockLookAlike(address(_good.ecdsaMethod));
    _lookAlike.setAnswer(IPolicyMethod.name.selector, '');
    _good.ecdsaMethod = IPolicyMethod(address(_lookAlike));
    // it should revert
    // it should name ecdsaMethod and the address in the read failure
    vm.expectRevert(abi.encodeWithSelector(IDeploy.Deploy_ReadFailed.selector, 'ecdsaMethod', address(_lookAlike)));
    _script.checkDeployment(_good, _pins);
  }

  /// checkDeployment reverts with the read failure when the wallet method answers name with one word,
  /// the offset of a string whose length word is missing, an answer that is not the encoding of a
  /// string. The method is a look-alike of the kit's wallet method that passes every other call on.
  function test_RevertWhen_AMethodNameAnswerIsNotAString() external {
    DeployMockLookAlike _lookAlike = new DeployMockLookAlike(address(_good.ecdsaMethod));
    _lookAlike.setAnswer(IPolicyMethod.name.selector, abi.encode(uint256(32)));
    _good.ecdsaMethod = IPolicyMethod(address(_lookAlike));
    // it should revert
    // it should name ecdsaMethod and the address in the read failure
    vm.expectRevert(abi.encodeWithSelector(IDeploy.Deploy_ReadFailed.selector, 'ecdsaMethod', address(_lookAlike)));
    _script.checkDeployment(_good, _pins);
  }

  /// checkDeployment reverts naming recoveryAction and the address in the read failure when the
  /// action's place holds the kit's manager, which has none of the action's views, as when a
  /// broadcast lands out of order and each contract sits at another's address.
  function test_RevertWhen_TheActionPlaceHoldsTheManager() external {
    address _manager = address(_good.manager);
    _good.action = IAmbireRecoveryAction(_manager);
    // it should revert
    // it should name recoveryAction and the address in the read failure
    vm.expectRevert(abi.encodeWithSelector(IDeploy.Deploy_ReadFailed.selector, 'recoveryAction', _manager));
    _script.checkDeployment(_good, _pins);
  }

  /// checkDeployment reverts naming the wallet method when it declares a key admin.
  /// `_seed` is hashed into that admin's address.
  function test_RevertWhen_TheWalletMethodDeclaresARole(uint256 _seed) external {
    DeployMockMethod _method = new DeployMockMethod();
    _method.setAdmin(_freshAddress('admin', _seed));
    _good.ecdsaMethod = IPolicyMethod(address(_method));
    // it should revert
    // it should name the wallet method
    vm.expectRevert(abi.encodeWithSelector(IDeploy.Deploy_MethodDeclaresRoles.selector, address(_method)));
    _script.checkDeployment(_good, _pins);
  }

  /// checkDeployment reverts naming the passkey method when it declares a pause holder.
  /// `_seed` is hashed into that holder's address.
  function test_RevertWhen_ThePasskeyMethodDeclaresARole(uint256 _seed) external {
    DeployMockMethod _method = new DeployMockMethod();
    _method.setPauseHolder(_freshAddress('pauseHolder', _seed));
    _good.passkeyMethod = IPolicyMethod(address(_method));
    // it should revert
    // it should name the passkey method
    vm.expectRevert(abi.encodeWithSelector(IDeploy.Deploy_MethodDeclaresRoles.selector, address(_method)));
    _script.checkDeployment(_good, _pins);
  }

  /// checkDeployment reverts naming the manager and its id when the manager denies IPolicyManager.
  function test_RevertWhen_AContractDeniesItsInterface() external {
    DeployMockMethod _manager = new DeployMockMethod();
    _manager.refuse(type(IPolicyManager).interfaceId);
    // The action must name the manager under test, or the manager check fires first.
    _good.manager = IPolicyManager(address(_manager));
    _good.action = _newAction(address(_manager), _implementation);
    // it should revert
    // it should raise the missing interface
    vm.expectRevert(
      abi.encodeWithSelector(
        IDeploy.Deploy_InterfaceNotSupported.selector, address(_manager), type(IPolicyManager).interfaceId
      )
    );
    _script.checkDeployment(_good, _pins);
  }

  /// checkDeployment raises the manager mismatch when the action names another manager and its
  /// kit slot also collides, since the action check runs before the kit slot check.
  function test_RevertWhen_TheManagerIsWrongAndTheKitSlotCollides(uint256 _seed) external {
    address _otherManager = _freshAddress('otherManager', _seed);
    _good.action = IAmbireRecoveryAction(address(new DeployMockAction(_otherManager, _implementation, true)));
    // it should revert
    // it should raise the manager mismatch first
    vm.expectRevert(
      abi.encodeWithSelector(IDeploy.Deploy_ActionManagerMismatch.selector, address(_good.manager), _otherManager)
    );
    _script.checkDeployment(_good, _pins);
  }

  /// checkDeployment raises the kit slot collision when the slot collides and the wallet method
  /// also declares a role, since the kit slot check runs before the method role check.
  function test_RevertWhen_TheKitSlotCollidesAndAMethodDeclaresARole(uint256 _seed) external {
    DeployMockAction _action = new DeployMockAction(address(_good.manager), _implementation, true);
    _good.action = IAmbireRecoveryAction(address(_action));
    DeployMockMethod _method = new DeployMockMethod();
    _method.setAdmin(_freshAddress('admin', _seed));
    _good.ecdsaMethod = IPolicyMethod(address(_method));
    // it should revert
    // it should raise the kit slot collision first
    vm.expectRevert(
      abi.encodeWithSelector(
        IDeploy.Deploy_KitSlotCollides.selector, address(_action), _ambireHelperSlot(address(_action))
      )
    );
    _script.checkDeployment(_good, _pins);
  }

  /// checkDeployment raises the method role error when the wallet method declares a role and
  /// also denies IPolicyMethod, since the method role check runs before the interface check.
  function test_RevertWhen_AMethodDeclaresARoleAndDeniesItsInterface(uint256 _seed) external {
    DeployMockMethod _method = new DeployMockMethod();
    _method.setAdmin(_freshAddress('admin', _seed));
    _method.refuse(type(IPolicyMethod).interfaceId);
    _good.ecdsaMethod = IPolicyMethod(address(_method));
    // it should revert
    // it should raise the method role error first
    vm.expectRevert(abi.encodeWithSelector(IDeploy.Deploy_MethodDeclaresRoles.selector, address(_method)));
    _script.checkDeployment(_good, _pins);
  }

  /// checkDeployment raises the interface error when the wallet method denies IPolicyMethod and
  /// also answers another name, since the name check is the last one and runs after the
  /// interface check.
  function test_RevertWhen_AMethodDeniesItsInterfaceAndAnswersAnotherName() external {
    DeployMockMethod _method = new DeployMockMethod();
    _method.setName('method-passkey');
    _method.refuse(type(IPolicyMethod).interfaceId);
    _good.ecdsaMethod = IPolicyMethod(address(_method));
    // it should revert
    // it should raise the missing interface first
    vm.expectRevert(
      abi.encodeWithSelector(
        IDeploy.Deploy_InterfaceNotSupported.selector, address(_method), type(IPolicyMethod).interfaceId
      )
    );
    _script.checkDeployment(_good, _pins);
  }
}
