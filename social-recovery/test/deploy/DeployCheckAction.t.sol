// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {IDeploy} from 'script/IDeploy.sol';
import {IAmbireRecoveryAction} from 'contracts/actions/ambire/IAmbireRecoveryAction.sol';
import {PolicyManager} from 'contracts/manager/PolicyManager.sol';
import {DeployMockLookAlike} from 'test/mocks/DeployMockLookAlike.sol';
import {DeployMockRawAnswer} from 'test/mocks/DeployMockRawAnswer.sol';
import {DeployTestBase} from 'test/utils/DeployTestBase.sol';

/// @notice The second assertion: the action's MANAGER is the manager this run deployed and its
///         AMBIRE_IMPLEMENTATION is the pin. The action's constructor accepts any address for both,
///         and a wrong one is invisible until a recovery fails: the action would read attempts from
///         a manager nobody commits to, or refuse every account the factory builds.
contract DeployCheckActionTest is DeployTestBase {
  /// checkAction passes for the kit's action deployed with the manager and the pin it is asked about.
  function test_WhenTheActionNamesTheManagerAndThePin() external view {
    // it should pass
    _script.checkAction(_good.action, address(_good.manager), _implementation);
  }

  /// checkAction reverts naming both managers when the action was deployed with another manager.
  /// `_seed` is hashed into an address no fixture uses, the manager the action wrongly names.
  function test_RevertWhen_TheActionWasDeployedWithAnotherManager(uint256 _seed) external {
    address _otherManager = _freshAddress('otherManager', _seed);
    IAmbireRecoveryAction _action = _newAction(_otherManager, _implementation);
    // it should revert
    // it should name the expected and the actual manager
    vm.expectRevert(
      abi.encodeWithSelector(IDeploy.Deploy_ActionManagerMismatch.selector, address(_good.manager), _otherManager)
    );
    _script.checkAction(_action, address(_good.manager), _implementation);
  }

  /// checkAction reverts when the action names another deployed manager, a wrong contract that
  /// has code, which no check inside the action's constructor could tell from the right one.
  function test_RevertWhen_TheActionNamesAnotherDeployedManager() external {
    address _otherManager = address(new PolicyManager());
    IAmbireRecoveryAction _action = _newAction(_otherManager, _implementation);
    // it should revert
    // it should name the expected and the actual manager
    vm.expectRevert(
      abi.encodeWithSelector(IDeploy.Deploy_ActionManagerMismatch.selector, address(_good.manager), _otherManager)
    );
    _script.checkAction(_action, address(_good.manager), _implementation);
  }

  /// checkAction reverts when the action names the zero address as its manager.
  /// The constructor accepts zero, so only the deployment catches it.
  function test_RevertWhen_TheActionNamesTheZeroManager() external {
    IAmbireRecoveryAction _action = _newAction(address(0), _implementation);
    // it should revert
    // it should name the expected and the actual manager
    vm.expectRevert(
      abi.encodeWithSelector(IDeploy.Deploy_ActionManagerMismatch.selector, address(_good.manager), address(0))
    );
    _script.checkAction(_action, address(_good.manager), _implementation);
  }

  /// checkAction reverts naming both implementations when the action was deployed with another
  /// implementation. `_seed` is hashed into an address no fixture uses, which the test gives code,
  /// so the wrong implementation is a contract that has code.
  function test_RevertWhen_TheActionWasDeployedWithAnotherImplementation(uint256 _seed) external {
    address _otherImplementation = _freshAddress('otherImplementation', _seed);
    vm.etch(_otherImplementation, hex'00');
    IAmbireRecoveryAction _action = _newAction(address(_good.manager), _otherImplementation);
    // it should revert
    // it should name the expected and the actual implementation
    vm.expectRevert(
      abi.encodeWithSelector(
        IDeploy.Deploy_ActionImplementationMismatch.selector, _implementation, _otherImplementation
      )
    );
    _script.checkAction(_action, address(_good.manager), _implementation);
  }

  /// checkAction reverts when the action names the zero address as its implementation.
  /// The constructor accepts zero, so only the deployment catches it.
  function test_RevertWhen_TheActionNamesTheZeroImplementation() external {
    IAmbireRecoveryAction _action = _newAction(address(_good.manager), address(0));
    // it should revert
    // it should name the expected and the actual implementation
    vm.expectRevert(
      abi.encodeWithSelector(IDeploy.Deploy_ActionImplementationMismatch.selector, _implementation, address(0))
    );
    _script.checkAction(_action, address(_good.manager), _implementation);
  }

  /// checkAction reverts when the action is right but the pin it is checked against differs.
  /// `_seed` is hashed into an address no fixture uses, the pin the action was not deployed with.
  function test_RevertWhen_ThePinDiffersFromTheActionsImplementation(uint256 _seed) external {
    address _otherPin = _freshAddress('otherPin', _seed);
    // it should revert
    // it should name the pin as expected and the action's implementation as actual
    vm.expectRevert(
      abi.encodeWithSelector(IDeploy.Deploy_ActionImplementationMismatch.selector, _otherPin, _implementation)
    );
    _script.checkAction(_good.action, address(_good.manager), _otherPin);
  }

  /// checkAction reverts naming recoveryAction and the address when the action's address holds the
  /// kit's manager, a contract with no MANAGER view, as when a broadcast lands out of order. A
  /// failed read must name what was read where, not surface as a bare revert or a mismatch with a
  /// made-up value.
  function test_RevertWhen_TheActionAddressHoldsAContractWithoutTheActionsViews() external {
    address _manager = address(_good.manager);
    // it should revert
    // it should name recoveryAction and the address in the read failure
    vm.expectRevert(abi.encodeWithSelector(IDeploy.Deploy_ReadFailed.selector, 'recoveryAction', _manager));
    _script.checkAction(IAmbireRecoveryAction(_manager), _manager, _implementation);
  }

  /// checkAction reverts with the read failure when the action's address answers every call with no
  /// bytes, an answer that encodes no address, so an empty answer never reads as the zero address.
  function test_RevertWhen_TheActionAnswersNoBytes() external {
    address _action = address(new DeployMockRawAnswer(''));
    // it should revert
    // it should name recoveryAction and the address in the read failure
    vm.expectRevert(abi.encodeWithSelector(IDeploy.Deploy_ReadFailed.selector, 'recoveryAction', _action));
    _script.checkAction(IAmbireRecoveryAction(_action), address(_good.manager), _implementation);
  }

  /// checkAction reverts with the read failure when the action answers MANAGER with a word whose low
  /// twenty bytes are the right manager but whose upper twelve bytes are not all zero, so a dirty word
  /// is never cut down to an address that passes. `_upper` is bounded to a nonzero value of those
  /// twelve bytes.
  function test_RevertWhen_TheActionAnswersAWordWithBitsAboveAnAddress(uint256 _upper) external {
    _upper = bound(_upper, 1, type(uint96).max);
    bytes32 _word = bytes32((_upper << 160) | uint256(uint160(address(_good.manager))));
    address _action = address(new DeployMockRawAnswer(abi.encode(_word)));
    // it should revert
    // it should name recoveryAction and the address in the read failure
    vm.expectRevert(abi.encodeWithSelector(IDeploy.Deploy_ReadFailed.selector, 'recoveryAction', _action));
    _script.checkAction(IAmbireRecoveryAction(_action), address(_good.manager), _implementation);
  }

  /// checkAction reverts with the read failure when the action answers MANAGER rightly but answers
  /// AMBIRE_IMPLEMENTATION with no bytes. The action is a look-alike of the kit's good action that
  /// passes every other call on to it, so the implementation read is the only one that fails.
  function test_RevertWhen_TheImplementationReadFails() external {
    DeployMockLookAlike _lookAlike = new DeployMockLookAlike(address(_good.action));
    _lookAlike.setAnswer(IAmbireRecoveryAction.AMBIRE_IMPLEMENTATION.selector, '');
    // it should revert
    // it should name recoveryAction and the address in the read failure
    vm.expectRevert(abi.encodeWithSelector(IDeploy.Deploy_ReadFailed.selector, 'recoveryAction', address(_lookAlike)));
    _script.checkAction(IAmbireRecoveryAction(address(_lookAlike)), address(_good.manager), _implementation);
  }
}
