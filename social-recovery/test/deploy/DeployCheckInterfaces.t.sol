// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {IPolicyAction} from 'interfaces/IPolicyAction.sol';
import {IPolicyManager} from 'interfaces/IPolicyManager.sol';
import {IPolicyMethod} from 'interfaces/IPolicyMethod.sol';
import {IRecoveryAction} from 'interfaces/IRecoveryAction.sol';
import {IDeploy} from 'script/IDeploy.sol';
import {IAmbireRecoveryAction} from 'contracts/actions/ambire/IAmbireRecoveryAction.sol';
import {DeployMockAction} from 'test/mocks/DeployMockAction.sol';
import {DeployMockMalformedAnswer} from 'test/mocks/DeployMockMalformedAnswer.sol';
import {DeployMockMethod} from 'test/mocks/DeployMockMethod.sol';
import {DeployTestBase} from 'test/utils/DeployTestBase.sol';

/// @notice The fifth assertion: each deployed contract answers ERC-165 for its interfaces, the
///         manager for IPolicyManager, both methods for IPolicyMethod, and the action for
///         IPolicyAction, IRecoveryAction and IAmbireRecoveryAction. The setup screen and the SDK
///         ask these ids to tell what an address is, so a deployed contract that denies one is
///         shown to a holder as something it is not. Each crafted bad deployment replaces one
///         contract with a mock that answers true for every id except the one the test refuses.
contract DeployCheckInterfacesTest is DeployTestBase {
  function _expectNotSupported(address _target, bytes4 _interfaceId) internal {
    vm.expectRevert(abi.encodeWithSelector(IDeploy.Deploy_InterfaceNotSupported.selector, _target, _interfaceId));
  }

  /// @notice Requires `_target` to answer false for `_refused` and true for every other id the
  ///         check asks of any contract, so the revert that follows comes from that one id.
  function _assertRefusesOnly(address _target, bytes4 _refused) internal view {
    bytes4[5] memory _ids = [
      type(IPolicyManager).interfaceId,
      type(IPolicyMethod).interfaceId,
      type(IPolicyAction).interfaceId,
      type(IRecoveryAction).interfaceId,
      type(IAmbireRecoveryAction).interfaceId
    ];
    for (uint256 _i; _i < _ids.length; ++_i) {
      bool _answer = IPolicyMethod(_target).supportsInterface(_ids[_i]);
      assertEq(_answer, _ids[_i] != _refused, 'the mock refuses only the one id');
    }
  }

  /// @notice A mock action that names the good manager and pin and refuses `_interfaceId`.
  function _actionRefusing(bytes4 _interfaceId) internal returns (DeployMockAction _action) {
    _action = new DeployMockAction(address(_good.manager), _implementation, false);
    _action.refuse(_interfaceId);
  }

  /// @notice A mock method that declares no party and refuses `_interfaceId`.
  function _methodRefusing(bytes4 _interfaceId) internal returns (DeployMockMethod _method) {
    _method = new DeployMockMethod();
    _method.refuse(_interfaceId);
  }

  /// checkInterfaces passes for the kit's real manager, methods and action.
  function test_WhenEveryContractAnswersItsInterfaces() external view {
    // it should pass
    _script.checkInterfaces(_good);
  }

  /// checkInterfaces reverts naming the manager and the IPolicyManager id when the manager
  /// answers false for that id.
  function test_RevertWhen_TheManagerDeniesIPolicyManager() external {
    bytes4 _id = type(IPolicyManager).interfaceId;
    _good.manager = IPolicyManager(address(_methodRefusing(_id)));
    _assertRefusesOnly(address(_good.manager), _id);
    // it should revert
    // it should name the manager and the id
    _expectNotSupported(address(_good.manager), _id);
    _script.checkInterfaces(_good);
  }

  /// checkInterfaces reverts naming the wallet method and the IPolicyMethod id when the wallet
  /// method answers false for that id.
  function test_RevertWhen_TheWalletMethodDeniesIPolicyMethod() external {
    bytes4 _id = type(IPolicyMethod).interfaceId;
    _good.ecdsaMethod = IPolicyMethod(address(_methodRefusing(_id)));
    _assertRefusesOnly(address(_good.ecdsaMethod), _id);
    // it should revert
    // it should name the wallet method and the id
    _expectNotSupported(address(_good.ecdsaMethod), _id);
    _script.checkInterfaces(_good);
  }

  /// checkInterfaces reverts naming the passkey method and the IPolicyMethod id when the passkey
  /// method answers false for that id.
  function test_RevertWhen_ThePasskeyMethodDeniesIPolicyMethod() external {
    bytes4 _id = type(IPolicyMethod).interfaceId;
    _good.passkeyMethod = IPolicyMethod(address(_methodRefusing(_id)));
    _assertRefusesOnly(address(_good.passkeyMethod), _id);
    // it should revert
    // it should name the passkey method and the id
    _expectNotSupported(address(_good.passkeyMethod), _id);
    _script.checkInterfaces(_good);
  }

  /// checkInterfaces reverts naming the action and the IPolicyAction id when the action answers
  /// false for that id alone.
  function test_RevertWhen_TheActionDeniesIPolicyAction() external {
    bytes4 _id = type(IPolicyAction).interfaceId;
    _good.action = IAmbireRecoveryAction(address(_actionRefusing(_id)));
    _assertRefusesOnly(address(_good.action), _id);
    // it should revert
    // it should name the action and the id
    _expectNotSupported(address(_good.action), _id);
    _script.checkInterfaces(_good);
  }

  /// checkInterfaces reverts naming the action and the IRecoveryAction id when the action answers
  /// false for that id alone.
  function test_RevertWhen_TheActionDeniesIRecoveryAction() external {
    bytes4 _id = type(IRecoveryAction).interfaceId;
    _good.action = IAmbireRecoveryAction(address(_actionRefusing(_id)));
    _assertRefusesOnly(address(_good.action), _id);
    // it should revert
    // it should name the action and the id
    _expectNotSupported(address(_good.action), _id);
    _script.checkInterfaces(_good);
  }

  /// checkInterfaces reverts naming the action and the IAmbireRecoveryAction id when the action
  /// answers false for that id alone.
  function test_RevertWhen_TheActionDeniesIAmbireRecoveryAction() external {
    bytes4 _id = type(IAmbireRecoveryAction).interfaceId;
    _good.action = IAmbireRecoveryAction(address(_actionRefusing(_id)));
    _assertRefusesOnly(address(_good.action), _id);
    // it should revert
    // it should name the action and the id
    _expectNotSupported(address(_good.action), _id);
    _script.checkInterfaces(_good);
  }

  /// checkInterfaces reverts naming the manager and its id when the manager's supportsInterface
  /// reverts. A revert is not an answer, so the check must not let it through as a pass.
  function test_RevertWhen_TheManagersAnswerReverts() external {
    _good.manager = IPolicyManager(address(new DeployMockMalformedAnswer(DeployMockMalformedAnswer.Answer.Revert)));
    // it should revert
    // it should name the manager and the id
    _expectNotSupported(address(_good.manager), type(IPolicyManager).interfaceId);
    _script.checkInterfaces(_good);
  }

  /// checkInterfaces reverts naming the manager and its id when the manager answers with no
  /// bytes, the answer of a contract whose fallback swallows unknown calls.
  function test_RevertWhen_TheManagerAnswersNothing() external {
    _good.manager = IPolicyManager(address(new DeployMockMalformedAnswer(DeployMockMalformedAnswer.Answer.Empty)));
    // it should revert
    // it should name the manager and the id
    _expectNotSupported(address(_good.manager), type(IPolicyManager).interfaceId);
    _script.checkInterfaces(_good);
  }

  /// checkInterfaces reverts naming the manager and its id when the manager answers the word 2,
  /// which is no ABI encoding of a bool.
  function test_RevertWhen_TheManagerAnswersAWordThatIsNoBool() external {
    _good.manager = IPolicyManager(address(new DeployMockMalformedAnswer(DeployMockMalformedAnswer.Answer.WordTwo)));
    // it should revert
    // it should name the manager and the id
    _expectNotSupported(address(_good.manager), type(IPolicyManager).interfaceId);
    _script.checkInterfaces(_good);
  }

  /// checkInterfaces reverts naming the passkey method and its id when the address holds no code.
  /// `_seed` is hashed into that address, one no fixture uses. A call to it succeeds and answers
  /// nothing, which must not read as support.
  function test_RevertWhen_AMethodHasNoCode(uint256 _seed) external {
    _good.passkeyMethod = IPolicyMethod(_freshAddress('methodWithoutCode', _seed));
    // it should revert
    // it should name the method and the id
    _expectNotSupported(address(_good.passkeyMethod), type(IPolicyMethod).interfaceId);
    _script.checkInterfaces(_good);
  }

  /// checkInterfaces reverts naming the manager and its id when the manager's supportsInterface
  /// reverts with the word 1 as revert data. Revert data is not an answer, so a check reading the
  /// returned bytes without the call's success must not read it as true.
  function test_RevertWhen_TheManagerRevertsWithTheWordOne() external {
    _good.manager =
      IPolicyManager(address(new DeployMockMalformedAnswer(DeployMockMalformedAnswer.Answer.RevertWithWordOne)));
    // it should revert
    // it should name the manager and the id
    _expectNotSupported(address(_good.manager), type(IPolicyManager).interfaceId);
    _script.checkInterfaces(_good);
  }

  /// checkInterfaces reverts naming the manager and its id when the manager answers the word 1
  /// followed by a second word. An ABI bool is exactly one word, so a check that decodes only the
  /// first word would take an answer from something that is not a plain supportsInterface.
  function test_RevertWhen_TheManagerAnswersTrueWithExtraBytes() external {
    _good.manager =
      IPolicyManager(address(new DeployMockMalformedAnswer(DeployMockMalformedAnswer.Answer.WordOneThenMore)));
    // it should revert
    // it should name the manager and the id
    _expectNotSupported(address(_good.manager), type(IPolicyManager).interfaceId);
    _script.checkInterfaces(_good);
  }
}
