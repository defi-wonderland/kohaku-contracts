// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {IPolicyMethod} from 'interfaces/IPolicyMethod.sol';
import {IDeploy} from 'script/IDeploy.sol';
import {DeployMockMalformedAnswer} from 'test/mocks/DeployMockMalformedAnswer.sol';
import {DeployMockMethod} from 'test/mocks/DeployMockMethod.sol';
import {DeployTestBase} from 'test/utils/DeployTestBase.sol';

/// @notice The fourth assertion: the wallet and passkey methods declare no party, the zero address
///         as admin, pending admin, pause holder and pending pause holder, and an empty key list.
///         A holder whose rule uses only these two methods is promised that nobody can re-key or
///         stop it, so a deployed method declaring any role breaks that promise. Each crafted bad
///         method below declares exactly one field, so a failure names the field the check skips.
contract DeployCheckMethodRolesTest is DeployTestBase {
  DeployMockMethod internal _method;

  function setUp() public override {
    super.setUp();
    _method = new DeployMockMethod();
  }

  function _expectDeclaresRoles() internal {
    _expectDeclaresRoles(address(_method));
  }

  function _expectDeclaresRoles(address _target) internal {
    vm.expectRevert(abi.encodeWithSelector(IDeploy.Deploy_MethodDeclaresRoles.selector, _target));
  }

  /// @notice Requires the mock to declare exactly one party or key, so the revert that follows comes
  ///         from that one field and not from the mock answering something else.
  function _assertDeclaresOneField() internal view {
    (address _admin, address _pendingAdmin, bytes32[] memory _keys, address _pauseHolder, address _pendingPauseHolder) =
      _method.trustedParties();
    uint256 _declared = (_admin == address(0) ? 0 : 1) + (_pendingAdmin == address(0) ? 0 : 1) + _keys.length
      + (_pauseHolder == address(0) ? 0 : 1) + (_pendingPauseHolder == address(0) ? 0 : 1);
    assertEq(_declared, 1, 'the mock declares one field');
  }

  /// @notice A method that answers trustedParties with `_answer`.
  function _malformed(DeployMockMalformedAnswer.Answer _answer) internal returns (IPolicyMethod _target) {
    _target = IPolicyMethod(address(new DeployMockMalformedAnswer(_answer)));
  }

  /// checkMethodRoles passes for the kit's wallet method, which declares no party.
  function test_WhenTheWalletMethodIsChecked() external view {
    // it should pass
    _script.checkMethodRoles(_good.ecdsaMethod);
  }

  /// checkMethodRoles passes for the kit's passkey method, which declares no party.
  function test_WhenThePasskeyMethodIsChecked() external view {
    // it should pass
    _script.checkMethodRoles(_good.passkeyMethod);
  }

  /// checkMethodRoles reverts naming the method when it declares any key admin. `_seed` is hashed
  /// into the admin address, one no fixture uses.
  function test_RevertWhen_TheMethodDeclaresAnAdmin(uint256 _seed) external {
    _method.setAdmin(_freshAddress('admin', _seed));
    _assertDeclaresOneField();
    // it should revert
    // it should name the method in the error
    _expectDeclaresRoles();
    _script.checkMethodRoles(IPolicyMethod(address(_method)));
  }

  /// checkMethodRoles reverts naming the method when it declares any pending key admin, an
  /// address one acceptance away from re-keying the method. `_seed` is hashed into that address.
  function test_RevertWhen_TheMethodDeclaresAPendingAdmin(uint256 _seed) external {
    _method.setPendingAdmin(_freshAddress('pendingAdmin', _seed));
    _assertDeclaresOneField();
    // it should revert
    // it should name the method in the error
    _expectDeclaresRoles();
    _script.checkMethodRoles(IPolicyMethod(address(_method)));
  }

  /// checkMethodRoles reverts naming the method when it declares any one trusted key.
  /// A method that trusts a key depends on whoever holds it.
  function test_RevertWhen_TheMethodDeclaresATrustedKey(bytes32 _key) external {
    _method.addTrustedKey(_key);
    _assertDeclaresOneField();
    // it should revert
    // it should name the method in the error
    _expectDeclaresRoles();
    _script.checkMethodRoles(IPolicyMethod(address(_method)));
  }

  /// checkMethodRoles reverts when the key list holds one zero word. The list must be empty,
  /// so a check that looks at key values rather than at the list's length fails here.
  function test_RevertWhen_TheMethodDeclaresAZeroKey() external {
    _method.addTrustedKey(bytes32(0));
    _assertDeclaresOneField();
    // it should revert
    // it should name the method in the error
    _expectDeclaresRoles();
    _script.checkMethodRoles(IPolicyMethod(address(_method)));
  }

  /// checkMethodRoles reverts naming the method when it declares any pause holder, an address
  /// able to stop the method. `_seed` is hashed into that address.
  function test_RevertWhen_TheMethodDeclaresAPauseHolder(uint256 _seed) external {
    _method.setPauseHolder(_freshAddress('pauseHolder', _seed));
    _assertDeclaresOneField();
    // it should revert
    // it should name the method in the error
    _expectDeclaresRoles();
    _script.checkMethodRoles(IPolicyMethod(address(_method)));
  }

  /// checkMethodRoles reverts naming the method when it declares any pending pause holder, an
  /// address one acceptance away from stopping the method. `_seed` is hashed into that address.
  function test_RevertWhen_TheMethodDeclaresAPendingPauseHolder(uint256 _seed) external {
    _method.setPendingPauseHolder(_freshAddress('pendingPauseHolder', _seed));
    _assertDeclaresOneField();
    // it should revert
    // it should name the method in the error
    _expectDeclaresRoles();
    _script.checkMethodRoles(IPolicyMethod(address(_method)));
  }

  /// checkMethodRoles reverts naming the address when it holds no code. `_seed` is hashed into
  /// that address, one no fixture uses. A call to it succeeds and answers nothing, which declares
  /// no party only by accident.
  function test_RevertWhen_TheMethodHasNoCode(uint256 _seed) external {
    address _target = _freshAddress('methodWithoutCode', _seed);
    // it should revert
    // it should name the method in the error
    _expectDeclaresRoles(_target);
    _script.checkMethodRoles(IPolicyMethod(_target));
  }

  /// checkMethodRoles reverts naming the method when its trustedParties reverts, since a method
  /// that will not say who it trusts cannot promise it trusts nobody.
  function test_RevertWhen_TheMethodsAnswerReverts() external {
    IPolicyMethod _target = _malformed(DeployMockMalformedAnswer.Answer.Revert);
    // it should revert
    // it should name the method in the error
    _expectDeclaresRoles(address(_target));
    _script.checkMethodRoles(_target);
  }

  /// checkMethodRoles reverts naming the method when trustedParties answers no bytes, the answer
  /// of a contract whose fallback swallows unknown calls.
  function test_RevertWhen_TheMethodAnswersNothing() external {
    IPolicyMethod _target = _malformed(DeployMockMalformedAnswer.Answer.Empty);
    // it should revert
    // it should name the method in the error
    _expectDeclaresRoles(address(_target));
    _script.checkMethodRoles(_target);
  }

  /// checkMethodRoles reverts naming the method when trustedParties answers one word, too short to
  /// hold the five values of a declaration.
  function test_RevertWhen_TheMethodAnswersTooShort() external {
    IPolicyMethod _target = _malformed(DeployMockMalformedAnswer.Answer.WordTwo);
    // it should revert
    // it should name the method in the error
    _expectDeclaresRoles(address(_target));
    _script.checkMethodRoles(_target);
  }

  /// checkMethodRoles reverts naming the method when trustedParties reverts with the word 1 as its
  /// revert data. Revert data is not an answer, whatever bytes it carries.
  function test_RevertWhen_TheMethodRevertsWithTheWordOne() external {
    IPolicyMethod _target = _malformed(DeployMockMalformedAnswer.Answer.RevertWithWordOne);
    // it should revert
    // it should name the method in the error
    _expectDeclaresRoles(address(_target));
    _script.checkMethodRoles(_target);
  }

  /// checkMethodRoles reverts naming the method when trustedParties reverts with revert data equal
  /// to the encoding of an empty declaration. A check that decoded the bytes without looking at the
  /// call's success would read that revert as a method declaring nobody.
  function test_RevertWhen_TheMethodRevertsWithAnEmptyDeclaration() external {
    IPolicyMethod _target = _malformed(DeployMockMalformedAnswer.Answer.RevertWithEmptyDeclaration);
    // it should revert
    // it should name the method in the error
    _expectDeclaresRoles(address(_target));
    _script.checkMethodRoles(_target);
  }
}
