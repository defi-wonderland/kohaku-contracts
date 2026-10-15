// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {IPolicyMethod} from 'interfaces/IPolicyMethod.sol';
import {IPolicyMethodAdmin} from 'interfaces/IPolicyMethodAdmin.sol';
import {IPolicyMethodPause} from 'interfaces/IPolicyMethodPause.sol';
import {IDeployIdentity} from 'script/IDeployIdentity.sol';
import {DeployIdentityMockMethod} from 'test/mocks/DeployIdentityMockMethod.sol';
import {DeployIdentityTestBase} from 'test/utils/DeployIdentityTestBase.sol';

/// @notice The fifth assertion, over what was deployed: each identity method declares its own Safe as its key admin
///         and pause holder with no handover open and exactly the keys it was given, confirms its three
///         interfaces through ERC-165, and the Aadhaar method calls the pinned verifier. A holder reads these
///         answers before trusting a method, so a deployment that answers differently is caught before anyone
///         adopts it. Each bad deployment departs from the good one in one place.
contract DeployIdentityCheckDeploymentTest is DeployIdentityTestBase {
  /// checkDeployment passes for the kit's two methods, each built with its own Safe in both roles, the table's
  /// words and the table's Aadhaar key and verifier.
  function test_WhenBothMethodsMatchTheTableAndTheirSafes() external view {
    // it should pass
    _script.checkDeployment(_good, _pins, _inputs);
  }

  /// checkDeployment passes for a chain that ships no Aadhaar method, whose deployment and Aadhaar Safe are the
  /// zero address there, the mainnet shape.
  function test_WhenTheChainShipsNoAadhaarMethod() external view {
    IDeployIdentity.Inputs memory _operator = _inputs;
    _operator.aadhaarMethodSafe = address(0);
    IDeployIdentity.Pins memory _table = _pins;
    _table.shipsAadhaar = false;
    _table.aadhaarVerifier = address(0);
    _table.aadhaarVerifierCodehash = bytes32(0);
    _table.aadhaarKey = bytes32(0);
    IDeployIdentity.Deployment memory _deployment = _good;
    _deployment.aadhaarMethod = IPolicyMethod(address(0));
    // it should pass
    _script.checkDeployment(_deployment, _table, _operator);
  }

  /// checkDeployment passes when one address is both methods' Safe and both methods declare it in both roles,
  /// since the two Safes may be one multisig.
  function test_WhenBothMethodsShareOneSafe() external {
    IDeployIdentity.Inputs memory _operator = _inputs;
    _operator.aadhaarMethodSafe = _operator.zkPassportMethodSafe;
    address _shared = _operator.zkPassportMethodSafe;
    IDeployIdentity.Deployment memory _deployment = IDeployIdentity.Deployment({
      zkPassportMethod: _newZkPassportMethod(_shared, _shared, _words(_pins, _operator)),
      aadhaarMethod: _newAadhaarMethod(_shared, _shared, _pins.aadhaarKey, _pins.aadhaarVerifier)
    });
    // it should pass
    _script.checkDeployment(_deployment, _pins, _operator);
  }

  /*///////////////////////////////////////////////////////////////
                    THE ZKPASSPORT METHOD'S PARTIES
  ///////////////////////////////////////////////////////////////*/

  /// checkDeployment reverts naming the zkPassport method when it declares a key admin other than its Safe.
  function test_RevertWhen_TheZkPassportMethodDeclaresAnotherAdmin() external {
    IDeployIdentity.Deployment memory _deployment = _good;
    _deployment.zkPassportMethod =
      _newZkPassportMethod(_inputs.zkPassportMethodSafe, _freshAddress('otherAdmin', 0), _words(_pins, _inputs));
    // it should revert
    // it should name the zkPassport method
    _expectRolesMismatch(_deployment, address(_deployment.zkPassportMethod));
  }

  /// checkDeployment reverts naming the zkPassport method when it declares a pause holder other than its Safe.
  function test_RevertWhen_TheZkPassportMethodDeclaresAnotherPauseHolder() external {
    IDeployIdentity.Deployment memory _deployment = _good;
    _deployment.zkPassportMethod =
      _newZkPassportMethod(_freshAddress('otherPauseHolder', 0), _inputs.zkPassportMethodSafe, _words(_pins, _inputs));
    // it should revert
    // it should name the zkPassport method
    _expectRolesMismatch(_deployment, address(_deployment.zkPassportMethod));
  }

  /// checkDeployment reverts naming the zkPassport method when it declares the Aadhaar method's Safe in both roles,
  /// so a deployment that hands one method's roles to the other method's party is caught before anyone adopts it.
  function test_RevertWhen_TheZkPassportMethodDeclaresTheAadhaarMethodSafe() external {
    IDeployIdentity.Deployment memory _deployment = _good;
    _deployment.zkPassportMethod =
      _newZkPassportMethod(_inputs.aadhaarMethodSafe, _inputs.aadhaarMethodSafe, _words(_pins, _inputs));
    // it should revert
    // it should name the zkPassport method
    _expectRolesMismatch(_deployment, address(_deployment.zkPassportMethod));
  }

  /// checkDeployment reverts naming the zkPassport method when a key admin handover is open, since the offered
  /// address is one acceptance away from setting the method's keys.
  function test_RevertWhen_TheZkPassportMethodDeclaresAPendingAdmin() external {
    vm.prank(_inputs.zkPassportMethodSafe);
    IPolicyMethodAdmin(address(_good.zkPassportMethod)).transferAdmin(_freshAddress('pendingAdmin', 0));
    // it should revert
    // it should name the zkPassport method
    _expectRolesMismatch(_good, address(_good.zkPassportMethod));
  }

  /// checkDeployment reverts naming the zkPassport method when a pause holder handover is open.
  function test_RevertWhen_TheZkPassportMethodDeclaresAPendingPauseHolder() external {
    vm.prank(_inputs.zkPassportMethodSafe);
    IDeployIdentityOwnable2Step(address(_good.zkPassportMethod))
      .transferOwnership(_freshAddress('pendingPauseHolder', 0));
    // it should revert
    // it should name the zkPassport method
    _expectRolesMismatch(_good, address(_good.zkPassportMethod));
  }

  /// checkDeployment reverts naming the zkPassport method when its words differ from the ones the table and the
  /// inputs give, here in the root admin's word.
  function test_RevertWhen_TheZkPassportMethodDeclaresOtherKeys() external {
    IDeployIdentity.Inputs memory _otherInputs = _inputs;
    _otherInputs.rootAdmin = _freshAddress('otherRootAdmin', 0);
    IDeployIdentity.Deployment memory _deployment = _good;
    _deployment.zkPassportMethod =
      _newZkPassportMethod(_inputs.zkPassportMethodSafe, _inputs.zkPassportMethodSafe, _words(_pins, _otherInputs));
    // it should revert
    // it should name the zkPassport method
    _expectRolesMismatch(_deployment, address(_deployment.zkPassportMethod));
  }

  /// checkDeployment reverts naming the zkPassport method when it declares a key list of another length, here
  /// the eight words and a ninth.
  function test_RevertWhen_TheZkPassportMethodDeclaresALongerKeyList() external {
    bytes32[] memory _eight = _words(_pins, _inputs);
    bytes32[] memory _nine = new bytes32[](_KEY_COUNT + 1);
    for (uint256 _i; _i < _KEY_COUNT; ++_i) {
      _nine[_i] = _eight[_i];
    }
    _nine[_KEY_COUNT] = _eight[_KEY_COUNT - 1];
    IDeployIdentity.Deployment memory _deployment = _good;
    _deployment.zkPassportMethod = IPolicyMethod(
      address(
        new DeployIdentityMockMethod(_inputs.zkPassportMethodSafe, _inputs.zkPassportMethodSafe, _nine, address(0))
      )
    );
    // it should revert
    // it should name the zkPassport method
    _expectRolesMismatch(_deployment, address(_deployment.zkPassportMethod));
  }

  /*///////////////////////////////////////////////////////////////
                      THE AADHAAR METHOD'S PARTIES
  ///////////////////////////////////////////////////////////////*/

  /// checkDeployment reverts naming the Aadhaar method when it declares a key admin other than its Safe.
  function test_RevertWhen_TheAadhaarMethodDeclaresAnotherAdmin() external {
    IDeployIdentity.Deployment memory _deployment = _good;
    _deployment.aadhaarMethod = _newAadhaarMethod(
      _inputs.aadhaarMethodSafe, _freshAddress('otherAdmin', 0), _pins.aadhaarKey, _pins.aadhaarVerifier
    );
    // it should revert
    // it should name the Aadhaar method
    _expectRolesMismatch(_deployment, address(_deployment.aadhaarMethod));
  }

  /// checkDeployment reverts naming the Aadhaar method when it declares a pause holder other than its Safe.
  function test_RevertWhen_TheAadhaarMethodDeclaresAnotherPauseHolder() external {
    IDeployIdentity.Deployment memory _deployment = _good;
    _deployment.aadhaarMethod = _newAadhaarMethod(
      _freshAddress('otherPauseHolder', 0), _inputs.aadhaarMethodSafe, _pins.aadhaarKey, _pins.aadhaarVerifier
    );
    // it should revert
    // it should name the Aadhaar method
    _expectRolesMismatch(_deployment, address(_deployment.aadhaarMethod));
  }

  /// checkDeployment reverts naming the Aadhaar method when it declares the zkPassport method's Safe in both
  /// roles, so a deployment that hands one method's roles to the other method's party is caught.
  function test_RevertWhen_TheAadhaarMethodDeclaresTheZkPassportMethodSafe() external {
    IDeployIdentity.Deployment memory _deployment = _good;
    _deployment.aadhaarMethod = _newAadhaarMethod(
      _inputs.zkPassportMethodSafe, _inputs.zkPassportMethodSafe, _pins.aadhaarKey, _pins.aadhaarVerifier
    );
    // it should revert
    // it should name the Aadhaar method
    _expectRolesMismatch(_deployment, address(_deployment.aadhaarMethod));
  }

  /// checkDeployment reverts naming the Aadhaar method when a key admin handover is open.
  function test_RevertWhen_TheAadhaarMethodDeclaresAPendingAdmin() external {
    vm.prank(_inputs.aadhaarMethodSafe);
    IPolicyMethodAdmin(address(_good.aadhaarMethod)).transferAdmin(_freshAddress('pendingAdmin', 0));
    // it should revert
    // it should name the Aadhaar method
    _expectRolesMismatch(_good, address(_good.aadhaarMethod));
  }

  /// checkDeployment reverts naming the Aadhaar method when a pause holder handover is open.
  function test_RevertWhen_TheAadhaarMethodDeclaresAPendingPauseHolder() external {
    vm.prank(_inputs.aadhaarMethodSafe);
    IDeployIdentityOwnable2Step(address(_good.aadhaarMethod)).transferOwnership(_freshAddress('pendingPauseHolder', 0));
    // it should revert
    // it should name the Aadhaar method
    _expectRolesMismatch(_good, address(_good.aadhaarMethod));
  }

  /// checkDeployment reverts naming the Aadhaar method when its trusted key is not the table's key, here the
  /// published test key in place of UIDAI's.
  function test_RevertWhen_TheAadhaarMethodDeclaresAnotherKey() external {
    IDeployIdentity.Deployment memory _deployment = _good;
    _deployment.aadhaarMethod =
      _newAadhaarMethod(_inputs.aadhaarMethodSafe, _inputs.aadhaarMethodSafe, _AADHAAR_TEST_KEY, _pins.aadhaarVerifier);
    // it should revert
    // it should name the Aadhaar method
    _expectRolesMismatch(_deployment, address(_deployment.aadhaarMethod));
  }

  /// checkDeployment reverts naming the Aadhaar method when it declares two keys, the table's key twice.
  function test_RevertWhen_TheAadhaarMethodDeclaresALongerKeyList() external {
    bytes32[] memory _two = new bytes32[](2);
    _two[0] = _pins.aadhaarKey;
    _two[1] = _pins.aadhaarKey;
    IDeployIdentity.Deployment memory _deployment = _good;
    _deployment.aadhaarMethod = IPolicyMethod(
      address(
        new DeployIdentityMockMethod(_inputs.aadhaarMethodSafe, _inputs.aadhaarMethodSafe, _two, _pins.aadhaarVerifier)
      )
    );
    // it should revert
    // it should name the Aadhaar method
    _expectRolesMismatch(_deployment, address(_deployment.aadhaarMethod));
  }

  /*///////////////////////////////////////////////////////////////
                            ERC-165
  ///////////////////////////////////////////////////////////////*/

  /// checkDeployment reverts naming the zkPassport method and IPolicyMethod's id when the method denies it.
  function test_RevertWhen_TheZkPassportMethodDeniesIPolicyMethod() external {
    // it should revert
    // it should name the method and the id
    _expectZkPassportDenial(type(IPolicyMethod).interfaceId, DeployIdentityMockMethod.Answer.False);
  }

  /// checkDeployment reverts naming the zkPassport method and IPolicyMethodPause's id when the method denies it.
  function test_RevertWhen_TheZkPassportMethodDeniesIPolicyMethodPause() external {
    // it should revert
    // it should name the method and the id
    _expectZkPassportDenial(type(IPolicyMethodPause).interfaceId, DeployIdentityMockMethod.Answer.False);
  }

  /// checkDeployment reverts naming the zkPassport method and IPolicyMethodAdmin's id when the method denies it.
  function test_RevertWhen_TheZkPassportMethodDeniesIPolicyMethodAdmin() external {
    // it should revert
    // it should name the method and the id
    _expectZkPassportDenial(type(IPolicyMethodAdmin).interfaceId, DeployIdentityMockMethod.Answer.False);
  }

  /// checkDeployment reverts naming the Aadhaar method and IPolicyMethod's id when the method denies it.
  function test_RevertWhen_TheAadhaarMethodDeniesIPolicyMethod() external {
    // it should revert
    // it should name the method and the id
    _expectAadhaarDenial(type(IPolicyMethod).interfaceId);
  }

  /// checkDeployment reverts naming the Aadhaar method and IPolicyMethodPause's id when the method denies it.
  function test_RevertWhen_TheAadhaarMethodDeniesIPolicyMethodPause() external {
    // it should revert
    // it should name the method and the id
    _expectAadhaarDenial(type(IPolicyMethodPause).interfaceId);
  }

  /// checkDeployment reverts naming the Aadhaar method and IPolicyMethodAdmin's id when the method denies it.
  function test_RevertWhen_TheAadhaarMethodDeniesIPolicyMethodAdmin() external {
    // it should revert
    // it should name the method and the id
    _expectAadhaarDenial(type(IPolicyMethodAdmin).interfaceId);
  }

  /// checkDeployment reverts when the method's ERC-165 answer reverts, since a revert confirms nothing.
  function test_RevertWhen_TheInterfaceAnswerReverts() external {
    // it should revert
    // it should name the method and the id
    _expectZkPassportDenial(type(IPolicyMethod).interfaceId, DeployIdentityMockMethod.Answer.Revert);
  }

  /// checkDeployment reverts when the method's ERC-165 answer is empty, the answer of code with no such function.
  function test_RevertWhen_TheInterfaceAnswerIsEmpty() external {
    // it should revert
    // it should name the method and the id
    _expectZkPassportDenial(type(IPolicyMethod).interfaceId, DeployIdentityMockMethod.Answer.Empty);
  }

  /// checkDeployment reverts when the method answers the word 2, a word that is no ABI-encoded bool.
  function test_RevertWhen_TheInterfaceAnswerIsTheWordTwo() external {
    // it should revert
    // it should name the method and the id
    _expectZkPassportDenial(type(IPolicyMethod).interfaceId, DeployIdentityMockMethod.Answer.WordTwo);
  }

  /// checkDeployment reverts when the method answers true followed by a second word, since only a clean 32-byte
  /// true confirms an interface.
  function test_RevertWhen_TheInterfaceAnswerCarriesExtraBytes() external {
    // it should revert
    // it should name the method and the id
    _expectZkPassportDenial(type(IPolicyMethod).interfaceId, DeployIdentityMockMethod.Answer.TrueThenMore);
  }

  /*///////////////////////////////////////////////////////////////
                         THE AADHAAR VERIFIER
  ///////////////////////////////////////////////////////////////*/

  /// checkDeployment reverts naming the pin and the verifier the Aadhaar method calls when they differ. The
  /// method stores its verifier as given, so a method calling another verifier is caught here.
  function test_RevertWhen_TheAadhaarMethodCallsAnotherVerifier() external {
    address _otherVerifier = _codeAt('otherAadhaarVerifier');
    IDeployIdentity.Deployment memory _deployment = _good;
    _deployment.aadhaarMethod =
      _newAadhaarMethod(_inputs.aadhaarMethodSafe, _inputs.aadhaarMethodSafe, _pins.aadhaarKey, _otherVerifier);
    // it should revert
    // it should name the pin and the method's verifier
    vm.expectRevert(
      abi.encodeWithSelector(
        IDeployIdentity.DeployIdentity_AadhaarVerifierMismatch.selector, _pins.aadhaarVerifier, _otherVerifier
      )
    );
    _script.checkDeployment(_deployment, _pins, _inputs);
  }

  /*///////////////////////////////////////////////////////////////
                              HELPERS
  ///////////////////////////////////////////////////////////////*/

  function _expectRolesMismatch(IDeployIdentity.Deployment memory _deployment, address _method) internal {
    vm.expectRevert(abi.encodeWithSelector(IDeployIdentity.DeployIdentity_MethodRolesMismatch.selector, _method));
    _script.checkDeployment(_deployment, _pins, _inputs);
  }

  /// @notice Puts in the zkPassport method's place a mock that declares exactly the right parties and gives
  ///         `_answer` for `_interfaceId`, then expects the interface error naming the mock and the id.
  function _expectZkPassportDenial(bytes4 _interfaceId, DeployIdentityMockMethod.Answer _answer) internal {
    DeployIdentityMockMethod _mock = new DeployIdentityMockMethod(
      _inputs.zkPassportMethodSafe, _inputs.zkPassportMethodSafe, _words(_pins, _inputs), address(0)
    );
    _mock.refuse(_interfaceId, _answer);
    IDeployIdentity.Deployment memory _deployment = _good;
    _deployment.zkPassportMethod = IPolicyMethod(address(_mock));
    vm.expectRevert(
      abi.encodeWithSelector(
        IDeployIdentity.DeployIdentity_InterfaceNotSupported.selector, address(_mock), _interfaceId
      )
    );
    _script.checkDeployment(_deployment, _pins, _inputs);
  }

  /// @notice Puts in the Aadhaar method's place a mock that declares exactly the right parties and verifier and
  ///         answers false for `_interfaceId`, then expects the interface error naming the mock and the id.
  function _expectAadhaarDenial(bytes4 _interfaceId) internal {
    DeployIdentityMockMethod _mock = new DeployIdentityMockMethod(
      _inputs.aadhaarMethodSafe, _inputs.aadhaarMethodSafe, _oneKey(_pins.aadhaarKey), _pins.aadhaarVerifier
    );
    _mock.refuse(_interfaceId, DeployIdentityMockMethod.Answer.False);
    IDeployIdentity.Deployment memory _deployment = _good;
    _deployment.aadhaarMethod = IPolicyMethod(address(_mock));
    vm.expectRevert(
      abi.encodeWithSelector(
        IDeployIdentity.DeployIdentity_InterfaceNotSupported.selector, address(_mock), _interfaceId
      )
    );
    _script.checkDeployment(_deployment, _pins, _inputs);
  }
}

/// @notice The ownership handover the pause holder's role takes, which the identity methods inherit from
///         OpenZeppelin's Ownable2Step.
interface IDeployIdentityOwnable2Step {
  /// @notice Offers the pause holder's role to `_newOwner`, who holds it only once it accepts.
  /// @param _newOwner The address offered the role.
  function transferOwnership(address _newOwner) external;
}
