// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {IDeployIdentity} from 'script/IDeployIdentity.sol';
import {DeployIdentityTestBase} from 'test/utils/DeployIdentityTestBase.sol';

/// @notice inputsFromEnv, the wrapper that reads the operator's inputs from the environment: each identity method's
///         Safe and the three zkPassport role words. The environment is shared by every test in the run and forge
///         cannot unset a variable, so this is the only test that sets these variables, it sets values no other test
///         uses, and it leaves them empty at the end.
contract DeployIdentityInputsFromEnvTest is DeployIdentityTestBase {
  string internal constant _ZKPASSPORT_SAFE_VARIABLE = 'ZKPASSPORT_METHOD_SAFE';
  string internal constant _AADHAAR_SAFE_VARIABLE = 'AADHAAR_METHOD_SAFE';
  string internal constant _ROOT_ADMIN_VARIABLE = 'ZKPASSPORT_ROOT_ADMIN';
  string internal constant _ROOT_GUARDIAN_VARIABLE = 'ZKPASSPORT_ROOT_GUARDIAN';
  string internal constant _SUB_VERIFIER_ADMIN_VARIABLE = 'ZKPASSPORT_SUBVERIFIER_ADMIN';

  /// Each variable a chain needs is required: absent or empty, it makes inputsFromEnv revert naming it, so a
  /// forgotten role word never reads as zero and matches zkPassport's root guardian, zero today, and a forgotten
  /// Safe never leaves a method's roles to nobody. A zero Safe is refused by name. On a chain that deploys no
  /// Aadhaar method, AADHAAR_METHOD_SAFE is never read, whether absent, malformed or set, and the Aadhaar Safe comes
  /// back as the zero address, the value the record holds for that chain.
  function test_WhenTheInputsArriveOneByOne() external {
    // Forge cannot unset a variable, so an absent one is testable only before it is first set: the test walks the
    // variables in the order inputsFromEnv documents and runs only when none of the five is set yet.
    string[5] memory _all = _variables();
    for (uint256 _i; _i < 5; ++_i) {
      if (vm.envExists(_all[_i])) {
        vm.skip(true);
        return;
      }
    }
    string[4] memory _names =
      [_ZKPASSPORT_SAFE_VARIABLE, _ROOT_ADMIN_VARIABLE, _ROOT_GUARDIAN_VARIABLE, _SUB_VERIFIER_ADMIN_VARIABLE];
    address[4] memory _values = [
      _freshAddress('envZkPassportMethodSafe', 0),
      _freshAddress('envRootAdmin', 0),
      _freshAddress('envRootGuardian', 0),
      _freshAddress('envSubVerifierAdmin', 0)
    ];
    address _aadhaarSafe = _freshAddress('envAadhaarMethodSafe', 0);

    _walkTheRequiredVariables(_names, _values);
    _walkTheAadhaarSafe(_values);
    _walkTheZeroSafes(_values);

    vm.setEnv(_AADHAAR_SAFE_VARIABLE, vm.toString(_aadhaarSafe));
    IDeployIdentity.Inputs memory _withAadhaar = _script.inputsFromEnv(true);
    IDeployIdentity.Inputs memory _withoutAadhaar = _script.inputsFromEnv(false);
    vm.setEnv(_AADHAAR_SAFE_VARIABLE, vm.toString(_values[0]));
    IDeployIdentity.Inputs memory _shared = _script.inputsFromEnv(true);
    _restore();
    // it should answer every address once all are set
    _assertRead(_withAadhaar, _values, _aadhaarSafe);
    // it should answer the zero address for the Aadhaar safe on a chain that ships no Aadhaar even when it is set
    _assertRead(_withoutAadhaar, _values, address(0));
    // it should accept one address as both safes
    _assertRead(_shared, _values, _values[0]);
  }

  /// @notice Walks the four variables every chain needs while AADHAAR_METHOD_SAFE is absent: each one absent, then
  ///         empty, names itself, then takes its value. A chain without the Aadhaar method then reads all four and
  ///         leaves the Aadhaar Safe zero.
  function _walkTheRequiredVariables(string[4] memory _names, address[4] memory _values) internal {
    for (uint256 _i; _i < 4; ++_i) {
      // it should name the variable while it is absent
      _expectMissing(_names[_i], false);
      // it should name the variable when it is empty
      vm.setEnv(_names[_i], '');
      _expectMissing(_names[_i], false);
      vm.setEnv(_names[_i], vm.toString(_values[_i]));
    }
    // it should leave the Aadhaar safe zero without reading it on a chain that ships no Aadhaar
    _assertRead(_script.inputsFromEnv(false), _values, address(0));
  }

  /// @notice Walks AADHAAR_METHOD_SAFE, required on a chain with the Aadhaar method and never read on one without.
  function _walkTheAadhaarSafe(address[4] memory _values) internal {
    // it should name the Aadhaar safe variable while it is absent on a chain that ships Aadhaar
    _expectMissing(_AADHAAR_SAFE_VARIABLE, true);
    // it should name the Aadhaar safe variable when it is empty on a chain that ships Aadhaar
    vm.setEnv(_AADHAAR_SAFE_VARIABLE, '');
    _expectMissing(_AADHAAR_SAFE_VARIABLE, true);
    // it should not read a malformed Aadhaar safe on a chain that ships no Aadhaar
    vm.setEnv(_AADHAAR_SAFE_VARIABLE, 'not an address');
    _assertRead(_script.inputsFromEnv(false), _values, address(0));
  }

  /// @notice Walks a zero in each Safe variable: each is refused by name where it is read, the zkPassport one first.
  function _walkTheZeroSafes(address[4] memory _values) internal {
    // it should raise the zero safe error naming the variable that holds a zero safe
    vm.setEnv(_AADHAAR_SAFE_VARIABLE, vm.toString(address(0)));
    _expectZeroSafe(_AADHAAR_SAFE_VARIABLE, true);
    _assertRead(_script.inputsFromEnv(false), _values, address(0));
    vm.setEnv(_ZKPASSPORT_SAFE_VARIABLE, vm.toString(address(0)));
    _expectZeroSafe(_ZKPASSPORT_SAFE_VARIABLE, true);
    _expectZeroSafe(_ZKPASSPORT_SAFE_VARIABLE, false);
    vm.setEnv(_ZKPASSPORT_SAFE_VARIABLE, vm.toString(_values[0]));
  }

  /// @notice Requires inputsFromEnv to revert with the missing input error naming `_name`.
  function _expectMissing(string memory _name, bool _shipsAadhaar) internal {
    vm.expectRevert(abi.encodeWithSelector(IDeployIdentity.DeployIdentity_MissingInput.selector, _name));
    _script.inputsFromEnv(_shipsAadhaar);
  }

  /// @notice Requires inputsFromEnv to revert with the zero Safe error naming `_name`.
  function _expectZeroSafe(string memory _name, bool _shipsAadhaar) internal {
    vm.expectRevert(abi.encodeWithSelector(IDeployIdentity.DeployIdentity_ZeroSafe.selector, _name));
    _script.inputsFromEnv(_shipsAadhaar);
  }

  /// @notice Asserts that `_read` holds the zkPassport method's Safe and the three role words of `_values`, in the
  ///         order of `_variables` without the Aadhaar Safe, and `_aadhaarSafe` as the Aadhaar method's Safe.
  function _assertRead(IDeployIdentity.Inputs memory _read, address[4] memory _values, address _aadhaarSafe)
    internal
    pure
  {
    assertEq(_read.zkPassportMethodSafe, _values[0], 'zkPassport method safe');
    assertEq(_read.aadhaarMethodSafe, _aadhaarSafe, 'Aadhaar method safe');
    assertEq(_read.rootAdmin, _values[1], 'root admin');
    assertEq(_read.rootGuardian, _values[2], 'root guardian');
    assertEq(_read.subVerifierAdmin, _values[3], 'sub-verifier admin');
  }

  /// @notice The five variable names, in the order inputsFromEnv documents.
  function _variables() internal pure returns (string[5] memory _names) {
    _names = [
      _ZKPASSPORT_SAFE_VARIABLE,
      _AADHAAR_SAFE_VARIABLE,
      _ROOT_ADMIN_VARIABLE,
      _ROOT_GUARDIAN_VARIABLE,
      _SUB_VERIFIER_ADMIN_VARIABLE
    ];
  }

  /// @notice Leaves each variable empty, the closest forge comes to unsetting it. The test runs only when none of
  ///         the five was set before it.
  function _restore() internal {
    string[5] memory _names = _variables();
    for (uint256 _i; _i < 5; ++_i) {
      vm.setEnv(_names[_i], '');
    }
  }
}
