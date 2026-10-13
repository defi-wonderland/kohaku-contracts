// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {IDeployIdentity} from 'script/IDeployIdentity.sol';
import {DeployIdentityTestBase} from 'test/utils/DeployIdentityTestBase.sol';

/// @notice inputsFromEnv, the wrapper that reads the operator's four inputs from the environment. The environment
///         is shared by every test in the run and forge cannot unset a variable, so this is the only test that
///         sets these variables, it sets values no other test uses, and it leaves them empty at the end.
contract DeployIdentityInputsFromEnvTest is DeployIdentityTestBase {
  string internal constant _SAFE_VARIABLE = 'IDENTITY_SAFE';
  string internal constant _ROOT_ADMIN_VARIABLE = 'ZKPASSPORT_ROOT_ADMIN';
  string internal constant _ROOT_GUARDIAN_VARIABLE = 'ZKPASSPORT_ROOT_GUARDIAN';
  string internal constant _SUB_VERIFIER_ADMIN_VARIABLE = 'ZKPASSPORT_SUBVERIFIER_ADMIN';

  /// Each of the four variables is required: absent or empty, it makes inputsFromEnv revert naming it, so a
  /// forgotten role word never reads as zero and matches zkPassport's root guardian, zero today. A zero Safe is
  /// refused, and four real addresses come back in their fields.
  function test_WhenTheInputsArriveOneByOne() external {
    // Forge cannot unset a variable, so an absent one is testable only before it is first set: the test walks the
    // variables in the order inputsFromEnv documents and runs only when none of the four is set yet.
    string[4] memory _names = _variables();
    for (uint256 _i; _i < 4; ++_i) {
      if (vm.envExists(_names[_i])) {
        vm.skip(true);
        return;
      }
    }
    address[4] memory _values = [
      _freshAddress('envSafe', 0),
      _freshAddress('envRootAdmin', 0),
      _freshAddress('envRootGuardian', 0),
      _freshAddress('envSubVerifierAdmin', 0)
    ];

    for (uint256 _i; _i < 4; ++_i) {
      // it should name the variable while it is absent
      _expectMissing(_names[_i]);
      // it should name the variable when it is empty
      vm.setEnv(_names[_i], '');
      _expectMissing(_names[_i]);
      vm.setEnv(_names[_i], vm.toString(_values[_i]));
    }

    // it should raise the zero safe error when the safe is the zero address
    vm.setEnv(_SAFE_VARIABLE, vm.toString(address(0)));
    vm.expectRevert(IDeployIdentity.DeployIdentity_ZeroSafe.selector);
    _script.inputsFromEnv();

    vm.setEnv(_SAFE_VARIABLE, vm.toString(_values[0]));
    IDeployIdentity.Inputs memory _read = _script.inputsFromEnv();
    _restore();
    // it should answer the four addresses once all four are set
    assertEq(_read.safe, _values[0], 'safe');
    assertEq(_read.rootAdmin, _values[1], 'root admin');
    assertEq(_read.rootGuardian, _values[2], 'root guardian');
    assertEq(_read.subVerifierAdmin, _values[3], 'sub-verifier admin');
  }

  /// @notice Requires inputsFromEnv to revert with the missing input error naming `_name`.
  function _expectMissing(string memory _name) internal {
    vm.expectRevert(abi.encodeWithSelector(IDeployIdentity.DeployIdentity_MissingInput.selector, _name));
    _script.inputsFromEnv();
  }

  /// @notice The four variable names, in the order inputsFromEnv documents.
  function _variables() internal pure returns (string[4] memory _names) {
    _names = [_SAFE_VARIABLE, _ROOT_ADMIN_VARIABLE, _ROOT_GUARDIAN_VARIABLE, _SUB_VERIFIER_ADMIN_VARIABLE];
  }

  /// @notice Leaves each variable empty, the closest forge comes to unsetting it. The test runs only when none of
  ///         the four was set before it.
  function _restore() internal {
    string[4] memory _names = _variables();
    for (uint256 _i; _i < 4; ++_i) {
      vm.setEnv(_names[_i], '');
    }
  }
}
