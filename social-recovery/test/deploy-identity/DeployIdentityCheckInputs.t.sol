// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {IDeployIdentity} from 'script/IDeployIdentity.sol';
import {DeployIdentityTestBase} from 'test/utils/DeployIdentityTestBase.sol';

/// @notice The check over the operator's inputs. Each identity method's Safe becomes that method's pause holder and
///         key admin, so a deployment without it would hand those roles to nobody or to whoever runs the script. The
///         script never substitutes the operator's key or any other address for it. A chain that deploys no Aadhaar
///         method has no use for the Aadhaar method's Safe, so the check leaves that Safe alone there.
contract DeployIdentityCheckInputsTest is DeployIdentityTestBase {
  string internal constant _ZKPASSPORT_SAFE_VARIABLE = 'ZKPASSPORT_METHOD_SAFE';
  string internal constant _AADHAAR_SAFE_VARIABLE = 'AADHAAR_METHOD_SAFE';

  /// checkInputs passes, on a chain that deploys both methods, for two different nonzero Safes, whatever addresses
  /// they are. `_seed` builds each Safe and the three role words as addresses hashed from it with distinct labels.
  function test_WhenBothSafesAreNonzero(uint256 _seed) external view {
    // it should pass
    _script.checkInputs(_seeded(_seed), true);
  }

  /// checkInputs passes, on a chain that deploys both methods, when one nonzero address is given as both Safes,
  /// since the two methods may share one multisig. `_seed` builds the inputs as in the test above.
  function test_WhenBothMethodsShareOneSafe(uint256 _seed) external view {
    IDeployIdentity.Inputs memory _operator = _seeded(_seed);
    _operator.aadhaarMethodSafe = _operator.zkPassportMethodSafe;
    // it should pass
    _script.checkInputs(_operator, true);
  }

  /// checkInputs reverts naming ZKPASSPORT_METHOD_SAFE when the zkPassport method's Safe is zero, so a
  /// deployment never makes nobody the pause holder and key admin of a method holders will trust.
  function test_RevertWhen_TheZkPassportMethodSafeIsZero() external {
    IDeployIdentity.Inputs memory _operator = _inputs;
    _operator.zkPassportMethodSafe = address(0);
    // it should revert
    // it should raise the zero safe error naming ZKPASSPORT_METHOD_SAFE
    _expectZeroSafe(_ZKPASSPORT_SAFE_VARIABLE);
    _script.checkInputs(_operator, true);
  }

  /// checkInputs reverts naming AADHAAR_METHOD_SAFE when the chain deploys the Aadhaar method and its Safe is
  /// zero, so the Aadhaar method never goes out with nobody in its roles while the zkPassport method's Safe is set.
  function test_RevertWhen_TheAadhaarMethodSafeIsZeroOnAChainThatShipsAadhaar() external {
    IDeployIdentity.Inputs memory _operator = _inputs;
    _operator.aadhaarMethodSafe = address(0);
    // it should revert
    // it should raise the zero safe error naming AADHAAR_METHOD_SAFE
    _expectZeroSafe(_AADHAAR_SAFE_VARIABLE);
    _script.checkInputs(_operator, true);
  }

  /// checkInputs reverts naming ZKPASSPORT_METHOD_SAFE when both Safes are zero, since it checks the zkPassport
  /// method's Safe first, so the operator always learns of the same missing Safe first.
  function test_RevertWhen_BothSafesAreZero() external {
    IDeployIdentity.Inputs memory _operator = _inputs;
    _operator.zkPassportMethodSafe = address(0);
    _operator.aadhaarMethodSafe = address(0);
    // it should revert
    // it should raise the zero safe error naming ZKPASSPORT_METHOD_SAFE
    _expectZeroSafe(_ZKPASSPORT_SAFE_VARIABLE);
    _script.checkInputs(_operator, true);
  }

  /// checkInputs passes on a chain that deploys no Aadhaar method when the Aadhaar method's Safe is zero, the
  /// value such a chain's inputs and record hold, since no method there takes that Safe's roles.
  function test_WhenTheChainShipsNoAadhaarAndItsSafeIsZero() external view {
    IDeployIdentity.Inputs memory _operator = _inputs;
    _operator.aadhaarMethodSafe = address(0);
    // it should pass
    _script.checkInputs(_operator, false);
  }

  /// checkInputs passes on a chain that deploys no Aadhaar method whatever the Aadhaar method's Safe holds, since
  /// it does not check a Safe no method there takes. `_seed` builds the inputs as in the first test.
  function test_WhenTheChainShipsNoAadhaarAndItsSafeIsNonzero(uint256 _seed) external view {
    // it should pass
    _script.checkInputs(_seeded(_seed), false);
  }

  /// checkInputs still reverts naming ZKPASSPORT_METHOD_SAFE on a chain that deploys no Aadhaar method, since
  /// every chain deploys the zkPassport method.
  function test_RevertWhen_TheChainShipsNoAadhaarAndTheZkPassportMethodSafeIsZero() external {
    IDeployIdentity.Inputs memory _operator = _inputs;
    _operator.zkPassportMethodSafe = address(0);
    _operator.aadhaarMethodSafe = address(0);
    // it should revert
    // it should raise the zero safe error naming ZKPASSPORT_METHOD_SAFE
    _expectZeroSafe(_ZKPASSPORT_SAFE_VARIABLE);
    _script.checkInputs(_operator, false);
  }

  /// @notice Inputs whose two Safes and three role words are addresses hashed from `_seed` with distinct labels.
  function _seeded(uint256 _seed) internal pure returns (IDeployIdentity.Inputs memory _operator) {
    _operator = IDeployIdentity.Inputs({
      zkPassportMethodSafe: _freshAddress('anyZkPassportMethodSafe', _seed),
      aadhaarMethodSafe: _freshAddress('anyAadhaarMethodSafe', _seed),
      rootAdmin: _freshAddress('anyRootAdmin', _seed),
      rootGuardian: _freshAddress('anyRootGuardian', _seed),
      subVerifierAdmin: _freshAddress('anySubVerifierAdmin', _seed)
    });
  }

  /// @notice Expects the next call to revert with the zero Safe error naming `_name`.
  function _expectZeroSafe(string memory _name) internal {
    vm.expectRevert(abi.encodeWithSelector(IDeployIdentity.DeployIdentity_ZeroSafe.selector, _name));
  }
}
