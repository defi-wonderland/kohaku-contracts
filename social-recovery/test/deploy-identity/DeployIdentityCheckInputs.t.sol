// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {IDeployIdentity} from 'script/IDeployIdentity.sol';
import {DeployIdentityTestBase} from 'test/utils/DeployIdentityTestBase.sol';

/// @notice The check over the operator's inputs. The Safe becomes the pause holder and the key admin of both
///         identity methods, so a deployment without it would hand those roles to nobody or to whoever runs the
///         script. The script never substitutes the operator's key or any other address for it.
contract DeployIdentityCheckInputsTest is DeployIdentityTestBase {
  /// checkInputs passes for a nonzero Safe, whatever address it is. `_seed` builds the Safe and the three role
  /// words as addresses hashed from it with distinct labels.
  function test_WhenTheSafeIsNonzero(uint256 _seed) external view {
    IDeployIdentity.Inputs memory _operator = IDeployIdentity.Inputs({
      safe: _freshAddress('anySafe', _seed),
      rootAdmin: _freshAddress('anyRootAdmin', _seed),
      rootGuardian: _freshAddress('anyRootGuardian', _seed),
      subVerifierAdmin: _freshAddress('anySubVerifierAdmin', _seed)
    });
    // it should pass
    _script.checkInputs(_operator);
  }

  /// checkInputs reverts when the Safe is the zero address, so a deployment never makes nobody the pause holder
  /// and key admin of a method holders will trust.
  function test_RevertWhen_TheSafeIsZero() external {
    IDeployIdentity.Inputs memory _operator = _inputs;
    _operator.safe = address(0);
    // it should revert
    // it should raise the zero safe error
    vm.expectRevert(IDeployIdentity.DeployIdentity_ZeroSafe.selector);
    _script.checkInputs(_operator);
  }
}
