// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {IPolicyMethodAdmin} from 'interfaces/IPolicyMethodAdmin.sol';
import {AadhaarMethod} from 'contracts/methods/aadhaar/AadhaarMethod.sol';
import {MethodAadhaarTestBase} from 'test/utils/MethodAadhaarTestBase.sol';

/// @notice What the Aadhaar method's constructor sets up. It names the verifier the method calls, the pause holder,
///         the key admin, the one issuer key, the name and the version.
contract AadhaarMethodConstructorTest is MethodAadhaarTestBase {
  /// A valid deployment sets the pause holder, the key admin, the one issuer key, the verifier, the name and the
  /// version. It starts unpaused with no transfer open. It announces the admin and the key, so anyone can read the
  /// whole key history from events and check the method before adopting it.
  function test_WhenEveryArgumentIsValid() external {
    address _expected = vm.computeCreateAddress(address(this), vm.getNonce(address(this)));
    // it should emit AdminTransferred from zero to the key admin, then TrustedKeysUpdated from no keys to the key.
    vm.expectEmit(_expected);
    emit IPolicyMethodAdmin.AdminTransferred(address(0), _admin);
    vm.expectEmit(_expected);
    emit IPolicyMethodAdmin.TrustedKeysUpdated(new bytes32[](0), _aadhaarOneKey(_issuerKey));
    AadhaarMethod _deployed = _aadhaarDeploy(_owner, _admin, _aadhaarOneKey(_issuerKey), address(_verifier));
    assertEq(address(_deployed), _expected, 'deployed address');

    (
      address _declaredAdmin,
      address _pendingAdmin,
      bytes32[] memory _keys,
      address _pauseHolder,
      address _pendingPauseHolder
    ) = _deployed.trustedParties();
    // it should make the first address the pause holder.
    assertEq(_deployed.owner(), _owner, 'owner');
    assertEq(_pauseHolder, _owner, 'pause holder');
    // it should make the second address the key admin.
    assertEq(_declaredAdmin, _admin, 'key admin');
    // it should store the issuer key as the one trusted word.
    assertEq(_keys.length, 1, 'one word');
    assertEq(_keys[0], _issuerKey, 'the issuer key');
    // it should leave both pending holders at zero.
    assertEq(_pendingAdmin, address(0), 'pending admin');
    assertEq(_pendingPauseHolder, address(0), 'pending pause holder');
    // it should leave the method unpaused.
    assertFalse(_deployed.paused(), 'paused');
    // it should record the verifier.
    assertEq(_deployed.verifier(), address(_verifier), 'verifier');
    // it should set the name and the version.
    assertEq(_deployed.name(), 'method-aadhaar', 'name');
    assertEq(_deployed.version(), '1.0.0', 'version');
  }
}
