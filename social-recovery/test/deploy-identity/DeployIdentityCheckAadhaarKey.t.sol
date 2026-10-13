// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {IDeployIdentity} from 'script/IDeployIdentity.sol';
import {DeployIdentityTestBase} from 'test/utils/DeployIdentityTestBase.sol';

/// @notice The fourth assertion: the Aadhaar method never deploys with the Anon Aadhaar stack's published test
///         key as its trusted key. Anyone holding that published private key can sign any identity, so a method
///         trusting it would accept a forged proof for every holder who adopts it. Nor does it deploy with one of
///         UIDAI's two expired production keys, under which no current Aadhaar QR code is signed.
contract DeployIdentityCheckAadhaarKeyTest is DeployIdentityTestBase {
  /// checkAadhaarKey passes for the hash of UIDAI's current key, the key Sepolia's table carries.
  function test_WhenTheKeyIsUidaisKey() external view {
    // it should pass
    _script.checkAadhaarKey(_UIDAI_KEY);
  }

  /// checkAadhaarKey passes for any key other than the test key and the two expired keys, since the assertion
  /// refuses three values and leaves key rotations to the key admin. `_seed` builds the key as a hash of a label
  /// and the seed, moved off a refused key in the case where the hash would equal one.
  function test_WhenTheKeyIsAnyOtherKey(uint256 _seed) external view {
    bytes32 _key = keccak256(abi.encode('aadhaarKey', _seed));
    if (_key == _AADHAAR_TEST_KEY || _key == _AADHAAR_EXPIRED_2021_KEY || _key == _AADHAAR_EXPIRED_2024_KEY) {
      _key = keccak256(abi.encode(_key));
    }
    // it should pass
    _script.checkAadhaarKey(_key);
  }

  /// checkAadhaarKey reverts carrying the key when it is the published test key.
  function test_RevertWhen_TheKeyIsThePublishedTestKey() external {
    // it should revert
    // it should carry the key in the error
    vm.expectRevert(abi.encodeWithSelector(IDeployIdentity.DeployIdentity_AadhaarTestKey.selector, _AADHAAR_TEST_KEY));
    _script.checkAadhaarKey(_AADHAAR_TEST_KEY);
  }

  /// checkAadhaarKey reverts carrying the key when it is the hash of UIDAI's 2021 production key, whose
  /// certificate has expired. A method trusting it would accept no current QR code, so a holder could never
  /// recover with it.
  function test_RevertWhen_TheKeyIsThe2021ExpiredKey() external {
    // it should revert
    // it should carry the key in the error
    vm.expectRevert(
      abi.encodeWithSelector(IDeployIdentity.DeployIdentity_AadhaarExpiredKey.selector, _AADHAAR_EXPIRED_2021_KEY)
    );
    _script.checkAadhaarKey(_AADHAAR_EXPIRED_2021_KEY);
  }

  /// checkAadhaarKey reverts carrying the key when it is the hash of UIDAI's 2024 production key, whose
  /// certificate has expired. A method trusting it would accept no current QR code, so a holder could never
  /// recover with it.
  function test_RevertWhen_TheKeyIsThe2024ExpiredKey() external {
    // it should revert
    // it should carry the key in the error
    vm.expectRevert(
      abi.encodeWithSelector(IDeployIdentity.DeployIdentity_AadhaarExpiredKey.selector, _AADHAAR_EXPIRED_2024_KEY)
    );
    _script.checkAadhaarKey(_AADHAAR_EXPIRED_2024_KEY);
  }
}
