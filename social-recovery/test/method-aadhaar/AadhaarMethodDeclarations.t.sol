// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {IERC165} from '@openzeppelin/contracts/utils/introspection/IERC165.sol';
import {IPolicyMethod} from 'interfaces/IPolicyMethod.sol';
import {IPolicyMethodAdmin} from 'interfaces/IPolicyMethodAdmin.sol';
import {IPolicyMethodPause} from 'interfaces/IPolicyMethodPause.sol';
import {AadhaarMethod} from 'contracts/methods/aadhaar/AadhaarMethod.sol';
import {MethodAadhaarVerifierMock} from 'test/mocks/MethodAadhaarVerifierMock.sol';
import {MethodAadhaarTestBase} from 'test/utils/MethodAadhaarTestBase.sol';

/// @notice What the Aadhaar method declares about itself. That is its name, its version, the interfaces it answers
///         for, the verifier it calls and the parties a holder trusts by adopting it.
contract AadhaarMethodDeclarationsTest is MethodAadhaarTestBase {
  /// supportsInterface answers true for the IPolicyMethod interface id.
  /// The setup screen asks this before adopting a method. It warns the holder when the answer is false.
  function test_WhenAskedForTheIPolicyMethodInterfaceId() external view {
    // it should answer true
    assertTrue(_method.supportsInterface(type(IPolicyMethod).interfaceId));
  }

  /// supportsInterface answers true for the pause interface id.
  /// The Aadhaar method can be paused. The setup screen shows its pause holder only when this answer is true.
  function test_WhenAskedForThePauseInterfaceId() external view {
    // it should answer true
    assertTrue(_method.supportsInterface(type(IPolicyMethodPause).interfaceId));
  }

  /// supportsInterface answers true for the key admin interface id.
  /// The Aadhaar method holds an issuer key that its key admin can replace. The setup screen shows that admin.
  function test_WhenAskedForTheAdminInterfaceId() external view {
    // it should answer true
    assertTrue(_method.supportsInterface(type(IPolicyMethodAdmin).interfaceId));
  }

  /// supportsInterface answers true for the ERC-165 interface id.
  /// ERC-165 requires a contract to claim its own probe.
  function test_WhenAskedForTheERC165InterfaceId() external view {
    // it should answer true
    assertTrue(_method.supportsInterface(type(IERC165).interfaceId));
  }

  /// supportsInterface answers false for 0xffffffff.
  /// ERC-165 requires that answer. A caller relying on it would otherwise misread the method.
  function test_WhenAskedForTheInvalidInterfaceId() external view {
    // it should answer false
    assertFalse(_method.supportsInterface(0xffffffff));
  }

  /// name answers 'method-aadhaar'.
  /// The adoption screen shows it to the holder. It must name this module and no other.
  function test_WhenTheNameIsRead() external view {
    // it should answer method-aadhaar
    assertEq(_method.name(), 'method-aadhaar');
  }

  /// version answers '1.0.0'.
  /// The adoption screen shows it to the holder. It must name the release that was reviewed.
  function test_WhenTheVersionIsRead() external view {
    // it should answer 1.0.0
    assertEq(_method.version(), '1.0.0');
  }

  /// verifier answers the address the method was deployed with. Anyone can check which verifier a method calls
  /// before adopting it. A second deployment with another mock shows the answer follows the address passed in.
  function test_WhenTheVerifierIsRead() external {
    // it should answer the verifier the method was deployed with
    assertEq(_method.verifier(), address(_verifier), 'the fixture verifier');
    MethodAadhaarVerifierMock _other = new MethodAadhaarVerifierMock();
    AadhaarMethod _deployed = _aadhaarDeploy(_owner, _admin, _aadhaarOneKey(_issuerKey), address(_other));
    assertEq(_deployed.verifier(), address(_other), 'another verifier');
  }

  /// trustedParties names the key admin, the pause holder and the one issuer key. It never names the verifier. The
  /// verifier is code with no state at an address fixed at deployment, and a holder need not trust it as a party.
  function test_WhenTrustedPartiesAreRead() external view {
    // it should name the key admin, the pause holder and the issuer key and not the verifier
    (
      address _declaredAdmin,
      address _pendingAdmin,
      bytes32[] memory _keys,
      address _pauseHolder,
      address _pendingPauseHolder
    ) = _method.trustedParties();
    assertEq(_declaredAdmin, _admin, 'admin');
    assertEq(_pendingAdmin, address(0), 'pending admin');
    assertEq(_keys.length, 1, 'one word');
    assertEq(_keys[0], _issuerKey, 'the issuer key');
    assertTrue(_keys[0] != bytes32(uint256(uint160(address(_verifier)))), 'the verifier is not a key');
    assertEq(_pauseHolder, _owner, 'pause holder');
    assertEq(_pendingPauseHolder, address(0), 'pending pause holder');
    assertTrue(
      _declaredAdmin != address(_verifier) && _pauseHolder != address(_verifier), 'the verifier is not a party'
    );
  }
}
