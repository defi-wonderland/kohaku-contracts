// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {IPolicyMethod} from 'interfaces/IPolicyMethod.sol';
import {IPolicyMethodAdmin} from 'interfaces/IPolicyMethodAdmin.sol';
import {IPolicyMethodPause} from 'interfaces/IPolicyMethodPause.sol';
import {PasskeyMethodFixture} from 'test/utils/PasskeyMethodFixture.sol';

/// @notice The passkey method's declaration and metadata. It trusts no party and no key, answers
///         only for IPolicyMethod and ERC-165, carries no pause and reads no storage while verifying.
contract PasskeyMethodDeclarationsTest is PasskeyMethodFixture {
  /// trustedParties answers the zero address for the admin, the pause holder and both pending roles, and an empty key
  /// list.
  /// The method depends on nobody's word, and the setup screen shows a holder exactly that.
  function test_WhenTrustedPartiesAreRead() external view {
    // it should answer the zero address for every role and an empty key list
    (
      address _admin,
      address _pendingAdmin,
      bytes32[] memory _trustedKeys,
      address _pauseHolder,
      address _pendingPauseHolder
    ) = _method.trustedParties();
    assertEq(_admin, address(0), 'admin');
    assertEq(_pendingAdmin, address(0), 'pendingAdmin');
    assertEq(_trustedKeys.length, 0, 'trustedKeys');
    assertEq(_pauseHolder, address(0), 'pauseHolder');
    assertEq(_pendingPauseHolder, address(0), 'pendingPauseHolder');
  }

  /// supportsInterface answers true for the IPolicyMethod interface id.
  /// The setup screen asks this before adopting a method and warns when the answer is false.
  function test_WhenAskedForTheIPolicyMethodInterfaceId() external view {
    // it should answer true
    assertTrue(_method.supportsInterface(type(IPolicyMethod).interfaceId));
  }

  /// supportsInterface answers true for the ERC-165 interface id 0x01ffc9a7.
  /// ERC-165 requires a contract to claim its own probe.
  function test_WhenAskedForTheERC165InterfaceId() external view {
    // it should answer true
    assertTrue(_method.supportsInterface(0x01ffc9a7));
  }

  /// supportsInterface answers false for 0xffffffff.
  /// ERC-165 requires that answer, and a probe relying on it would otherwise misread the method.
  function test_WhenAskedForTheInvalidInterfaceId() external view {
    // it should answer false
    assertFalse(_method.supportsInterface(0xffffffff));
  }

  /// supportsInterface answers false for the pause interface id.
  /// The passkey method carries no stop, so claiming one would mislead the setup screen.
  function test_WhenAskedForThePauseInterfaceId() external view {
    // it should answer false
    assertFalse(_method.supportsInterface(type(IPolicyMethodPause).interfaceId));
  }

  /// supportsInterface answers false for the key admin interface id.
  /// The passkey method holds no trusted key, so nobody administers one.
  function test_WhenAskedForTheAdminInterfaceId() external view {
    // it should answer false
    assertFalse(_method.supportsInterface(type(IPolicyMethodAdmin).interfaceId));
  }

  /// A call to paused() never answers the encoding of true.
  /// The manager refuses a method whose pause read answers true, which would stop every passkey credential.
  function test_WhenThePauseReadIsMade() external view {
    // it should not answer the encoding of true
    bytes memory _pausedCall = abi.encodeCall(IPolicyMethodPause.paused, ());
    (bool _success, bytes memory _returned) = address(_method).staticcall(_pausedCall);
    assertFalse(_success && keccak256(_returned) == keccak256(abi.encode(true)), 'the method answers paused');
  }

  /// name answers 'method-passkey'.
  /// The adoption screen shows it to the holder, so it must name this module and no other.
  function test_WhenTheNameIsRead() external view {
    // it should answer method-passkey
    assertEq(_method.name(), 'method-passkey');
  }

  /// version answers '1.0.0'.
  /// The adoption screen shows it to the holder, so it must name the release that was reviewed.
  function test_WhenTheVersionIsRead() external view {
    // it should answer 1.0.0
    assertEq(_method.version(), '1.0.0');
  }

  /// Verifying an accepted proof reads and writes no storage slot of the method.
  /// The verdict depends only on the config, the digest and the proof, so no stored value can change it.
  function test_WhenAProofIsVerified() external {
    // it should touch no storage slot
    bytes memory _proof = _guardianProof(_extraFieldClientData(_placeDigest));
    vm.record();
    bytes4 _magicValue = _method.verify(_guardianConfig, _placeDigest, _proof);
    (bytes32[] memory _reads, bytes32[] memory _writes) = vm.accesses(address(_method));
    assertEq(_magicValue, IPolicyMethod.verify.selector);
    assertEq(_reads.length, 0, 'verify read storage');
    assertEq(_writes.length, 0, 'verify wrote storage');
  }
}
