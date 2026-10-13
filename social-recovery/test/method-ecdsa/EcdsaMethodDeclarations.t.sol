// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {IERC165} from '@openzeppelin/contracts/utils/introspection/IERC165.sol';
import {IPolicyMethod} from 'interfaces/IPolicyMethod.sol';
import {IPolicyMethodAdmin} from 'interfaces/IPolicyMethodAdmin.sol';
import {IPolicyMethodPause} from 'interfaces/IPolicyMethodPause.sol';
import {EcdsaMethod} from 'contracts/methods/ecdsa/EcdsaMethod.sol';
import {MethodEcdsaMagic1271} from 'test/mocks/MethodEcdsaGuardianMocks.sol';
import {MethodEcdsaTestBase} from 'test/utils/MethodEcdsaTestBase.sol';

/// @notice Tests what the wallet method says about itself and the shape of every answer it gives. A holder reads
///         these answers before adopting the method, so they must show that it trusts nobody and keeps no state.
/// @dev The wallet method checks that one guardian approved the digest of a recovery. The guardian is the address
///      named in the config. The magic value is the selector of verify, 0x024ad318. Verify returns it when the
///      guardian approved. The manager counts an approval only when verify returns exactly that one word.
///      A trusted party is an address or key that can change the method or pause it after adoption. An address
///      waiting to take over one of those roles is a trusted party too.
contract EcdsaMethodDeclarationsTest is MethodEcdsaTestBase {
  /// @notice trustedParties names nobody. Every address it returns is the zero address, and its key list is empty.
  /// @dev The wallet method has no key anyone can change and no stop, so a holder adopting it trusts nobody else.
  function test_WhenTrustedPartiesAreRead() external view {
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

  /// @notice supportsInterface answers true for the policy method interface id.
  /// @dev The setup screen asks this before adoption and warns on a module that answers false.
  function test_WhenAskedForThePolicyMethodInterface() external view {
    assertTrue(_method.supportsInterface(type(IPolicyMethod).interfaceId));
  }

  /// @notice supportsInterface answers true for ERC-165 itself, 0x01ffc9a7.
  /// @dev ERC-165 requires it, and a probing client relies on it before asking anything else.
  function test_WhenAskedForTheErc165Interface() external view {
    assertTrue(_method.supportsInterface(type(IERC165).interfaceId));
    assertTrue(_method.supportsInterface(0x01ffc9a7));
  }

  /// @notice supportsInterface answers false for 0xffffffff.
  /// @dev ERC-165 requires false there, so a client can tell a real implementation from a catch-all.
  function test_WhenAskedForTheInvalidInterfaceId() external view {
    assertFalse(_method.supportsInterface(0xffffffff));
  }

  /// @notice supportsInterface answers false for the pause and key admin interfaces.
  /// @dev The wallet method carries neither role, so claiming them would mislead the setup screen.
  function test_WhenAskedForThePauseOrAdminInterface() external view {
    assertFalse(_method.supportsInterface(type(IPolicyMethodPause).interfaceId));
    assertFalse(_method.supportsInterface(type(IPolicyMethodAdmin).interfaceId));
  }

  /// @notice name and version are never empty. They stay the same after a verification and on a second deployment.
  /// @dev The adoption screen shows them, and a constant answer means every deployment reads the same.
  function test_WhenNameAndVersionAreRead() external {
    string memory _moduleName = _method.name();
    string memory _moduleVersion = _method.version();
    assertGt(bytes(_moduleName).length, 0, 'name empty');
    assertGt(bytes(_moduleVersion).length, 0, 'version empty');

    _method.verify(_config(_guardian), _digest, _sign(_guardianKey, _digest));
    assertEq(_method.name(), _moduleName);
    assertEq(_method.version(), _moduleVersion);

    IPolicyMethod _second = IPolicyMethod(address(new EcdsaMethod()));
    assertEq(_second.name(), _moduleName);
    assertEq(_second.version(), _moduleVersion);
  }

  /// @notice verify always answers exactly one ABI word, whether the guardian is a key or a smart account.
  ///         The word is the magic value on a pass and a different value on a refusal.
  /// @dev The manager accepts one word holding the selector of verify and nothing else.
  function test_WhenVerifyAnswers() external {
    bytes memory _call =
      abi.encodeCall(IPolicyMethod.verify, (_config(_guardian), _digest, _sign(_guardianKey, _digest)));
    (bool _ok, bytes memory _ret) = address(_method).staticcall(_call);
    assertTrue(_ok);
    assertEq(_ret, abi.encode(IPolicyMethod.verify.selector), 'passing verdict is not exactly one magic word');

    _call = abi.encodeCall(IPolicyMethod.verify, (_config(_guardian), _digest, _sign(_strangerKey, _digest)));
    (_ok, _ret) = address(_method).staticcall(_call);
    assertTrue(_ok);
    assertEq(_ret.length, 32, 'refusal is not one word');
    assertTrue(keccak256(_ret) != keccak256(abi.encode(IPolicyMethod.verify.selector)), 'refusal is the magic word');

    address _contractGuardian = address(new MethodEcdsaMagic1271());
    _call = abi.encodeCall(IPolicyMethod.verify, (_config(_contractGuardian), _digest, _sign(_strangerKey, _digest)));
    (_ok, _ret) = address(_method).staticcall(_call);
    assertTrue(_ok);
    assertEq(_ret, abi.encode(IPolicyMethod.verify.selector));
  }

  /// @notice No function of the method reads or writes a storage slot.
  /// @dev The method holds no storage, so no account's recovery can leak into another's verdict.
  function test_WhenAnyFunctionRuns() external {
    address _contractGuardian = address(new MethodEcdsaMagic1271());
    vm.record();
    _method.verify(_config(_guardian), _digest, _sign(_guardianKey, _digest));
    _method.verify(_config(_guardian), _digest, _sign(_strangerKey, _digest));
    _method.verify(_config(_contractGuardian), _digest, _sign(_strangerKey, _digest));
    _method.verify(_config(address(0)), _digest, '');
    _method.trustedParties();
    _method.supportsInterface(type(IPolicyMethod).interfaceId);
    _method.supportsInterface(0xffffffff);
    _method.name();
    _method.version();
    (bytes32[] memory _reads, bytes32[] memory _writes) = vm.accesses(address(_method));
    assertEq(_reads.length, 0, 'the method read storage');
    assertEq(_writes.length, 0, 'the method wrote storage');
  }
}
