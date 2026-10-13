// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {Test} from 'forge-std/Test.sol';
import {VmSafe} from 'forge-std/Vm.sol';
import {IPolicyManager} from 'interfaces/IPolicyManager.sol';
import {IPolicyMethod} from 'interfaces/IPolicyMethod.sol';
import {IDeploy} from 'script/IDeploy.sol';
import {AmbireRecoveryAction} from 'contracts/actions/ambire/AmbireRecoveryAction.sol';
import {IAmbireRecoveryAction} from 'contracts/actions/ambire/IAmbireRecoveryAction.sol';
import {EcdsaMethod} from 'contracts/methods/ecdsa/EcdsaMethod.sol';
import {PasskeyMethod} from 'contracts/methods/passkey/PasskeyMethod.sol';
import {PolicyManager} from 'contracts/manager/PolicyManager.sol';
import {DeployHarness} from 'test/utils/DeployHarness.sol';

/// @notice Shared setup for the deployment script's tests. It creates the script and a good
///         deployment built by hand from the kit's real contracts, which the check functions accept
///         and each crafted bad pin departs from in one place.
abstract contract DeployTestBase is Test {
  /// @notice The AmbireAccount implementation both supported chains pin, the one the recovery
  ///         action serves.
  address internal constant _PINNED_IMPLEMENTATION = 0x0F2AA7bcda3d9D210dF69a394b6965CB2566c828;
  /// @notice Mainnet's chain id.
  uint256 internal constant _MAINNET_CHAIN_ID = 1;
  /// @notice Sepolia's chain id.
  uint256 internal constant _SEPOLIA_CHAIN_ID = 11_155_111;
  /// @notice The codehash of the pinned implementation, identical on mainnet and Sepolia.
  bytes32 internal constant _PINNED_CODEHASH = 0x7e8a122a0f0ca10438a7f18eedb8cf5609c2f41f7ea175e9dbb9d19ec0c2af91;

  /// @notice The environment variable the script reads the record's label from.
  string internal constant _LABEL_ENV = 'DEPLOYMENT_LABEL';

  DeployHarness internal _script;
  /// @notice A local stand-in for the pinned implementation: an address that holds code. The local
  ///         pins carry its codehash.
  address internal _implementation;
  IDeploy.Pins internal _pins;
  /// @notice A good deployment, built from the kit's real contracts with the action naming the
  ///         manager and `_implementation`.
  IDeploy.Deployment internal _good;
  /// @notice Whether DEPLOYMENT_LABEL was set before the test changed it, and its value then.
  bool internal _labelWasSet;
  string internal _originalLabel;

  function setUp() public virtual {
    _script = new DeployHarness();
    _implementation = makeAddr('ambireImplementation');
    vm.etch(_implementation, hex'00');
    _pins =
      IDeploy.Pins({ambireImplementation: _implementation, ambireImplementationCodehash: _implementation.codehash});
    PolicyManager _manager = new PolicyManager();
    _good = IDeploy.Deployment({
      manager: IPolicyManager(address(_manager)),
      ecdsaMethod: IPolicyMethod(address(new EcdsaMethod())),
      passkeyMethod: IPolicyMethod(address(new PasskeyMethod())),
      action: _newAction(address(_manager), _implementation)
    });
  }

  /// @notice Deploys the kit's real recovery action with the given manager and implementation.
  function _newAction(address _manager, address _ambireImplementation)
    internal
    returns (IAmbireRecoveryAction _action)
  {
    _action = IAmbireRecoveryAction(address(new AmbireRecoveryAction(IPolicyManager(_manager), _ambireImplementation)));
  }

  /// @notice Hashes a fuzzed number and a label into an address no fixture uses. The fuzzer seeds
  ///         its inputs with addresses it reads from state, so a number mapped straight onto an
  ///         address can land on a fixture address.
  function _freshAddress(string memory _label, uint256 _seed) internal pure returns (address _fresh) {
    _fresh = address(uint160(uint256(keccak256(abi.encode(_label, _seed)))));
  }

  /// @notice The slot Ambire's own helper derives for a validator bound with empty data: the low
  ///         twenty bytes of keccak256(abi.encode(validator, bytes(""))).
  function _ambireHelperSlot(address _validator) internal pure returns (address _slot) {
    _slot = address(uint160(uint256(keccak256(abi.encode(_validator, bytes(''))))));
  }

  /// @notice Counts the contract creations among recorded account accesses, reverted ones
  ///         included, so a creation that a later revert undid still counts.
  function _creations(VmSafe.AccountAccess[] memory _accesses) internal pure returns (uint256 _count) {
    for (uint256 _i; _i < _accesses.length; ++_i) {
      if (_accesses[_i].kind == VmSafe.AccountAccessKind.Create) ++_count;
    }
  }

  /// @notice Calls deploy with `_deployPins` while recording account accesses, requires it to revert
  ///         with exactly `_expectedRevert`, and returns how many contracts it created before it
  ///         reverted.
  function _deployExpectingRevert(IDeploy.Pins memory _deployPins, bytes memory _expectedRevert)
    internal
    returns (uint256 _created)
  {
    vm.startStateDiffRecording();
    try _script.deploy(_deployPins) {
      fail('deploy did not revert');
    } catch (bytes memory _reason) {
      assertEq(_reason, _expectedRevert, 'revert data');
    }
    _created = _creations(vm.stopAndReturnStateDiff());
  }

  /// @notice Whether the recorded accesses hold a call, reverted or not, to `_target` with exactly
  ///         `_data` as calldata.
  function _called(VmSafe.AccountAccess[] memory _accesses, address _target, bytes memory _data)
    internal
    pure
    returns (bool _found)
  {
    for (uint256 _i; _i < _accesses.length && !_found; ++_i) {
      VmSafe.AccountAccessKind _kind = _accesses[_i].kind;
      _found = (_kind == VmSafe.AccountAccessKind.Call || _kind == VmSafe.AccountAccessKind.StaticCall)
        && _accesses[_i].account == _target && keccak256(_accesses[_i].data) == keccak256(_data);
    }
  }

  /// @notice Sets DEPLOYMENT_LABEL to `_label`, remembering what it held so `_restoreLabel` can put
  ///         it back. The environment is shared by every test in the run.
  function _setLabel(string memory _label) internal {
    _labelWasSet = vm.envExists(_LABEL_ENV);
    if (_labelWasSet) _originalLabel = vm.envOr(_LABEL_ENV, string(''));
    vm.setEnv(_LABEL_ENV, _label);
  }

  /// @notice Puts DEPLOYMENT_LABEL back to the value it held before `_setLabel`. Forge cannot unset
  ///         a variable, so one that was unset is left set to the empty string.
  function _restoreLabel() internal {
    vm.setEnv(_LABEL_ENV, _labelWasSet ? _originalLabel : '');
  }
}
