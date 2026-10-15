// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {Script} from 'forge-std/Script.sol';
import {VmSafe} from 'forge-std/Vm.sol';

import {IPolicyAction} from 'interfaces/IPolicyAction.sol';
import {IPolicyManager} from 'interfaces/IPolicyManager.sol';
import {IPolicyMethod} from 'interfaces/IPolicyMethod.sol';
import {IRecoveryAction} from 'interfaces/IRecoveryAction.sol';

import {IDeploy} from 'script/IDeploy.sol';
import {AmbireRecoveryAction} from 'contracts/actions/ambire/AmbireRecoveryAction.sol';
import {IAmbireRecoveryAction} from 'contracts/actions/ambire/IAmbireRecoveryAction.sol';
import {EcdsaMethod} from 'contracts/methods/ecdsa/EcdsaMethod.sol';
import {PasskeyMethod} from 'contracts/methods/passkey/PasskeyMethod.sol';
import {PolicyManager} from 'contracts/manager/PolicyManager.sol';

/// @title Deploy
/// @author defi-wonderland
/// @notice Deploys the demo path on mainnet or Sepolia and checks it before anything is sent.
/// @dev Every kit contract is created directly with its real constructor arguments, with no proxy
///      and no upgrade admin. Each check reads the deployed contracts and the pins back from the
///      chain rather than trusting what the script meant to deploy. Each read of a deployed
///      contract's answer is a low-level call, so a revert, an empty answer or a malformed one fails
///      with this script's own error rather than with the target's.
contract Deploy is Script, IDeploy {
  /*///////////////////////////////////////////////////////////////
                          STATE VARIABLES
  ///////////////////////////////////////////////////////////////*/

  /// @notice Ethereum mainnet's chain id.
  uint256 internal constant _MAINNET_CHAIN_ID = 1;

  /// @notice Sepolia's chain id.
  uint256 internal constant _SEPOLIA_CHAIN_ID = 11_155_111;

  /// @notice The AmbireAccount implementation the action serves, the same address on both chains.
  address internal constant _AMBIRE_IMPLEMENTATION = 0x0F2AA7bcda3d9D210dF69a394b6965CB2566c828;

  /// @notice The code hash the pinned AmbireAccount implementation has, the same on both chains.
  /// @dev This is the hash of the code at 0x0F2AA7bcda3d9D210dF69a394b6965CB2566c828, read on
  ///      mainnet and on Sepolia, where it is the same. It is the code the recovery action's fork
  ///      tests run against. The deployed code predates the source revision the kit pins, so the
  ///      hash cannot be recomputed from that source. It pins the code that was reviewed and
  ///      tested, so a wrong address that has code fails the check.
  bytes32 internal constant _AMBIRE_IMPLEMENTATION_CODEHASH =
    0x7e8a122a0f0ca10438a7f18eedb8cf5609c2f41f7ea175e9dbb9d19ec0c2af91;

  /// @notice The start of the eth_call parameters: a call to the P256VERIFY precompile at 0x100,
  ///         the address the passkey method calls, whose data follows.
  string internal constant _P256_CALL_PREFIX = '[{"to":"0x0000000000000000000000000000000000000100","data":"';

  /// @notice The end of the eth_call parameters: the call runs against the latest block.
  string internal constant _P256_CALL_SUFFIX = '"},"latest"]';

  /// @notice The size of one ABI word, the only length a P256VERIFY answer for a valid signature
  ///         has.
  uint256 internal constant _WORD = 32;

  /// @notice The frozen passkey proof vectors, relative to the project root.
  string internal constant _PASSKEY_PROOF_VECTORS = '/test/fixtures/kats/method-passkey-proof.json';

  /// @notice The frozen passkey config vectors, relative to the project root.
  string internal constant _PASSKEY_CONFIG_VECTORS = '/test/fixtures/kats/method-passkey-config.json';

  /// @notice The proof vector whose signature the precompile must accept.
  string internal constant _VALID_PROOF_ROW = '$.vectors[?(@.id == \'valid-extra-client-field\')]';

  /// @notice The config vector that holds the public key behind that signature.
  string internal constant _KEY_ROW = '$.vectors[?(@.id == \'recover-example\')]';

  /// @notice Where the record files live, relative to the project root.
  string internal constant _DEPLOYMENTS_DIR = '/script/deployments/';

  /// @notice The suffix of the candidate record run writes.
  string internal constant _PENDING_SUFFIX = '.pending.json';

  /// @notice The suffix of the published record confirm writes.
  string internal constant _RECORD_SUFFIX = '.json';

  /// @notice The environment variable that names the record files instead of the chain id.
  string internal constant _LABEL_VARIABLE = 'DEPLOYMENT_LABEL';

  /// @notice The longest label accepted, in characters.
  uint256 internal constant _MAX_LABEL_LENGTH = 64;

  /// @notice The name the wallet method answers.
  string internal constant _ECDSA_METHOD_NAME = 'method-ecdsa';

  /// @notice The name the passkey method answers.
  string internal constant _PASSKEY_METHOD_NAME = 'method-passkey';

  /// @notice The record key of the recovery action, for the errors that name it.
  string internal constant _ACTION_KEY = 'recoveryAction';

  /// @notice The record key of the wallet method, for the errors that name it.
  string internal constant _ECDSA_METHOD_KEY = 'ecdsaMethod';

  /// @notice The record key of the passkey method, for the errors that name it.
  string internal constant _PASSKEY_METHOD_KEY = 'passkeyMethod';

  /*///////////////////////////////////////////////////////////////
                          EXTERNAL FUNCTIONS
  ///////////////////////////////////////////////////////////////*/

  /// @inheritdoc IDeploy
  function run() external returns (Deployment memory _deployment) {
    Pins memory _pins = _pinsFor(block.chainid);
    string memory _label = _recordLabel(block.chainid);
    _deployment = _deploy(_pins);
    if (vm.isContext(VmSafe.ForgeContext.ScriptBroadcast) || vm.isContext(VmSafe.ForgeContext.ScriptResume)) {
      string memory _dir = string.concat(vm.projectRoot(), _DEPLOYMENTS_DIR);
      vm.createDir(_dir, true);
      vm.writeJson(_recordJson(_deployment, _pins, block.chainid), string.concat(_dir, _label, _PENDING_SUFFIX));
    }
  }

  /// @inheritdoc IDeploy
  function confirm() external returns (Deployment memory _deployment) {
    Pins memory _pins = _pinsFor(block.chainid);
    _deployment = _confirmLabel(_recordLabel(block.chainid), _pins);
  }

  /// @inheritdoc IDeploy
  function confirmLabel(string calldata _label) external returns (Deployment memory _deployment) {
    Pins memory _pins = _pinsFor(block.chainid);
    _deployment = _confirmLabel(_labelFor(true, _label, block.chainid), _pins);
  }

  /*///////////////////////////////////////////////////////////////
                          INTERNAL FUNCTIONS
  ///////////////////////////////////////////////////////////////*/

  /// @notice Checks the chain, deploys the four contracts in one broadcast and checks what was
  ///         deployed.
  /// @dev The checks that need nothing deployed run first. The contracts are then created inside
  ///      one broadcast, the action with this run's manager and the pinned implementation as its
  ///      constructor arguments, and the checks over the deployment run last, the code check
  ///      after the others. The broadcast stops before those checks, so the local copy the code
  ///      check builds is never sent. forge script simulates the whole run before it sends any
  ///      transaction, so a failing check reverts the script before anything is broadcast.
  /// @param _pins The pins to deploy with.
  /// @return _deployment What this run deployed.
  function _deploy(Pins memory _pins) internal returns (Deployment memory _deployment) {
    _checkP256Verify();
    _checkImplementation(_pins);

    vm.startBroadcast();
    PolicyManager _manager = new PolicyManager();
    _deployment.manager = _manager;
    _deployment.ecdsaMethod = new EcdsaMethod();
    _deployment.passkeyMethod = new PasskeyMethod();
    _deployment.action = new AmbireRecoveryAction(_manager, _pins.ambireImplementation);
    vm.stopBroadcast();

    _checkDeployment(_deployment, _pins);
    _checkKitCode(_deployment, _pins);
  }

  /// @notice Publishes the candidate record a label names, once the chain confirms it.
  /// @dev confirm and confirmLabel share this body. They resolve this chain's pins before they read
  ///      the label, so an unsupported chain stops with Deploy_UnsupportedChain before anything
  ///      else, and the label is already valid when it arrives here. The P256VERIFY probe runs
  ///      first in this body, before the candidate is read, so publishing reruns every check the
  ///      broadcast ran against the live chain. Every check runs before anything is written. The
  ///      published record is rebuilt from the values the checks read, never copied from the
  ///      candidate's text, so a key no check read never reaches it.
  /// @param _label The label that names the candidate and the published record.
  /// @param _pins This chain's table entry.
  /// @return _deployment The deployment the record names.
  function _confirmLabel(string memory _label, Pins memory _pins) internal returns (Deployment memory _deployment) {
    _checkP256Verify();

    string memory _base = string.concat(vm.projectRoot(), _DEPLOYMENTS_DIR, _label);
    string memory _pendingPath = string.concat(_base, _PENDING_SUFFIX);
    string memory _json = vm.readFile(_pendingPath);

    uint256 _recordedChainId = vm.parseJsonUint(_json, '.chainId');
    require(_recordedChainId == block.chainid, Deploy_RecordChainMismatch(_recordedChainId, block.chainid));

    _deployment.manager = IPolicyManager(_requireDeployed(vm.parseJsonAddress(_json, '.policyManager')));
    _deployment.ecdsaMethod = IPolicyMethod(_requireDeployed(vm.parseJsonAddress(_json, '.ecdsaMethod')));
    _deployment.passkeyMethod = IPolicyMethod(_requireDeployed(vm.parseJsonAddress(_json, '.passkeyMethod')));
    _deployment.action = IAmbireRecoveryAction(_requireDeployed(vm.parseJsonAddress(_json, '.recoveryAction')));

    _requireRecordedPin(_json, _pins);
    _checkImplementation(_pins);
    _checkDeployment(_deployment, _pins);
    _checkKitCode(_deployment, _pins);

    vm.writeJson(_recordJson(_deployment, _pins, block.chainid), string.concat(_base, _RECORD_SUFFIX));
    vm.removeFile(_pendingPath);
  }

  /// @notice Sends P256VERIFY the known valid signature through the node the script runs against
  ///         and checks the node's answer. The passkey method relies on the precompile at 0x100,
  ///         and a chain without it would refuse every passkey.
  /// @dev forge runs the script in its own EVM, whose precompiles follow the project's EVM
  ///      version rather than the chain's, so a call made inside the script says nothing about
  ///      the chain. This check therefore sends an eth_call to the node at the latest block.
  ///      Without a node the cheatcode fails and the script stops, since there is no chain to
  ///      deploy to. vm.rpc decodes a hex result into its bytes, so the answer arrives as the raw words the
  ///      precompile returned, and as empty bytes from a chain without it. Virtual so that a
  ///      configuration for a chain without a node, such as the local test chain, can supply its own check.
  function _checkP256Verify() internal virtual {
    string memory _params = string.concat(_P256_CALL_PREFIX, vm.toString(_p256VerifyInput()), _P256_CALL_SUFFIX);
    _checkP256VerifyAnswer(vm.rpc('eth_call', _params));
  }

  /// @notice Requires each of the four addresses to run exactly the kit's code. The other checks
  ///         read answers a contract chooses, so a contract written to give the same answers would
  ///         pass them. Only the code hash ties an address to the code that was reviewed.
  /// @dev The manager and the two methods hold no immutable, so their code is the compiled runtime
  ///      code. The action holds immutables, two of them derived from its own address, so its
  ///      expected code is the one its constructor returns at that address with the recorded
  ///      manager and the pinned implementation. No broadcast is active here, so nothing is sent.
  /// @param _deployment The deployment to check.
  /// @param _pins The pins it was deployed with.
  function _checkKitCode(Deployment memory _deployment, Pins memory _pins) internal {
    _requireKitCode('policyManager', address(_deployment.manager), keccak256(type(PolicyManager).runtimeCode));
    _requireKitCode('ecdsaMethod', address(_deployment.ecdsaMethod), keccak256(type(EcdsaMethod).runtimeCode));
    _requireKitCode('passkeyMethod', address(_deployment.passkeyMethod), keccak256(type(PasskeyMethod).runtimeCode));

    address _action = address(_deployment.action);
    bytes memory _actionInitCode = abi.encodePacked(
      type(AmbireRecoveryAction).creationCode, abi.encode(_deployment.manager, _pins.ambireImplementation)
    );
    _requireKitCode('recoveryAction', _action, _runtimeCodeHashAt(_action, _actionInitCode));
  }

  /// @notice Runs a creation code at a given address and hashes the runtime code it returns, the
  ///         code a constructor run at that address would leave there.
  /// @dev The address's own code is put back right after, and a constructor that writes no
  ///      storage leaves nothing else changed. This is how the script builds a contract whose
  ///      immutables depend on its own address. The cheatcodes change only the script's local
  ///      copy of the chain and send nothing. A creation code that reverts gives zero, which no
  ///      code hash equals.
  /// @param _target The address the constructor runs at.
  /// @param _initCode The creation code with its constructor arguments.
  /// @return _codehash The hash of the runtime code returned, or zero when the creation code
  ///         reverted.
  function _runtimeCodeHashAt(address _target, bytes memory _initCode) internal returns (bytes32 _codehash) {
    bytes memory _deployedCode = _target.code;
    vm.etch(_target, _initCode);
    (bool _success, bytes memory _runtimeCode) = _target.call('');
    vm.etch(_target, _deployedCode);
    if (_success) _codehash = keccak256(_runtimeCode);
  }

  /// @notice Builds the record of one deployment, the JSON that run writes for the SDK and the
  ///         screens.
  /// @dev The keys are chainId, policyManager, ecdsaMethod, passkeyMethod, recoveryAction,
  ///      ambireImplementation and ambireImplementationCodehash.
  /// @param _deployment What the run deployed.
  /// @param _pins The pins it deployed with.
  /// @param _chainId The chain the deployment lives on.
  /// @return _json The record.
  function _recordJson(Deployment memory _deployment, Pins memory _pins, uint256 _chainId)
    internal
    returns (string memory _json)
  {
    string memory _key = 'deployment';
    vm.serializeUint(_key, 'chainId', _chainId);
    vm.serializeAddress(_key, 'policyManager', address(_deployment.manager));
    vm.serializeAddress(_key, 'ecdsaMethod', address(_deployment.ecdsaMethod));
    vm.serializeAddress(_key, 'passkeyMethod', address(_deployment.passkeyMethod));
    vm.serializeAddress(_key, 'recoveryAction', address(_deployment.action));
    vm.serializeAddress(_key, 'ambireImplementation', _pins.ambireImplementation);
    _json = vm.serializeBytes32(_key, 'ambireImplementationCodehash', _pins.ambireImplementationCodehash);
  }

  /// @notice Requires the pinned implementation to have code on this chain, and that code to be
  ///         the pinned one. An action pinned to an address with no code would serve no account,
  ///         and one pinned to the wrong code would serve accounts it was never reviewed against.
  /// @param _pins The pins, which name the implementation and its code hash.
  function _checkImplementation(Pins memory _pins) internal view {
    address _implementation = _pins.ambireImplementation;
    require(_implementation.code.length != 0, Deploy_ImplementationHasNoCode(_implementation));

    bytes32 _codehash = _implementation.codehash;
    require(
      _codehash == _pins.ambireImplementationCodehash,
      Deploy_ImplementationCodehashMismatch(_implementation, _pins.ambireImplementationCodehash, _codehash)
    );
  }

  /// @notice Reads DEPLOYMENT_LABEL from the environment and applies the label rule to it. The
  ///         label names the record files of one deployment, for example tenderly-sepolia for a
  ///         rehearsal on a fork that keeps Sepolia's chain id.
  /// @param _chainId The chain id used when no label is set.
  /// @return _label The label.
  function _recordLabel(uint256 _chainId) internal view returns (string memory _label) {
    _label = _labelFor(vm.envExists(_LABEL_VARIABLE), vm.envOr(_LABEL_VARIABLE, string('')), _chainId);
  }

  /// @notice Requires an address a candidate record names to have code on this chain.
  /// @param _target The recorded address.
  /// @return _deployed The same address, once it is known to have code.
  function _requireDeployed(address _target) internal view returns (address _deployed) {
    require(_target.code.length != 0, Deploy_NotDeployed(_target));
    _deployed = _target;
  }

  /// @notice Requires an address to carry the expected code hash.
  /// @param _component The record key that names the address, for the error.
  /// @param _target The address.
  /// @param _expected The code hash of the kit's code for that address.
  function _requireKitCode(string memory _component, address _target, bytes32 _expected) internal view {
    bytes32 _actual = _target.codehash;
    require(_actual == _expected, Deploy_CodeMismatch(_component, _target, _expected, _actual));
  }

  /// @notice Reads the P256VERIFY input for the known valid signature from the frozen vectors.
  /// @dev The values are the signature the passkey method's own tests accept, read rather than
  ///      copied into the script.
  /// @return _input signedHash || r || s || x || y, 160 bytes.
  function _p256VerifyInput() internal view returns (bytes memory _input) {
    string memory _root = vm.projectRoot();
    string memory _proofs = vm.readFile(string.concat(_root, _PASSKEY_PROOF_VECTORS));
    string memory _configs = vm.readFile(string.concat(_root, _PASSKEY_CONFIG_VECTORS));

    _input = abi.encode(
      vm.parseJsonBytes32(_proofs, string.concat(_VALID_PROOF_ROW, '.expected.signedHash')),
      vm.parseJsonUint(_proofs, string.concat(_VALID_PROOF_ROW, '.input.r')),
      vm.parseJsonUint(_proofs, string.concat(_VALID_PROOF_ROW, '.input.s')),
      vm.parseJsonUint(_configs, string.concat(_KEY_ROW, '.input.x')),
      vm.parseJsonUint(_configs, string.concat(_KEY_ROW, '.input.y'))
    );
  }

  /// @notice Runs the checks over one deployment: the action's first, then the method roles, the
  ///         ERC-165 answers and the method names last.
  /// @dev The two methods answer the role and ERC-165 checks the same way, so only their names tell
  ///      them apart. The name check is what catches a record that swaps the two.
  /// @param _deployment The deployment to check.
  /// @param _pins The pins it was deployed with.
  function _checkDeployment(Deployment memory _deployment, Pins memory _pins) internal view {
    _checkAction(_deployment.action, address(_deployment.manager), _pins.ambireImplementation);
    _checkKitSlot(_deployment.action);
    _checkMethodRoles(_deployment.ecdsaMethod);
    _checkMethodRoles(_deployment.passkeyMethod);
    _checkInterfaces(_deployment);
    _checkMethodName(_deployment.ecdsaMethod, _ECDSA_METHOD_KEY, _ECDSA_METHOD_NAME);
    _checkMethodName(_deployment.passkeyMethod, _PASSKEY_METHOD_KEY, _PASSKEY_METHOD_NAME);
  }

  /// @notice Requires the action to name the given manager and implementation, read back from it.
  ///         The action's constructor stores both as given, so this is where a wrong one is caught.
  /// @dev Each read is a guarded call, so an address that holds another contract, or none, fails
  ///      with Deploy_ReadFailed naming the action rather than with the target's own revert.
  /// @param _action The action.
  /// @param _manager The manager this run deployed.
  /// @param _implementation The pinned implementation.
  function _checkAction(IAmbireRecoveryAction _action, address _manager, address _implementation) internal view {
    address _actionManager = _readActionAddress(_action, abi.encodeCall(IAmbireRecoveryAction.MANAGER, ()));
    require(_actionManager == _manager, Deploy_ActionManagerMismatch(_manager, _actionManager));

    address _actionImplementation =
      _readActionAddress(_action, abi.encodeCall(IAmbireRecoveryAction.AMBIRE_IMPLEMENTATION, ()));
    require(
      _actionImplementation == _implementation,
      Deploy_ActionImplementationMismatch(_implementation, _actionImplementation)
    );
  }

  /// @notice Requires the action's slot to differ from the slot Ambire's helper derives for it.
  /// @dev Ambire's helper places a validator's entry at the low twenty bytes of
  ///      keccak256(abi.encode(validator, data)). With this action as the validator and empty
  ///      data, that is the slot the binding would take, computed here from the action's address.
  ///      The slot is read with a guarded call, so a failed read stops with Deploy_ReadFailed.
  /// @param _action The action.
  function _checkKitSlot(IAmbireRecoveryAction _action) internal view {
    address _kitSlot = _readActionAddress(_action, abi.encodeCall(IAmbireRecoveryAction.KIT_SLOT, ()));
    address _ambireHelperSlot = address(uint160(uint256(keccak256(abi.encode(address(_action), bytes(''))))));
    require(_kitSlot != _ambireHelperSlot, Deploy_KitSlotCollides(address(_action), _kitSlot));
  }

  /// @notice Requires a method to answer name() with the name its slot in the deployment expects.
  ///         The wallet guardians' approvals verify only at the wallet method, and the passkey
  ///         guardians' only at the passkey method, so a record that swaps the two breaks every
  ///         recovery it serves.
  /// @dev The name is read with a guarded call. A call that reverts, an empty answer or an answer
  ///      that is not a well-formed string stops with Deploy_ReadFailed naming the method's record
  ///      key, and a name that differs stops with Deploy_MethodMismatch.
  /// @param _method The method.
  /// @param _component The record key of the method's place, for the read error.
  /// @param _expected The name the method must answer.
  function _checkMethodName(IPolicyMethod _method, string memory _component, string memory _expected) internal view {
    (bool _read, string memory _actual) = _readString(address(_method), abi.encodeCall(IPolicyMethod.name, ()));
    require(_read, Deploy_ReadFailed(_component, address(_method)));
    require(
      keccak256(bytes(_actual)) == keccak256(bytes(_expected)),
      Deploy_MethodMismatch(address(_method), _expected, _actual)
    );
  }

  /// @notice Reads one address from the action and requires the read to succeed.
  /// @param _action The action.
  /// @param _callData The read.
  /// @return _value The address read.
  function _readActionAddress(IAmbireRecoveryAction _action, bytes memory _callData)
    internal
    view
    returns (address _value)
  {
    bool _read;
    (_read, _value) = _readAddress(address(_action), _callData);
    require(_read, Deploy_ReadFailed(_ACTION_KEY, address(_action)));
  }

  /// @notice Reads one address from a contract with a low-level static call.
  /// @dev The answer counts only when the call succeeded and returned exactly one word whose upper
  ///      twelve bytes are zero. A revert, an empty answer (what an address with no code gives) or
  ///      any other answer is a failed read.
  /// @param _target The contract read.
  /// @param _callData The read.
  /// @return _read Whether the read gave a well-formed address.
  /// @return _value The address read, or address(0) when the read failed.
  function _readAddress(address _target, bytes memory _callData) internal view returns (bool _read, address _value) {
    (bool _success, bytes memory _answer) = _target.staticcall(_callData);
    if (_success && _answer.length == _WORD) {
      if (abi.decode(_answer, (uint256)) >> 160 == 0) {
        _read = true;
        _value = abi.decode(_answer, (address));
      }
    }
  }

  /// @notice Reads one string from a contract with a low-level static call.
  /// @dev The answer counts only when the call succeeded and returned the encoding Solidity gives a
  ///      single string: an offset word equal to 32, a length word, and at least that many bytes
  ///      after them. Decoding is attempted only then, so a revert, an empty answer or a malformed
  ///      one is a failed read rather than a decode error.
  /// @param _target The contract read.
  /// @param _callData The read.
  /// @return _read Whether the read gave a well-formed string.
  /// @return _value The string read, or the empty string when the read failed.
  function _readString(address _target, bytes memory _callData)
    internal
    view
    returns (bool _read, string memory _value)
  {
    (bool _success, bytes memory _answer) = _target.staticcall(_callData);
    if (_success && _answer.length > 2 * _WORD - 1) {
      (uint256 _offset, uint256 _length) = abi.decode(_answer, (uint256, uint256));
      if (_offset == _WORD && _length < _answer.length - 2 * _WORD + 1) {
        _read = true;
        _value = abi.decode(_answer, (string));
      }
    }
  }

  /// @notice Requires a method to declare no key admin, no pending admin, no trusted key, no
  ///         pause holder and no pending pause holder. The wallet and passkey methods carry none,
  ///         so a rule built from them alone names no role.
  /// @dev The only answer accepted is the ABI encoding of nothing declared: four zero addresses
  ///      and an empty key list. Comparing the raw answer with that encoding, rather than decoding
  ///      it, makes a revert, a method with no code (an empty answer) and an answer too short or
  ///      too malformed to decode all fail with the same error, naming the method.
  /// @param _method The method.
  function _checkMethodRoles(IPolicyMethod _method) internal view {
    (bool _success, bytes memory _answer) =
      address(_method).staticcall(abi.encodeCall(IPolicyMethod.trustedParties, ()));
    bytes memory _nothingDeclared = abi.encode(address(0), address(0), new bytes32[](0), address(0), address(0));
    bool _declaresNothing = _success && keccak256(_answer) == keccak256(_nothingDeclared);
    require(_declaresNothing, Deploy_MethodDeclaresRoles(address(_method)));
  }

  /// @notice Requires every deployed contract to answer ERC-165 for each of its interfaces: the
  ///         manager for IPolicyManager, each method for IPolicyMethod, and the action for
  ///         IPolicyAction, IRecoveryAction and IAmbireRecoveryAction. The setup screen asks these
  ///         questions before it adopts a module.
  /// @param _deployment The deployment to check.
  function _checkInterfaces(Deployment memory _deployment) internal view {
    _requireInterface(address(_deployment.manager), type(IPolicyManager).interfaceId);
    _requireInterface(address(_deployment.ecdsaMethod), type(IPolicyMethod).interfaceId);
    _requireInterface(address(_deployment.passkeyMethod), type(IPolicyMethod).interfaceId);
    _requireInterface(address(_deployment.action), type(IPolicyAction).interfaceId);
    _requireInterface(address(_deployment.action), type(IRecoveryAction).interfaceId);
    _requireInterface(address(_deployment.action), type(IAmbireRecoveryAction).interfaceId);
  }

  /// @notice Requires a contract to answer ERC-165 with exactly one ABI-encoded true.
  /// @dev A low-level static call lets a revert, an empty answer or a malformed answer count as
  ///      no instead of reverting with the target's own error.
  /// @param _target The contract asked.
  /// @param _interfaceId The interface id asked about.
  function _requireInterface(address _target, bytes4 _interfaceId) internal view {
    (bool _success, bytes memory _answer) =
      _target.staticcall(abi.encodeWithSelector(IPolicyMethod.supportsInterface.selector, _interfaceId));
    require(
      _success && _answer.length == _WORD && abi.decode(_answer, (uint256)) == 1,
      Deploy_InterfaceNotSupported(_target, _interfaceId)
    );
  }

  /// @notice Requires the pin a candidate record holds to equal this chain's table entry.
  /// @dev The errors are the ones the deployment checks raise for the same mistake: a wrong code
  ///      hash is the implementation check's mismatch, and a wrong implementation address is the
  ///      action check's mismatch, each with the table's value as the expected one and the
  ///      candidate's value as the actual one.
  /// @param _json The candidate record.
  /// @param _pins This chain's table entry.
  function _requireRecordedPin(string memory _json, Pins memory _pins) internal pure {
    bytes32 _recordedCodehash = vm.parseJsonBytes32(_json, '.ambireImplementationCodehash');
    require(
      _recordedCodehash == _pins.ambireImplementationCodehash,
      Deploy_ImplementationCodehashMismatch(
        _pins.ambireImplementation, _pins.ambireImplementationCodehash, _recordedCodehash
      )
    );

    address _recordedImplementation = vm.parseJsonAddress(_json, '.ambireImplementation');
    require(
      _recordedImplementation == _pins.ambireImplementation,
      Deploy_ActionImplementationMismatch(_pins.ambireImplementation, _recordedImplementation)
    );
  }

  /// @notice Requires a P256VERIFY answer to be exactly the 32-byte word 1, the answer for a valid
  ///         signature. An empty answer is what a chain without the precompile returns.
  /// @param _answer What the precompile answered.
  function _checkP256VerifyAnswer(bytes memory _answer) internal pure {
    require(_answer.length == _WORD && abi.decode(_answer, (uint256)) == 1, Deploy_P256VerifyNotLive(_answer));
  }

  /// @notice The label rule: the decimal chain id without a set value, else the value once it
  ///         passes the character and length checks.
  /// @param _isSet Whether a label value was given.
  /// @param _value The label value, read only when _isSet is true.
  /// @param _chainId The chain id used when no value is set.
  /// @return _label The label.
  function _labelFor(bool _isSet, string memory _value, uint256 _chainId) internal pure returns (string memory _label) {
    if (_isSet) {
      _requireValidLabel(_value);
      _label = _value;
    } else {
      _label = vm.toString(_chainId);
    }
  }

  /// @notice Requires a label to be 1 to 64 characters of lowercase letters, digits and the
  ///         hyphen, with at least one character that is not a digit. A slash or a dot could lead
  ///         the record outside script/deployments, and a label of digits alone could take another
  ///         chain's default record name, such as 1.json written from Sepolia.
  /// @param _label The label.
  function _requireValidLabel(string memory _label) internal pure {
    bytes memory _characters = bytes(_label);
    bool _valid = _characters.length != 0 && _characters.length < _MAX_LABEL_LENGTH + 1;
    bool _hasNonDigit;
    for (uint256 _i; _valid && _i < _characters.length; ++_i) {
      _valid = _isLabelCharacter(_characters[_i]);
      _hasNonDigit = _hasNonDigit || !_isDigit(_characters[_i]);
    }
    require(_valid && _hasNonDigit, Deploy_InvalidLabel(_label));
  }

  /// @notice Tells whether a character may appear in a label.
  /// @dev The bounds sit one past the range: 0x60 and 0x7b around a to z.
  /// @param _character The character.
  /// @return _allowed True for a lowercase letter, a digit or the hyphen.
  function _isLabelCharacter(bytes1 _character) internal pure returns (bool _allowed) {
    bool _isLetter = _character > 0x60 && _character < 0x7b;
    _allowed = _isLetter || _isDigit(_character) || _character == '-';
  }

  /// @notice Tells whether a character is a decimal digit.
  /// @dev The bounds sit one past the range: 0x2f and 0x3a around 0 to 9.
  /// @param _character The character.
  /// @return _digit True for 0 to 9.
  function _isDigit(bytes1 _character) internal pure returns (bool _digit) {
    _digit = _character > 0x2f && _character < 0x3a;
  }

  /// @notice Looks up the pins for one chain in the table.
  /// @dev Virtual so that a configuration for another chain, such as the local test chain, can supply its own pins
  ///      and keep the deploy logic of this script.
  /// @param _chainId The chain id.
  /// @return _pins The pins for that chain.
  function _pinsFor(uint256 _chainId) internal pure virtual returns (Pins memory _pins) {
    require(_chainId == _MAINNET_CHAIN_ID || _chainId == _SEPOLIA_CHAIN_ID, Deploy_UnsupportedChain(_chainId));
    _pins = Pins({
      ambireImplementation: _AMBIRE_IMPLEMENTATION, ambireImplementationCodehash: _AMBIRE_IMPLEMENTATION_CODEHASH
    });
  }
}
