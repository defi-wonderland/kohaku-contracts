// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {IPolicyManager} from 'interfaces/IPolicyManager.sol';
import {IPolicyMethod} from 'interfaces/IPolicyMethod.sol';
import {IDeploy} from 'script/IDeploy.sol';
import {AmbireRecoveryAction} from 'contracts/actions/ambire/AmbireRecoveryAction.sol';
import {IAmbireRecoveryAction} from 'contracts/actions/ambire/IAmbireRecoveryAction.sol';
import {DeployMockLookAlike} from 'test/mocks/DeployMockLookAlike.sol';
import {DeployMockMethod} from 'test/mocks/DeployMockMethod.sol';
import {DeployForkTestBase} from 'test/utils/DeployForkTestBase.sol';

/// @notice confirmLabel, the whole of confirm, the operator's second step, for an explicit label,
///         on a mainnet fork, and on a Sepolia fork for the swapped methods. forge runs a whole script, file
///         writes included, before it sends any transaction, so run writes only a candidate record
///         and confirm publishes it once the chain holds what it names. Each test deploys the kit on
///         the fork, writes the candidate itself under a label used by no other test, passes that
///         label to confirmLabel, and removes every file it wrote. A published record that names
///         addresses which never landed, or another chain's deployment, would send every client of
///         the SDK to contracts that do not exist. Each test skips cleanly when its endpoint is unset:
///         MAINNET_RPC_URL, or SEPOLIA_RPC_URL for the one test on a Sepolia fork.
contract DeployConfirmLabelForkTest is DeployForkTestBase {
  /// @notice Ambire's account factory on mainnet, a contract that has code and is not the pin.
  address internal constant _AMBIRE_FACTORY = 0x26cE6745A633030A6faC5e64e41D21fb6246dc2d;
  /// @notice The number of keys a published record holds: the chain id, the four addresses, the
  ///         Ambire implementation and its code hash.
  uint256 internal constant _RECORD_KEY_COUNT = 7;

  function _pendingPath(string memory _label) internal pure returns (string memory _path) {
    _path = string.concat('script/deployments/', _label, '.pending.json');
  }

  function _publishedPath(string memory _label) internal pure returns (string memory _path) {
    _path = string.concat('script/deployments/', _label, '.json');
  }

  /// @notice Removes the candidate and the published record of `_label` when they exist.
  function _clean(string memory _label) internal {
    if (vm.exists(_pendingPath(_label))) vm.removeFile(_pendingPath(_label));
    if (vm.exists(_publishedPath(_label))) vm.removeFile(_publishedPath(_label));
  }

  /// @notice Deploys the kit on the fork with the table's pins, makes sure script/deployments
  ///         exists, and clears any file `_label` left.
  function _deployFor(string memory _label)
    internal
    returns (IDeploy.Deployment memory _deployment, IDeploy.Pins memory _chainPins)
  {
    _chainPins = _script.pinsFor(block.chainid);
    _deployment = _script.deploy(_chainPins);
    vm.createDir('script/deployments', true);
    _clean(_label);
  }

  /// @notice Writes the candidate `_json` under `_label`, runs confirmLabel expecting exactly
  ///         `_expectedRevert`, requires that no published record was left, and cleans up.
  function _confirmExpectingRevert(string memory _label, string memory _json, bytes memory _expectedRevert) internal {
    vm.writeFile(_pendingPath(_label), _json);
    vm.expectRevert(_expectedRevert);
    _script.confirmLabel(_label);
    assertFalse(vm.exists(_publishedPath(_label)), 'a published record after a revert');
    _clean(_label);
  }

  /// confirmLabel publishes the candidate under <label>.json byte for byte, removes the candidate,
  /// and returns the recorded deployment, when every recorded value holds on chain. The candidate is
  /// written with vm.writeJson, pretty-printed, as run writes it, so a confirm that rewrote the
  /// record in another layout, compact or otherwise, would publish a file that differs from the one
  /// the operator reviewed.
  function test_WhenTheCandidateHoldsOnChain() external {
    if (!_forkMainnet()) return;
    string memory _label = 'test-confirm-publishes';
    (IDeploy.Deployment memory _deployment, IDeploy.Pins memory _chainPins) = _deployFor(_label);
    string memory _json = _script.recordJson(_deployment, _chainPins, block.chainid);
    vm.writeJson(_json, _pendingPath(_label));
    bytes memory _candidateBytes = bytes(vm.readFile(_pendingPath(_label)));
    assertNotEq(_candidateBytes, bytes(_json), 'fixture: the candidate is not pretty-printed');
    IDeploy.Deployment memory _confirmed = _script.confirmLabel(_label);
    // it should publish the candidate's bytes under the label
    assertTrue(vm.exists(_publishedPath(_label)), 'published record');
    assertEq(bytes(vm.readFile(_publishedPath(_label))), _candidateBytes, 'published bytes');
    // it should remove the candidate
    assertFalse(vm.exists(_pendingPath(_label)), 'candidate left behind');
    // it should return the recorded deployment
    assertEq(address(_confirmed.manager), address(_deployment.manager), 'manager');
    assertEq(address(_confirmed.ecdsaMethod), address(_deployment.ecdsaMethod), 'wallet method');
    assertEq(address(_confirmed.passkeyMethod), address(_deployment.passkeyMethod), 'passkey method');
    assertEq(address(_confirmed.action), address(_deployment.action), 'action');
    _clean(_label);
  }

  /// confirmLabel with no fork active stops on the P256VERIFY probe before it reads the candidate, so
  /// a chain without the precompile never gets a record. No candidate file exists, so reading it first
  /// would give forge's file error instead of the revert checkP256Verify gives alone. The test chain
  /// takes Sepolia's chain id first: confirm looks up the chain's pins before the probe, so on the
  /// local chain id it would stop on the unsupported chain error instead and never reach the probe.
  function test_RevertWhen_NoForkIsActive() external {
    vm.chainId(_SEPOLIA_CHAIN_ID);
    string memory _label = 'test-confirm-no-fork';
    vm.createDir('script/deployments', true);
    _clean(_label);
    bytes memory _probeRevert;
    try _script.checkP256Verify() {
      fail('the probe passed with no fork');
    } catch (bytes memory _reason) {
      _probeRevert = _reason;
    }
    bytes memory _confirmRevert;
    bool _confirmed;
    try _script.confirmLabel(_label) {
      _confirmed = true;
    } catch (bytes memory _reason) {
      _confirmRevert = _reason;
    }
    bool _published = vm.exists(_publishedPath(_label));
    bool _candidateWritten = vm.exists(_pendingPath(_label));
    _clean(_label);
    // it should revert
    assertFalse(_confirmed, 'confirm passed with no fork');
    // it should carry the probe's revert data
    assertEq(_confirmRevert, _probeRevert, 'revert data');
    // it should publish no record
    assertFalse(_published, 'a published record after a revert');
    // it should write no candidate
    assertFalse(_candidateWritten, 'a candidate after a revert');
  }

  /// confirmLabel reverts naming both chain ids, and publishes nothing, when the candidate records
  /// Sepolia's chain id on mainnet, a record written on another chain.
  function test_RevertWhen_TheCandidateNamesAnotherChain() external {
    if (!_forkMainnet()) return;
    string memory _label = 'test-confirm-other-chain';
    (IDeploy.Deployment memory _deployment, IDeploy.Pins memory _chainPins) = _deployFor(_label);
    // it should revert
    // it should name the recorded and the current chain id
    // it should publish no record
    _confirmExpectingRevert(
      _label,
      _script.recordJson(_deployment, _chainPins, _SEPOLIA_CHAIN_ID),
      abi.encodeWithSelector(IDeploy.Deploy_RecordChainMismatch.selector, _SEPOLIA_CHAIN_ID, block.chainid)
    );
  }

  /// @notice Runs confirm over a candidate whose deployment names `_missing`, an address with no
  ///         code, in the place `_deployment` already carries it, expecting the not deployed error.
  function _expectNotDeployed(
    string memory _label,
    IDeploy.Deployment memory _deployment,
    IDeploy.Pins memory _chainPins,
    address _missing
  ) internal {
    _confirmExpectingRevert(
      _label,
      _script.recordJson(_deployment, _chainPins, block.chainid),
      abi.encodeWithSelector(IDeploy.Deploy_NotDeployed.selector, _missing)
    );
  }

  /// confirmLabel reverts naming the manager address, and publishes nothing, when the recorded manager
  /// has no code, as when its transaction never landed. The address is hashed from a label.
  function test_RevertWhen_TheRecordedManagerHasNoCode() external {
    if (!_forkMainnet()) return;
    string memory _label = 'test-confirm-no-manager';
    (IDeploy.Deployment memory _deployment, IDeploy.Pins memory _chainPins) = _deployFor(_label);
    address _missing = _freshAddress('notDeployedManager', 0);
    _deployment.manager = IPolicyManager(_missing);
    // it should revert
    // it should name the address in the not deployed error
    // it should publish no record
    _expectNotDeployed(_label, _deployment, _chainPins, _missing);
  }

  /// confirmLabel reverts naming the wallet method's address, and publishes nothing, when the recorded
  /// wallet method has no code. The address is hashed from a label.
  function test_RevertWhen_TheRecordedWalletMethodHasNoCode() external {
    if (!_forkMainnet()) return;
    string memory _label = 'test-confirm-no-wallet-method';
    (IDeploy.Deployment memory _deployment, IDeploy.Pins memory _chainPins) = _deployFor(_label);
    address _missing = _freshAddress('notDeployedWalletMethod', 0);
    _deployment.ecdsaMethod = IPolicyMethod(_missing);
    // it should revert
    // it should name the address in the not deployed error
    // it should publish no record
    _expectNotDeployed(_label, _deployment, _chainPins, _missing);
  }

  /// confirmLabel reverts naming the passkey method's address, and publishes nothing, when the recorded
  /// passkey method has no code. The address is hashed from a label.
  function test_RevertWhen_TheRecordedPasskeyMethodHasNoCode() external {
    if (!_forkMainnet()) return;
    string memory _label = 'test-confirm-no-passkey-method';
    (IDeploy.Deployment memory _deployment, IDeploy.Pins memory _chainPins) = _deployFor(_label);
    address _missing = _freshAddress('notDeployedPasskeyMethod', 0);
    _deployment.passkeyMethod = IPolicyMethod(_missing);
    // it should revert
    // it should name the address in the not deployed error
    // it should publish no record
    _expectNotDeployed(_label, _deployment, _chainPins, _missing);
  }

  /// confirmLabel reverts naming the action's address, and publishes nothing, when the recorded action
  /// has no code. The address is hashed from a label.
  function test_RevertWhen_TheRecordedActionHasNoCode() external {
    if (!_forkMainnet()) return;
    string memory _label = 'test-confirm-no-action';
    (IDeploy.Deployment memory _deployment, IDeploy.Pins memory _chainPins) = _deployFor(_label);
    address _missing = _freshAddress('notDeployedAction', 0);
    _deployment.action = IAmbireRecoveryAction(_missing);
    // it should revert
    // it should name the address in the not deployed error
    // it should publish no record
    _expectNotDeployed(_label, _deployment, _chainPins, _missing);
  }

  /// confirmLabel reverts naming the recorded manager and the action's own, and publishes nothing,
  /// when the candidate names the manager of a second kit deployed on the same fork, a manager
  /// with code that is not the action's. A record whose manager is not the action's would have
  /// clients sign approvals for a manager the account's action never calls, and a confirm that
  /// wrote the record before this check would leave it published.
  function test_RevertWhen_TheRecordedManagerIsAnotherManagerWithCode() external {
    if (!_forkMainnet()) return;
    string memory _label = 'test-confirm-other-manager';
    (IDeploy.Deployment memory _deployment, IDeploy.Pins memory _chainPins) = _deployFor(_label);
    address _actionManager = address(_deployment.manager);
    IPolicyManager _otherManager = _script.deploy(_chainPins).manager;
    assertGt(address(_otherManager).code.length, 0, 'fixture: the other manager has no code');
    _deployment.manager = _otherManager;
    // it should revert
    // it should name the recorded manager and the action's manager
    // it should publish no record
    _confirmExpectingRevert(
      _label,
      _script.recordJson(_deployment, _chainPins, block.chainid),
      abi.encodeWithSelector(IDeploy.Deploy_ActionManagerMismatch.selector, address(_otherManager), _actionManager)
    );
  }

  /// confirmLabel reverts naming the passkey method, the name method-ecdsa and the name it
  /// answered, and publishes nothing, when the candidate on a Sepolia fork names the wallet and
  /// passkey methods in each other's place. Both methods declare no role and answer the same
  /// interfaces, so only their names tell them apart, and a swapped record would send every
  /// wallet guardian to the passkey method.
  function test_RevertWhen_TheCandidateSwapsTheTwoMethods() external {
    if (!_forkSepolia()) return;
    string memory _label = 'test-confirm-swapped-methods';
    (IDeploy.Deployment memory _deployment, IDeploy.Pins memory _chainPins) = _deployFor(_label);
    address _passkeyMethod = address(_deployment.passkeyMethod);
    (_deployment.ecdsaMethod, _deployment.passkeyMethod) = (_deployment.passkeyMethod, _deployment.ecdsaMethod);
    // it should revert
    // it should name the passkey method, the expected name and the answered name
    // it should publish no record
    _confirmExpectingRevert(
      _label,
      _script.recordJson(_deployment, _chainPins, block.chainid),
      abi.encodeWithSelector(IDeploy.Deploy_MethodMismatch.selector, _passkeyMethod, 'method-ecdsa', 'method-passkey')
    );
  }

  /// confirmLabel reverts naming the table's implementation, the table's codehash and the recorded
  /// codehash, and publishes nothing, when the candidate records the table's pin with another
  /// codehash. The table's values are always the expected ones.
  function test_RevertWhen_TheRecordedCodehashDiffersFromTheTable() external {
    if (!_forkMainnet()) return;
    string memory _label = 'test-confirm-other-codehash';
    (IDeploy.Deployment memory _deployment, IDeploy.Pins memory _chainPins) = _deployFor(_label);
    bytes32 _recordedCodehash = keccak256('otherCodehash');
    IDeploy.Pins memory _recorded = IDeploy.Pins({
      ambireImplementation: _chainPins.ambireImplementation, ambireImplementationCodehash: _recordedCodehash
    });
    // it should revert
    // it should name the table's implementation, the table's codehash and the recorded codehash
    // it should publish no record
    _confirmExpectingRevert(
      _label,
      _script.recordJson(_deployment, _recorded, block.chainid),
      abi.encodeWithSelector(
        IDeploy.Deploy_ImplementationCodehashMismatch.selector,
        _chainPins.ambireImplementation,
        _chainPins.ambireImplementationCodehash,
        _recordedCodehash
      )
    );
  }

  /// confirmLabel reverts naming the table's implementation and the recorded one, and publishes
  /// nothing, when the candidate records another contract that has code, Ambire's factory, with
  /// the table's codehash. The codehash comparison passes, so the address comparison refuses it.
  function test_RevertWhen_TheRecordedPinDiffersFromTheTable() external {
    if (!_forkMainnet()) return;
    string memory _label = 'test-confirm-other-pin';
    (IDeploy.Deployment memory _deployment, IDeploy.Pins memory _chainPins) = _deployFor(_label);
    IDeploy.Pins memory _recorded = IDeploy.Pins({
      ambireImplementation: _AMBIRE_FACTORY, ambireImplementationCodehash: _chainPins.ambireImplementationCodehash
    });
    // it should revert
    // it should name the table's implementation and the recorded one
    // it should publish no record
    _confirmExpectingRevert(
      _label,
      _script.recordJson(_deployment, _recorded, block.chainid),
      abi.encodeWithSelector(
        IDeploy.Deploy_ActionImplementationMismatch.selector, _chainPins.ambireImplementation, _AMBIRE_FACTORY
      )
    );
  }

  /*///////////////////////////////////////////////////////////////
                    A RECORD REBUILT FROM CHECKED VALUES
  ///////////////////////////////////////////////////////////////*/

  /// @notice Publishes the candidate `_json` under `_label` and requires the published record to
  ///         hold exactly the seven record keys, each equal to the value confirm checked, and not
  ///         `_extraKey`. Removes the files it wrote.
  function _confirmAndRequireCheckedRecord(
    string memory _label,
    string memory _json,
    IDeploy.Deployment memory _deployment,
    IDeploy.Pins memory _chainPins,
    string memory _extraKey
  ) internal {
    vm.writeFile(_pendingPath(_label), _json);
    _script.confirmLabel(_label);
    string memory _published = vm.readFile(_publishedPath(_label));
    _clean(_label);
    assertFalse(vm.keyExistsJson(_published, string.concat('.', _extraKey)), 'the extra key was published');
    assertEq(vm.parseJsonKeys(_published, '$').length, _RECORD_KEY_COUNT, 'key count');
    assertEq(vm.parseJsonUint(_published, '.chainId'), block.chainid, 'chainId');
    assertEq(vm.parseJsonAddress(_published, '.policyManager'), address(_deployment.manager), 'policyManager');
    assertEq(vm.parseJsonAddress(_published, '.ecdsaMethod'), address(_deployment.ecdsaMethod), 'ecdsaMethod');
    assertEq(vm.parseJsonAddress(_published, '.passkeyMethod'), address(_deployment.passkeyMethod), 'passkeyMethod');
    assertEq(vm.parseJsonAddress(_published, '.recoveryAction'), address(_deployment.action), 'recoveryAction');
    assertEq(
      vm.parseJsonAddress(_published, '.ambireImplementation'), _chainPins.ambireImplementation, 'ambireImplementation'
    );
    assertEq(
      vm.parseJsonBytes32(_published, '.ambireImplementationCodehash'),
      _chainPins.ambireImplementationCodehash,
      'ambireImplementationCodehash'
    );
  }

  /// confirmLabel publishes a record without the key recoveryActionV2 when the candidate adds it,
  /// naming an address of its own, to a record that holds on chain. No check reads that key, so a
  /// confirm that copied the candidate's text would publish an unchecked address an SDK might call.
  /// The published record holds exactly the seven record keys, each the value confirm checked.
  function test_WhenTheCandidateCarriesAnExtraAddressKey() external {
    if (!_forkMainnet()) return;
    string memory _label = 'test-confirm-extra-address-key';
    (IDeploy.Deployment memory _deployment, IDeploy.Pins memory _chainPins) = _deployFor(_label);
    vm.serializeJson('extraAddressKey', _script.recordJson(_deployment, _chainPins, block.chainid));
    string memory _json =
      vm.serializeAddress('extraAddressKey', 'recoveryActionV2', _freshAddress('extraRecoveryActionV2', 0));
    assertTrue(vm.keyExistsJson(_json, '.recoveryActionV2'), 'fixture: the candidate lacks the extra key');
    // it should publish no key the checks did not read
    // it should publish exactly the seven record keys, each the checked value
    _confirmAndRequireCheckedRecord(_label, _json, _deployment, _chainPins, 'recoveryActionV2');
  }

  /// confirmLabel publishes a record without the field sdkEndpoint when the candidate adds that
  /// unrelated string field to a record that holds on chain, so nothing a hand edit adds reaches the
  /// file the SDK reads. The published record holds exactly the seven record keys, each the value
  /// confirm checked.
  function test_WhenTheCandidateCarriesAnExtraUnrelatedField() external {
    if (!_forkMainnet()) return;
    string memory _label = 'test-confirm-extra-field';
    (IDeploy.Deployment memory _deployment, IDeploy.Pins memory _chainPins) = _deployFor(_label);
    vm.serializeJson('extraField', _script.recordJson(_deployment, _chainPins, block.chainid));
    string memory _json = vm.serializeString('extraField', 'sdkEndpoint', 'https://example.invalid/rpc');
    assertTrue(vm.keyExistsJson(_json, '.sdkEndpoint'), 'fixture: the candidate lacks the extra field');
    // it should publish no key the checks did not read
    // it should publish exactly the seven record keys, each the checked value
    _confirmAndRequireCheckedRecord(_label, _json, _deployment, _chainPins, 'sdkEndpoint');
  }

  /*///////////////////////////////////////////////////////////////
                            LOOK-ALIKES
  ///////////////////////////////////////////////////////////////*/

  /// @notice Writes the candidate `_json` under `_label`, runs confirmLabel, requires it to revert
  ///         with the code mismatch error, that no record was published, and cleans up. Returns the
  ///         error's four values.
  function _confirmExpectingCodeMismatch(string memory _label, string memory _json)
    internal
    returns (string memory _component, address _target, bytes32 _expected, bytes32 _actual)
  {
    vm.writeFile(_pendingPath(_label), _json);
    bytes memory _reason;
    try _script.confirmLabel(_label) {
      fail('confirmLabel did not revert');
    } catch (bytes memory _caught) {
      _reason = _caught;
    }
    assertFalse(vm.exists(_publishedPath(_label)), 'a published record after a revert');
    _clean(_label);
    assertGe(_reason.length, 4, 'revert data shorter than a selector');
    bytes memory _arguments = new bytes(_reason.length - 4);
    for (uint256 _i; _i < _arguments.length; ++_i) {
      _arguments[_i] = _reason[_i + 4];
    }
    assertEq(_reason, abi.encodePacked(IDeploy.Deploy_CodeMismatch.selector, _arguments), 'the code mismatch error');
    (_component, _target, _expected, _actual) = abi.decode(_arguments, (string, address, bytes32, bytes32));
  }

  /// @notice Requires a code mismatch error to name `_component` at `_target`, with `_expected` as
  ///         the kit's code hash and the look-alike's own code hash as the one found.
  function _assertCodeMismatch(
    string memory _component,
    address _target,
    bytes32 _expected,
    string memory _expectedComponent,
    address _lookAlike,
    bytes32 _kitCodehash
  ) internal pure {
    assertEq(_component, _expectedComponent, 'component');
    assertEq(_target, _lookAlike, 'target');
    assertEq(_expected, _kitCodehash, 'expected code hash');
  }

  /// confirmLabel reverts with the code mismatch naming policyManager, and publishes nothing, when
  /// the candidate's manager is a look-alike: a different contract that passes every call on to the
  /// real manager, so it answers ERC-165 like it, served by a genuine action built for the
  /// look-alike. Every other check passes, so only the code hash tells it apart, and a record
  /// naming it would send every approval to code nobody reviewed.
  function test_RevertWhen_TheRecordedManagerIsALookAlike() external {
    if (!_forkMainnet()) return;
    string memory _label = 'test-confirm-look-alike-manager';
    (IDeploy.Deployment memory _deployment, IDeploy.Pins memory _chainPins) = _deployFor(_label);
    bytes32 _kitCodehash = address(_deployment.manager).codehash;
    address _lookAlike = address(new DeployMockLookAlike(address(_deployment.manager)));
    bytes32 _lookAlikeCodehash = _lookAlike.codehash;
    _deployment.manager = IPolicyManager(_lookAlike);
    _deployment.action = IAmbireRecoveryAction(
      address(new AmbireRecoveryAction(IPolicyManager(_lookAlike), _chainPins.ambireImplementation))
    );
    // it should revert
    // it should name policyManager, the look-alike, the kit's code hash and the one found
    // it should publish no record
    (string memory _component, address _target, bytes32 _expected, bytes32 _actual) =
      _confirmExpectingCodeMismatch(_label, _script.recordJson(_deployment, _chainPins, block.chainid));
    _assertCodeMismatch(_component, _target, _expected, 'policyManager', _lookAlike, _kitCodehash);
    assertEq(_actual, _lookAlikeCodehash, 'actual code hash');
  }

  /// @notice The code hash the kit's action has when built at `_where` for `_manager` and
  ///         `_implementation`. The action's constructor derives values from its own address, so
  ///         the kit's code depends on where it sits. The state is restored afterwards.
  function _kitActionCodehashAt(address _where, address _manager, address _implementation)
    internal
    returns (bytes32 _codehash)
  {
    bytes memory _lookAlikeCode = _where.code;
    deployCodeTo('AmbireRecoveryAction.sol:AmbireRecoveryAction', abi.encode(_manager, _implementation), _where);
    _codehash = _where.codehash;
    vm.etch(_where, _lookAlikeCode);
  }

  /// confirmLabel reverts with the code mismatch naming recoveryAction, and publishes nothing, when
  /// the candidate's action is a look-alike that passes every call on to the real action, so it
  /// answers MANAGER, AMBIRE_IMPLEMENTATION, KIT_SLOT and ERC-165 like it. The expected code hash is
  /// the kit's action built at the look-alike's address with the same manager and implementation.
  /// An account that bound a look-alike would hand its keys to code nobody reviewed.
  function test_RevertWhen_TheRecordedActionIsALookAlike() external {
    if (!_forkMainnet()) return;
    string memory _label = 'test-confirm-look-alike-action';
    (IDeploy.Deployment memory _deployment, IDeploy.Pins memory _chainPins) = _deployFor(_label);
    address _lookAlike = address(new DeployMockLookAlike(address(_deployment.action)));
    bytes32 _kitCodehash =
      _kitActionCodehashAt(_lookAlike, address(_deployment.manager), _chainPins.ambireImplementation);
    bytes32 _lookAlikeCodehash = _lookAlike.codehash;
    _deployment.action = IAmbireRecoveryAction(_lookAlike);
    // it should revert
    // it should name recoveryAction, the look-alike, the kit's code hash and the one found
    // it should publish no record
    (string memory _component, address _target, bytes32 _expected, bytes32 _actual) =
      _confirmExpectingCodeMismatch(_label, _script.recordJson(_deployment, _chainPins, block.chainid));
    _assertCodeMismatch(_component, _target, _expected, 'recoveryAction', _lookAlike, _kitCodehash);
    assertEq(_actual, _lookAlikeCodehash, 'actual code hash');
  }

  /// confirmLabel reverts with the code mismatch naming the look-alike manager or the look-alike
  /// action, and publishes nothing, when the candidate names both: a manager that passes every
  /// call on to the real manager, and an action that passes every call on to the real action but
  /// answers MANAGER with the look-alike manager. The pair passes every view check together, so
  /// either code hash must refuse it.
  function test_RevertWhen_TheRecordedManagerAndActionAreLookAlikes() external {
    if (!_forkMainnet()) return;
    string memory _label = 'test-confirm-look-alike-pair';
    (IDeploy.Deployment memory _deployment, IDeploy.Pins memory _chainPins) = _deployFor(_label);
    bytes32 _kitManagerCodehash = address(_deployment.manager).codehash;
    address _lookAlikeManager = address(new DeployMockLookAlike(address(_deployment.manager)));
    DeployMockLookAlike _lookAlikeAction = new DeployMockLookAlike(address(_deployment.action));
    _lookAlikeAction.setAnswer(IAmbireRecoveryAction.MANAGER.selector, abi.encode(_lookAlikeManager));
    assertEq(
      address(IAmbireRecoveryAction(address(_lookAlikeAction)).MANAGER()),
      _lookAlikeManager,
      'fixture: the look-alike action names another manager'
    );
    bytes32 _kitActionCodehash =
      _kitActionCodehashAt(address(_lookAlikeAction), _lookAlikeManager, _chainPins.ambireImplementation);
    bytes32 _managerCodehash = _lookAlikeManager.codehash;
    bytes32 _actionCodehash = address(_lookAlikeAction).codehash;
    _deployment.manager = IPolicyManager(_lookAlikeManager);
    _deployment.action = IAmbireRecoveryAction(address(_lookAlikeAction));
    // it should revert
    // it should name either look-alike with the kit's code hash and the one found
    // it should publish no record
    (string memory _component, address _target, bytes32 _expected, bytes32 _actual) =
      _confirmExpectingCodeMismatch(_label, _script.recordJson(_deployment, _chainPins, block.chainid));
    if (_target == _lookAlikeManager) {
      _assertCodeMismatch(_component, _target, _expected, 'policyManager', _lookAlikeManager, _kitManagerCodehash);
    } else {
      _assertCodeMismatch(
        _component, _target, _expected, 'recoveryAction', address(_lookAlikeAction), _kitActionCodehash
      );
    }
    assertEq(_actual, _target == _lookAlikeManager ? _managerCodehash : _actionCodehash, 'actual code hash');
  }

  /// confirmLabel reverts with the code mismatch naming ecdsaMethod, and publishes nothing, when the
  /// candidate's wallet method is a look-alike that passes every call on to the real one, so it
  /// answers name, trustedParties and ERC-165 like it. A record naming it would send every wallet
  /// guardian's approval to code nobody reviewed.
  function test_RevertWhen_TheRecordedWalletMethodIsALookAlike() external {
    if (!_forkMainnet()) return;
    string memory _label = 'test-confirm-look-alike-wallet';
    (IDeploy.Deployment memory _deployment, IDeploy.Pins memory _chainPins) = _deployFor(_label);
    bytes32 _kitCodehash = address(_deployment.ecdsaMethod).codehash;
    address _lookAlike = address(new DeployMockLookAlike(address(_deployment.ecdsaMethod)));
    bytes32 _lookAlikeCodehash = _lookAlike.codehash;
    _deployment.ecdsaMethod = IPolicyMethod(_lookAlike);
    // it should revert
    // it should name ecdsaMethod, the look-alike, the kit's code hash and the one found
    // it should publish no record
    (string memory _component, address _target, bytes32 _expected, bytes32 _actual) =
      _confirmExpectingCodeMismatch(_label, _script.recordJson(_deployment, _chainPins, block.chainid));
    _assertCodeMismatch(_component, _target, _expected, 'ecdsaMethod', _lookAlike, _kitCodehash);
    assertEq(_actual, _lookAlikeCodehash, 'actual code hash');
  }

  /// confirmLabel reverts with the code mismatch naming passkeyMethod, and publishes nothing, when
  /// the candidate's passkey method is a look-alike that passes every call on to the real one, so it
  /// answers name, trustedParties and ERC-165 like it.
  function test_RevertWhen_TheRecordedPasskeyMethodIsALookAlike() external {
    if (!_forkMainnet()) return;
    string memory _label = 'test-confirm-look-alike-passkey';
    (IDeploy.Deployment memory _deployment, IDeploy.Pins memory _chainPins) = _deployFor(_label);
    bytes32 _kitCodehash = address(_deployment.passkeyMethod).codehash;
    address _lookAlike = address(new DeployMockLookAlike(address(_deployment.passkeyMethod)));
    bytes32 _lookAlikeCodehash = _lookAlike.codehash;
    _deployment.passkeyMethod = IPolicyMethod(_lookAlike);
    // it should revert
    // it should name passkeyMethod, the look-alike, the kit's code hash and the one found
    // it should publish no record
    (string memory _component, address _target, bytes32 _expected, bytes32 _actual) =
      _confirmExpectingCodeMismatch(_label, _script.recordJson(_deployment, _chainPins, block.chainid));
    _assertCodeMismatch(_component, _target, _expected, 'passkeyMethod', _lookAlike, _kitCodehash);
    assertEq(_actual, _lookAlikeCodehash, 'actual code hash');
  }

  /*///////////////////////////////////////////////////////////////
                           FAILED READS
  ///////////////////////////////////////////////////////////////*/

  /// confirmLabel reverts naming recoveryAction and the recorded address, and publishes nothing,
  /// when the candidate's action address holds the deployed manager, a contract with none of the
  /// action's views, as when a broadcast lands out of order. The operator must learn which record
  /// key names a contract that cannot be read, not meet a bare revert.
  function test_RevertWhen_TheRecordedActionHoldsTheManager() external {
    if (!_forkMainnet()) return;
    string memory _label = 'test-confirm-action-holds-manager';
    (IDeploy.Deployment memory _deployment, IDeploy.Pins memory _chainPins) = _deployFor(_label);
    address _manager = address(_deployment.manager);
    _deployment.action = IAmbireRecoveryAction(_manager);
    // it should revert
    // it should name recoveryAction and the recorded address in the read failure
    // it should publish no record
    _confirmExpectingRevert(
      _label,
      _script.recordJson(_deployment, _chainPins, block.chainid),
      abi.encodeWithSelector(IDeploy.Deploy_ReadFailed.selector, 'recoveryAction', _manager)
    );
  }

  /// confirmLabel reverts naming ecdsaMethod and the recorded address, and publishes nothing, when
  /// the candidate's wallet method address holds a stand-in that declares no role and answers every
  /// interface but whose name call reverts, so only the name read fails.
  function test_RevertWhen_TheRecordedWalletMethodCannotBeNamed() external {
    if (!_forkMainnet()) return;
    string memory _label = 'test-confirm-wallet-method-no-name';
    (IDeploy.Deployment memory _deployment, IDeploy.Pins memory _chainPins) = _deployFor(_label);
    DeployMockMethod _method = new DeployMockMethod();
    _method.revertName();
    _deployment.ecdsaMethod = IPolicyMethod(address(_method));
    // it should revert
    // it should name ecdsaMethod and the recorded address in the read failure
    // it should publish no record
    _confirmExpectingRevert(
      _label,
      _script.recordJson(_deployment, _chainPins, block.chainid),
      abi.encodeWithSelector(IDeploy.Deploy_ReadFailed.selector, 'ecdsaMethod', address(_method))
    );
  }
}
