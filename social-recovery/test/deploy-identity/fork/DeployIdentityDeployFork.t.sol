// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {VmSafe} from 'forge-std/Vm.sol';
import {IPolicyMethod} from 'interfaces/IPolicyMethod.sol';
import {IPolicyMethodAdmin} from 'interfaces/IPolicyMethodAdmin.sol';
import {IPolicyMethodPause} from 'interfaces/IPolicyMethodPause.sol';
import {IDeployIdentity} from 'script/IDeployIdentity.sol';
import {IAadhaarMethod} from 'contracts/methods/aadhaar/IAadhaarMethod.sol';
import {DeployIdentityForkTestBase} from 'test/utils/DeployIdentityForkTestBase.sol';

/// @notice deploy against the real chains. It checks the operator's inputs, the table's code, the zkPassport words
///         against the live contracts and the Aadhaar key, creates the zkPassport method everywhere and the Aadhaar
///         method on Sepolia alone, then checks what it created. forge script simulates the whole run before it
///         sends a transaction, so a check that fails before the first creation keeps a bad input or pin from ever
///         reaching the chain. The tests record every account access, reverted ones included, so a contract
///         created and then undone by the revert still counts. Each test skips cleanly when its endpoint is unset.
contract DeployIdentityDeployForkTest is DeployIdentityForkTestBase {
  /*///////////////////////////////////////////////////////////////
                          GOOD VALUES
  ///////////////////////////////////////////////////////////////*/

  /// deploy on Sepolia broadcasts exactly two creations, the zkPassport and Aadhaar methods it returns. A proxy
  /// or any other extra contract would add a creation, and the identity methods deploy directly. The count is of
  /// what the broadcaster creates, the transactions a broadcast sends: the local Aadhaar copy the code check
  /// builds after the broadcast stops is never sent, so it does not count.
  function test_WhenSepoliasTableIsDeployed() external {
    if (!_forkSepolia()) return;
    IDeployIdentity.Pins memory _table = _script.pinsFor(block.chainid);
    vm.startStateDiffRecording();
    IDeployIdentity.Deployment memory _deployment = _script.deploy(_table, _liveInputs(_table));
    VmSafe.AccountAccess[] memory _accesses = vm.stopAndReturnStateDiff();
    // it should create exactly the two returned methods
    assertEq(_broadcastCreations(_accesses), 2, 'creations');
    assertTrue(address(_deployment.zkPassportMethod).code.length != 0, 'zkPassport method');
    assertTrue(address(_deployment.aadhaarMethod).code.length != 0, 'Aadhaar method');
    for (uint256 _i; _i < _accesses.length; ++_i) {
      if (_accesses[_i].kind != VmSafe.AccountAccessKind.Create || _accesses[_i].accessor != DEFAULT_SENDER) continue;
      address _created = _accesses[_i].account;
      assertTrue(
        _created == address(_deployment.zkPassportMethod) || _created == address(_deployment.aadhaarMethod),
        'a creation the deployment does not return'
      );
    }
  }

  /// deploy on mainnet creates exactly one contract, the zkPassport method it returns, and returns the zero
  /// address for the Aadhaar method, since no Aadhaar verifier is published on mainnet. The inputs give the Aadhaar
  /// method's Safe as the zero address, which a chain without that method accepts.
  function test_WhenMainnetsTableIsDeployed() external {
    if (!_forkMainnet()) return;
    IDeployIdentity.Pins memory _table = _script.pinsFor(block.chainid);
    vm.startStateDiffRecording();
    IDeployIdentity.Deployment memory _deployment = _script.deploy(_table, _liveInputs(_table));
    VmSafe.AccountAccess[] memory _accesses = vm.stopAndReturnStateDiff();
    // it should create only the zkPassport method
    assertEq(_creations(_accesses), 1, 'creations');
    assertTrue(address(_deployment.zkPassportMethod).code.length != 0, 'zkPassport method');
    // it should return no Aadhaar method
    assertEq(address(_deployment.aadhaarMethod), address(0), 'Aadhaar method');
  }

  /// The zkPassport method deploy returns on Sepolia declares its own Safe as key admin and pause holder, not the
  /// Aadhaar method's Safe, which the inputs make a different address, no open handover, and the eight words in the
  /// method's order, so a holder reading it sees the reviewed route and the operator's role words.
  function test_WhenTheDeployedZkPassportMethodIsRead() external {
    if (!_forkSepolia()) return;
    IDeployIdentity.Pins memory _table = _script.pinsFor(block.chainid);
    IDeployIdentity.Inputs memory _operator = _liveInputs(_table);
    IDeployIdentity.Deployment memory _deployment = _script.deploy(_table, _operator);
    (address _admin, address _pendingAdmin, bytes32[] memory _keys, address _pauseHolder, address _pendingPauseHolder) =
      _deployment.zkPassportMethod.trustedParties();
    // it should declare its own safe in both roles with no handover open
    assertEq(_admin, _operator.zkPassportMethodSafe, 'admin');
    assertEq(_pendingAdmin, address(0), 'pending admin');
    assertEq(_pauseHolder, _operator.zkPassportMethodSafe, 'pause holder');
    assertEq(_pendingPauseHolder, address(0), 'pending pause holder');
    // it should declare the eight words in order
    bytes32[] memory _expected = _words(_table, _operator);
    assertEq(_keys.length, _KEY_COUNT, 'word count');
    for (uint256 _i; _i < _KEY_COUNT; ++_i) {
      assertEq(_keys[_i], _expected[_i], 'word');
    }
  }

  /// The Aadhaar method deploy returns on Sepolia declares its own Safe as key admin and pause holder, not the
  /// zkPassport method's Safe, which the inputs make a different address, no open handover, UIDAI's key as its one
  /// trusted key, and calls the pinned Sepolia verifier.
  function test_WhenTheDeployedAadhaarMethodIsRead() external {
    if (!_forkSepolia()) return;
    IDeployIdentity.Pins memory _table = _script.pinsFor(block.chainid);
    IDeployIdentity.Inputs memory _operator = _liveInputs(_table);
    IDeployIdentity.Deployment memory _deployment = _script.deploy(_table, _operator);
    (address _admin, address _pendingAdmin, bytes32[] memory _keys, address _pauseHolder, address _pendingPauseHolder) =
      _deployment.aadhaarMethod.trustedParties();
    // it should declare its own safe in both roles with no handover open
    assertEq(_admin, _operator.aadhaarMethodSafe, 'admin');
    assertEq(_pendingAdmin, address(0), 'pending admin');
    assertEq(_pauseHolder, _operator.aadhaarMethodSafe, 'pause holder');
    assertEq(_pendingPauseHolder, address(0), 'pending pause holder');
    // it should declare UIDAI's key alone
    assertEq(_keys.length, 1, 'key count');
    assertEq(_keys[0], _UIDAI_KEY, 'key');
    // it should call the pinned verifier
    assertEq(IAadhaarMethod(address(_deployment.aadhaarMethod)).verifier(), _SEPOLIA_AADHAAR_VERIFIER, 'verifier');
  }

  /// deploy itself reads, on the methods it returns, everything the fifth assertion checks: trustedParties on
  /// both, supportsInterface for each of the three interface ids on both, and the Aadhaar method's verifier. A
  /// deploy that skipped a check would leave its read missing from the recorded calls.
  function test_WhenTheChecksDeployMakesAreRecorded() external {
    if (!_forkSepolia()) return;
    IDeployIdentity.Pins memory _table = _script.pinsFor(block.chainid);
    IDeployIdentity.Inputs memory _operator = _liveInputs(_table);
    vm.startStateDiffRecording();
    IDeployIdentity.Deployment memory _deployment = _script.deploy(_table, _operator);
    VmSafe.AccountAccess[] memory _accesses = vm.stopAndReturnStateDiff();
    address _zkPassport = address(_deployment.zkPassportMethod);
    address _aadhaar = address(_deployment.aadhaarMethod);
    // it should read both methods' trusted parties
    bytes memory _parties = abi.encodeCall(IPolicyMethod.trustedParties, ());
    assertTrue(_called(_accesses, _zkPassport, _parties), 'zkPassport trustedParties');
    assertTrue(_called(_accesses, _aadhaar, _parties), 'Aadhaar trustedParties');
    // it should ask both methods for each of the three interface ids
    _assertAskedAll(_accesses, _zkPassport, 'zkPassport');
    _assertAskedAll(_accesses, _aadhaar, 'Aadhaar');
    // it should read the Aadhaar method's verifier
    assertTrue(_called(_accesses, _aadhaar, abi.encodeCall(IAadhaarMethod.verifier, ())), 'verifier');
  }

  /// deploy places at the returned addresses exactly the code the kit's two methods have when built there with each
  /// method's own Safe in both its roles, the eight words, UIDAI's key and the pinned verifier. The test rebuilds each
  /// method in place with those arguments and compares the code before and after, so a substituted contract or a
  /// different constructor argument stored in code shows up.
  function test_WhenTheDeployedMethodsAreRebuiltInPlace() external {
    if (!_forkSepolia()) return;
    IDeployIdentity.Pins memory _table = _script.pinsFor(block.chainid);
    IDeployIdentity.Inputs memory _operator = _liveInputs(_table);
    IDeployIdentity.Deployment memory _deployment = _script.deploy(_table, _operator);
    address _zkPassport = address(_deployment.zkPassportMethod);
    address _aadhaar = address(_deployment.aadhaarMethod);
    bytes memory _zkPassportCode = _zkPassport.code;
    bytes memory _aadhaarCode = _aadhaar.code;
    deployCodeTo(
      'ZkPassportMethod.sol:ZkPassportMethod',
      abi.encode(_operator.zkPassportMethodSafe, _operator.zkPassportMethodSafe, _words(_table, _operator)),
      _zkPassport
    );
    deployCodeTo(
      'AadhaarMethod.sol:AadhaarMethod',
      abi.encode(
        _operator.aadhaarMethodSafe, _operator.aadhaarMethodSafe, _oneKey(_UIDAI_KEY), _SEPOLIA_AADHAAR_VERIFIER
      ),
      _aadhaar
    );
    // it should hold the kit's zkPassport method
    assertEq(_zkPassportCode, _zkPassport.code, 'zkPassport method');
    // it should hold the kit's Aadhaar method built with the pinned verifier
    assertEq(_aadhaarCode, _aadhaar.code, 'Aadhaar method');
  }

  /*///////////////////////////////////////////////////////////////
                           BAD VALUES
  ///////////////////////////////////////////////////////////////*/

  /// deploy reverts with the role mismatch, carrying the input and the live root admin, having created nothing,
  /// when the operator's root admin is not the live one.
  function test_RevertWhen_ARoleInputDiffersFromTheLiveRole() external {
    if (!_forkSepolia()) return;
    IDeployIdentity.Pins memory _table = _script.pinsFor(block.chainid);
    IDeployIdentity.Inputs memory _operator = _liveInputs(_table);
    address _live = _operator.rootAdmin;
    _operator.rootAdmin = _freshAddress('deployOtherRootAdmin', 0);
    (bytes memory _reason, uint256 _created) = _deployReverting(_table, _operator);
    // it should revert
    // it should carry the input and the live role
    _assertNamedMismatch(
      _reason, IDeployIdentity.DeployIdentity_RoleMismatch.selector, 'rootAdmin', _operator.rootAdmin, _live
    );
    // it should create no contract
    assertEq(_created, 0, 'contracts created before the role check');
  }

  /// deploy reverts with the component mismatch, carrying the pin and the live sub-verifier, having created
  /// nothing, when the table pins another contract with code as the sub-verifier, here the root verifier itself.
  function test_RevertWhen_AComponentPinDiffersFromTheLiveRoute() external {
    if (!_forkSepolia()) return;
    IDeployIdentity.Pins memory _table = _script.pinsFor(block.chainid);
    IDeployIdentity.Inputs memory _operator = _liveInputs(_table);
    _table.subVerifier = _ROOT_VERIFIER;
    (bytes memory _reason, uint256 _created) = _deployReverting(_table, _operator);
    // it should revert
    // it should carry the pin and the live component
    _assertNamedMismatch(
      _reason,
      IDeployIdentity.DeployIdentity_ComponentMismatch.selector,
      'subVerifier',
      _ROOT_VERIFIER,
      _SEPOLIA_SUB_VERIFIER
    );
    // it should create no contract
    assertEq(_created, 0, 'contracts created before the component check');
  }

  /// deploy reverts carrying the key, having created nothing, when Sepolia's table carries the Anon Aadhaar
  /// stack's published test key in place of UIDAI's.
  function test_RevertWhen_TheAadhaarKeyIsThePublishedTestKey() external {
    if (!_forkSepolia()) return;
    IDeployIdentity.Pins memory _table = _script.pinsFor(block.chainid);
    IDeployIdentity.Inputs memory _operator = _liveInputs(_table);
    _table.aadhaarKey = _AADHAAR_TEST_KEY;
    (bytes memory _reason, uint256 _created) = _deployReverting(_table, _operator);
    // it should revert
    // it should carry the key in the error
    assertEq(
      _reason,
      abi.encodeWithSelector(IDeployIdentity.DeployIdentity_AadhaarTestKey.selector, _AADHAAR_TEST_KEY),
      'revert data'
    );
    // it should create no contract
    assertEq(_created, 0, 'contracts created before the key check');
  }

  function _assertAskedAll(VmSafe.AccountAccess[] memory _accesses, address _target, string memory _label)
    internal
    pure
  {
    bytes4 _selector = IPolicyMethod.supportsInterface.selector;
    assertTrue(
      _called(_accesses, _target, abi.encodeWithSelector(_selector, type(IPolicyMethod).interfaceId)),
      string.concat(_label, ' IPolicyMethod')
    );
    assertTrue(
      _called(_accesses, _target, abi.encodeWithSelector(_selector, type(IPolicyMethodPause).interfaceId)),
      string.concat(_label, ' IPolicyMethodPause')
    );
    assertTrue(
      _called(_accesses, _target, abi.encodeWithSelector(_selector, type(IPolicyMethodAdmin).interfaceId)),
      string.concat(_label, ' IPolicyMethodAdmin')
    );
  }
}
