// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {IPolicyMethod} from 'interfaces/IPolicyMethod.sol';
import {IDeployIdentity} from 'script/IDeployIdentity.sol';
import {DeployIdentityMockLiveReads} from 'test/mocks/DeployIdentityMockLiveReads.sol';
import {DeployIdentityTestBase} from 'test/utils/DeployIdentityTestBase.sol';

/// @notice deploy on the local test chain: the operator's inputs, the table's code, and the comparison of the
///         zkPassport words with a mock root verifier and sub-verifier standing in for the live contracts. forge
///         script simulates the whole run before it sends a transaction, so a check that fails before the first
///         creation keeps a bad input or pin from ever reaching the chain. The tests record every account access,
///         reverted ones included, so a contract created and then undone by the revert still counts.
contract DeployIdentityDeployTest is DeployIdentityTestBase {
  /// deploy reverts with the zero Safe error naming ZKPASSPORT_METHOD_SAFE, having created nothing, when the
  /// zkPassport method's Safe is zero. The script never falls back to the operator's key or any other address
  /// for the party that can stop and re-key the method.
  function test_RevertWhen_TheZkPassportMethodSafeIsZero() external {
    IDeployIdentity.Inputs memory _operator = _inputs;
    _operator.zkPassportMethodSafe = address(0);
    (bytes memory _reason, uint256 _created) = _deployReverting(_pins, _operator);
    // it should revert
    // it should raise the zero safe error naming ZKPASSPORT_METHOD_SAFE
    assertEq(
      _reason,
      abi.encodeWithSelector(IDeployIdentity.DeployIdentity_ZeroSafe.selector, 'ZKPASSPORT_METHOD_SAFE'),
      'revert data'
    );
    // it should create no contract
    assertEq(_created, 0, 'contracts created before the input check');
  }

  /// deploy reverts with the zero Safe error naming AADHAAR_METHOD_SAFE, having created nothing, when the chain
  /// deploys the Aadhaar method and that method's Safe is zero, even though the zkPassport method's Safe is set.
  function test_RevertWhen_TheAadhaarMethodSafeIsZero() external {
    IDeployIdentity.Inputs memory _operator = _inputs;
    _operator.aadhaarMethodSafe = address(0);
    (bytes memory _reason, uint256 _created) = _deployReverting(_pins, _operator);
    // it should revert
    // it should raise the zero safe error naming AADHAAR_METHOD_SAFE
    assertEq(
      _reason,
      abi.encodeWithSelector(IDeployIdentity.DeployIdentity_ZeroSafe.selector, 'AADHAAR_METHOD_SAFE'),
      'revert data'
    );
    // it should create no contract
    assertEq(_created, 0, 'contracts created before the input check');
  }

  /// deploy reverts naming the sub-verifier, having created nothing, when the table's sub-verifier has no code.
  function test_RevertWhen_ATableAddressHasNoCode() external {
    IDeployIdentity.Pins memory _table = _pins;
    _table.subVerifier = _freshAddress('deploySubVerifierWithoutCode', 0);
    (bytes memory _reason, uint256 _created) = _deployReverting(_table, _inputs);
    // it should revert
    // it should name the address in the no code error
    assertEq(
      _reason, abi.encodeWithSelector(IDeployIdentity.DeployIdentity_NoCode.selector, _table.subVerifier), 'revert data'
    );
    // it should create no contract
    assertEq(_created, 0, 'contracts created before the code check');
  }

  /// deploy reverts naming the Aadhaar verifier, having created nothing, when the chain ships the Aadhaar
  /// method and its verifier has no code.
  function test_RevertWhen_TheAadhaarVerifierHasNoCode() external {
    IDeployIdentity.Pins memory _table = _pins;
    _table.aadhaarVerifier = _freshAddress('deployAadhaarVerifierWithoutCode', 0);
    (bytes memory _reason, uint256 _created) = _deployReverting(_table, _inputs);
    // it should revert
    // it should name the address in the no code error
    assertEq(
      _reason,
      abi.encodeWithSelector(IDeployIdentity.DeployIdentity_NoCode.selector, _table.aadhaarVerifier),
      'revert data'
    );
    // it should create no contract
    assertEq(_created, 0, 'contracts created before the code check');
  }

  /// deploy reverts with the role mismatch named rootAdmin, having created nothing, when the live root admin read
  /// disagrees with the operator's root admin input. The mock root and sub-verifier agree with every other word.
  function test_RevertWhen_ALiveReadDisagrees() external {
    _useLiveReadMocks();
    address _live = _freshAddress('deployLiveRootAdmin', 0);
    _rootMock.setAnswer(_ADMIN, DeployIdentityMockLiveReads.Mode.Value, _live);
    (bytes memory _reason, uint256 _created) = _deployReverting(_pins, _inputs);
    // it should revert
    // it should name rootAdmin and carry the input and the live value
    _assertNamedMismatch(
      _reason, IDeployIdentity.DeployIdentity_RoleMismatch.selector, 'rootAdmin', _inputs.rootAdmin, _live
    );
    // it should create no contract
    assertEq(_created, 0, 'contracts created before the live comparison');
  }

  /// deploy with a table and inputs every mocked live read agrees with broadcasts exactly two creations, the
  /// zkPassport and Aadhaar methods it returns, and they pass the deployment check. The count is of what the
  /// broadcaster creates, the transactions a broadcast sends: the local copy the code check builds after the
  /// broadcast stops is never sent, so it does not count.
  function test_WhenEveryLiveReadAgrees() external {
    _useLiveReadMocks();
    vm.startStateDiffRecording();
    IDeployIdentity.Deployment memory _deployment = _script.deploy(_pins, _inputs);
    uint256 _created = _broadcastCreations(vm.stopAndReturnStateDiff());
    // it should create the two methods
    assertEq(_created, 2, 'creations');
    assertTrue(address(_deployment.zkPassportMethod).code.length != 0, 'zkPassport method');
    assertTrue(address(_deployment.aadhaarMethod).code.length != 0, 'Aadhaar method');
    // it should return methods the deployment check accepts
    _script.checkDeployment(_deployment, _pins, _inputs);
  }

  /// deploy gives both roles of each method to that method's own Safe when the two Safes differ, so the party that
  /// can stop or re-key one method holds nothing on the other. A rule that pairs the two methods relies on that
  /// split to contain a key admin who forges proofs.
  function test_WhenEachMethodHasItsOwnSafe() external {
    _useLiveReadMocks();
    IDeployIdentity.Deployment memory _deployment = _script.deploy(_pins, _inputs);
    // it should make the zkPassport method's safe its key admin and pause holder
    _assertRoles(_deployment.zkPassportMethod, _inputs.zkPassportMethodSafe, 'zkPassport');
    // it should make the Aadhaar method's safe its key admin and pause holder
    _assertRoles(_deployment.aadhaarMethod, _inputs.aadhaarMethodSafe, 'Aadhaar');
  }

  /// deploy accepts one address given as both methods' Safe and makes it the key admin and pause holder of both,
  /// since the two Safes may be one multisig.
  function test_WhenBothMethodsShareOneSafe() external {
    _useLiveReadMocks();
    IDeployIdentity.Inputs memory _operator = _inputs;
    _operator.aadhaarMethodSafe = _operator.zkPassportMethodSafe;
    IDeployIdentity.Deployment memory _deployment = _script.deploy(_pins, _operator);
    // it should make the shared safe both methods' key admin and pause holder
    _assertRoles(_deployment.zkPassportMethod, _operator.zkPassportMethodSafe, 'zkPassport');
    _assertRoles(_deployment.aadhaarMethod, _operator.zkPassportMethodSafe, 'Aadhaar');
    // it should return methods the deployment check accepts
    _script.checkDeployment(_deployment, _pins, _operator);
  }

  /// deploy on a chain that deploys no Aadhaar method accepts a zero Aadhaar Safe, since no method takes that
  /// Safe's roles, and creates the zkPassport method alone, with its roles on its own Safe.
  function test_WhenTheChainShipsNoAadhaarAndItsSafeIsZero() external {
    _useLiveReadMocks();
    IDeployIdentity.Pins memory _table = _pins;
    _table.shipsAadhaar = false;
    IDeployIdentity.Inputs memory _operator = _inputs;
    _operator.aadhaarMethodSafe = address(0);
    vm.startStateDiffRecording();
    IDeployIdentity.Deployment memory _deployment = _script.deploy(_table, _operator);
    uint256 _created = _broadcastCreations(vm.stopAndReturnStateDiff());
    // it should create the zkPassport method alone
    assertEq(_created, 1, 'creations');
    assertEq(address(_deployment.aadhaarMethod), address(0), 'Aadhaar method');
    // it should make the zkPassport method's safe its key admin and pause holder
    _assertRoles(_deployment.zkPassportMethod, _operator.zkPassportMethodSafe, 'zkPassport');
  }

  /// @notice Asserts that `_method` declares `_safe` as key admin and pause holder with no handover open.
  function _assertRoles(IPolicyMethod _method, address _safe, string memory _label) internal view {
    (address _admin, address _pendingAdmin,, address _pauseHolder, address _pendingPauseHolder) =
      _method.trustedParties();
    assertEq(_admin, _safe, string.concat(_label, ' admin'));
    assertEq(_pendingAdmin, address(0), string.concat(_label, ' pending admin'));
    assertEq(_pauseHolder, _safe, string.concat(_label, ' pause holder'));
    assertEq(_pendingPauseHolder, address(0), string.concat(_label, ' pending pause holder'));
  }
}
