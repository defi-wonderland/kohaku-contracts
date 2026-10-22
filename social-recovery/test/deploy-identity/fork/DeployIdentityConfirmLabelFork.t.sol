// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {IPolicyMethod} from 'interfaces/IPolicyMethod.sol';
import {IDeployIdentity} from 'script/IDeployIdentity.sol';
import {AadhaarMethod} from 'contracts/methods/aadhaar/AadhaarMethod.sol';
import {DeployMockLookAlike} from 'test/mocks/DeployMockLookAlike.sol';
import {DeployIdentityForkTestBase} from 'test/utils/DeployIdentityForkTestBase.sol';

/// @notice confirmLabel, the whole of confirm, the operator's second step, for an explicit label. forge runs a
///         whole script, file writes included, before it sends any transaction, so run writes only a candidate
///         record and confirm publishes it once the chain holds what it names. Each test deploys the identity
///         methods on a fork, writes the candidate itself as <label>.identity.pending.json under a label no other
///         test uses, passes that label to confirmLabel, and removes every file it wrote. A published record
///         naming methods that never landed, or methods whose parties disagree with the chain, would send every
///         client to the wrong contract or show holders the wrong parties. Each test skips cleanly when its
///         endpoint is unset.
contract DeployIdentityConfirmLabelForkTest is DeployIdentityForkTestBase {
  /// @notice The number of keys a published record holds: the chain id, the two methods, each method's Safe, the
  ///         eight words, the Aadhaar verifier, its code hash and the Aadhaar key.
  uint256 internal constant _RECORD_KEY_COUNT = 9;

  function _pendingPath(string memory _label) internal pure returns (string memory _path) {
    _path = string.concat('script/deployments/', _label, '.identity.pending.json');
  }

  function _publishedPath(string memory _label) internal pure returns (string memory _path) {
    _path = string.concat('script/deployments/', _label, '.identity.json');
  }

  /// @notice Removes the candidate and the published record of `_label` when they exist.
  function _clean(string memory _label) internal {
    if (vm.exists(_pendingPath(_label))) vm.removeFile(_pendingPath(_label));
    if (vm.exists(_publishedPath(_label))) vm.removeFile(_publishedPath(_label));
  }

  /// @notice Deploys the identity methods on the fork with the table and good inputs, makes sure
  ///         script/deployments exists, and clears any file `_label` left.
  function _deployFor(string memory _label)
    internal
    returns (
      IDeployIdentity.Deployment memory _deployment,
      IDeployIdentity.Pins memory _table,
      IDeployIdentity.Inputs memory _operator
    )
  {
    _table = _script.pinsFor(block.chainid);
    _operator = _liveInputs(_table);
    _deployment = _script.deploy(_table, _operator);
    vm.createDir('script/deployments', true);
    _clean(_label);
  }

  /// @notice Writes the candidate `_json` under `_label`, runs confirmLabel and returns its revert data, requires
  ///         that it reverted and left no published record, and cleans up.
  function _confirmReverting(string memory _label, string memory _json) internal returns (bytes memory _reason) {
    vm.writeFile(_pendingPath(_label), _json);
    try _script.confirmLabel(_label) {
      fail('confirmLabel did not revert');
    } catch (bytes memory _caught) {
      _reason = _caught;
    }
    assertFalse(vm.exists(_publishedPath(_label)), 'a published record after a revert');
    _clean(_label);
  }

  /// @notice Writes the candidate `_json` under `_label` with vm.writeJson, pretty-printed, as run writes it, and
  ///         returns the bytes the file holds, which confirm must publish unchanged.
  function _writeCandidate(string memory _label, string memory _json) internal returns (bytes memory _candidateBytes) {
    vm.writeJson(_json, _pendingPath(_label));
    _candidateBytes = bytes(vm.readFile(_pendingPath(_label)));
    assertNotEq(_candidateBytes, bytes(_json), 'fixture: the candidate is not pretty-printed');
  }

  /*///////////////////////////////////////////////////////////////
                          GOOD RECORDS
  ///////////////////////////////////////////////////////////////*/

  /// On Sepolia, confirmLabel publishes the candidate as <label>.identity.json byte for byte, removes the
  /// candidate, and returns the recorded methods, when every recorded value holds on chain. The candidate is
  /// pretty-printed as run writes it, so a confirm that rewrote the record in another layout would publish a
  /// file that differs from the one the operator reviewed.
  function test_WhenASepoliaCandidateHoldsOnChain() external {
    if (!_forkSepolia()) return;
    string memory _label = 'test-identity-confirm-sepolia';
    (
      IDeployIdentity.Deployment memory _deployment,
      IDeployIdentity.Pins memory _table,
      IDeployIdentity.Inputs memory _operator
    ) = _deployFor(_label);
    bytes memory _candidateBytes =
      _writeCandidate(_label, _script.recordJson(_deployment, _table, _operator, block.chainid));
    IDeployIdentity.Deployment memory _confirmed = _script.confirmLabel(_label);
    // it should publish the candidate's bytes under the label
    assertTrue(vm.exists(_publishedPath(_label)), 'published record');
    assertEq(bytes(vm.readFile(_publishedPath(_label))), _candidateBytes, 'published bytes');
    // it should remove the candidate
    assertFalse(vm.exists(_pendingPath(_label)), 'candidate left behind');
    // it should return the recorded methods
    assertEq(address(_confirmed.zkPassportMethod), address(_deployment.zkPassportMethod), 'zkPassport method');
    assertEq(address(_confirmed.aadhaarMethod), address(_deployment.aadhaarMethod), 'Aadhaar method');
    _clean(_label);
  }

  /// On mainnet, where no Aadhaar method ships, confirmLabel publishes byte for byte a candidate that records the
  /// zero address for the Aadhaar method, pretty-printed as run writes it, and returns the zero address there.
  function test_WhenAMainnetCandidateHoldsOnChain() external {
    if (!_forkMainnet()) return;
    string memory _label = 'test-identity-confirm-mainnet';
    (
      IDeployIdentity.Deployment memory _deployment,
      IDeployIdentity.Pins memory _table,
      IDeployIdentity.Inputs memory _operator
    ) = _deployFor(_label);
    bytes memory _candidateBytes =
      _writeCandidate(_label, _script.recordJson(_deployment, _table, _operator, block.chainid));
    IDeployIdentity.Deployment memory _confirmed = _script.confirmLabel(_label);
    // it should publish the candidate's bytes under the label
    assertEq(bytes(vm.readFile(_publishedPath(_label))), _candidateBytes, 'published bytes');
    // it should remove the candidate
    assertFalse(vm.exists(_pendingPath(_label)), 'candidate left behind');
    // it should return the zkPassport method and no Aadhaar method
    assertEq(address(_confirmed.zkPassportMethod), address(_deployment.zkPassportMethod), 'zkPassport method');
    assertEq(address(_confirmed.aadhaarMethod), address(0), 'Aadhaar method');
    _clean(_label);
  }

  /*///////////////////////////////////////////////////////////////
                           BAD RECORDS
  ///////////////////////////////////////////////////////////////*/

  /// confirmLabel reverts naming both chain ids, and publishes nothing, when the candidate records mainnet's
  /// chain id on Sepolia, a record written on another chain.
  function test_RevertWhen_TheCandidateNamesAnotherChain() external {
    if (!_forkSepolia()) return;
    string memory _label = 'test-identity-confirm-other-chain';
    (
      IDeployIdentity.Deployment memory _deployment,
      IDeployIdentity.Pins memory _table,
      IDeployIdentity.Inputs memory _operator
    ) = _deployFor(_label);
    // it should revert
    // it should name the recorded and the current chain id
    // it should publish no record
    bytes memory _reason =
      _confirmReverting(_label, _script.recordJson(_deployment, _table, _operator, _MAINNET_CHAIN_ID));
    assertEq(
      _reason,
      abi.encodeWithSelector(
        IDeployIdentity.DeployIdentity_RecordChainMismatch.selector, _MAINNET_CHAIN_ID, block.chainid
      )
    );
  }

  /// confirmLabel reverts naming the address, and publishes nothing, when the recorded zkPassport method has no
  /// code, as when its transaction never landed. The address is hashed from a label.
  function test_RevertWhen_TheRecordedZkPassportMethodHasNoCode() external {
    if (!_forkSepolia()) return;
    string memory _label = 'test-identity-confirm-no-zkpassport';
    (
      IDeployIdentity.Deployment memory _deployment,
      IDeployIdentity.Pins memory _table,
      IDeployIdentity.Inputs memory _operator
    ) = _deployFor(_label);
    address _missing = _freshAddress('notDeployedZkPassportMethod', 0);
    _deployment.zkPassportMethod = IPolicyMethod(_missing);
    // it should revert
    // it should name the address in the not deployed error
    // it should publish no record
    bytes memory _reason = _confirmReverting(_label, _script.recordJson(_deployment, _table, _operator, block.chainid));
    assertEq(_reason, abi.encodeWithSelector(IDeployIdentity.DeployIdentity_NotDeployed.selector, _missing));
  }

  /// confirmLabel reverts naming the address, and publishes nothing, when the recorded Aadhaar method has no code
  /// on Sepolia, where the method ships. The address is hashed from a label.
  function test_RevertWhen_TheRecordedAadhaarMethodHasNoCode() external {
    if (!_forkSepolia()) return;
    string memory _label = 'test-identity-confirm-no-aadhaar';
    (
      IDeployIdentity.Deployment memory _deployment,
      IDeployIdentity.Pins memory _table,
      IDeployIdentity.Inputs memory _operator
    ) = _deployFor(_label);
    address _missing = _freshAddress('notDeployedAadhaarMethod', 0);
    _deployment.aadhaarMethod = IPolicyMethod(_missing);
    // it should revert
    // it should name the address in the not deployed error
    // it should publish no record
    bytes memory _reason = _confirmReverting(_label, _script.recordJson(_deployment, _table, _operator, block.chainid));
    assertEq(_reason, abi.encodeWithSelector(IDeployIdentity.DeployIdentity_NotDeployed.selector, _missing));
  }

  /// confirmLabel reverts naming the pinned and the recorded verifier, and publishes nothing, when the candidate
  /// records an Aadhaar verifier other than the table's.
  function test_RevertWhen_TheRecordedTableDiffersFromTheTable() external {
    if (!_forkSepolia()) return;
    string memory _label = 'test-identity-confirm-other-table';
    (
      IDeployIdentity.Deployment memory _deployment,
      IDeployIdentity.Pins memory _table,
      IDeployIdentity.Inputs memory _operator
    ) = _deployFor(_label);
    address _pinned = _table.aadhaarVerifier;
    _table.aadhaarVerifier = _ROOT_VERIFIER;
    // it should revert
    // it should publish no record
    bytes memory _reason = _confirmReverting(_label, _script.recordJson(_deployment, _table, _operator, block.chainid));
    assertEq(
      _reason,
      abi.encodeWithSelector(IDeployIdentity.DeployIdentity_AadhaarVerifierMismatch.selector, _pinned, _ROOT_VERIFIER)
    );
  }

  /// confirmLabel reverts with the role mismatch, carrying the recorded word and the live root admin, and
  /// publishes nothing, when the candidate's root admin word is not the live one. confirm reruns the live
  /// comparison over the recorded words, so a record whose words drifted from the chain is never published.
  function test_RevertWhen_TheRecordedRoleWordDiffersFromTheLiveRole() external {
    if (!_forkSepolia()) return;
    string memory _label = 'test-identity-confirm-other-role';
    (
      IDeployIdentity.Deployment memory _deployment,
      IDeployIdentity.Pins memory _table,
      IDeployIdentity.Inputs memory _operator
    ) = _deployFor(_label);
    address _live = _operator.rootAdmin;
    _operator.rootAdmin = _freshAddress('recordedOtherRootAdmin', 0);
    // it should revert
    // it should carry the recorded word and the live role
    // it should publish no record
    bytes memory _reason = _confirmReverting(_label, _script.recordJson(_deployment, _table, _operator, block.chainid));
    _assertNamedMismatch(
      _reason, IDeployIdentity.DeployIdentity_RoleMismatch.selector, 'rootAdmin', _operator.rootAdmin, _live
    );
  }

  /// confirmLabel reverts with the method roles mismatch naming the zkPassport method, and publishes nothing, when
  /// the candidate records another zkPassport method Safe than the one that method declares. The record names the
  /// Safe holders and the screens show as that method's pause holder and key admin, so it must be the one on chain.
  function test_RevertWhen_TheRecordedZkPassportMethodSafeIsNotItsSafe() external {
    if (!_forkSepolia()) return;
    string memory _label = 'test-identity-confirm-other-zkpassport-safe';
    (
      IDeployIdentity.Deployment memory _deployment,
      IDeployIdentity.Pins memory _table,
      IDeployIdentity.Inputs memory _operator
    ) = _deployFor(_label);
    _operator.zkPassportMethodSafe = _freshAddress('recordedOtherZkPassportMethodSafe', 0);
    // it should revert
    // it should name the zkPassport method in the roles error
    // it should publish no record
    bytes memory _reason = _confirmReverting(_label, _script.recordJson(_deployment, _table, _operator, block.chainid));
    assertEq(_reason, _rolesMismatch(address(_deployment.zkPassportMethod)));
  }

  /// confirmLabel reverts with the method roles mismatch naming the Aadhaar method, and publishes nothing, when the
  /// candidate records the zkPassport method's Safe as the Aadhaar method's Safe while the Aadhaar method declares
  /// its own. Each method is checked against its own recorded Safe, so a record that names one method's party for
  /// the other is caught even though the address it names holds a role on chain.
  function test_RevertWhen_TheRecordedAadhaarMethodSafeIsTheOtherMethodsSafe() external {
    if (!_forkSepolia()) return;
    string memory _label = 'test-identity-confirm-other-aadhaar-safe';
    (
      IDeployIdentity.Deployment memory _deployment,
      IDeployIdentity.Pins memory _table,
      IDeployIdentity.Inputs memory _operator
    ) = _deployFor(_label);
    _operator.aadhaarMethodSafe = _operator.zkPassportMethodSafe;
    // it should revert
    // it should name the Aadhaar method in the roles error
    // it should publish no record
    bytes memory _reason = _confirmReverting(_label, _script.recordJson(_deployment, _table, _operator, block.chainid));
    assertEq(_reason, _rolesMismatch(address(_deployment.aadhaarMethod)));
  }

  /// confirmLabel reverts with the method roles mismatch, naming one of the two methods, and publishes nothing,
  /// when the candidate records the two Safes under each other's keys. Both addresses hold roles on chain, but
  /// each on the other method, so a record that lists them crosswise would show holders the wrong party.
  function test_RevertWhen_TheCandidateSwapsTheTwoSafes() external {
    if (!_forkSepolia()) return;
    string memory _label = 'test-identity-confirm-swapped-safes';
    (
      IDeployIdentity.Deployment memory _deployment,
      IDeployIdentity.Pins memory _table,
      IDeployIdentity.Inputs memory _operator
    ) = _deployFor(_label);
    address _zkPassportMethodSafe = _operator.zkPassportMethodSafe;
    _operator.zkPassportMethodSafe = _operator.aadhaarMethodSafe;
    _operator.aadhaarMethodSafe = _zkPassportMethodSafe;
    // it should revert
    // it should name a method in the roles error
    // it should publish no record
    bytes memory _reason = _confirmReverting(_label, _script.recordJson(_deployment, _table, _operator, block.chainid));
    bool _namesZkPassport = keccak256(_reason) == keccak256(_rolesMismatch(address(_deployment.zkPassportMethod)));
    bool _namesAadhaar = keccak256(_reason) == keccak256(_rolesMismatch(address(_deployment.aadhaarMethod)));
    assertTrue(_namesZkPassport || _namesAadhaar, 'the roles error naming one of the methods');
  }

  /// @notice The method roles mismatch naming `_method`.
  function _rolesMismatch(address _method) internal pure returns (bytes memory _reason) {
    _reason = abi.encodeWithSelector(IDeployIdentity.DeployIdentity_MethodRolesMismatch.selector, _method);
  }

  /// confirmLabel reverts with the method roles mismatch naming the Aadhaar method, and publishes nothing, when the
  /// candidate records the two methods at each other's addresses, as a broadcast that landed out of order leaves
  /// them. The zkPassport entry then holds the Aadhaar method, whose one trusted key is not the eight words.
  function test_RevertWhen_TheCandidateSwapsTheTwoMethods() external {
    if (!_forkSepolia()) return;
    string memory _label = 'test-identity-confirm-swapped-methods';
    (
      IDeployIdentity.Deployment memory _deployment,
      IDeployIdentity.Pins memory _table,
      IDeployIdentity.Inputs memory _operator
    ) = _deployFor(_label);
    IPolicyMethod _aadhaarMethod = _deployment.aadhaarMethod;
    _deployment.aadhaarMethod = _deployment.zkPassportMethod;
    _deployment.zkPassportMethod = _aadhaarMethod;
    // it should revert
    // it should name the Aadhaar method in the roles error
    // it should publish no record
    bytes memory _reason = _confirmReverting(_label, _script.recordJson(_deployment, _table, _operator, block.chainid));
    assertEq(
      _reason,
      abi.encodeWithSelector(IDeployIdentity.DeployIdentity_MethodRolesMismatch.selector, address(_aadhaarMethod))
    );
  }

  /// confirmLabel reverts naming the aadhaarVerifierCodehash field, and publishes nothing, when the candidate
  /// records another code hash for the Aadhaar verifier than the table's, so a record never vouches for code
  /// nobody reviewed.
  function test_RevertWhen_TheRecordedCodehashDiffersFromTheTable() external {
    if (!_forkSepolia()) return;
    string memory _label = 'test-identity-confirm-other-codehash';
    (
      IDeployIdentity.Deployment memory _deployment,
      IDeployIdentity.Pins memory _table,
      IDeployIdentity.Inputs memory _operator
    ) = _deployFor(_label);
    _table.aadhaarVerifierCodehash = keccak256('otherAadhaarVerifierCodehash');
    // it should revert
    // it should name the field in the record mismatch error
    // it should publish no record
    bytes memory _reason = _confirmReverting(_label, _script.recordJson(_deployment, _table, _operator, block.chainid));
    assertEq(
      _reason, abi.encodeWithSelector(IDeployIdentity.DeployIdentity_RecordMismatch.selector, 'aadhaarVerifierCodehash')
    );
  }

  /// confirmLabel reverts naming the zkPassportKeys field, and publishes nothing, when the candidate's first word
  /// names version 0.22.0 rather than the table's accepted version. The version word is one of the eight words,
  /// which the record keeps under zkPassportKeys.
  function test_RevertWhen_TheRecordedVersionWordDiffersFromTheTable() external {
    if (!_forkSepolia()) return;
    string memory _label = 'test-identity-confirm-other-version';
    (
      IDeployIdentity.Deployment memory _deployment,
      IDeployIdentity.Pins memory _table,
      IDeployIdentity.Inputs memory _operator
    ) = _deployFor(_label);
    _table.acceptedVersion = 0x0000001600000000000000000000000000000000000000000000000000000000;
    // it should revert
    // it should name the field in the record mismatch error
    // it should publish no record
    bytes memory _reason = _confirmReverting(_label, _script.recordJson(_deployment, _table, _operator, block.chainid));
    assertEq(_reason, abi.encodeWithSelector(IDeployIdentity.DeployIdentity_RecordMismatch.selector, 'zkPassportKeys'));
  }

  /// confirmLabel reverts naming the aadhaarKey field, and publishes nothing, when the candidate records another
  /// Aadhaar key than the table's, here the published test key.
  function test_RevertWhen_TheRecordedAadhaarKeyDiffersFromTheTable() external {
    if (!_forkSepolia()) return;
    string memory _label = 'test-identity-confirm-other-key';
    (
      IDeployIdentity.Deployment memory _deployment,
      IDeployIdentity.Pins memory _table,
      IDeployIdentity.Inputs memory _operator
    ) = _deployFor(_label);
    _table.aadhaarKey = _AADHAAR_TEST_KEY;
    // it should revert
    // it should name the field in the record mismatch error
    // it should publish no record
    bytes memory _reason = _confirmReverting(_label, _script.recordJson(_deployment, _table, _operator, block.chainid));
    assertEq(_reason, abi.encodeWithSelector(IDeployIdentity.DeployIdentity_RecordMismatch.selector, 'aadhaarKey'));
  }

  /// On mainnet, where no Aadhaar method ships, confirmLabel reverts naming the recorded Aadhaar method, and
  /// publishes nothing, when the candidate records a nonzero address there. The SDK would read that address as
  /// a deployed Aadhaar method. The address is hashed from a label.
  function test_RevertWhen_AMainnetCandidateRecordsAnAadhaarMethod() external {
    if (!_forkMainnet()) return;
    string memory _label = 'test-identity-confirm-mainnet-aadhaar';
    (
      IDeployIdentity.Deployment memory _deployment,
      IDeployIdentity.Pins memory _table,
      IDeployIdentity.Inputs memory _operator
    ) = _deployFor(_label);
    address _recorded = _freshAddress('mainnetAadhaarMethod', 0);
    _deployment.aadhaarMethod = IPolicyMethod(_recorded);
    // it should revert
    // it should name the recorded address in the not deployed error
    // it should publish no record
    bytes memory _reason = _confirmReverting(_label, _script.recordJson(_deployment, _table, _operator, block.chainid));
    assertEq(_reason, abi.encodeWithSelector(IDeployIdentity.DeployIdentity_NotDeployed.selector, _recorded));
  }

  /// confirmLabel under the label test-identity-stem publishes test-identity-stem.identity.json and leaves
  /// test-identity-stem-identity.json, which the core script writes for the label test-identity-stem-identity, byte
  /// for byte as it was. The identity file name holds a dot, which no label may hold, so an identity record can
  /// never overwrite a core record. The labels carry the suite's test prefix, so no real record is touched. The
  /// test writes the core record itself as a sentinel and removes it at the end.
  function test_WhenAnIdentityRecordSharesItsLabelStemWithACoreRecord() external {
    if (!_forkSepolia()) return;
    string memory _label = 'test-identity-stem';
    string memory _corePath = 'script/deployments/test-identity-stem-identity.json';
    string memory _sentinel = '{"sentinel":"core record of the label test-identity-stem-identity"}';
    (
      IDeployIdentity.Deployment memory _deployment,
      IDeployIdentity.Pins memory _table,
      IDeployIdentity.Inputs memory _operator
    ) = _deployFor(_label);
    vm.writeFile(_corePath, _sentinel);
    bytes memory _candidateBytes =
      _writeCandidate(_label, _script.recordJson(_deployment, _table, _operator, block.chainid));
    _script.confirmLabel(_label);
    // it should publish the identity record under a name holding the dot
    assertTrue(vm.exists(_publishedPath(_label)), 'identity record');
    assertEq(bytes(vm.readFile(_publishedPath(_label))), _candidateBytes, 'identity record bytes');
    // it should leave the core record untouched
    assertEq(vm.readFile(_corePath), _sentinel, 'core record');
    vm.removeFile(_corePath);
    _clean(_label);
  }

  /// confirmLabel reverts with the zero Safe error naming ZKPASSPORT_METHOD_SAFE, and publishes nothing, when the
  /// candidate records the zero address as the zkPassport method's Safe. The method was deployed with a nonzero
  /// Safe; only the record says zero. A record whose Safe is nobody would show holders no pause holder and no key
  /// admin, which a deployment would never accept.
  function test_RevertWhen_TheRecordedZkPassportMethodSafeIsZero() external {
    if (!_forkSepolia()) return;
    string memory _label = 'test-identity-confirm-zero-zkpassport-safe';
    (
      IDeployIdentity.Deployment memory _deployment,
      IDeployIdentity.Pins memory _table,
      IDeployIdentity.Inputs memory _operator
    ) = _deployFor(_label);
    _operator.zkPassportMethodSafe = address(0);
    // it should revert
    // it should raise the zero safe error naming ZKPASSPORT_METHOD_SAFE
    // it should publish no record
    bytes memory _reason = _confirmReverting(_label, _script.recordJson(_deployment, _table, _operator, block.chainid));
    assertEq(
      _reason, abi.encodeWithSelector(IDeployIdentity.DeployIdentity_ZeroSafe.selector, 'ZKPASSPORT_METHOD_SAFE')
    );
  }

  /// confirmLabel reverts with the zero Safe error naming AADHAAR_METHOD_SAFE, and publishes nothing, when a Sepolia
  /// candidate, whose chain deploys the Aadhaar method, records the zero address as that method's Safe.
  function test_RevertWhen_TheRecordedAadhaarMethodSafeIsZero() external {
    if (!_forkSepolia()) return;
    string memory _label = 'test-identity-confirm-zero-aadhaar-safe';
    (
      IDeployIdentity.Deployment memory _deployment,
      IDeployIdentity.Pins memory _table,
      IDeployIdentity.Inputs memory _operator
    ) = _deployFor(_label);
    _operator.aadhaarMethodSafe = address(0);
    // it should revert
    // it should raise the zero safe error naming AADHAAR_METHOD_SAFE
    // it should publish no record
    bytes memory _reason = _confirmReverting(_label, _script.recordJson(_deployment, _table, _operator, block.chainid));
    assertEq(_reason, abi.encodeWithSelector(IDeployIdentity.DeployIdentity_ZeroSafe.selector, 'AADHAAR_METHOD_SAFE'));
  }

  /// On mainnet, which deploys no Aadhaar method, confirmLabel reverts naming the aadhaarMethodSafe field, and
  /// publishes nothing, when the candidate records a nonzero Aadhaar method Safe. A record naming a party for a
  /// method that does not exist would show holders a role nobody can use.
  function test_RevertWhen_AMainnetCandidateRecordsAnAadhaarMethodSafe() external {
    if (!_forkMainnet()) return;
    string memory _label = 'test-identity-confirm-mainnet-aadhaar-safe';
    (
      IDeployIdentity.Deployment memory _deployment,
      IDeployIdentity.Pins memory _table,
      IDeployIdentity.Inputs memory _operator
    ) = _deployFor(_label);
    _operator.aadhaarMethodSafe = _freshAddress('mainnetAadhaarMethodSafe', 0);
    // it should revert
    // it should name the field in the record mismatch error
    // it should publish no record
    bytes memory _reason = _confirmReverting(_label, _script.recordJson(_deployment, _table, _operator, block.chainid));
    assertEq(
      _reason, abi.encodeWithSelector(IDeployIdentity.DeployIdentity_RecordMismatch.selector, 'aadhaarMethodSafe')
    );
  }

  /// confirmLabel reverts naming the verifier helper, and publishes nothing, when a valid candidate meets a chain where
  /// the table's verifier helper has lost its code, here etched away after the deployment. confirm reruns the code
  /// check, so a record is never published for a route whose contracts are gone.
  function test_RevertWhen_ATableAddressHasLostItsCode() external {
    if (!_forkSepolia()) return;
    string memory _label = 'test-identity-confirm-verifier-helper-gone';
    (
      IDeployIdentity.Deployment memory _deployment,
      IDeployIdentity.Pins memory _table,
      IDeployIdentity.Inputs memory _operator
    ) = _deployFor(_label);
    string memory _json = _script.recordJson(_deployment, _table, _operator, block.chainid);
    vm.etch(_table.verifierHelper, '');
    // it should revert
    // it should name the address in the no code error
    // it should publish no record
    bytes memory _reason = _confirmReverting(_label, _json);
    assertEq(_reason, abi.encodeWithSelector(IDeployIdentity.DeployIdentity_NoCode.selector, _table.verifierHelper));
  }

  /*///////////////////////////////////////////////////////////////
                  A RECORD REBUILT FROM CHECKED VALUES
  ///////////////////////////////////////////////////////////////*/

  /// @notice Publishes the candidate `_json` under `_label` and requires the published record to hold exactly the
  ///         nine record keys, each equal to the value confirm checked, and not `_extraKey`. Removes the files it
  ///         wrote.
  function _confirmAndRequireCheckedRecord(
    string memory _label,
    string memory _json,
    IDeployIdentity.Deployment memory _deployment,
    IDeployIdentity.Pins memory _table,
    IDeployIdentity.Inputs memory _operator,
    string memory _extraKey
  ) internal {
    vm.writeFile(_pendingPath(_label), _json);
    _script.confirmLabel(_label);
    string memory _published = vm.readFile(_publishedPath(_label));
    _clean(_label);
    assertFalse(vm.keyExistsJson(_published, string.concat('.', _extraKey)), 'the extra key was published');
    assertEq(vm.parseJsonKeys(_published, '$').length, _RECORD_KEY_COUNT, 'key count');
    assertEq(vm.parseJsonUint(_published, '.chainId'), block.chainid, 'chainId');
    assertEq(
      vm.parseJsonAddress(_published, '.zkPassportMethod'), address(_deployment.zkPassportMethod), 'zkPassportMethod'
    );
    assertEq(vm.parseJsonAddress(_published, '.aadhaarMethod'), address(_deployment.aadhaarMethod), 'aadhaarMethod');
    assertEq(
      vm.parseJsonAddress(_published, '.zkPassportMethodSafe'), _operator.zkPassportMethodSafe, 'zkPassportMethodSafe'
    );
    assertEq(vm.parseJsonAddress(_published, '.aadhaarMethodSafe'), _operator.aadhaarMethodSafe, 'aadhaarMethodSafe');
    bytes32[] memory _recorded = vm.parseJsonBytes32Array(_published, '.zkPassportKeys');
    bytes32[] memory _expected = _words(_table, _operator);
    assertEq(_recorded.length, _KEY_COUNT, 'word count');
    for (uint256 _i; _i < _KEY_COUNT; ++_i) {
      assertEq(_recorded[_i], _expected[_i], 'zkPassport word');
    }
    assertEq(vm.parseJsonAddress(_published, '.aadhaarVerifier'), _table.aadhaarVerifier, 'aadhaarVerifier');
    assertEq(
      vm.parseJsonBytes32(_published, '.aadhaarVerifierCodehash'),
      _table.aadhaarVerifierCodehash,
      'aadhaarVerifierCodehash'
    );
    assertEq(vm.parseJsonBytes32(_published, '.aadhaarKey'), _table.aadhaarKey, 'aadhaarKey');
  }

  /// On Sepolia, confirmLabel publishes a record without the key zkPassportMethodV2 when the candidate adds it,
  /// naming an address of its own, to a record that holds on chain. No check reads that key, so a confirm that
  /// copied the candidate's text would publish an unchecked address a client might call. The published record
  /// holds exactly the nine record keys, each the value confirm checked.
  function test_WhenTheCandidateCarriesAnExtraAddressKey() external {
    if (!_forkSepolia()) return;
    string memory _label = 'test-identity-confirm-extra-address-key';
    (
      IDeployIdentity.Deployment memory _deployment,
      IDeployIdentity.Pins memory _table,
      IDeployIdentity.Inputs memory _operator
    ) = _deployFor(_label);
    vm.serializeJson('identityExtraAddressKey', _script.recordJson(_deployment, _table, _operator, block.chainid));
    string memory _json =
      vm.serializeAddress('identityExtraAddressKey', 'zkPassportMethodV2', _freshAddress('extraZkPassportMethodV2', 0));
    assertTrue(vm.keyExistsJson(_json, '.zkPassportMethodV2'), 'fixture: the candidate lacks the extra key');
    // it should publish no key the checks did not read
    // it should publish exactly the nine record keys, each the checked value
    _confirmAndRequireCheckedRecord(_label, _json, _deployment, _table, _operator, 'zkPassportMethodV2');
  }

  /// On Sepolia, confirmLabel publishes a record without the field sdkEndpoint when the candidate adds that
  /// unrelated string field to a record that holds on chain, so nothing a hand edit adds reaches the file the
  /// screens read. The published record holds exactly the nine record keys, each the value confirm checked.
  function test_WhenTheCandidateCarriesAnExtraUnrelatedField() external {
    if (!_forkSepolia()) return;
    string memory _label = 'test-identity-confirm-extra-field';
    (
      IDeployIdentity.Deployment memory _deployment,
      IDeployIdentity.Pins memory _table,
      IDeployIdentity.Inputs memory _operator
    ) = _deployFor(_label);
    vm.serializeJson('identityExtraField', _script.recordJson(_deployment, _table, _operator, block.chainid));
    string memory _json = vm.serializeString('identityExtraField', 'sdkEndpoint', 'https://example.invalid/rpc');
    assertTrue(vm.keyExistsJson(_json, '.sdkEndpoint'), 'fixture: the candidate lacks the extra field');
    // it should publish no key the checks did not read
    // it should publish exactly the nine record keys, each the checked value
    _confirmAndRequireCheckedRecord(_label, _json, _deployment, _table, _operator, 'sdkEndpoint');
  }

  /*///////////////////////////////////////////////////////////////
                            LOOK-ALIKES
  ///////////////////////////////////////////////////////////////*/

  /// @notice Requires `_reason` to be exactly the code mismatch naming `_component` at `_target`, with the kit's
  ///         code hash `_expected` and the code hash `_actual` found there.
  function _assertCodeMismatch(
    bytes memory _reason,
    string memory _component,
    address _target,
    bytes32 _expected,
    bytes32 _actual
  ) internal pure {
    assertEq(
      _reason,
      abi.encodeWithSelector(
        IDeployIdentity.DeployIdentity_CodeMismatch.selector, _component, _target, _expected, _actual
      ),
      'the code mismatch error'
    );
  }

  /// On Sepolia, confirmLabel reverts with the code mismatch naming zkPassportMethod, and publishes nothing, when
  /// the candidate's zkPassport method is a look-alike that passes every call on to the real one, so it answers
  /// trustedParties and ERC-165 like it. Every other check passes, so only the code hash tells it apart, and a
  /// record naming it would send every passport guardian's proof to code nobody reviewed.
  function test_RevertWhen_TheRecordedZkPassportMethodIsALookAlike() external {
    if (!_forkSepolia()) return;
    string memory _label = 'test-identity-confirm-look-alike-zkpassport';
    (
      IDeployIdentity.Deployment memory _deployment,
      IDeployIdentity.Pins memory _table,
      IDeployIdentity.Inputs memory _operator
    ) = _deployFor(_label);
    bytes32 _kitCodehash = address(_deployment.zkPassportMethod).codehash;
    address _lookAlike = address(new DeployMockLookAlike(address(_deployment.zkPassportMethod)));
    bytes32 _lookAlikeCodehash = _lookAlike.codehash;
    _deployment.zkPassportMethod = IPolicyMethod(_lookAlike);
    // it should revert
    // it should name zkPassportMethod, the look-alike, the kit's code hash and the one found
    // it should publish no record
    bytes memory _reason = _confirmReverting(_label, _script.recordJson(_deployment, _table, _operator, block.chainid));
    _assertCodeMismatch(_reason, 'zkPassportMethod', _lookAlike, _kitCodehash, _lookAlikeCodehash);
  }

  /// On mainnet, where no Aadhaar method ships, confirmLabel reverts with the code mismatch naming
  /// zkPassportMethod, and publishes nothing, when the candidate's zkPassport method is a look-alike that passes
  /// every call on to the real one and its Aadhaar method is the zero address. Mainnet records skip every Aadhaar
  /// check, so the zkPassport code hash must still be compared there, or a mainnet record could name code nobody
  /// reviewed. The code hashes are read before confirm runs.
  function test_RevertWhen_AMainnetZkPassportMethodIsALookAlike() external {
    if (!_forkMainnet()) return;
    string memory _label = 'test-identity-confirm-mainnet-look-alike';
    (
      IDeployIdentity.Deployment memory _deployment,
      IDeployIdentity.Pins memory _table,
      IDeployIdentity.Inputs memory _operator
    ) = _deployFor(_label);
    bytes32 _kitCodehash = address(_deployment.zkPassportMethod).codehash;
    address _lookAlike = address(new DeployMockLookAlike(address(_deployment.zkPassportMethod)));
    bytes32 _lookAlikeCodehash = _lookAlike.codehash;
    _deployment.zkPassportMethod = IPolicyMethod(_lookAlike);
    _deployment.aadhaarMethod = IPolicyMethod(address(0));
    // it should revert
    // it should name zkPassportMethod, the look-alike, the kit's code hash and the one found
    // it should publish no record
    bytes memory _reason = _confirmReverting(_label, _script.recordJson(_deployment, _table, _operator, block.chainid));
    _assertCodeMismatch(_reason, 'zkPassportMethod', _lookAlike, _kitCodehash, _lookAlikeCodehash);
  }

  /// On Sepolia, confirmLabel reverts with the code mismatch naming aadhaarMethod, and publishes nothing, when the
  /// candidate's Aadhaar method is a look-alike that passes every call on to the real one, so it answers
  /// trustedParties, its verifier and ERC-165 like it. The kit's code hash is the real method's, built with the
  /// same Safe, key and verifier.
  function test_RevertWhen_TheRecordedAadhaarMethodIsALookAlike() external {
    if (!_forkSepolia()) return;
    string memory _label = 'test-identity-confirm-look-alike-aadhaar';
    (
      IDeployIdentity.Deployment memory _deployment,
      IDeployIdentity.Pins memory _table,
      IDeployIdentity.Inputs memory _operator
    ) = _deployFor(_label);
    bytes32 _kitCodehash = address(_deployment.aadhaarMethod).codehash;
    address _lookAlike = address(new DeployMockLookAlike(address(_deployment.aadhaarMethod)));
    bytes32 _lookAlikeCodehash = _lookAlike.codehash;
    _deployment.aadhaarMethod = IPolicyMethod(_lookAlike);
    // it should revert
    // it should name aadhaarMethod, the look-alike, the kit's code hash and the one found
    // it should publish no record
    bytes memory _reason = _confirmReverting(_label, _script.recordJson(_deployment, _table, _operator, block.chainid));
    _assertCodeMismatch(_reason, 'aadhaarMethod', _lookAlike, _kitCodehash, _lookAlikeCodehash);
  }

  /// On Sepolia, confirmLabel reverts with the code mismatch naming aadhaarMethod, and publishes nothing, when the
  /// candidate's Aadhaar method is the kit's own code built with another verifier, an address hashed from a label,
  /// whose verifier read is mocked to answer the table's verifier. Its roles, key and interfaces are the real
  /// ones, so only the code hash of a copy built with the table's verifier shows it would send every proof to
  /// another verifier.
  function test_RevertWhen_TheRecordedAadhaarMethodStoresAnotherVerifier() external {
    if (!_forkSepolia()) return;
    string memory _label = 'test-identity-confirm-other-verifier';
    (
      IDeployIdentity.Deployment memory _deployment,
      IDeployIdentity.Pins memory _table,
      IDeployIdentity.Inputs memory _operator
    ) = _deployFor(_label);
    bytes32 _kitCodehash = address(_deployment.aadhaarMethod).codehash;
    AadhaarMethod _other = new AadhaarMethod(
      _operator.aadhaarMethodSafe,
      _operator.aadhaarMethodSafe,
      _oneKey(_table.aadhaarKey),
      _freshAddress('otherAadhaarVerifier', 0)
    );
    vm.mockCall(address(_other), abi.encodeCall(AadhaarMethod.verifier, ()), abi.encode(_table.aadhaarVerifier));
    assertEq(_other.verifier(), _table.aadhaarVerifier, 'fixture: the verifier read names another verifier');
    bytes32 _otherCodehash = address(_other).codehash;
    _deployment.aadhaarMethod = IPolicyMethod(address(_other));
    // it should revert
    // it should name aadhaarMethod, the method, the kit's code hash and the one found
    // it should publish no record
    bytes memory _reason = _confirmReverting(_label, _script.recordJson(_deployment, _table, _operator, block.chainid));
    _assertCodeMismatch(_reason, 'aadhaarMethod', address(_other), _kitCodehash, _otherCodehash);
  }
}
