// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {VmSafe} from 'forge-std/Vm.sol';
import {DeployIdentity} from 'script/DeployIdentity.s.sol';
import {IDeploy} from 'script/IDeploy.sol';
import {IDeployIdentity} from 'script/IDeployIdentity.sol';
import {DeployForkTestBase} from 'test/utils/DeployForkTestBase.sol';
import {DeployHarness} from 'test/utils/DeployHarness.sol';

/// @notice recordLabel, the wrapper that hands the DEPLOYMENT_LABEL environment variable to the
///         label rule, in both deployment scripts: the demo path's and the identity methods', and run,
///         which applies that rule to the variable before it deploys anything and reads it on every
///         run, a dry run included. The rule itself is tested through each script's labelFor, with no
///         environment read. The environment is shared by every test in the run and forge runs tests
///         in parallel, and forge cannot unset a variable, so this is the only test that sets the
///         variable and the only one that calls run on a supported chain. It checks both scripts and
///         both entry points in one test. run on the local chain, in other tests, stops on the chain
///         check before it reads the label, and confirm does the same.
contract DeployRecordLabelTest is DeployForkTestBase {
  /// @notice A valid label no other test uses, under which run executes on the Sepolia fork.
  string internal constant _RUN_LABEL = 'test-record-label-run';

  /// @notice What the run on the Sepolia fork gave: whether it succeeded, the contracts it created,
  ///         and whether a candidate appeared under the run label or under Sepolia's default name.
  struct ForkRun {
    uint256 creations;
    bool succeeded;
    bool labelCandidateWritten;
    bool defaultCandidateWritten;
  }

  /// @notice What run gave in each script for each invalid label: its revert data and the contracts
  ///         it created.
  struct InvalidRuns {
    bytes[3] reverts;
    bytes[3] identityReverts;
    uint256[3] creations;
    uint256[3] identityCreations;
  }

  /// @notice The label values the rule refuses that the run checks use: digits only, an uppercase
  ///         letter, and 65 characters, one more than the rule allows.
  function _invalidLabels() internal pure returns (string[3] memory _labels) {
    _labels = ['12345', 'Tenderly-sepolia', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'];
  }

  function _candidatePath(string memory _label) internal pure returns (string memory _path) {
    _path = string.concat('script/deployments/', _label, '.pending.json');
  }

  /// recordLabel answers the value DEPLOYMENT_LABEL holds, in the demo path's script and in the
  /// identity script, so an operator's rehearsal label reaches both records' names. Then, for each of
  /// three values the rule refuses, run in both scripts on Sepolia's chain id, outside a broadcast and
  /// with no fork, as a dry run, stops with the invalid label error and creates no contract, so an
  /// operator learns of a bad label from the dry run rather than after a deployment. Without the label
  /// check first, run would go on to the P256VERIFY probe and fail with forge's own error.
  /// Last, under a valid label, run on a Sepolia fork outside a broadcast deploys the kit and writes no
  /// candidate, neither under the label nor under Sepolia's default record name: a dry run that wrote
  /// one would replace the candidate of a real broadcast with addresses that never landed. That part
  /// runs only when SEPOLIA_RPC_URL is set, and the test refuses to start when either candidate exists
  /// already, so it never touches an operator's file. The test collects every result before it
  /// restores the variable and asserts afterwards, so a failing assertion never leaves a label set
  /// for other tests.
  function test_WhenTheVariableIsSet() external {
    string memory _sepoliaUrl = vm.envOr('SEPOLIA_RPC_URL', string(''));
    bool _forkRun = bytes(_sepoliaUrl).length > 0;
    string memory _defaultCandidate = _candidatePath(vm.toString(_SEPOLIA_CHAIN_ID));
    string memory _labelCandidate = _candidatePath(_RUN_LABEL);
    assertFalse(vm.exists(_defaultCandidate), 'fixture: a Sepolia candidate exists already');
    assertFalse(vm.exists(_labelCandidate), 'fixture: a candidate exists under the run label');

    DeployIdentity _identityScript = new DeployIdentity();
    _setLabel('test-record-label-wrapper');
    string memory _label = _script.recordLabel(_SEPOLIA_CHAIN_ID);
    string memory _identityLabel = _identityScript.recordLabel(_SEPOLIA_CHAIN_ID);
    vm.chainId(_SEPOLIA_CHAIN_ID);
    string[3] memory _invalid = _invalidLabels();
    InvalidRuns memory _runs = _runWithInvalidLabels(_invalid, address(_identityScript));
    ForkRun memory _fork;
    if (_forkRun) {
      vm.setEnv(_LABEL_ENV, _RUN_LABEL);
      _fork = _runOnSepoliaFork(_sepoliaUrl, _labelCandidate, _defaultCandidate);
    }
    _restoreLabel();

    // it should answer the variable's value
    assertEq(_label, 'test-record-label-wrapper', 'demo path script');
    // it should answer the same value through the identity script
    assertEq(_identityLabel, 'test-record-label-wrapper', 'identity script');
    for (uint256 _i; _i < 3; ++_i) {
      // it should stop the demo path's run with the invalid label error
      assertEq(
        _runs.reverts[_i], abi.encodeWithSelector(IDeploy.Deploy_InvalidLabel.selector, _invalid[_i]), 'run revert'
      );
      // it should stop the identity script's run with the invalid label error
      assertEq(
        _runs.identityReverts[_i],
        abi.encodeWithSelector(IDeployIdentity.DeployIdentity_InvalidLabel.selector, _invalid[_i]),
        'identity run revert'
      );
      // it should create no contract in either run
      assertEq(_runs.creations[_i], 0, 'run created contracts');
      assertEq(_runs.identityCreations[_i], 0, 'identity run created contracts');
    }
    if (_forkRun) {
      // it should deploy the kit when run on a fork under a valid label
      assertTrue(_fork.succeeded, 'run reverted on the Sepolia fork');
      assertEq(_fork.creations, 4, 'contracts created on the fork');
      // it should write no candidate outside a broadcast
      assertFalse(_fork.labelCandidateWritten, 'run wrote a candidate under the label outside a broadcast');
      assertFalse(_fork.defaultCandidateWritten, 'run wrote a candidate under the default name outside a broadcast');
    }
  }

  /// @notice Sets DEPLOYMENT_LABEL to each of `_invalid` in turn and calls run in the demo path's
  ///         script and in `_identityScript`, recording what each gave. The caller restores the
  ///         variable.
  function _runWithInvalidLabels(string[3] memory _invalid, address _identityScript)
    internal
    returns (InvalidRuns memory _runs)
  {
    for (uint256 _i; _i < 3; ++_i) {
      vm.setEnv(_LABEL_ENV, _invalid[_i]);
      (_runs.reverts[_i], _runs.creations[_i]) = _runReverting(address(_script));
      (_runs.identityReverts[_i], _runs.identityCreations[_i]) = _runReverting(_identityScript);
    }
  }

  /// @notice Calls run on `_target`, one of the two scripts, while recording account accesses, and
  ///         returns its revert data, empty if it did not revert, and the contracts it created.
  function _runReverting(address _target) internal returns (bytes memory _reason, uint256 _created) {
    vm.startStateDiffRecording();
    (bool _success, bytes memory _returned) = _target.call(abi.encodeWithSelector(IDeploy.run.selector));
    _created = _creations(vm.stopAndReturnStateDiff());
    if (!_success) _reason = _returned;
  }

  /// @notice Forks Sepolia at the pinned block, creates the demo path's script there, and calls run
  ///         outside a broadcast while recording account accesses. Records whether run succeeded, the
  ///         contracts it created, and whether either candidate appeared, and removes any that did.
  function _runOnSepoliaFork(string memory _url, string memory _labelCandidate, string memory _defaultCandidate)
    internal
    returns (ForkRun memory _result)
  {
    vm.createSelectFork(_url, _SEPOLIA_BLOCK);
    DeployHarness _forkScript = new DeployHarness();
    vm.startStateDiffRecording();
    (_result.succeeded,) = address(_forkScript).call(abi.encodeWithSelector(IDeploy.run.selector));
    VmSafe.AccountAccess[] memory _accesses = vm.stopAndReturnStateDiff();
    _result.creations = _creations(_accesses);
    _result.labelCandidateWritten = vm.exists(_labelCandidate);
    _result.defaultCandidateWritten = vm.exists(_defaultCandidate);
    if (_result.labelCandidateWritten) vm.removeFile(_labelCandidate);
    if (_result.defaultCandidateWritten) vm.removeFile(_defaultCandidate);
  }
}
