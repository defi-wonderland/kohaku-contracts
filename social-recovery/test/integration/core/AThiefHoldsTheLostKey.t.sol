// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {Vm} from 'forge-std/Vm.sol';
import {SetupBody} from 'libraries/SetupBody.sol';
import {IPolicyManager} from 'interfaces/IPolicyManager.sol';
import {IAmbireAccount} from 'contracts/actions/ambire/IAmbireAccount.sol';
import {ActionBatch} from 'test/utils/ActionBatch.sol';
import {IntegrationDemoKitTestBase} from 'test/utils/IntegrationDemoKitTestBase.sol';

/// @notice A thief stole the holder's key, and the guardians open a recovery. The kit does not
///         defend against a stolen key, because that key keeps every power the account gives it. The
///         thief can cancel the recovery, replace the rule, or spend the approval without running the
///         handover. These tests show exactly what happens in each case.
contract AThiefHoldsTheLostKeyTest is IntegrationDemoKitTestBase {
  /// @notice The attempt the guardians opened.
  IPolicyManager.Attempt internal _guardiansAttempt;

  function setUp() public override {
    super.setUp();
    _authorizeAndCommit();
    _open(_openingSet());
    _guardiansAttempt = _state().attempt;
  }

  /// @notice The thief cancels with the stolen key one second before the wait ends. The manager
  ///         records the account as the canceller, the same as for the holder. A second later the
  ///         executor finds nothing to spend.
  function test_WhenTheThiefCancelsAtTheLastSecond() external {
    // it should cancel the guardians' attempt in the account's name
    vm.warp(_guardiansAttempt.consumableAfter - 1);
    vm.expectEmit(true, true, true, true, address(_manager));
    emit IPolicyManager.AttemptCancelled(_account, address(_action), 1, _account, address(0), 1, new uint256[](0));
    _asKey(_holderKey, _one(_cancelByOwnerCall()));

    vm.warp(_guardiansAttempt.consumableAfter);
    vm.expectRevert(_notConsumable(IPolicyManager.AttemptState.Cancelled, _guardiansAttempt));
    _executeHandover();
    assertEq(_privilege(_holderKey), _SIGNER_VALUE, 'the thief lost the key');
  }

  /// @notice The thief commits a rule that names a guardian of their own. The new rule cancels the
  ///         guardians' attempt and moves the nonce, so their next request is refused. The thief's
  ///         guardian opens an attempt under the new rule, and the handover installs the thief's key.
  function test_WhenTheThiefCommitsARuleOfTheirOwn() external {
    // it should retire the holder's rule and let the thief's own guardian recover the account to the thief
    (address _accomplice, uint256 _accompliceKey) = makeAddrAndKey('thiefGuardian');
    bytes32 _salt = keccak256('thief salt');
    IPolicyManager.Clause[] memory _clauses = new IPolicyManager.Clause[](1);
    _clauses[0].threshold = 1;
    _clauses[0].credentials = new bytes32[](1);
    _clauses[0].credentials[0] = keccak256(abi.encode(address(_ecdsa), abi.encode(_accomplice), _salt));
    bytes memory _thiefRule = SetupBody.encode(_WAIT, false, _clauses);

    vm.expectEmit(true, true, true, true, address(_manager));
    emit IPolicyManager.AttemptCancelled(_account, address(_action), 1, address(0), address(0), 1, new uint256[](0));
    _asKey(_holderKey, _one(_commitCall(2, _commitmentOf(2, _thiefRule))));

    IPolicyManager.AttemptRequest memory _guardiansAgain = _request(_places(_BOB, _CAROL, _PHONE), 2, 1, _window());
    vm.expectRevert(_wrongNonce(1, 2));
    _send(_guardiansAgain);

    address _thiefKey = makeAddr('thiefFreshKey');
    bytes memory _toTheThief = ActionBatch.payload(_thiefKey, _holderKey);
    IPolicyManager.AttemptRequest memory _req = _requestOver(_thiefRule, new uint256[](0), 2, 2, _window());
    _req.payload = _toTheThief;
    _req.proofs = new IPolicyManager.ProofPlace[](1);
    _req.proofs[0] = IPolicyManager.ProofPlace({
      place: 0, method: address(_ecdsa), config: abi.encode(_accomplice), salt: _salt, proof: ''
    });
    (uint8 _v, bytes32 _r, bytes32 _s) = vm.sign(_accompliceKey, _manager.hashApproval(_req, 0));
    _req.proofs[0].proof = abi.encodePacked(_r, _s, _v);
    _send(_req);

    vm.warp(_state().attempt.consumableAfter);
    _executeHandoverOf(_toTheThief);
    assertEq(_privilege(_thiefKey), _KEY_VALUE, 'the thief key holds no key value');
    assertEq(_privilege(_newKey), bytes32(0), 'the new key the guardians chose was installed');
  }

  /// @notice After the wait, the thief calls the manager's spend directly from the account. The
  ///         approval is spent but no key changes. The executor then finds the attempt already spent, so
  ///         the account's own key can waste an approval.
  function test_WhenTheThiefSpendsTheApprovalAlone() external {
    // it should consume the attempt with no key moved and refuse the handover after
    vm.warp(_guardiansAttempt.consumableAfter);
    bytes memory _consume = abi.encodeCall(
      IPolicyManager.consume, (address(_action), _guardiansAttempt.attemptId, _guardiansAttempt.payloadHash)
    );
    vm.recordLogs();
    _asKey(_holderKey, _one(_managerCall(_consume)));
    Vm.Log[] memory _logs = vm.getRecordedLogs();

    assertEq(uint256(_state().attempt.state), uint256(IPolicyManager.AttemptState.Consumed), 'nothing was spent');
    assertEq(_countLogs(_logs, IPolicyManager.AttemptConsumed.selector), 1, 'not released exactly once');
    for (uint256 _i; _i < _logs.length; ++_i) {
      assertTrue(_logs[_i].topics[0] != IAmbireAccount.LogPrivilegeChanged.selector, 'a privilege moved');
    }
    assertEq(_privilege(_holderKey), _SIGNER_VALUE, 'the thief lost the key');
    assertEq(_privilege(_newKey), bytes32(0), 'the new key was installed');

    vm.expectRevert(_notConsumable(IPolicyManager.AttemptState.Consumed, _guardiansAttempt));
    _executeHandover();
  }

  /// @notice At the exact end of the wait, the executor's handover runs before the thief's cancel. The
  ///         stolen key is no longer a key of the account, so the account refuses the thief's cancel.
  function test_WhenTheHandoverRunsFirstAtTheBoundary() external {
    // it should refuse the thief's cancel for want of a privilege
    vm.warp(_guardiansAttempt.consumableAfter);
    _executeHandover();
    vm.expectRevert(bytes('INSUFFICIENT_PRIVILEGE'));
    _asKey(_holderKey, _one(_cancelByOwnerCall()));
    assertEq(_privilege(_newKey), _KEY_VALUE, 'the new key holds no key value');
  }

  /// @notice At the exact end of the wait, the thief's cancel runs before the executor's handover. The
  ///         attempt is cancelled and the handover is refused. Whichever transaction comes first wins.
  function test_WhenTheThiefCancelsFirstAtTheBoundary() external {
    // it should refuse the handover of the cancelled attempt
    vm.warp(_guardiansAttempt.consumableAfter);
    _asKey(_holderKey, _one(_cancelByOwnerCall()));
    vm.expectRevert(_notConsumable(IPolicyManager.AttemptState.Cancelled, _guardiansAttempt));
    _executeHandover();
    assertEq(_privilege(_holderKey), _SIGNER_VALUE, 'the thief lost the key');
  }
}
