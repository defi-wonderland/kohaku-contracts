// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {Vm} from 'forge-std/Vm.sol';
import {IPolicyManager} from 'interfaces/IPolicyManager.sol';
import {IntegrationDemoKitTestBase} from 'test/utils/IntegrationDemoKitTestBase.sol';

/// @notice The submitter adds an extra place the rule does not need: a credential under a
///         third-party method that its owner can pause. The places a request uses, not the rule,
///         decide which paused methods veto the spend. The extra place lets that method's pause veto
///         the holder's recovery.
contract AnExtraProofBeforeTheSpendTest is IntegrationDemoKitTestBase {
  /// @notice Alice, Bob, the phone and the extra third-party credential.
  function _setWithExtraPlace() internal pure returns (uint256[] memory _list) {
    _list = new uint256[](4);
    (_list[0], _list[1], _list[2], _list[3]) = (_ALICE, _BOB, _PHONE, _THIRD_PARTY);
  }

  /// @notice A pause on the extra method, turned on one second before the wait ends, makes it veto
  ///         the spend. The attempt recorded that method as used, so the spend checks its pause. The whole
  ///         batch reverts, the attempt keeps waiting and no key changes.
  function test_RevertWhen_TheExtraMethodIsStoppedAtTheSpend() external {
    // it should revert
    _authorizeAndCommit();
    vm.recordLogs();
    _open(_setWithExtraPlace());
    StartedLog memory _started = _startedLog(vm.getRecordedLogs());
    assertEq(_started.usedMethods.length, 3, 'the attempt did not record each distinct method once');
    assertEq(_started.usedMethods[0], address(_ecdsa), 'the first used method is not the wallet method');
    assertEq(_started.usedMethods[1], address(_passkey), 'the second used method is not the passkey method');
    assertEq(_started.usedMethods[2], address(_thirdParty), 'the extra method was not recorded');
    assertEq(abi.encode(_state().attempt.usedMethods), abi.encode(_started.usedMethods), 'stored and published differ');

    IPolicyManager.Attempt memory _waiting = _state().attempt;
    vm.warp(_waiting.consumableAfter - 1);
    _stopThirdParty();
    vm.warp(_waiting.consumableAfter);
    vm.expectRevert(
      abi.encodeWithSelector(IPolicyManager.PolicyManager_MethodVetoedSpend.selector, address(_thirdParty))
    );
    _executeHandover();
    assertEq(uint256(_state().attempt.state), uint256(IPolicyManager.AttemptState.Waiting), 'the attempt ended');
    assertEq(_privilege(_holderKey), _SIGNER_VALUE, 'the vetoed batch moved the lost key');
    assertEq(_privilege(_newKey), bytes32(0), 'the vetoed batch installed the new key');
  }

  /// @notice While the pause is on, anyone can cancel the attempt by veto, naming the paused method,
  ///         and the event names it. After the pause lifts, the cancelled attempt stays cancelled, and the
  ///         method works again for a new attempt.
  function test_WhenAnyoneCancelsByVetoWhileTheStopIsOn() external {
    // it should end the attempt naming the paused method and leave the method working after the lift
    _authorizeAndCommit();
    _open(_setWithExtraPlace());
    IPolicyManager.Attempt memory _waiting = _state().attempt;
    vm.warp(_waiting.consumableAfter - 1);
    _stopThirdParty();
    vm.warp(_waiting.consumableAfter);

    address _anyone = makeAddr('anyone');
    vm.expectEmit(true, true, true, true, address(_manager));
    emit IPolicyManager.AttemptCancelled(
      _account, address(_action), 1, _anyone, address(_thirdParty), 1, new uint256[](0)
    );
    vm.prank(_anyone);
    _manager.cancelByVeto(_account, address(_action), 1, address(_thirdParty));

    _liftThirdParty();
    vm.expectRevert(_notConsumable(IPolicyManager.AttemptState.Cancelled, _waiting));
    _executeHandover();
    _open(_places(_ALICE, _BOB, _THIRD_PARTY));
    assertEq(_state().attempt.attemptId, 2, 'the lifted method did not open a fresh attempt');
  }

  /// @notice Without the extra place, the third-party pause cannot veto the recovery. The attempt
  ///         never recorded that method, so a cancel by veto naming it is refused. The handover runs while the
  ///         method is still paused.
  function test_WhenTheSetLeavesTheExtraPlaceOut() external {
    // it should run the handover while the third-party method is paused
    _authorizeAndCommit();
    _open(_openingSet());
    IPolicyManager.Attempt memory _waiting = _state().attempt;
    assertEq(_waiting.usedMethods.length, 2, 'the attempt recorded a method its set did not use');
    _stopThirdParty();
    vm.warp(_waiting.consumableAfter);

    vm.expectRevert(
      abi.encodeWithSelector(IPolicyManager.PolicyManager_MethodNotUsed.selector, 1, address(_thirdParty))
    );
    _manager.cancelByVeto(_account, address(_action), 1, address(_thirdParty));
    _executeHandover();
    assertEq(uint256(_state().attempt.state), uint256(IPolicyManager.AttemptState.Consumed), 'nothing was spent');
    assertEq(_privilege(_newKey), _KEY_VALUE, 'the new key holds no key value');
  }

  /// @notice When the pause lifts while the attempt still waits, the recovery can run at once. The
  ///         pause did not reset the attempt's clock. The vetoed handover runs in the next block.
  function test_WhenTheStopLiftsBeforeAnyoneCancels() external {
    // it should run the handover in the block after the lift with the clock unchanged
    _authorizeAndCommit();
    _open(_setWithExtraPlace());
    IPolicyManager.Attempt memory _waiting = _state().attempt;
    _stopThirdParty();
    vm.warp(uint256(_waiting.consumableAfter) + 30 days);
    vm.expectRevert(
      abi.encodeWithSelector(IPolicyManager.PolicyManager_MethodVetoedSpend.selector, address(_thirdParty))
    );
    _executeHandover();

    _liftThirdParty();
    vm.roll(block.number + 1);
    assertEq(_state().attempt.consumableAfter, _waiting.consumableAfter, 'the stop re-timed the attempt');
    _executeHandover();
    assertEq(uint256(_state().attempt.state), uint256(IPolicyManager.AttemptState.Consumed), 'nothing was spent');
    assertEq(_privilege(_newKey), _KEY_VALUE, 'the new key holds no key value');
  }

  /// @notice A holder can commit that pauses never veto their recovery. Then the request opens while
  ///         the method is paused, nobody can cancel by veto, and the handover runs without
  ///         reading the pause at all.
  function test_WhenTheSetupIgnoresStops() external {
    // it should open, refuse the veto and run the handover through the pause
    bytes memory _ignoring = _rule(_WAIT, true);
    _asHolder(_two(_authorizeCall(), _commitCall(1, _commitmentOf(1, _ignoring))));
    _stopThirdParty();
    _send(_requestOver(_ignoring, _setWithExtraPlace(), 1, 1, _window()));
    IPolicyManager.Attempt memory _waiting = _state().attempt;
    assertTrue(_waiting.ignoresPause, 'the attempt did not copy the choice');

    vm.expectRevert(abi.encodeWithSelector(IPolicyManager.PolicyManager_AttemptIgnoresPause.selector, 1));
    _manager.cancelByVeto(_account, address(_action), 1, address(_thirdParty));

    vm.warp(_waiting.consumableAfter);
    vm.startStateDiffRecording();
    _executeHandover();
    Vm.AccountAccess[] memory _accesses = vm.stopAndReturnStateDiff();
    for (uint256 _i; _i < _accesses.length; ++_i) {
      assertTrue(_accesses[_i].account != address(_thirdParty), 'the spend read the stop it was told to ignore');
    }
    assertEq(uint256(_state().attempt.state), uint256(IPolicyManager.AttemptState.Consumed), 'nothing was spent');
    assertEq(_privilege(_newKey), _KEY_VALUE, 'the new key holds no key value');
  }
}
