// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {IPolicyManager} from 'interfaces/IPolicyManager.sol';
import {IntegrationDemoKitTestBase} from 'test/utils/IntegrationDemoKitTestBase.sol';

/// @notice A cancel and the spend race for the same attempt once its wait is over. A cancel by veto
///         needs the method the attempt used to be paused, and a cancel by proofs needs guardians who
///         meet the rule. Whichever call runs first decides the attempt, and the other one is refused.
contract ACancelRacesTheSpendTest is IntegrationDemoKitTestBase {
  /// @notice Alice, Bob and the credential under the third-party method that can be paused.
  function _setWithThePausableMethod() internal pure returns (uint256[] memory _list) {
    _list = _places(_ALICE, _BOB, _THIRD_PARTY);
  }

  /// @notice Anyone's cancel by veto of attempt one, naming the third-party method.
  function _vetoAs(address _anyone) internal {
    vm.prank(_anyone);
    _manager.cancelByVeto(_account, address(_action), 1, address(_thirdParty));
  }

  /// @notice The refusal of a cancel that finds no attempt waiting.
  function _noActiveAttempt() internal view returns (bytes memory _err) {
    _err = abi.encodeWithSelector(IPolicyManager.PolicyManager_NoActiveAttempt.selector, _account, address(_action));
  }

  /// @notice The refusal of a spend that the paused third-party method vetoes.
  function _vetoedSpend() internal view returns (bytes memory _err) {
    _err = abi.encodeWithSelector(IPolicyManager.PolicyManager_MethodVetoedSpend.selector, address(_thirdParty));
  }

  /// @notice Asserts the attempt is in `_expected` and the lost key still holds the account.
  function _assertKeysUnchanged(IPolicyManager.AttemptState _expected) internal view {
    assertEq(uint256(_state().attempt.state), uint256(_expected), 'the attempt is in another state');
    assertEq(_privilege(_holderKey), _SIGNER_VALUE, 'the lost key was removed');
    assertEq(_privilege(_newKey), bytes32(0), 'the new key was installed');
  }

  /// @notice Asserts the spend ran: the attempt is spent, the new key holds the account and the lost
  ///         key does not.
  function _assertHandedOver() internal view {
    assertEq(uint256(_state().attempt.state), uint256(IPolicyManager.AttemptState.Consumed), 'nothing was spent');
    assertEq(_privilege(_newKey), _KEY_VALUE, 'the new key holds no key value');
    assertEq(_privilege(_holderKey), bytes32(0), 'the lost key still holds a privilege');
  }

  /*///////////////////////////////////////////////////////////////
                          CANCEL BY VETO
  ///////////////////////////////////////////////////////////////*/

  /// @notice When the spend runs before the method is paused, the recovery is done and a pause that
  ///         comes after it reaches nothing. Anyone's veto is refused because no attempt waits.
  ///         `_late` is how long after the wait the spend runs, and `_seed` builds the caller's address.
  function test_RevertWhen_TheSpendRunsBeforeThePause(uint256 _late, uint256 _seed) external {
    // it should revert
    _authorizeAndCommit();
    _open(_setWithThePausableMethod());
    vm.warp(uint256(_state().attempt.consumableAfter) + bound(_late, 0, 30 days));
    _executeHandover();
    _stopThirdParty();

    vm.expectRevert(_noActiveAttempt());
    _vetoAs(_fresh('anyone', _seed));
    _assertHandedOver();
  }

  /// @notice When the method is paused during the wait, the spend at the end of the wait is vetoed and
  ///         the attempt keeps waiting with no key moved. In a later block anyone ends it by veto, and
  ///         the spend stays refused. `_seed` builds the caller's address.
  function test_WhenThePauseComesBeforeTheSpend(uint256 _seed) external {
    // it should veto the spend, keep the attempt waiting and let anyone end it
    _authorizeAndCommit();
    _open(_setWithThePausableMethod());
    IPolicyManager.Attempt memory _waiting = _state().attempt;
    vm.warp(_waiting.consumableAfter - 1);
    _stopThirdParty();

    vm.warp(_waiting.consumableAfter);
    vm.expectRevert(_vetoedSpend());
    _executeHandover();
    _assertKeysUnchanged(IPolicyManager.AttemptState.Waiting);

    vm.roll(block.number + 1);
    address _anyone = _fresh('anyone', _seed);
    vm.expectEmit(true, true, true, true, address(_manager));
    emit IPolicyManager.AttemptCancelled(
      _account, address(_action), 1, _anyone, address(_thirdParty), 1, new uint256[](0)
    );
    _vetoAs(_anyone);
    _assertKeysUnchanged(IPolicyManager.AttemptState.Cancelled);

    vm.expectRevert(_notConsumable(IPolicyManager.AttemptState.Cancelled, _waiting));
    _executeHandover();
  }

  /// @notice In one block the method is paused, then the spend is sent before the veto. The spend
  ///         cannot run through the pause, so the veto that follows it still finds the attempt and ends
  ///         it. `_seed` builds the caller's address.
  function test_WhenTheSpendIsOrderedBeforeTheVetoInOneBlock(uint256 _seed) external {
    // it should refuse the spend and let the veto end the attempt
    _authorizeAndCommit();
    _open(_setWithThePausableMethod());
    vm.warp(_state().attempt.consumableAfter);
    _stopThirdParty();

    vm.expectRevert(_vetoedSpend());
    _executeHandover();
    _vetoAs(_fresh('anyone', _seed));
    _assertKeysUnchanged(IPolicyManager.AttemptState.Cancelled);
  }

  /// @notice In one block the method is paused, then the veto is sent before the spend. The veto ends
  ///         the attempt, so the spend that follows finds it cancelled and no key moves. `_seed` builds
  ///         the caller's address.
  function test_RevertWhen_TheVetoIsOrderedBeforeTheSpendInOneBlock(uint256 _seed) external {
    // it should revert
    _authorizeAndCommit();
    _open(_setWithThePausableMethod());
    IPolicyManager.Attempt memory _waiting = _state().attempt;
    vm.warp(_waiting.consumableAfter);
    _stopThirdParty();

    _vetoAs(_fresh('anyone', _seed));
    vm.expectRevert(_notConsumable(IPolicyManager.AttemptState.Cancelled, _waiting));
    _executeHandover();
    _assertKeysUnchanged(IPolicyManager.AttemptState.Cancelled);
  }

  /// @notice A holder who committed that pauses never reach their recovery keeps it through the pause.
  ///         Anyone's veto is refused while the attempt waits, the spend runs in the same block, and a
  ///         veto after it finds nothing to cancel. `_seed` builds the caller's address.
  function test_WhenTheSetupIgnoresThePause(uint256 _seed) external {
    // it should refuse the veto and run the spend through the pause
    bytes memory _ignoring = _rule(_WAIT, true);
    _asHolder(_two(_authorizeCall(), _commitCall(1, _commitmentOf(1, _ignoring))));
    _send(_requestOver(_ignoring, _setWithThePausableMethod(), 1, 1, _window()));
    vm.warp(_state().attempt.consumableAfter);
    _stopThirdParty();

    address _anyone = _fresh('anyone', _seed);
    vm.expectRevert(abi.encodeWithSelector(IPolicyManager.PolicyManager_AttemptIgnoresPause.selector, 1));
    _vetoAs(_anyone);
    _executeHandover();
    _assertHandedOver();

    vm.expectRevert(_noActiveAttempt());
    _vetoAs(_anyone);
  }

  /*///////////////////////////////////////////////////////////////
                          CANCEL BY PROOFS
  ///////////////////////////////////////////////////////////////*/

  /// @notice At the end of the wait, guardians who meet the rule send their cancellation before the
  ///         spend. The attempt ends and the handover sent after it in the same block is refused, so the
  ///         lost key keeps the account. `_seed` builds the canceller's address.
  function test_RevertWhen_TheCancellationIsOrderedFirst(uint256 _seed) external {
    // it should revert
    _authorizeAndCommit();
    _open(_openingSet());
    IPolicyManager.Attempt memory _waiting = _state().attempt;
    vm.warp(_waiting.consumableAfter);
    IPolicyManager.CancelRequest memory _cancel = _cancelRequest(_places(_ALICE, _CAROL, _PHONE), 1, 1, _window());

    vm.prank(_fresh('canceller', _seed));
    _manager.cancelByProofs(_cancel);
    vm.expectRevert(_notConsumable(IPolicyManager.AttemptState.Cancelled, _waiting));
    _executeHandover();
    _assertKeysUnchanged(IPolicyManager.AttemptState.Cancelled);
  }

  /// @notice At the end of the wait, the spend is sent before the guardians' cancellation. The recovery
  ///         is done, and the cancellation that follows in the same block is refused because no attempt
  ///         waits. `_seed` builds the canceller's address.
  function test_RevertWhen_TheSpendIsOrderedFirst(uint256 _seed) external {
    // it should revert
    _authorizeAndCommit();
    _open(_openingSet());
    vm.warp(_state().attempt.consumableAfter);
    IPolicyManager.CancelRequest memory _cancel = _cancelRequest(_places(_ALICE, _CAROL, _PHONE), 1, 1, _window());

    _executeHandover();
    vm.expectRevert(_noActiveAttempt());
    vm.prank(_fresh('canceller', _seed));
    _manager.cancelByProofs(_cancel);
    _assertHandedOver();
  }
}
