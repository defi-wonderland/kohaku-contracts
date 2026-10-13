// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {IPolicyManager} from 'interfaces/IPolicyManager.sol';
import {ActionAmbireAccountFixture} from 'test/mocks/ActionAmbireAccountFixture.sol';
import {ActionBatch} from 'test/utils/ActionBatch.sol';
import {IntegrationDemoKitTestBase} from 'test/utils/IntegrationDemoKitTestBase.sol';

/// @notice The holder recovers once, loses the new key too, and recovers again under the same rule.
///         A recovery leaves the rule in place, so the same guardians can open a second attempt. No
///         approval from the first attempt counts for the second.
contract RecoverTwiceTest is IntegrationDemoKitTestBase {
  function setUp() public override {
    super.setUp();
    _authorizeAndCommit();
  }

  /// @notice After the first handover, the rule and nonce stay the same and the next attempt id is two.
  ///         The first attempt's approvals are refused. The guardians open a second attempt that waits
  ///         the full delay, and the holder's new key can cancel it and commit a new setup.
  function test_WhenTheRecoveredHolderCancelsTheSecondAttempt() external {
    // it should keep the rule live, refuse the first approvals and let the recovered key cancel and re-commit
    IPolicyManager.AttemptRequest memory _first = _recoverOnce();
    IPolicyManager.ActionState memory _afterSpend = _state();
    assertEq(_afterSpend.setupNonce, 1, 'the spend moved the setup nonce');
    assertEq(_afterSpend.setupCommitment, _commitmentOf(1, _body()), 'the spend moved the commitment');
    assertEq(_afterSpend.nextAttemptId, 2, 'the spend did not move the attempt counter');
    assertTrue(_action.isAuthorized(_account), 'the spend removed the kit slot');

    // The first request, sent again unchanged, names an attempt id already used.
    vm.expectRevert(abi.encodeWithSelector(IPolicyManager.PolicyManager_WrongAttemptId.selector, 1, 2));
    _send(_first);
    // With the next id and a new window, the request is refused because its proofs signed the old id.
    _first.attemptId = 2;
    _first.validUntil = _window();
    vm.expectRevert(_proofRejected(_ALICE, address(_ecdsa)));
    _send(_first);

    // The same guardians open a second attempt that removes the key the first one installed.
    address _newerKey = makeAddr('newerKey');
    bytes memory _second = ActionBatch.payload(_newerKey, _newKey);
    _openWith(_openingSet(), _second, _order());
    IPolicyManager.Attempt memory _waiting = _state().attempt;
    assertEq(_waiting.attemptId, 2, 'the second attempt took another id');
    assertEq(uint256(_waiting.state), uint256(IPolicyManager.AttemptState.Waiting), 'the second one is not waiting');
    assertEq(_waiting.consumableAfter, block.timestamp + _WAIT, 'the second attempt skipped part of the wait');
    assertEq(_waiting.payloadHash, keccak256(_second), 'the second attempt holds another payload');

    // The key the first recovery installed cancels the second attempt from the account.
    vm.expectEmit(true, true, true, true, address(_manager));
    emit IPolicyManager.AttemptCancelled(_account, address(_action), 2, _account, address(0), 1, new uint256[](0));
    _asKey(_newKey, _one(_cancelByOwnerCall()));
    assertEq(uint256(_state().attempt.state), uint256(IPolicyManager.AttemptState.Cancelled), 'the attempt waits');

    // It then commits the rule again under the next nonce, which retires the old setup.
    _asKey(_newKey, _one(_commitCall(2, _commitmentOf(2, _body()))));
    assertEq(_state().setupNonce, 2, 'the recovered key could not re-commit');
    assertEq(_state().nextAttemptId, 3, 'the re-commit moved the attempt counter');
  }

  /// @notice If nobody cancels it, the second attempt waits the full delay and then runs like the first.
  ///         The newer key becomes a key, both earlier keys stop being keys, and the kit slot stays. The
  ///         payee is paid once per handover. `_seed` builds the newer key's address.
  function test_WhenTheSecondAttemptWaitsAndRuns(uint256 _seed) external {
    // it should hand the account to the newer key after a second full wait
    address _newerKey = _fresh('newerKey', _seed);
    uint256 _accountNonce = ActionAmbireAccountFixture(payable(_account)).nonce();
    uint256 _payeeBefore = _token.balanceOf(_payee);
    _recoverOnce();

    bytes memory _second = ActionBatch.payload(_newerKey, _newKey);
    _openWith(_openingSet(), _second, _order());
    IPolicyManager.Attempt memory _waiting = _state().attempt;
    vm.warp(_waiting.consumableAfter - 1);
    vm.expectRevert(_notConsumable(IPolicyManager.AttemptState.Waiting, _waiting));
    _executeHandoverOf(_second);

    vm.warp(_waiting.consumableAfter);
    _executeHandoverOf(_second);
    assertEq(_privilege(_newerKey), _KEY_VALUE, 'the newer key holds no key value');
    assertEq(_privilege(_newKey), bytes32(0), 'the key the first recovery installed still holds a privilege');
    assertEq(_privilege(_holderKey), bytes32(0), 'the first lost key came back');
    assertTrue(_action.isAuthorized(_account), 'the kit slot did not survive the second batch');
    IPolicyManager.ActionState memory _end = _state();
    assertEq(uint256(_end.attempt.state), uint256(IPolicyManager.AttemptState.Consumed), 'nothing was spent');
    assertEq(_end.attempt.attemptId, 2, 'another attempt was spent');
    assertEq(_end.nextAttemptId, 3, 'the counter did not move once per opening');
    assertEq(_end.setupNonce, 1, 'a spend moved the nonce');
    assertEq(ActionAmbireAccountFixture(payable(_account)).nonce(), _accountNonce + 2, 'not one account run per spend');
    assertEq(_token.balanceOf(_payee), _payeeBefore + 2 * _PAYMENT, 'the payee was not paid once per spend');
  }

  /// @notice Opens the first attempt with the default set, waits out its delay and hands the account
  ///         to the new key. It returns the request that opened the attempt.
  function _recoverOnce() internal returns (IPolicyManager.AttemptRequest memory _first) {
    _first = _open(_openingSet());
    vm.warp(_state().attempt.consumableAfter);
    _executeHandover();
    assertEq(_privilege(_newKey), _KEY_VALUE, 'given: the first recovery installed the new key');
    assertEq(_privilege(_holderKey), bytes32(0), 'given: the first recovery removed the lost key');
  }
}
