// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {ActionInvariantSetup} from 'test/action/invariants/Setup.t.sol';

/// @notice Runs random sequences of calls against a fixture of Ambire's account, a real policy
///         manager and the recovery action. After each call it checks that only the batch the
///         guardians approved can change the account's keys, and that it does so exactly once.
/// @dev The handlers:
///      - open attempts that name any two addresses of a pool, the zero address and the kit slot
///        included, with a payload that sometimes carries a trailing byte;
///      - order no payment, a token payment or a native payment, to a fixed payee or an open one;
///      - cancel the waiting attempt as the account;
///      - let time pass;
///      - have the account write its own privilege entries;
///      - switch the token to answer false instead of paying;
///      - send the handover through executeHandover;
///      - send the approved batch straight to the account;
///      - send an altered batch: calls reordered, added, dropped or changed, or another payment;
///      - send again a batch that already ran;
///      - pay a payee that calls the account again while it is being paid.
///      Terms used in this suite:
///      - The approved batch is the spend of the attempt at the manager, the grant of key value 1
///        to the new key, the revoke of the removed key and, when the order has an amount, the
///        payment.
///      - A batch runs when the account's execute returns without reverting.
///      - The kit slot is the privilege entry where the account stores the action's binding. The
///        account authorizes the action while that entry holds the binding.
contract ActionInvariants is ActionInvariantSetup {
  /// @notice Logs how far the run got: how many handovers ran on each path, how many altered
  ///         batches and repeated batches were sent, how often a payee called back in, and how often
  ///         each refusal fired. An invariant proves something about a path only when its count is
  ///         above zero.
  function afterInvariant() external {
    emit log_named_uint('ran through executeHandover', _handler.ghost_ranThroughExecuteHandover());
    emit log_named_uint('ran as the approved batch sent directly', _handler.ghost_ranThroughExecute());
    emit log_named_uint('ran with a payment', _handler.ghost_ranWithPayment());
    emit log_named_uint('ran with an open order', _handler.ghost_ranWithOpenOrder());
    emit log_named_uint('payee calls back into the account', _handler.ghost_payeeCallbacks());
    emit log_named_uint('altered batches sent', _handler.ghost_otherBatchesSent());
    emit log_named_uint('batches sent again', _handler.ghost_batchesSentAgain());
    string[] memory _labels = _handler.refusalLabels();
    for (uint256 _i; _i < _labels.length; ++_i) {
      emit log_named_uint(string.concat('refused: ', _labels[_i]), _handler.ghost_refusals(_labels[_i]));
    }
  }

  /*///////////////////////////////////////////////////////////////
                              INVARIANTS
  ///////////////////////////////////////////////////////////////*/

  /// @notice The spend and the key writes happen together or not at all. No call spends the attempt
  ///         unless the grant, the revoke and the payment run with it. No batch writes keys without
  ///         spending the attempt. So a recovery is never left half done.
  function invariant_theSpendRunsWithTheKeyWritesOrNotAtAll() external view {
    assertFalse(_handler.ghost_spendWithoutWrites(), 'the attempt was spent without its writes');
    assertFalse(_handler.ghost_writesWithoutSpend(), 'a batch ran without spending the attempt');
  }

  /// @notice A batch runs at most once. Sending it again later reverts, and so does a payee that
  ///         sends it again while it is being paid. One approval replaces one key, once.
  function invariant_aSecondRunOfTheSameBatchRevertsWhole() external view {
    assertFalse(_handler.ghost_batchRanTwice(), 'a batch that ran ran again');
  }

  /// @notice Only the approved batch runs. A batch that differs from it never runs, whether it
  ///         reorders, adds, drops or alters a call, or pays another token, amount, payee or asset.
  ///         The guardians' approval cannot be used to run anything beyond the handover they signed.
  function invariant_onlyTheApprovedBatchRuns() external view {
    assertFalse(_handler.ghost_otherBatchRan(), 'a batch other than the approved one ran');
  }

  /// @notice While the account authorizes the action, the action's own check refuses every batch
  ///         that differs from the approved one, with one of the action's named errors. Such a batch
  ///         is never stopped only because some later call happens to fail. The check guards the
  ///         account, not luck.
  function invariant_everyOtherBatchIsRefusedByTheCheck() external view {
    assertFalse(_handler.ghost_otherBatchPassedTheCheck(), 'an altered batch passed the check');
  }

  /// @notice After a handover runs, the removed address holds nothing, though it held a key value
  ///         just before. So the lost key cannot take the account back.
  function invariant_theLostKeyHoldsNoPowerOnceTheHandoverRuns() external view {
    assertFalse(_handler.ghost_lostKeyKeptPower(), 'a handover that ran left the lost key in place');
  }

  /// @notice After a handover runs, the new key holds exactly the key value 1. It held nothing just
  ///         before. It never gets the other key value 2, or a marker the account gives to code it trusts.
  function invariant_theNewKeyHoldsExactlyTheKeyValue() external view {
    assertFalse(_handler.ghost_newKeyWrong(), 'a handover that ran wrote the new key wrongly');
  }

  /// @notice A handover that runs changes no privilege entry except its two keys, and the account
  ///         still authorizes the action afterwards. It moves exactly the order's payment to the
  ///         order's payee, or to the payee the sender picks when the order leaves it open. It moves
  ///         nothing when the token answers false.
  function invariant_aHandoverTouchesOnlyItsKeysAndItsPayment() external view {
    assertFalse(_handler.ghost_otherEntryChanged(), 'a handover that ran changed another entry');
    assertFalse(_handler.ghost_paymentWrong(), 'a handover that ran moved value other than its payment');
  }

  /// @notice The approved batch runs whenever its conditions hold. The conditions are: the attempt's
  ///         wait is over, the committed payload is the canonical encoding of two distinct nonzero
  ///         keys, the new key holds nothing, the removed key holds a key value, the account
  ///         authorizes the action, and the payment can be made. So the check never blocks a valid
  ///         recovery.
  function invariant_theApprovedBatchRunsWhenItsConditionsHold() external view {
    assertFalse(_handler.ghost_approvedBatchRefused(), vm.toString(_handler.ghost_lastUnexpectedRevert()));
  }
}
