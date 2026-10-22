// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

/// @notice Every ghost variable of the recovery action's invariant suite. A handler sets a flag when
///         a call breaks a property, and the invariants read the flags. The counters record how far
///         the run got: how many handovers ran on each path, and how often each refusal fired.
/// @dev One flag per property keeps each invariant's failure message exact.
// solhint-disable-next-line max-states-count
abstract contract ActionGhostStorage {
  /*///////////////////////////////////////////////////////////////
                            PROPERTY FLAGS
  ///////////////////////////////////////////////////////////////*/

  /// @notice A call spent the attempt while the grant, the revoke or the payment did not run with it.
  bool public ghost_spendWithoutWrites;
  /// @notice A call wrote a privilege entry or moved a payment through the action's route while
  ///         the attempt was not spent in the same call.
  bool public ghost_writesWithoutSpend;
  /// @notice A batch that differs from the approved one ran.
  bool public ghost_otherBatchRan;
  /// @notice A batch that differs from the approved one was refused by something other than the
  ///         action's own check while the account authorized the action.
  bool public ghost_otherBatchPassedTheCheck;
  /// @notice A batch ran a second time, sent again directly or by a payee while it was being paid.
  bool public ghost_batchRanTwice;
  /// @notice A handover that ran left the removed key with a nonzero entry, or removed an address
  ///         that held no key value when it ran.
  bool public ghost_lostKeyKeptPower;
  /// @notice A handover that ran wrote the new key with a value other than 1, or installed an address
  ///         that already held an entry.
  bool public ghost_newKeyWrong;
  /// @notice A handover that ran changed a privilege entry other than its two keys.
  bool public ghost_otherEntryChanged;
  /// @notice A handover that ran moved value other than the order's payment, or paid someone other
  ///         than the order's payee.
  bool public ghost_paymentWrong;
  /// @notice The approved batch was refused while every condition for it held.
  bool public ghost_approvedBatchRefused;

  /// @notice The revert data of the last refusal that raised ghost_approvedBatchRefused or
  ///         ghost_otherBatchPassedTheCheck, for the failure message.
  bytes public ghost_lastUnexpectedRevert;

  /*///////////////////////////////////////////////////////////////
                              REACH
  ///////////////////////////////////////////////////////////////*/

  /// @notice Handovers that ran through executeHandover.
  uint256 public ghost_ranThroughExecuteHandover;
  /// @notice Handovers that ran as the approved batch sent straight to the account.
  uint256 public ghost_ranThroughExecute;
  /// @notice Batches that differ from the approved one and were sent to the account.
  uint256 public ghost_otherBatchesSent;
  /// @notice Batches that ran and were sent to the account again.
  uint256 public ghost_batchesSentAgain;
  /// @notice Handovers whose payee called the account again while being paid.
  uint256 public ghost_payeeCallbacks;
  /// @notice Handovers that ran with a payment.
  uint256 public ghost_ranWithPayment;
  /// @notice Handovers that ran with an open order, paying a payee the sender chose.
  uint256 public ghost_ranWithOpenOrder;

  /// @notice The refusal labels seen, in first-seen order.
  string[] internal _refusalLabels;
  /// @notice How often each refusal label fired.
  mapping(string _label => uint256 _count) public ghost_refusals;

  /// @notice The refusal labels seen.
  function refusalLabels() external view returns (string[] memory _labels) {
    _labels = _refusalLabels;
  }

  /// @notice Counts one refusal under `_label`.
  function _countRefusal(string memory _label) internal {
    if (ghost_refusals[_label] == 0) _refusalLabels.push(_label);
    ++ghost_refusals[_label];
  }
}
