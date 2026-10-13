// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {IPolicyManager} from 'interfaces/IPolicyManager.sol';
import {IAmbireRecoveryAction} from 'contracts/actions/ambire/IAmbireRecoveryAction.sol';
import {AmbireRecoveryAction} from 'contracts/actions/ambire/AmbireRecoveryAction.sol';
import {PolicyManager} from 'contracts/manager/PolicyManager.sol';
import {IntegrationDemoKitTestBase} from 'test/utils/IntegrationDemoKitTestBase.sol';

/// @notice Approvals the guardians sign for this chain, this manager and this action open nothing
///         anywhere else. Each test sends the same signed request to a place that stores the same
///         setup. Only the chain, manager or action the guardians signed for differs.
contract ApprovalsStayInTheirDomainTest is IntegrationDemoKitTestBase {
  function setUp() public override {
    super.setUp();
    _authorizeAndCommit();
  }

  /// @notice On another chain, the request matches the stored setup but the first proof is refused.
  ///         The guardians signed for the home chain's id. Back on the home chain, the same request
  ///         opens the attempt. `_seed` picks the other chain id, never the home one.
  function test_RevertWhen_TheRequestIsSentOnAnotherChain(uint256 _seed) external {
    // it should revert
    uint256 _home = block.chainid;
    uint256 _other = bound(_seed, 1, type(uint64).max - 1);
    if (_other > _home - 1) ++_other;
    IPolicyManager.AttemptRequest memory _req = _nextRequest(_openingSet());
    IPolicyManager.ActionState memory _before = _state();

    vm.chainId(_other);
    vm.expectRevert(_proofRejected(_ALICE, address(_ecdsa)));
    _send(_req);
    _assertSameState(_before, _state(), 'the request on another chain changed the state');

    vm.chainId(_home);
    _send(_req);
    assertEq(uint256(_state().attempt.state), uint256(IPolicyManager.AttemptState.Waiting), 'the home chain refused');
  }

  /// @notice A second manager that holds the same setup for the same account refuses the request at
  ///         its first proof. The guardians signed for the first manager's address. Approvals for one
  ///         manager never open an attempt on another.
  function test_RevertWhen_TheRequestIsSentToASecondManager() external {
    // it should revert
    PolicyManager _second = new PolicyManager();
    _asHolder(
      _one(
        IAmbireRecoveryAction.Transaction({
          to: address(_second),
          value: 0,
          data: abi.encodeCall(
            IPolicyManager.commitSetup,
            (address(_action), _commitmentOf(1, _body()), 1, _PUBLIC_METADATA, _PRIVATE_METADATA)
          )
        })
      )
    );
    assertEq(
      _second.stateOf(_account, address(_action)).setupCommitment,
      _state().setupCommitment,
      'given: the two managers hold different commitments'
    );
    IPolicyManager.AttemptRequest memory _req = _nextRequest(_openingSet());

    vm.expectRevert(_proofRejected(_ALICE, address(_ecdsa)));
    vm.prank(_submitter);
    _second.startAttempt(_req);
    assertEq(_second.stateOf(_account, address(_action)).nextAttemptId, 1, 'the second manager opened an attempt');
    _send(_req);
    assertEq(uint256(_state().attempt.state), uint256(IPolicyManager.AttemptState.Waiting), 'the home manager refused');
  }

  /// @notice The account commits the same rule for a second action. The request, pointed at that
  ///         action, is refused at its first proof, because every proof signs the action. Approvals for
  ///         one action never count for another.
  function test_RevertWhen_TheRequestIsSentForASecondAction() external {
    // it should revert
    AmbireRecoveryAction _otherAction = new AmbireRecoveryAction(IPolicyManager(address(_manager)), _implementation);
    bytes32 _otherCommitment = keccak256(abi.encode(_account, address(_otherAction), uint64(1), _body()));
    _asHolder(
      _one(
        _managerCall(
          abi.encodeCall(
            IPolicyManager.commitSetup,
            (address(_otherAction), _otherCommitment, 1, _PUBLIC_METADATA, _PRIVATE_METADATA)
          )
        )
      )
    );
    IPolicyManager.AttemptRequest memory _req = _nextRequest(_openingSet());
    _req.action = address(_otherAction);

    vm.expectRevert(_proofRejected(_ALICE, address(_ecdsa)));
    _send(_req);
    assertEq(_manager.stateOf(_account, address(_otherAction)).nextAttemptId, 1, 'the other action opened an attempt');
    assertEq(_state().nextAttemptId, 1, 'the refused request reached the first action');
  }
}
