// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {IPolicyManager} from 'interfaces/IPolicyManager.sol';
import {MethodEcdsaWrongValue1271} from 'test/mocks/MethodEcdsaGuardianMocks.sol';
import {IntegrationSmartWalletGuardian} from 'test/mocks/IntegrationSmartWalletGuardian.sol';
import {IntegrationDemoKitTestBase} from 'test/utils/IntegrationDemoKitTestBase.sol';

/// @notice The holder commits a wallet guardian's address, not what kind of thing sits there. The
///         wallet method checks a plain signature when the address has no code, and asks the address
///         through ERC-1271 when it has code. These tests cover a smart-wallet guardian, and a guardian
///         whose key delegates to code under EIP-7702 during the wait.
contract AGuardianChangesKindTest is IntegrationDemoKitTestBase {
  /// @notice The code an EIP-7702 delegation points Bob's address at: it refuses every signature.
  address internal _refusingCode;

  function setUp() public override {
    super.setUp();
    _refusingCode = address(new MethodEcdsaWrongValue1271());
  }

  /// @notice A smart wallet at Bob's place approves the opening and the cancel through ERC-1271.
  ///         The method asks the wallet about the exact digest and proof. A holder can name a
  ///         contract as a guardian.
  function test_WhenASmartWalletGuardianApprovesAndCancels() external {
    // it should open and cancel through the wallet's ERC-1271 answer
    IntegrationSmartWalletGuardian _wallet = _bobIsASmartWallet();
    _authorizeAndCommit();

    IPolicyManager.AttemptRequest memory _req = _nextRequest(_openingSet());
    bytes32 _digest = _manager.hashApproval(_req, _BOB);
    // The wallet method forwards the 65 proof bytes unchanged. The expected call ends at the last
    // proof byte and ignores any padding after it.
    vm.expectCall(
      address(_wallet),
      abi.encodePacked(
        IntegrationSmartWalletGuardian.isValidSignature.selector,
        _digest,
        uint256(64),
        uint256(65),
        _req.proofs[1].proof
      ),
      1
    );
    _send(_req);
    assertEq(
      uint256(_state().attempt.state), uint256(IPolicyManager.AttemptState.Waiting), 'the wallet did not approve'
    );

    IPolicyManager.CancelRequest memory _cancel = _cancelRequest(_openingSet(), 1, 1, _window());
    vm.expectEmit(true, true, true, true, address(_manager));
    emit IPolicyManager.AttemptCancelled(_account, address(_action), 1, _executor, address(0), 1, _openingSet());
    vm.prank(_executor);
    _manager.cancelByProofs(_cancel);
  }

  /// @notice When the smart wallet changes owner during the wait, it answers for the new owner. The
  ///         old owner's cancel is refused at Bob's place and the new owner's goes through. The
  ///         wallet decides who signs for it, not the holder's commitment.
  function test_WhenTheSmartWalletChangesHandsDuringTheWait() external {
    // it should refuse the old owner and accept the new one at the wallet's place
    IntegrationSmartWalletGuardian _wallet = _bobIsASmartWallet();
    _authorizeAndCommit();
    _open(_openingSet());

    (address _nextOwner, uint256 _nextOwnerKey) = makeAddrAndKey('walletNextOwner');
    address _firstOwner = _wallet.owner();
    vm.prank(_firstOwner);
    _wallet.setOwner(_nextOwner);

    IPolicyManager.CancelRequest memory _signedByTheOldOwner = _cancelRequest(_openingSet(), 1, 1, _window());
    vm.expectRevert(_proofRejected(_BOB, address(_ecdsa)));
    vm.prank(_executor);
    _manager.cancelByProofs(_signedByTheOldOwner);

    _guardianKeys[_BOB] = _nextOwnerKey;
    IPolicyManager.CancelRequest memory _signedByTheNewOwner = _cancelRequest(_openingSet(), 1, 1, _window());
    vm.prank(_executor);
    _manager.cancelByProofs(_signedByTheNewOwner);
    assertEq(uint256(_state().attempt.state), uint256(IPolicyManager.AttemptState.Cancelled), 'the attempt waits');
  }

  /// @notice Once Bob delegates his address to code under EIP-7702, the method asks that code
  ///         instead of his key. A cancel that needs Bob is refused and the attempt keeps waiting. A
  ///         cancel through Carol still ends it.
  function test_RevertWhen_ACancelLeansOnAGuardianWhoDelegated() external {
    // it should revert
    _authorizeAndCommit();
    _open(_openingSet());
    IPolicyManager.Attempt memory _waiting = _state().attempt;
    _bobDelegatesTo(_refusingCode);
    IPolicyManager.ActionState memory _before = _state();

    IPolicyManager.CancelRequest memory _throughBob = _cancelRequest(_openingSet(), 1, 1, _window());
    vm.expectRevert(_proofRejected(_BOB, address(_ecdsa)));
    vm.prank(_executor);
    _manager.cancelByProofs(_throughBob);

    // it should leave the attempt as it was judged and let a cancel through Carol end it
    _assertSameState(_before, _state(), 'the refused cancel changed the state');
    assertEq(abi.encode(_state().attempt), abi.encode(_waiting), 'the delegation re-judged the attempt');
    uint256[] memory _throughCarol = _places(_ALICE, _CAROL, _PHONE);
    IPolicyManager.CancelRequest memory _throughCarolCancel = _cancelRequest(_throughCarol, 1, 1, _window());
    vm.prank(_executor);
    _manager.cancelByProofs(_throughCarolCancel);
    assertEq(uint256(_state().attempt.state), uint256(IPolicyManager.AttemptState.Cancelled), 'the attempt waits');
  }

  /// @notice Bob's delegation during the wait does not undo an attempt he already approved. The
  ///         manager never checks his approval again. The handover runs after the wait even though
  ///         Bob's address now holds code that refuses every signature.
  function test_WhenAGuardianDelegatesAfterTheOpening() external {
    // it should run the handover the attempt was approved for
    _authorizeAndCommit();
    _open(_openingSet());
    _bobDelegatesTo(_refusingCode);
    assertGt(_guardians[_BOB].code.length, 0, 'given: Bob has no code');

    vm.warp(_state().attempt.consumableAfter);
    _executeHandover();
    assertEq(uint256(_state().attempt.state), uint256(IPolicyManager.AttemptState.Consumed), 'nothing was spent');
    assertEq(_privilege(_newKey), _KEY_VALUE, 'the new key holds no key value');
  }

  /// @notice When Bob's delegation ends, his address has no code again. The method checks his own
  ///         key once more, and a cancel through Bob goes through.
  function test_WhenTheDelegationEnds() external {
    // it should count Bob's bare key again
    _authorizeAndCommit();
    _open(_openingSet());
    _bobDelegatesTo(_refusingCode);
    IPolicyManager.CancelRequest memory _whileDelegated = _cancelRequest(_openingSet(), 1, 1, _window());
    vm.expectRevert(_proofRejected(_BOB, address(_ecdsa)));
    vm.prank(_executor);
    _manager.cancelByProofs(_whileDelegated);

    _bobDelegatesTo(address(0));
    assertEq(_guardians[_BOB].code.length, 0, 'the delegation did not end');
    IPolicyManager.CancelRequest memory _afterTheDelegation = _cancelRequest(_openingSet(), 1, 1, _window());
    vm.prank(_executor);
    _manager.cancelByProofs(_afterTheDelegation);
    assertEq(uint256(_state().attempt.state), uint256(IPolicyManager.AttemptState.Cancelled), 'the attempt waits');
  }

  /// @notice Puts a smart wallet owned by Bob's key at Bob's place. The rule commits the wallet's
  ///         address, and the wallet checks Bob's signatures.
  function _bobIsASmartWallet() internal returns (IntegrationSmartWalletGuardian _wallet) {
    _wallet = new IntegrationSmartWalletGuardian(_guardians[_BOB]);
    _guardians[_BOB] = address(_wallet);
  }

  /// @notice Bob signs an EIP-7702 authorization that points his address at `_code`, or clears his
  ///         delegation when `_code` is zero. A call to his own address carries the authorization and
  ///         succeeds either way.
  function _bobDelegatesTo(address _code) internal {
    vm.signAndAttachDelegation(_code, _guardianKeys[_BOB]);
    vm.prank(_guardians[_BOB]);
    (bool _succeeded,) =
      _guardians[_BOB].call(abi.encodeCall(MethodEcdsaWrongValue1271.isValidSignature, (bytes32(0), '')));
    assertTrue(_succeeded, 'the call carrying the authorization failed');
  }
}
