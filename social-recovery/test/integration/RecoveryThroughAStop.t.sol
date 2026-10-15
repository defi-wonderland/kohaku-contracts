// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {IPolicyManager} from 'interfaces/IPolicyManager.sol';
import {IRecoveryAction} from 'interfaces/IRecoveryAction.sol';

import {PolicyMethodRoles} from 'contracts/methods/roles/PolicyMethodRoles.sol';

import {IntegrationBase} from 'test/integration/base/IntegrationBase.sol';

/// @notice Diana chose at setup that a security stop must not hold up her recovery: her rule takes her passkey or her
///         passport through zkPassport, either alone, with a 48-hour wait, and ignores stops. She lost the phone with
///         the passkey, the pause holder stops the zkPassport method, and she still recovers with her passport. The
///         story is told once; each kind below says when the stop comes.
abstract contract RecoveryThroughAStop is IntegrationBase {
  /// @notice Local only: its rule names an identity credential, which no story can prove on a fork.
  function _runsOnForks() internal pure override returns (bool _runs) {
    _runs = false;
  }

  /// @notice Diana's account.
  address internal _account;
  /// @notice Diana's rule, as the backup holds it.
  Rule internal _dianaRule;

  function setUp() public virtual override {
    super.setUp();
    _account = _openAccount(_originalKey.addr);
    Rule memory _r = _passkeyOrPassport(_account, true);
    _keep(_dianaRule, _r);
    _setUpRecovery(_account, _originalKey, _r);
  }

  /*///////////////////////////////////////////////////////////////
                         WHAT EACH KIND SAYS
  ///////////////////////////////////////////////////////////////*/

  /// @notice Whether the pause holder stops the zkPassport method before Diana's attempt opens, rather than while it
  ///         waits.
  function _stopComesBeforeTheOpening() internal pure virtual returns (bool _before);

  /*///////////////////////////////////////////////////////////////
                              THE WALK
  ///////////////////////////////////////////////////////////////*/

  /// @notice With the zkPassport method stopped, Diana's passport still opens her attempt, and the handover executes
  ///         after 48 hours. The stop she opted out of never stands between her and her account.
  function test_WhenTheHolderRecoversThroughAStop() external {
    Rule memory _r = _dianaRule;
    // When the kind says so, the pause holder stops the zkPassport method before the opening.
    if (_stopComesBeforeTheOpening()) _pauseHolderStopsZkPassport();

    // Diana proves her passport for place 1 over a handover to her new key, and sends startAttempt from the new key.
    bytes memory _payload = _handover(_newKey.addr, _originalKey.addr);
    IPolicyManager.AttemptRequest memory _req =
      _request(_account, _r, _payload, _noPayment(), uint48(block.timestamp + 24 hours));
    _signApproval(_req, _r, 1);
    vm.deal(_newKey.addr, 0.05 ether);
    _submits(_newKey.addr, _req);

    // When the kind says so, the pause holder stops the zkPassport method while the attempt waits.
    if (!_stopComesBeforeTheOpening()) _pauseHolderStopsZkPassport();

    // 48 hours pass, and Diana sends executeHandover from the new key.
    skip(48 hours);
    _executes(_newKey.addr, _account, _payload);

    // The stop is still on, and Diana's new key controls the account.
    assertTrue(_zkPassportMethod.paused(), 'the zkPassport method is still stopped');
    _assertKeyControls(_account, _newKey, 'the new key');
    _assertKeyLocked(_account, _originalKey);
  }

  /*///////////////////////////////////////////////////////////////
                              UTILITIES
  ///////////////////////////////////////////////////////////////*/

  /// @notice A rule of any 1 of Maya's passkey and a passport, with a 48-hour wait and the given stop choice.
  function _passkeyOrPassport(address _target, bool _ignoresPause) internal returns (Rule memory _r) {
    _r = _rule(
      _target,
      48 hours,
      _ignoresPause,
      _thresholds(1),
      _sizes(2),
      _credentials(_passkey(_mayaPasskey), _passport(keccak256(abi.encode('passport chip', _target))))
    );
  }

  /// @notice The pause holder stops the zkPassport method.
  function _pauseHolderStopsZkPassport() internal {
    vm.prank(_identitySafe);
    PolicyMethodRoles(address(_zkPassportMethod)).pause();
  }
}

/// @notice The stop is on before Diana's attempt opens. This kind also carries the cases where the story must hold even
///         if someone tries something else, and the trade-off the kit accepts.
contract RecoveryThroughAStopOnBeforeTheOpening is RecoveryThroughAStop {
  function _stopComesBeforeTheOpening() internal pure override returns (bool _before) {
    _before = true;
  }

  /// @notice One stop over three accounts on one manager: one whose attempt used zkPassport and keeps stops on, one
  ///         whose attempt used zkPassport and ignores stops, and one whose rule names zkPassport but whose attempt did
  ///         not use it. Only the first is refused and ended by a veto: only the methods an attempt used can stop it,
  ///         and only when the holder kept stops on.
  function test_WhenOneStopMeetsSeveralHolders() external {
    // Three holders set up recovery: Uma keeps stops on, Victor ignores them, and Wes keeps them on.
    (address _uma, Person memory _umaKey, Rule memory _umaRule) = _holderWithRecovery('Uma', false);
    (address _victor, Person memory _victorKey, Rule memory _victorRule) = _holderWithRecovery('Victor', true);
    (address _wes, Person memory _wesKey, Rule memory _wesRule) = _holderWithRecovery('Wes', false);

    // Uma and Victor open attempts with their passports, and Wes opens his with his passkey.
    bytes memory _umaPayload = _opens(_uma, _umaKey, _umaRule, 1);
    bytes memory _victorPayload = _opens(_victor, _victorKey, _victorRule, 1);
    bytes memory _wesPayload = _opens(_wes, _wesKey, _wesRule, 0);

    // The pause holder stops the zkPassport method.
    _pauseHolderStopsZkPassport();

    // The wait passes, and someone sends executeHandover on all three accounts.
    skip(48 hours);
    vm.prank(_executor);
    vm.expectPartialRevert(IPolicyManager.PolicyManager_MethodVetoedSpend.selector);
    _action.executeHandover(_uma, _umaPayload);
    _executes(_executor, _victor, _victorPayload);
    _executes(_executor, _wes, _wesPayload);

    // Someone sends cancelByVeto on Uma's attempt, and it ends.
    vm.prank(_friend);
    _manager.cancelByVeto(_uma, address(_action), 1, address(_zkPassportMethod));
    assertEq(uint8(_attempt(_uma).state), uint8(IPolicyManager.AttemptState.Cancelled), 'Uma attempt is vetoed');

    // Uma keeps her account, and Victor's and Wes's new keys control theirs.
    _assertKeyControls(_uma, _umaKey, 'Uma key');
    _assertKeyControls(_victor, _newKey, 'Victor new key');
    _assertKeyControls(_wes, _newKey, 'Wes new key');
  }

  /*///////////////////////////////////////////////////////////////
                              EVEN IF
  ///////////////////////////////////////////////////////////////*/

  /// @notice Someone sends cancelByVeto naming the stopped method, and it fails, since Diana's setup ignores stops.
  function test_RevertWhen_SomeoneVetoesAnOptedOutAttempt() external {
    Rule memory _r = _dianaRule;
    // The pause holder stops the zkPassport method.
    _pauseHolderStopsZkPassport();

    // Diana proves her passport and her attempt opens through the stop.
    bytes memory _payload = _handover(_newKey.addr, _originalKey.addr);
    IPolicyManager.AttemptRequest memory _req =
      _request(_account, _r, _payload, _noPayment(), uint48(block.timestamp + 24 hours));
    _signApproval(_req, _r, 1);
    _submits(_friend, _req);

    // The pause holder names the stopped method in a veto, and it fails.
    vm.prank(_identitySafe);
    vm.expectPartialRevert(IPolicyManager.PolicyManager_AttemptIgnoresPause.selector);
    _manager.cancelByVeto(_account, address(_action), 1, address(_zkPassportMethod));

    // The attempt still waits and, after 48 hours, hands Diana her account.
    assertEq(uint8(_attempt(_account).state), uint8(IPolicyManager.AttemptState.Waiting), 'the attempt still waits');
    skip(48 hours);
    _executes(_executor, _account, _payload);
    _assertKeyControls(_account, _newKey, 'the new key');
  }

  /// @notice A thief who took Diana's phone opens a recovery with her passkey. Diana's cancel by proofs, which leans on
  ///         her passport through the stopped method, works for her, since her setup ignores stops.
  function test_WhenTheHolderCancelsThroughTheStop() external {
    Rule memory _r = _dianaRule;
    // The thief asserts Diana's passkey over a handover to the thief's key, and the attempt opens.
    bytes memory _payload = _handover(_attacker.addr, _originalKey.addr);
    IPolicyManager.AttemptRequest memory _theft =
      _request(_account, _r, _payload, _noPayment(), uint48(block.timestamp + 24 hours));
    _signApproval(_theft, _r, 0);
    _submits(_attacker.addr, _theft);

    // The pause holder stops the zkPassport method.
    _pauseHolderStopsZkPassport();

    // Diana proves her passport over the cancellation of attempt 1, and a friend sends it.
    IPolicyManager.CancelRequest memory _cancel = _cancelRequest(_account, _r, 1, uint48(block.timestamp + 24 hours));
    _signCancel(_cancel, _r, 1);
    _submitsCancel(_friend, _cancel);

    // The wait passes, and the thief sends executeHandover. It reverts, since the attempt is cancelled.
    IPolicyManager.Attempt memory _cancelled = _attempt(_account);
    assertEq(uint8(_cancelled.state), uint8(IPolicyManager.AttemptState.Cancelled), 'the theft is cancelled');
    skip(48 hours);
    vm.prank(_attacker.addr);
    vm.expectRevert(
      abi.encodeWithSelector(
        IRecoveryAction.RecoveryAction_NotConsumable.selector,
        _account,
        IPolicyManager.AttemptState.Cancelled,
        _cancelled.consumableAfter,
        _cancelled.payloadHash
      )
    );
    _action.executeHandover(_account, _payload);
    assertEq(_privilegeOf(_account, _attacker.addr), bytes32(0), 'the thief holds nothing');
  }

  /*///////////////////////////////////////////////////////////////
                             TRADE-OFFS
  ///////////////////////////////////////////////////////////////*/

  /// @notice Ignoring stops cuts both ways: a forged passport proof through the stopped method also opens, nobody can
  ///         veto it, and after 48 hours the attacker holds Diana's account.
  function test_WhenAForgedProofPassesThroughTheStop() external {
    Rule memory _r = _dianaRule;
    // The pause holder stops the zkPassport method over a suspected bug.
    _pauseHolderStopsZkPassport();

    // The attacker forges Diana's passport proof through the suspect method and opens an attempt to their key. The
    // local verifier stand-in accepts any well-formed proof, so producing it from the credential's config is the
    // forgery.
    bytes memory _payload = _handover(_attacker.addr, _originalKey.addr);
    IPolicyManager.AttemptRequest memory _forged =
      _request(_account, _r, _payload, _noPayment(), uint48(block.timestamp + 24 hours));
    _signApproval(_forged, _r, 1);
    _submits(_attacker.addr, _forged);

    // The pause holder tries to end it by naming the stopped method, and fails.
    vm.prank(_identitySafe);
    vm.expectPartialRevert(IPolicyManager.PolicyManager_AttemptIgnoresPause.selector);
    _manager.cancelByVeto(_account, address(_action), 1, address(_zkPassportMethod));

    // 48 hours pass, and the attacker executes.
    skip(48 hours);
    _executes(_attacker.addr, _account, _payload);
    _assertKeyControls(_account, _attacker, 'the attacker');
    _assertKeyLocked(_account, _originalKey);
  }

  /*///////////////////////////////////////////////////////////////
                              UTILITIES
  ///////////////////////////////////////////////////////////////*/

  /// @notice A holder's account set up with their passkey or their passport, keeping or ignoring stops.
  function _holderWithRecovery(string memory _name, bool _ignoresPause)
    internal
    returns (address _holderAccount, Person memory _key, Rule memory _r)
  {
    _key = _person(string.concat(_name, ' key'));
    _holderAccount = _openAccount(_key.addr);
    _r = _passkeyOrPassport(_holderAccount, _ignoresPause);
    _setUpRecovery(_holderAccount, _key, _r);
  }

  /// @notice The holder proves one place over a handover to the new key, and a friend opens the attempt.
  function _opens(address _holderAccount, Person memory _key, Rule memory _r, uint256 _place)
    internal
    returns (bytes memory _payload)
  {
    _payload = _handover(_newKey.addr, _key.addr);
    IPolicyManager.AttemptRequest memory _req =
      _request(_holderAccount, _r, _payload, _noPayment(), uint48(block.timestamp + 24 hours));
    _signApproval(_req, _r, _place);
    _submits(_friend, _req);
  }
}

/// @notice The pause holder stops the zkPassport method while Diana's attempt waits.
contract RecoveryThroughAStopTurnedOnDuringTheWait is RecoveryThroughAStop {
  function _stopComesBeforeTheOpening() internal pure override returns (bool _before) {
    _before = false;
  }
}
