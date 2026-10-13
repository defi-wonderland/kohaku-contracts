// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {SafeCast} from '@openzeppelin/contracts/utils/math/SafeCast.sol';

import {BindingDigest} from 'libraries/BindingDigest.sol';
import {SetupBody} from 'libraries/SetupBody.sol';
import {IPolicyAction} from 'interfaces/IPolicyAction.sol';
import {IPolicyManager} from 'interfaces/IPolicyManager.sol';
import {IPolicyMethod} from 'interfaces/IPolicyMethod.sol';
import {IPolicyMethodPause} from 'interfaces/IPolicyMethodPause.sol';

/// @title PolicyManager
/// @author defi-wonderland
/// @notice The one contract that judges recoveries. It holds every setup and every attempt, keyed by
///         the account and the action, and holds no authority over any account.
/// @dev The manager never calls an account; accounts call it. Only an account can write its own
///      setup or cancel its own attempt, and none of those three calls asks any method anything, so
///      no method, and no pause on one, can stop the holder from changing their setup or cancelling
///      with their own key.
contract PolicyManager is IPolicyManager {
  /*///////////////////////////////////////////////////////////////
                          STATE VARIABLES
  ///////////////////////////////////////////////////////////////*/

  /// @notice Every account's setup per action. No other setup configuration is stored.
  /// @dev A setup write records its block through a checked cast, so a block number past the uint48 width
  ///      reverts rather than wrapping: a truncated block would point a rebuild client at the wrong block.
  mapping(address _account => mapping(address _action => Setup)) internal _setups;

  /// @notice Every account's latest attempt record per action. Each new attempt overwrites it.
  mapping(address _account => mapping(address _action => Attempt)) internal _attempts;

  /*///////////////////////////////////////////////////////////////
                        EXTERNAL FUNCTIONS
  ///////////////////////////////////////////////////////////////*/

  /// @inheritdoc IPolicyManager
  function commitSetup(
    address _action,
    bytes32 _setupCommitment,
    uint64 _nonce,
    bytes calldata _publicMetadata,
    bytes calldata _privateMetadata
  ) external {
    Setup storage _setup = _setups[msg.sender][_action];
    uint64 _next = _setup.nonce + 1;
    require(_nonce == _next, PolicyManager_WrongSetupNonce(_nonce, _next));
    require(
      _setupCommitment != bytes32(0)
        && _setupCommitment != BindingDigest.setupCommitment(msg.sender, _action, _next, ''),
      PolicyManager_InvalidCommitment(_setupCommitment)
    );
    (bool _success, bytes32 _result) =
      _tryStaticCallWord(_action, abi.encodeCall(IPolicyAction.supportsAccount, (msg.sender)));
    require(_success && _result == bytes32(uint256(1)), PolicyManager_ActionDoesNotServeAccount(msg.sender, _action));

    _writeSetup(_setup, msg.sender, _action, _setupCommitment, _next);
    emit SetupCommitted(msg.sender, _action, _next, _setupCommitment, _publicMetadata, _privateMetadata);
  }

  /// @inheritdoc IPolicyManager
  function clearSetup(address _action) external {
    Setup storage _setup = _existingSetup(msg.sender, _action);
    uint64 _next = _setup.nonce + 1;
    _writeSetup(_setup, msg.sender, _action, bytes32(0), _next);
    emit SetupCleared(msg.sender, _action, _next);
  }

  /// @inheritdoc IPolicyManager
  function cancelByOwner(address _action) external {
    Attempt storage _attempt = _attempts[msg.sender][_action];
    require(_attempt.state == AttemptState.Waiting, PolicyManager_NoActiveAttempt(msg.sender, _action));
    _cancel(msg.sender, _action, _attempt, msg.sender, address(0), new uint256[](0));
  }

  /// @inheritdoc IPolicyManager
  function startAttempt(AttemptRequest calldata _request) external {
    Setup storage _setup = _existingSetup(_request.account, _request.action);
    Attempt storage _attempt = _attempts[_request.account][_request.action];
    require(
      _attempt.state != AttemptState.Waiting,
      PolicyManager_AttemptAlreadyActive(_request.account, _request.action, _attempt.attemptId)
    );
    require(_request.setupNonce == _setup.nonce, PolicyManager_WrongSetupNonce(_request.setupNonce, _setup.nonce));
    uint64 _nextAttemptId = _setup.attemptCounter + 1;
    require(_request.attemptId == _nextAttemptId, PolicyManager_WrongAttemptId(_request.attemptId, _nextAttemptId));
    uint48 _now =
      _checkWindowAndBody(_request.account, _request.action, _setup, _request.validUntil, _request.setupBody);

    bytes32[] memory _digests = _approvalDigests(_request);
    (uint48 _wait, bool _ignoresPause, address[] memory _usedMethods, uint256[] memory _usedPlaces) =
      _verifyProofs(_request.proofs, _request.setupBody, _digests);

    uint48 _consumableAfter = _now + _wait;
    _attempt.attemptId = _request.attemptId;
    _attempt.setupNonce = _setup.nonce;
    _attempt.consumableAfter = _consumableAfter;
    _attempt.state = AttemptState.Waiting;
    _attempt.ignoresPause = _ignoresPause;
    _attempt.payloadHash = keccak256(_request.payload);
    _attempt.order = _request.order;
    _attempt.usedMethods = _usedMethods;
    _setup.attemptCounter = _request.attemptId;
    _emitAttemptStarted(_request, _usedPlaces, _usedMethods, _consumableAfter);
  }

  /// @inheritdoc IPolicyManager
  function cancelByProofs(CancelRequest calldata _request) external {
    Attempt storage _attempt = _attempts[_request.account][_request.action];
    require(_attempt.state == AttemptState.Waiting, PolicyManager_NoActiveAttempt(_request.account, _request.action));
    Setup storage _setup = _setups[_request.account][_request.action];
    require(_request.setupNonce == _setup.nonce, PolicyManager_WrongSetupNonce(_request.setupNonce, _setup.nonce));
    require(_attempt.setupNonce == _setup.nonce, PolicyManager_StaleAttempt(_attempt.setupNonce, _setup.nonce));
    require(
      _request.attemptId == _attempt.attemptId, PolicyManager_WrongAttemptId(_request.attemptId, _attempt.attemptId)
    );
    _checkWindowAndBody(_request.account, _request.action, _setup, _request.validUntil, _request.setupBody);

    bytes32[] memory _digests = _cancelDigests(_request);
    // A cancellation reads only the places the proofs filled, so the other answers are dropped on purpose.
    // slither-disable-next-line unused-return
    (,,, uint256[] memory _usedPlaces) = _verifyProofs(_request.proofs, _request.setupBody, _digests);

    _cancel(_request.account, _request.action, _attempt, msg.sender, address(0), _usedPlaces);
  }

  /// @inheritdoc IPolicyManager
  function cancelByVeto(address _account, address _action, uint64 _attemptId, address _method) external {
    Attempt storage _attempt = _liveAttempt(_account, _action, _attemptId);
    require(!_attempt.ignoresPause, PolicyManager_AttemptIgnoresPause(_attemptId));
    // A veto must name a method the attempt's accepted proofs used, so a caller cannot make the
    // manager query a contract the holder never chose.
    address[] storage _usedMethods = _attempt.usedMethods;
    uint256 _methodCount = _usedMethods.length;
    bool _used = false;
    for (uint256 _i; _i < _methodCount; ++_i) {
      if (_usedMethods[_i] == _method) {
        _used = true;
        break;
      }
    }
    require(_used, PolicyManager_MethodNotUsed(_attemptId, _method));
    require(_vetoes(_method), PolicyManager_MethodNotStopped(_method));

    _cancel(_account, _action, _attempt, msg.sender, _method, new uint256[](0));
  }

  /// @inheritdoc IPolicyManager
  function consume(address _action, uint64 _attemptId, bytes32 _payloadHash) external {
    Attempt storage _attempt = _liveAttempt(msg.sender, _action, _attemptId);
    uint48 _now = SafeCast.toUint48(block.timestamp);
    require(!(_now < _attempt.consumableAfter), PolicyManager_WaitNotOver(_now, _attempt.consumableAfter));
    require(_payloadHash == _attempt.payloadHash, PolicyManager_WrongPayload(_payloadHash, _attempt.payloadHash));
    if (!_attempt.ignoresPause) {
      // Each method the attempt used is asked whether it is stopped, in the order the attempt
      // recorded them, and the first that says yes refuses the spend. This runs last, so no method
      // is asked about a spend the manager would refuse anyway.
      address[] storage _usedMethods = _attempt.usedMethods;
      uint256 _methodCount = _usedMethods.length;
      for (uint256 _i; _i < _methodCount; ++_i) {
        address _method = _usedMethods[_i];
        require(!_vetoes(_method), PolicyManager_MethodVetoedSpend(_method));
      }
    }

    _attempt.state = AttemptState.Consumed;
    emit AttemptConsumed(msg.sender, _action, _attemptId);
  }

  /// @inheritdoc IPolicyManager
  function stateOf(address _account, address _action) external view returns (ActionState memory _state) {
    Setup storage _setup = _setups[_account][_action];
    _state = ActionState({
      setupCommitment: _setup.commitment,
      setupNonce: _setup.nonce,
      nextAttemptId: _setup.attemptCounter + 1,
      setupCommittedAtBlock: _setup.setupCommittedAtBlock,
      attempt: _attempts[_account][_action]
    });
  }

  /// @inheritdoc IPolicyManager
  function hashApproval(AttemptRequest calldata _request, uint256 _place) external view returns (bytes32 _digest) {
    _digest = BindingDigest.approvalDigest(_domainSeparator(), _request, _place);
  }

  /// @inheritdoc IPolicyManager
  function hashCancel(CancelRequest calldata _request, uint256 _place) external view returns (bytes32 _digest) {
    _digest = BindingDigest.cancelDigest(_domainSeparator(), _request, _place);
  }

  /// @inheritdoc IPolicyManager
  function eip712Domain()
    external
    view
    returns (
      bytes1 _fields,
      string memory _name,
      string memory _version,
      uint256 _chainId,
      address _verifyingContract,
      bytes32 _salt,
      uint256[] memory _extensions
    )
  {
    _fields = hex'0f';
    _name = BindingDigest.DOMAIN_NAME;
    _version = BindingDigest.DIGEST_VERSION;
    _chainId = block.chainid;
    _verifyingContract = address(this);
    _salt = bytes32(0);
    _extensions = new uint256[](0);
  }

  /// @inheritdoc IPolicyManager
  function supportsInterface(bytes4 _interfaceId) external pure returns (bool _supported) {
    // The ERC-165 interface id is the selector of its one function, supportsInterface.
    _supported =
      _interfaceId == type(IPolicyManager).interfaceId || _interfaceId == IPolicyManager.supportsInterface.selector;
  }

  /// @inheritdoc IPolicyManager
  function name() external pure returns (string memory _managerName) {
    _managerName = 'PolicyManager';
  }

  /// @inheritdoc IPolicyManager
  function version() external pure returns (string memory _managerVersion) {
    _managerVersion = '1.0.0';
  }

  /*///////////////////////////////////////////////////////////////
                        INTERNAL FUNCTIONS
  ///////////////////////////////////////////////////////////////*/

  /// @notice Writes a setup: cancels the waiting attempt if there is one, then stores the commitment,
  ///         the nonce and the block of the write. Committing a setup and clearing it both end here.
  /// @dev The cancel comes before the nonce moves, so no attempt outlives the setup it was judged under,
  ///      and its event comes before the caller's setup event. The event's canceller is address(0),
  ///      never the account, the way ERC-20 marks a mint with a zero sender: the account's own cancel
  ///      names the account, so a zero tells a watcher the attempt ended because the holder rewrote or
  ///      cleared the setup, not because they cancelled it. No transaction comes from address(0), so
  ///      the zero never names a real caller. The block goes through a checked cast, so a block number
  ///      past the uint48 width reverts rather than wrapping.
  /// @param _setup The setup record being written.
  /// @param _account The account whose setup is being written.
  /// @param _action The action whose setup is being written.
  /// @param _commitment The commitment to store, or zero when the setup is cleared.
  /// @param _nonce The new setup nonce, one past the stored one.
  function _writeSetup(Setup storage _setup, address _account, address _action, bytes32 _commitment, uint64 _nonce)
    internal
  {
    Attempt storage _attempt = _attempts[_account][_action];
    if (_attempt.state == AttemptState.Waiting) {
      _cancel(_account, _action, _attempt, address(0), address(0), new uint256[](0));
    }
    _setup.commitment = _commitment;
    _setup.nonce = _nonce;
    _setup.setupCommittedAtBlock = SafeCast.toUint48(block.number);
  }

  /// @notice Ends a waiting attempt without spending it and emits the cancel event. The holder's own
  ///         cancel, a cancel by proofs, a cancel by veto and a setup write all end an attempt here.
  /// @dev It leaves the setup nonce and the attempt counter alone. A setup write moves the nonce
  ///      itself, after this returns.
  /// @param _account The account whose attempt is cancelled.
  /// @param _action The action the attempt runs under.
  /// @param _attempt The waiting attempt record.
  /// @param _canceller Who ended the attempt. It is the account for the holder's own cancel, the
  ///        caller for a cancel by proofs or by veto, and address(0) for a setup write.
  /// @param _stoppedMethod The stopped method a cancel by veto named. Every other cancel passes
  ///        address(0), because no stopped method is behind it.
  /// @param _usedPlaces The places the cancelling proofs filled. Only a cancel by proofs fills any, so
  ///        every other cancel passes an empty list.
  function _cancel(
    address _account,
    address _action,
    Attempt storage _attempt,
    address _canceller,
    address _stoppedMethod,
    uint256[] memory _usedPlaces
  ) internal {
    _attempt.state = AttemptState.Cancelled;
    emit AttemptCancelled(
      _account, _action, _attempt.attemptId, _canceller, _stoppedMethod, _attempt.setupNonce, _usedPlaces
    );
  }

  /// @notice Emits the opening event, carrying the body and the payload in the clear.
  /// @dev The request's setup nonce is the stored one, which the opening checked before any place was
  ///      read.
  /// @param _request The accepted request.
  /// @param _usedPlaces The places the accepted proofs filled.
  /// @param _usedMethods The distinct methods the accepted proofs used, in proof order.
  /// @param _consumableAfter When the wait ends.
  function _emitAttemptStarted(
    AttemptRequest calldata _request,
    uint256[] memory _usedPlaces,
    address[] memory _usedMethods,
    uint48 _consumableAfter
  ) internal {
    emit AttemptStarted(
      _request.account,
      _request.action,
      _request.attemptId,
      _request.setupNonce,
      _request.setupBody,
      _usedPlaces,
      _usedMethods,
      _request.payload,
      _request.order,
      _consumableAfter
    );
  }

  /// @notice The EIP-712 domain separator of this deployment on the chain that runs the call. The
  ///         library reads the live chain id on every call and none is stored, so approvals signed
  ///         for one branch of a chain split never verify on the other.
  /// @return _separator The domain separator the digests are computed under.
  function _domainSeparator() internal view returns (bytes32 _separator) {
    _separator = BindingDigest.domainSeparator(address(this));
  }

  /// @notice Finds the setup an account holds for an action, for the calls that make sense only once
  ///         a setup exists: clearing it and opening an attempt under it.
  /// @dev A setup exists while its commitment is not zero, since clearing writes a zero commitment and a
  ///      fresh pair has never written one.
  /// @param _account The account that holds the setup.
  /// @param _action The action the setup is for.
  /// @return _setup The stored setup.
  function _existingSetup(address _account, address _action) internal view returns (Setup storage _setup) {
    _setup = _setups[_account][_action];
    require(_setup.commitment != bytes32(0), PolicyManager_NoSetup(_account, _action));
  }

  /// @notice Returns the attempt a spend or a veto names, and reverts unless it is waiting and carries
  ///         the id the caller named. Naming the id means a spend or a veto prepared for one attempt
  ///         can never act on the one that replaces it.
  /// @dev It also checks that the attempt was accepted under the setup still in place. That check
  ///      fails only if a setup write forgot to cancel the waiting attempt, and it stays so that such
  ///      a bug still cannot release an attempt approved under an older setup.
  /// @param _account The account whose attempt is named.
  /// @param _action The action the attempt runs under.
  /// @param _attemptId The attempt id the caller named.
  /// @return _attempt The live attempt record.
  function _liveAttempt(address _account, address _action, uint64 _attemptId)
    internal
    view
    returns (Attempt storage _attempt)
  {
    _attempt = _attempts[_account][_action];
    require(_attempt.state == AttemptState.Waiting, PolicyManager_NoActiveAttempt(_account, _action));
    require(_attemptId == _attempt.attemptId, PolicyManager_WrongAttemptId(_attemptId, _attempt.attemptId));
    Setup storage _setup = _setups[_account][_action];
    require(_attempt.setupNonce == _setup.nonce, PolicyManager_StaleAttempt(_attempt.setupNonce, _setup.nonce));
  }

  /// @notice Runs the last two checks an opening and a cancellation share before any proof is read:
  ///         the request is still valid, and the body it reveals is the one the holder committed.
  /// @dev The two callers check different things before this, so each keeps its own head and calls
  ///      this at the end of it. The body check comes last because no field of the body may count
  ///      until it passes: the body is hashed with the account, the action and the stored setup
  ///      nonce, and the result must equal the stored commitment.
  /// @param _account The account the request names.
  /// @param _action The action the request names.
  /// @param _setup The stored setup of that account and action.
  /// @param _validUntil The last timestamp at which the request is accepted.
  /// @param _body The setup body the request carries.
  /// @return _now The current block timestamp, which an opening adds the wait to.
  function _checkWindowAndBody(
    address _account,
    address _action,
    Setup storage _setup,
    uint48 _validUntil,
    bytes calldata _body
  ) internal view returns (uint48 _now) {
    _now = SafeCast.toUint48(block.timestamp);
    require(!(_now > _validUntil), PolicyManager_RequestExpired(_now, _validUntil));
    bytes32 _recomputed = BindingDigest.setupCommitment(_account, _action, _setup.nonce, _body);
    require(_recomputed == _setup.commitment, PolicyManager_SetupCommitmentMismatch(_recomputed, _setup.commitment));
  }

  /// @notice Computes the Approval digest each proof of an opening must approve, one per proof, in
  ///         proof order.
  /// @dev The domain separator is computed once for the whole request.
  /// @param _request The opening request.
  /// @return _digests The digest for each proof's place.
  function _approvalDigests(AttemptRequest calldata _request) internal view returns (bytes32[] memory _digests) {
    bytes32 _separator = _domainSeparator();
    uint256 _proofCount = _request.proofs.length;
    _digests = new bytes32[](_proofCount);
    for (uint256 _i; _i < _proofCount; ++_i) {
      _digests[_i] = BindingDigest.approvalDigest(_separator, _request, _request.proofs[_i].place);
    }
  }

  /// @notice Computes the Cancellation digest each proof of a cancellation must approve, one per
  ///         proof, in proof order.
  /// @dev The domain separator is computed once for the whole request. A Cancellation names the
  ///      attempt and no outcome, under a type name an approval never signs, so no approval can be
  ///      replayed as a cancellation.
  /// @param _request The cancellation request.
  /// @return _digests The digest for each proof's place.
  function _cancelDigests(CancelRequest calldata _request) internal view returns (bytes32[] memory _digests) {
    bytes32 _separator = _domainSeparator();
    uint256 _proofCount = _request.proofs.length;
    _digests = new bytes32[](_proofCount);
    for (uint256 _i; _i < _proofCount; ++_i) {
      _digests[_i] = BindingDigest.cancelDigest(_separator, _request, _request.proofs[_i].place);
    }
  }

  /// @notice Decides whether a set of proofs satisfies the holder's rule. An opening and a
  ///         cancellation both use it, and differ only in the digests their proofs must approve.
  /// @dev The body is decoded once. Each proof then runs its checks in a fixed order: its position and
  ///      credential, its method's stop the first time the method appears, and last the method's
  ///      verdict. A method is therefore never asked about a proof that already failed a cheaper
  ///      check. The rule is checked once every proof has passed.
  /// @param _proofs The request's proofs, whose body already matched the commitment.
  /// @param _body The setup body the request carries.
  /// @param _digests The digest each proof must approve, in proof order.
  /// @return _wait The body's wait in seconds.
  /// @return _ignoresPause Whether the body says a method's stop does not reach this holder.
  /// @return _usedMethods The distinct methods the proofs used, in the order the proofs first name
  ///         them.
  /// @return _usedPlaces The places the proofs filled, in the order given.
  function _verifyProofs(ProofPlace[] calldata _proofs, bytes calldata _body, bytes32[] memory _digests)
    internal
    view
    returns (uint48 _wait, bool _ignoresPause, address[] memory _usedMethods, uint256[] memory _usedPlaces)
  {
    Clause[] memory _clauses;
    (_wait, _ignoresPause, _clauses) = SetupBody.decode(_body);
    uint256 _proofCount = _proofs.length;
    _usedMethods = new address[](_proofCount);
    _usedPlaces = new uint256[](_proofCount);
    uint256 _methodCount = 0;
    for (uint256 _i; _i < _proofCount; ++_i) {
      ProofPlace calldata _proof = _proofs[_i];
      _checkPlace(_proofs, _i, _clauses);
      _methodCount = _checkStopOnFirstUse(_proof, _ignoresPause, _usedMethods, _methodCount);
      _checkVerdict(_proof, _digests[_i]);
      _usedPlaces[_i] = _proof.place;
    }
    _checkRule(_clauses, _proofs);
    _usedMethods = _filledPart(_usedMethods, _methodCount);
  }

  /// @notice Refuses a proof whose method is stopped, asking each method once, at its first proof,
  ///         and never when the body says the holder ignores stops.
  /// @dev A method seen for the first time is appended to the list of distinct methods, which the
  ///      opening records and emits.
  /// @param _proof The proof checked.
  /// @param _ignoresPause Whether the body says a method's stop does not reach this holder.
  /// @param _usedMethods The distinct methods seen so far, filled up to _methodCount.
  /// @param _methodCount How many entries of _usedMethods are filled.
  /// @return _newMethodCount How many entries of _usedMethods are filled after this proof.
  function _checkStopOnFirstUse(
    ProofPlace calldata _proof,
    bool _ignoresPause,
    address[] memory _usedMethods,
    uint256 _methodCount
  ) internal view returns (uint256 _newMethodCount) {
    _newMethodCount = _methodCount;
    if (!_alreadySeen(_usedMethods, _methodCount, _proof.method)) {
      require(_ignoresPause || !_vetoes(_proof.method), PolicyManager_MethodStopped(_proof.place, _proof.method));
      _usedMethods[_methodCount] = _proof.method;
      _newMethodCount = _methodCount + 1;
    }
  }

  /// @notice Asks a proof's method for its verdict and refuses the proof unless the answer is the
  ///         magic value.
  /// @dev The call is static, so the method writes no state. The verdict counts only when the call
  ///      succeeds and returns exactly one word equal to the selector of verify, left-aligned. A
  ///      revert, an empty return, a shorter or longer return and any other word all refuse.
  /// @param _proof The proof whose method is asked.
  /// @param _digest The digest the proof must approve.
  function _checkVerdict(ProofPlace calldata _proof, bytes32 _digest) internal view {
    (bool _success, bytes32 _result) =
      _tryStaticCallWord(_proof.method, abi.encodeCall(IPolicyMethod.verify, (_proof.config, _digest, _proof.proof)));
    require(
      _success && _result == bytes32(IPolicyMethod.verify.selector),
      PolicyManager_ProofRejected(_proof.place, _proof.method)
    );
  }

  /// @notice Reads whether a method reports itself stopped. Only an answer of exactly true counts.
  /// @dev A method that declares no pause read, or whose read reverts, returns nothing, returns more
  ///      or less than one word, or returns any word other than the encoding of true, is not
  ///      stopped. The word is compared whole, since decoding it as a bool would revert on any other
  ///      word.
  /// @param _method The method asked.
  /// @return _stopped True when paused() returned exactly the ABI encoding of true.
  function _vetoes(address _method) internal view returns (bool _stopped) {
    (bool _success, bytes32 _result) = _tryStaticCallWord(_method, abi.encodeCall(IPolicyMethodPause.paused, ()));
    _stopped = _success && _result == bytes32(uint256(1));
  }

  /// @notice Makes a static call and returns its answer when the call succeeded with exactly one
  ///         word. It never reverts: a failed call or an answer of any other size comes back as a
  ///         false success flag.
  /// @dev The size the callee returned is read before anything is copied back, and only one word is
  ///      ever copied, into the scratch space. Copying the whole return first would let a callee
  ///      charge the caller for an arbitrarily long answer, and bounding the copy without reading
  ///      the size would make every longer answer look like one word.
  /// @param _target The contract called.
  /// @param _data The call data.
  /// @return _success True when the call succeeded and returned exactly 32 bytes.
  /// @return _result The returned word, or zero when _success is false.
  function _tryStaticCallWord(address _target, bytes memory _data)
    internal
    view
    returns (bool _success, bytes32 _result)
  {
    assembly ('memory-safe') {
      let _called := staticcall(gas(), _target, add(_data, 0x20), mload(_data), 0, 0)
      if and(_called, eq(returndatasize(), 0x20)) {
        returndatacopy(0, 0, 0x20)
        _result := mload(0)
        _success := 1
      }
    }
  }

  /// @notice Checks that a proof points at a real place in the rule and brings the credential the
  ///         holder committed there.
  /// @dev Places must rise strictly from one proof to the next, so no place is filled twice. The
  ///      proof's method, config and salt are hashed and compared with the credential stored at its
  ///      place in the body.
  /// @param _proofs The request's proofs.
  /// @param _index The position of the proof checked.
  /// @param _clauses The decoded clauses of the body.
  function _checkPlace(ProofPlace[] calldata _proofs, uint256 _index, Clause[] memory _clauses) internal pure {
    ProofPlace calldata _proof = _proofs[_index];
    uint256 _place = _proof.place;
    require(_index == 0 || _place > _proofs[_index - 1].place, PolicyManager_PlacesNotStrictlyIncreasing(_place));
    bytes32 _recomputed = BindingDigest.credentialCommitment(_proof.method, _proof.config, _proof.salt);
    require(
      _recomputed == SetupBody.credentialAt(_clauses, _place), PolicyManager_CredentialMismatch(_place, _recomputed)
    );
  }

  /// @notice Refuses a proof set that does not satisfy the rule.
  /// @dev Every proof has verified by the time this runs, so the count covers verified places only.
  /// @param _clauses The decoded clauses of the body.
  /// @param _proofs The verified proofs.
  function _checkRule(Clause[] memory _clauses, ProofPlace[] calldata _proofs) internal pure {
    (bool _satisfied, uint256 _failingClause) = SetupBody.ruleSatisfied(_clauses, _proofs);
    require(_satisfied, PolicyManager_RuleUnsatisfied(_failingClause));
  }

  /// @notice Whether a method already appeared in an earlier proof of the same request.
  /// @dev A method's stop is read only at its first proof, and the list of distinct methods names each
  ///      method once, so every proof asks this before either happens. Only the filled entries are
  ///      searched, since the rest of the list is still zero.
  /// @param _list The distinct methods seen so far.
  /// @param _length How many entries of the list are filled.
  /// @param _item The method looked for.
  /// @return _found True when the method is among the filled entries.
  function _alreadySeen(address[] memory _list, uint256 _length, address _item) internal pure returns (bool _found) {
    for (uint256 _i; _i < _length; ++_i) {
      if (_list[_i] == _item) return true;
    }
  }

  /// @notice Returns the entries of the list of distinct methods that were actually filled.
  /// @dev The list is allocated with one entry per proof, since how many distinct methods there are is
  ///      known only after every proof is read. The unfilled entries are zero and must not reach the
  ///      attempt record or the event.
  /// @param _list The list copied from.
  /// @param _length How many entries are filled.
  /// @return _filled The first _length entries of the list.
  function _filledPart(address[] memory _list, uint256 _length) internal pure returns (address[] memory _filled) {
    _filled = new address[](_length);
    for (uint256 _i; _i < _length; ++_i) {
      _filled[_i] = _list[_i];
    }
  }
}
