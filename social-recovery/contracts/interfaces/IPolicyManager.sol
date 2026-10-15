// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

/// @title IPolicyManager
/// @author defi-wonderland
/// @notice The one contract that approves attempts, for any action. It stores each account's
///         policy per action and judges requests against it. It runs the attempt state machine
///         and holds no authority over any account.
/// @dev The manager never calls an account. The account spends an approved attempt by calling
///      consume, and it can do so exactly once. The action's code decides what runs around that
///      spend. The manager carries no pause and no owner. The only stop in the kit is the pause a
///      method may carry. The manager reads that pause at an opening, at a cancel by proofs, at the
///      spend and at a cancel by veto.
interface IPolicyManager {
  /*///////////////////////////////////////////////////////////////
                               ENUMS
  ///////////////////////////////////////////////////////////////*/

  /// @notice The state of one attempt record. Waiting is the only live state. Cancelled and Consumed
  ///         are history, and None means no attempt was ever recorded.
  enum AttemptState {
    None,
    Waiting,
    Cancelled,
    Consumed
  }

  /*///////////////////////////////////////////////////////////////
                              STRUCTS
  ///////////////////////////////////////////////////////////////*/

  /// @notice What the account pays, and to whom. The guardians approve it inside the digest, so nobody
  ///         can redirect it after they sign. A zero amount means nobody is paid.
  /// @param token The ERC-20 token paid, or address(0) for the native asset.
  /// @param amount The amount of the transfer the batch carries. Whether the payee receives it
  ///        depends on the token, since the manager reads no balance.
  /// @param payee Who is paid, usually the submitter or their paymaster. address(0) leaves the order
  ///        open, so whoever builds the batch names the payee.
  struct PaymentOrder {
    address token;
    uint256 amount;
    address payee;
  }

  /// @notice Everything one attempt submission carries. It names the account and the action, writes
  ///         out the rule, and carries the outcome being approved in the committed action's own
  ///         layout, what the account pays for it and the proofs.
  /// @param account The account the action runs on.
  /// @param action The action the setup was committed under.
  /// @param attemptId The attempt id, which must equal stateOf(account, action).nextAttemptId.
  /// @param setupNonce The setup version the proofs were signed under. Any value other than the
  ///        stored one fails as PolicyManager_WrongSetupNonce, never as a rejected proof.
  /// @param setupBody The committed rule written out in full. The manager hashes it with the account,
  ///        the action and setupNonce, and the result must equal the stored commitment.
  /// @param payload The outcome being approved, in the committed action's layout. The manager stores
  ///        its hash.
  /// @param order What the account pays at execution, and to whom.
  /// @param validUntil The time until which this signed request may still be submitted. Every proof
  ///        signs it.
  /// @param proofs One entry per filled place, with place values strictly increasing.
  // solhint-disable-next-line gas-struct-packing
  struct AttemptRequest {
    address account;
    address action;
    uint64 attemptId;
    uint64 setupNonce;
    bytes setupBody;
    bytes payload;
    PaymentOrder order;
    uint48 validUntil;
    ProofPlace[] proofs;
  }

  /// @notice One filled place in the rule. At each place the body stores only the hash of a
  ///         credential's method, config and salt. The manager recomputes that hash from this entry
  ///         and requires it to equal the hash at `place`, so the method, config and salt must be
  ///         exactly the ones the holder committed.
  /// @param place Which place in which clause of the rule this entry fills.
  /// @param method The module that verifies this credential.
  /// @param config The credential in the method's own layout, which only that method decodes.
  /// @param salt This credential's supplied salt. The manager derives no default and only hashes what
  ///        it is given.
  /// @param proof The method's proof bytes, in the method's own layout, which only that method
  ///        decodes.
  struct ProofPlace {
    uint256 place;
    address method;
    bytes config;
    bytes32 salt;
    bytes proof;
  }

  /// @notice A cancellation submission. It is like AttemptRequest but approves no outcome, which is
  ///         why it carries no payload. It carries its own validUntil, so a cancel signed ahead of
  ///         the attempt it names cannot wait for that attempt forever.
  /// @param account The account whose attempt is cancelled.
  /// @param action The action the attempt belongs to.
  /// @param attemptId The exact attempt these proofs cancel.
  /// @param setupNonce The setup version the cancel proofs were signed under, checked like the
  ///        opening request's.
  /// @param setupBody The committed rule written out.
  /// @param validUntil The time until which this signed cancellation may still be submitted.
  /// @param proofs Proofs signed as cancellations of this exact attempt.
  // solhint-disable-next-line gas-struct-packing
  struct CancelRequest {
    address account;
    address action;
    uint64 attemptId;
    uint64 setupNonce;
    bytes setupBody;
    uint48 validUntil;
    ProofPlace[] proofs;
  }

  /// @notice A summary of one action on one account in a single read, which stateOf returns.
  /// @param setupCommitment The committed setup, or bytes32(0) when no setup exists.
  /// @param setupNonce The current setup nonce. Every commitSetup and clearSetup raises it by one and
  ///        nothing lowers it, so a proof signed under an older setup never matches again.
  /// @param nextAttemptId The id the next accepted request must carry.
  /// @param setupCommittedAtBlock The block of the last setup write, a block number rather than a
  ///        time.
  /// @param attempt The last attempt record. Waiting is the only live state, and the others are
  ///        history.
  struct ActionState {
    bytes32 setupCommitment;
    uint64 setupNonce;
    uint64 nextAttemptId;
    uint48 setupCommittedAtBlock;
    Attempt attempt;
  }

  /// @notice The attempt record per action. Each new attempt overwrites it, and nothing deletes it.
  ///         It holds the clock and what the spend checks, all of it public since the opening event.
  /// @param attemptId The id this attempt was allocated.
  /// @param setupNonce The setup version it was judged under. Consume and cancel refuse any other.
  /// @param consumableAfter When the wait ends.
  /// @param state Waiting while live, and Cancelled or Consumed once ended.
  /// @param ignoresPause Copied from the body this attempt was judged under, so the spend and the
  ///        cancel by veto read it without the body. It sits beside state so the first five fields
  ///        share one storage slot.
  /// @param payloadHash keccak256 of the committed payload, which consume checks.
  /// @param order The payment the guardians approved.
  /// @param usedMethods The distinct methods the accepted set used, in the order the proofs named
  ///        them. Consume asks each one whether it vetoes the spend.
  // solhint-disable-next-line gas-struct-packing
  struct Attempt {
    uint64 attemptId;
    uint64 setupNonce;
    uint48 consumableAfter;
    AttemptState state;
    bool ignoresPause;
    bytes32 payloadHash;
    PaymentOrder order;
    address[] usedMethods;
  }

  /// @notice What the manager remembers about one action on one account. The commitment and the
  ///         nonce are the configuration only the account writes; the attempt counter is moved by
  ///         the permissionless opening call, and the block is written by every setup write.
  /// @param commitment keccak256(account, action, nonce, body); bytes32(0) when none.
  /// @param nonce Rises on every setup write, never rewinds.
  /// @param attemptCounter The last allocated attempt id, never rewinds.
  /// @param setupCommittedAtBlock The block of the last setup write, including a clear, so a client
  ///        reads that one block rather than the whole history, taking the last matching event in it
  ///        since two writes for one action can share a block; a block number rather than a time,
  ///        unlike every other uint48 here.
  struct Setup {
    bytes32 commitment;
    uint64 nonce;
    uint64 attemptCounter;
    uint48 setupCommittedAtBlock;
  }

  /// @notice One clause of the setup body. The rule is the AND of the clauses.
  /// @param threshold How many of this clause's credentials must fill.
  /// @param credentials Each keccak256(method, config, salt), in the holder's order.
  struct Clause {
    uint8 threshold;
    bytes32[] credentials;
  }

  /*///////////////////////////////////////////////////////////////
                              EVENTS
  ///////////////////////////////////////////////////////////////*/

  /// @notice The account committed a new setup for one action.
  /// @param _account The account that committed the setup.
  /// @param _action The action the setup governs.
  /// @param _nonce The setup nonce this write holds.
  /// @param _setupCommitment The commitment written.
  /// @param _publicMetadata The holder's optional public note, for anyone to read. It is empty by
  ///        default.
  /// @param _privateMetadata The holder's own copy of their configuration for a future device,
  ///        encrypted unless the holder chose the clear path. It is a separate field because its
  ///        audience is the opposite of the public one's.
  // solhint-disable-next-line gas-indexed-events
  event SetupCommitted(
    address indexed _account,
    address indexed _action,
    uint64 _nonce,
    bytes32 _setupCommitment,
    bytes _publicMetadata,
    bytes _privateMetadata
  );

  /// @notice The account removed the action's setup through clearSetup. A recommit emits
  ///         SetupCommitted alone, so each setup write emits one event.
  /// @param _account The account whose setup was removed.
  /// @param _action The action whose setup was removed.
  /// @param _nonce The nonce this clear wrote, which is the previous one plus one. SetupCommitted
  ///        carries the same value for a write.
  // solhint-disable-next-line gas-indexed-events
  event SetupCleared(address indexed _account, address indexed _action, uint64 _nonce);

  /// @notice A complete proof set opened an attempt.
  /// @param _account The account the attempt runs on.
  /// @param _action The action the attempt runs under.
  /// @param _attemptId The id the attempt was allocated.
  /// @param _setupNonce The setup version the attempt was judged under, so a watcher
  ///        binds the attempt to the setup that authorized it.
  /// @param _setupBody The committed rule written out, in the clear.
  /// @param _usedPlaces The place values the accepted set filled, strictly increasing. The configs in
  ///        the transaction's calldata show which person each place is.
  /// @param _usedMethods The distinct methods that set used, which consume asks for a veto. With them
  ///        the event stream carries the whole attempt the manager stored.
  /// @param _payload The outcome approved, in the committed action's layout, in the clear.
  /// @param _order The payment the guardians approved.
  /// @param _consumableAfter When the wait ends.
  event AttemptStarted(
    address indexed _account,
    address indexed _action,
    uint64 _attemptId,
    uint64 _setupNonce,
    bytes _setupBody,
    uint256[] _usedPlaces,
    address[] _usedMethods,
    bytes _payload,
    PaymentOrder _order,
    uint48 _consumableAfter
  );

  /// @notice The attempt was cancelled.
  /// @param _account The account whose attempt was cancelled.
  /// @param _action The action the attempt ran under.
  /// @param _attemptId The attempt cancelled.
  /// @param _canceller Who cancelled. It is the account itself for the holder's cancel and the caller
  ///        for a cancel by proofs or by veto. It is zero for a cancel that a setup write caused.
  /// @param _stoppedMethod The stopped method whose veto authorized a cancel by veto, and address(0)
  ///        on every other path. So a watcher never reads an administrative cancellation as a guardian
  ///        set withdrawing.
  /// @param _setupNonce The setup version the cancelled attempt was judged under.
  /// @param _usedPlaces The places the cancelling set filled. It is empty for the holder's own cancel
  ///        and for a cancel by veto. It mirrors the opening event, so a holder can tell their own
  ///        guardians withdrawing from a set they should worry about.
  event AttemptCancelled(
    address indexed _account,
    address indexed _action,
    uint64 _attemptId,
    address _canceller,
    address _stoppedMethod,
    uint64 _setupNonce,
    uint256[] _usedPlaces
  );

  /// @notice The account spent the attempt, and the manager saw nothing more. The batch around the
  ///         spend performed the writes and the payment. A reader finds those in the account's own
  ///         transaction and state, never in this event.
  /// @param _account The account that spent the attempt.
  /// @param _action The action the attempt ran under.
  /// @param _attemptId The attempt spent.
  // solhint-disable-next-line gas-indexed-events
  event AttemptConsumed(address indexed _account, address indexed _action, uint64 _attemptId);

  /*///////////////////////////////////////////////////////////////
                              ERRORS
  ///////////////////////////////////////////////////////////////*/

  /// @notice The commitment is bytes32(0), which means no setup, or the commitment of zero-length
  ///         bytes.
  /// @param _supplied The commitment supplied.
  error PolicyManager_InvalidCommitment(bytes32 _supplied);

  /// @notice The nonce is not the expected one: commitSetup got a nonce other than the current one
  ///         plus one, clearSetup got one other than the current one, or a request was signed under a
  ///         nonce other than the stored one.
  /// @param _supplied The nonce supplied.
  /// @param _expected The nonce expected.
  error PolicyManager_WrongSetupNonce(uint64 _supplied, uint64 _expected);

  /// @notice commitSetup named an action that does not serve the calling account: the action's
  ///         supportsAccount did not answer exactly true for it.
  /// @param _account The account that called.
  /// @param _action The action it named.
  error PolicyManager_ActionDoesNotServeAccount(address _account, address _action);

  /// @notice The place is past the end of the revealed rule.
  /// @param _place The place asked for.
  /// @param _count The number of places the rule has.
  error PolicyManager_PlaceOutOfRange(uint256 _place, uint256 _count);

  /// @notice An attempt or a clearSetup named an action with no committed setup.
  /// @param _account The account asked about.
  /// @param _action The action asked about.
  error PolicyManager_NoSetup(address _account, address _action);

  /// @notice A cancel or a consume found no attempt running.
  /// @param _account The account asked about.
  /// @param _action The action asked about.
  error PolicyManager_NoActiveAttempt(address _account, address _action);

  /// @notice A startAttempt arrived while an attempt is already running.
  /// @param _account The account asked about.
  /// @param _action The action asked about.
  /// @param _attemptId The id of the attempt already running.
  error PolicyManager_AttemptAlreadyActive(address _account, address _action, uint64 _attemptId);

  /// @notice A request named an id that is not the next one, or a cancel or a consume named one that
  ///         is not the live one.
  /// @param _supplied The attempt id supplied.
  /// @param _expected The attempt id expected.
  error PolicyManager_WrongAttemptId(uint64 _supplied, uint64 _expected);

  /// @notice The written-out rule does not hash to the commitment.
  /// @param _recomputed The commitment recomputed from the request.
  /// @param _committed The commitment stored.
  error PolicyManager_SetupCommitmentMismatch(bytes32 _recomputed, bytes32 _committed);

  /// @notice The setup changed after the attempt was accepted: the stored setup nonce is no longer
  ///         the one the attempt was judged under.
  /// @param _judgedUnder The setup nonce the attempt was judged under.
  /// @param _currentNonce The setup nonce stored now.
  error PolicyManager_StaleAttempt(uint64 _judgedUnder, uint64 _currentNonce);

  /// @notice The method, the config and the salt do not hash to the credential at this place.
  /// @param _place The place checked.
  /// @param _recomputed The credential hash recomputed from method, config and salt.
  error PolicyManager_CredentialMismatch(uint256 _place, bytes32 _recomputed);

  /// @notice The proofs array holds a duplicate or an out-of-order place.
  /// @param _place The place that broke the strictly increasing order.
  error PolicyManager_PlacesNotStrictlyIncreasing(uint256 _place);

  /// @notice The request or cancellation arrived after its validUntil, the deadline every proof in
  ///         it signed.
  /// @param _blockTimestamp The block's timestamp.
  /// @param _validUntil The request's deadline.
  error PolicyManager_RequestExpired(uint48 _blockTimestamp, uint48 _validUntil);

  /// @notice This method rejected the proof at this place in the rule.
  /// @param _place The place whose proof was rejected.
  /// @param _method The method that rejected it.
  error PolicyManager_ProofRejected(uint256 _place, address _method);

  /// @notice At an opening or a cancel by proofs, the method at this place reports itself stopped,
  ///         so its proof is refused. Never raised when the setup ignores stops.
  /// @param _place The place the stopped method judges.
  /// @param _method The stopped method.
  error PolicyManager_MethodStopped(uint256 _place, address _method);

  /// @notice At consume, a method the attempt used reports itself stopped, so the spend is refused.
  ///         Never raised when the setup ignores stops.
  /// @param _method The method that vetoed the spend.
  error PolicyManager_MethodVetoedSpend(address _method);

  /// @notice cancelByVeto named a method this attempt did not use. A stop only lets anyone cancel the
  ///         attempts that rely on the stopped method. cancelByProofs has no such limit, since any
  ///         set that satisfies the rule may cancel.
  /// @param _attemptId The attempt the cancel named.
  /// @param _method The method named.
  error PolicyManager_MethodNotUsed(uint64 _attemptId, address _method);

  /// @notice A cancel by veto named an attempt whose setup committed to ignore a method's stop.
  /// @param _attemptId The attempt the cancel named.
  error PolicyManager_AttemptIgnoresPause(uint64 _attemptId);

  /// @notice A cancel by veto named a method that did not answer the pause read with true.
  /// @param _method The method named.
  error PolicyManager_MethodNotStopped(address _method);

  /// @notice Every proof verified, but they do not satisfy the rule: this clause has fewer filled
  ///         places than its threshold. A body with no clauses, or whose every threshold is zero,
  ///         fails with clause zero, because a stranger could satisfy it with no proof.
  /// @param _clause The clause whose threshold was missed.
  error PolicyManager_RuleUnsatisfied(uint256 _clause);

  /// @notice A consume arrived before the wait ended.
  /// @param _blockTimestamp The block's timestamp.
  /// @param _consumableAfter When the wait ends.
  error PolicyManager_WaitNotOver(uint48 _blockTimestamp, uint48 _consumableAfter);

  /// @notice A consume named a payload that is not the attempt's.
  /// @param _supplied The payload hash supplied.
  /// @param _committed The payload hash the attempt committed to.
  error PolicyManager_WrongPayload(bytes32 _supplied, bytes32 _committed);

  /*///////////////////////////////////////////////////////////////
                              LOGIC
  ///////////////////////////////////////////////////////////////*/

  // ---- Configuration. Callable by the account alone. ----

  /// @notice Create or replace the caller's setup for the given action.
  /// @dev Increments the setup nonce and cancels the action's active attempt, if one exists. It
  ///      reverts in four cases. A commitment of bytes32(0) is refused because that value means
  ///      no setup (PolicyManager_InvalidCommitment). The commitment of zero-length bytes is refused
  ///      because no setup body produces it (PolicyManager_InvalidCommitment). A nonce other than
  ///      the current one plus one is refused (PolicyManager_WrongSetupNonce). An action that does
  ///      not serve the caller is refused (PolicyManager_ActionDoesNotServeAccount): the manager
  ///      asks the action's supportsAccount(caller) as a static call and accepts only a call that
  ///      succeeds and returns exactly one word equal to true, so an action with no code, one that
  ///      reverts and one that answers anything else are all refused. The check runs before anything
  ///      is written. clearSetup and cancelByOwner make no such call, so an account its action no
  ///      longer serves can still remove its setup. The commitment and the
  ///      nonce arrive as separate arguments. So the nonce check catches a caller whose nonce is
  ///      stale, but it never proves that the commitment was computed over that nonce. A commitment
  ///      built over a different nonce stores a setup that no request can ever match.
  /// @param _action The action this setup governs, by its address.
  /// @param _setupCommitment keccak256 of the account, the action, the nonce this
  ///        write will hold, and the setup body.
  /// @param _nonce The nonce the commitment was computed over, which must be the current one plus
  ///        one.
  /// @param _publicMetadata What the holder chose to show everyone about this setup. It is empty
  ///        by default, and anyone may read it.
  /// @param _privateMetadata The holder's backup of their configuration, which may be empty. It is
  ///        encrypted unless the holder chose the clear path, and it is public on chain like
  ///        everything else.
  function commitSetup(
    address _action,
    bytes32 _setupCommitment,
    uint64 _nonce,
    bytes calldata _publicMetadata,
    bytes calldata _privateMetadata
  ) external;

  /// @notice Remove the caller's setup for the given action.
  /// @dev Increments the setup nonce and cancels the action's active attempt, if one exists.
  ///      Reverts when the action has no setup (PolicyManager_NoSetup), then when the nonce is
  ///      not the current one (PolicyManager_WrongSetupNonce). Naming the nonce ties a signed
  ///      account batch to the setup it removes, so a batch that reverted and is sent again later
  ///      cannot remove a setup committed after it.
  /// @param _action The action whose setup is removed.
  /// @param _nonce The setup nonce the caller removes, which must be the current one.
  function clearSetup(address _action, uint64 _nonce) external;

  /// @notice Cancel the caller's own active attempt with the account's own key.
  /// @dev Only the account may call it, as with commitSetup and clearSetup. Reverts when no
  ///      attempt is waiting (PolicyManager_NoActiveAttempt), then when the waiting attempt has
  ///      another id (PolicyManager_WrongAttemptId). Attempt ids never repeat for one account and
  ///      action, so naming the id ties a signed account batch to the one attempt it cancels, and
  ///      a batch that reverted and is sent again later cannot cancel a later attempt.
  /// @param _action The action whose active attempt is cancelled.
  /// @param _attemptId The id of the waiting attempt the caller cancels.
  function cancelByOwner(address _action, uint64 _attemptId) external;

  // ---- Attempts. Permissionless to call, authorized by proofs alone. ----

  /// @notice Open an attempt with a complete proof set in one transaction.
  /// @dev Anyone may call it. The proofs authorize the attempt, and no check reads the caller's
  ///      identity. When a rule can be met in more than one way, the caller chooses which proofs
  ///      to submit. The attempt records the methods those proofs used, and only those methods
  ///      can veto the spend later. The manager never counts the caller as a filled place.
  /// @param _request The full request, laid out as AttemptRequest.
  function startAttempt(AttemptRequest calldata _request) external;

  /// @notice Cancel the active attempt with a proof set that satisfies the rule.
  /// @dev Anyone may call it, and the proofs authorize the cancel. A cancel proof signs a
  ///      Cancellation type naming one attempt, so an approval proof never counts as a cancel
  ///      proof.
  /// @param _request Like AttemptRequest but with no payload, since a cancel approves no outcome.
  function cancelByProofs(CancelRequest calldata _request) external;

  /// @notice Cancel a waiting attempt after one of its methods has been stopped. Anyone may call
  ///         it.
  /// @dev Anyone may call it, and the call carries no proofs. A stopped method is enough to
  ///      cancel. The method must be one the attempt's accepted proofs used, and its paused()
  ///      must return exactly true. The call reverts in six cases: no attempt is waiting
  ///      (PolicyManager_NoActiveAttempt), _attemptId is not the live attempt
  ///      (PolicyManager_WrongAttemptId), the setup nonce moved (PolicyManager_StaleAttempt), the
  ///      attempt's setup ignores stops (PolicyManager_AttemptIgnoresPause), the attempt did not use
  ///      the method (PolicyManager_MethodNotUsed), or paused() did not return exactly true
  ///      (PolicyManager_MethodNotStopped). The call needs no wait, no payload and no deadline. It
  ///      moves neither the setup nonce nor the attempt counter.
  /// @param _account The account whose attempt is cancelled.
  /// @param _action The action the attempt runs under.
  /// @param _attemptId The exact attempt, so a cancel aimed at one never reaches its successor.
  /// @param _method The stopped method the caller names. The manager checks that the attempt's
  ///        used methods include it, and that membership authorizes the cancel. So no caller can
  ///        make the manager read an address the holder never committed.
  function cancelByVeto(address _account, address _action, uint64 _attemptId, address _method) external;

  // ---- The spend door. Callable by the account alone. ----

  /// @notice Spend the caller's approved attempt under the given action, exactly once.
  /// @dev The caller is the account. The call reverts in six cases: no attempt is waiting
  ///      (PolicyManager_NoActiveAttempt), _attemptId is not the live attempt
  ///      (PolicyManager_WrongAttemptId), the setup nonce moved (PolicyManager_StaleAttempt), the
  ///      wait has not ended (PolicyManager_WaitNotOver), _payloadHash is not the committed one
  ///      (PolicyManager_WrongPayload), or a method the attempt used returns exactly true from
  ///      paused() (PolicyManager_MethodVetoedSpend). The manager skips that last read when the
  ///      attempt's setup ignores stops. A successful call sets the attempt to Consumed, so a second
  ///      call reverts. The action puts this call first in the batch that executes the payload. The
  ///      manager never sees that batch, so only the action's code keeps the spend and the writes
  ///      together.
  /// @param _action The action whose attempt is spent.
  /// @param _attemptId The exact attempt being spent, so a spend aimed at one attempt
  ///        can never release a successor.
  /// @param _payloadHash keccak256 of the payload being executed, checked against the
  ///        committed one.
  function consume(address _action, uint64 _attemptId, bytes32 _payloadHash) external;

  // ---- Views. ----

  /// @notice Everything a client needs about one action's setup and attempt, in one read. It
  ///         does not say whether the account authorizes the action: read that from the account.
  /// @param _account The account asked about.
  /// @param _action The action asked about.
  /// @return _state The committed setup, its nonce, the id the next request must
  ///         carry, and the attempt record.
  function stateOf(address _account, address _action) external view returns (ActionState memory _state);

  /// @notice Returns the digest that the proof at one place of a request must approve. The digest
  ///         is EIP-712 typed data under this deployment's domain. A client derives the same typed
  ///         data locally to sign it and uses this view as a cross-check.
  /// @param _request The request the digest is computed over. Its proofs are ignored.
  /// @param _place The place in the rule the approving credential fills.
  /// @return _digest What the proof at that place must approve.
  function hashApproval(AttemptRequest calldata _request, uint256 _place) external view returns (bytes32 _digest);

  /// @notice Returns the digest that the proof at one place of a cancellation must approve. The
  ///         digest binds one exact attempt, under a type distinct from an approval's.
  /// @param _request The cancellation the digest is computed over. Its proofs are ignored.
  /// @param _place The place in the rule the cancelling credential fills.
  /// @return _digest What the proof at that place must approve.
  function hashCancel(CancelRequest calldata _request, uint256 _place) external view returns (bytes32 _digest);

  /// @notice Returns the EIP-712 domain the digests are computed under, per ERC-5267. The domain
  ///         holds the name, DIGEST_VERSION, the chain id and this address. A client reads it to
  ///         derive the typed data locally.
  /// @return _fields 0x0f, the ERC-5267 bitmap of the four fields in use: name, version,
  ///         chain id and verifying contract.
  /// @return _name The EIP-712 domain's name.
  /// @return _version The EIP-712 domain's version, DIGEST_VERSION.
  /// @return _chainId The chain id of the domain.
  /// @return _verifyingContract This address.
  /// @return _salt Unused, bytes32(0).
  /// @return _extensions Unused, empty.
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
    );

  // ---- Introspection. ----

  /// @notice Answers ERC-165, so wallets and clients can ask what this contract is.
  /// @param _interfaceId The ERC-165 interface id asked about.
  /// @return _supported True when this contract implements that interface.
  function supportsInterface(bytes4 _interfaceId) external view returns (bool _supported);

  /// @notice The human-readable name of this deployment, for wallets and clients. It is not the
  ///         EIP-712 domain's name, which is the fixed string the domain view returns.
  /// @return _managerName The deployment's human-readable name.
  function name() external view returns (string memory _managerName);

  /// @notice The semantic version of this deployment.
  /// @return _managerVersion The deployment's semantic version.
  function version() external view returns (string memory _managerVersion);
}
