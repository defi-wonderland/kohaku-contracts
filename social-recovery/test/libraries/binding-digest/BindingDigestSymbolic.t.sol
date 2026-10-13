// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {Test} from 'forge-std/Test.sol';
import {IPolicyManager} from 'interfaces/IPolicyManager.sol';
import {BindingDigestHarness} from 'test/utils/BindingDigestHarness.sol';

/// @notice Every member of an attempt request, with each variable length member reduced to one 32
///         byte word so a symbolic engine can reason about it. The word becomes the member's bytes.
/// @param account The account the action runs on.
/// @param action The action the setup was committed under.
/// @param attemptId The attempt id.
/// @param setupNonce The setup version the proofs were signed under.
/// @param setupBody The 32 byte content of the setup body.
/// @param payload The 32 byte content of the approved outcome.
/// @param token The token of the payment order.
/// @param amount The amount of the payment order.
/// @param payee The payee of the payment order.
/// @param validUntil The time until which the request may be submitted.
// solhint-disable-next-line gas-struct-packing
struct RequestMembers {
  address account;
  address action;
  uint64 attemptId;
  uint64 setupNonce;
  bytes32 setupBody;
  bytes32 payload;
  address token;
  uint256 amount;
  address payee;
  uint48 validUntil;
}

/// @notice Symbolic tests for the binding digest library, run by Halmos. Halmos treats every parameter of a check_
///         function as a symbolic value and proves the assertion for every possible value, where a fuzz test samples
///         a thousand. Halmos models keccak256 as an injective function, so a proof that two hash inputs differ is a
///         proof that the hashes differ under that model. The whole kit rests on the same assumption, that keccak256
///         has no collision anyone can find.
/// @dev Terms used below. A member is one field a hash covers. The separator is the EIP-712 domain separator, the
///      hash of the manager's name, digest version, chain id and address that every digest is computed under. The
///      library reads the chain id of the chain running the call, so a check sets a symbolic chain id with
///      `vm.chainId`. A place is the index of one credential in the holder's rule. A proof is what a guardian supplies
///      to approve or cancel, and a digest is the hash that proof signs. Every bytes member is built from one 32 byte
///      word, so each check covers exactly the 32 byte length of that member unless its comment says otherwise. A
///      check that takes two values and returns early when they are equal proves nothing on that path, so the
///      property is proven for every pair that differs.
contract BindingDigestSymbolicTest is Test {
  BindingDigestHarness internal _harness;

  /// @dev Deploys the harness that exposes the library as external calls.
  function setUp() external {
    _harness = new BindingDigestHarness();
  }

  /*///////////////////////////////////////////////////////////////
                    APPROVAL AGAINST CANCELLATION
  ///////////////////////////////////////////////////////////////*/

  /// For every account, action, attempt id, setup nonce, 32 byte setup body, window, place
  /// and separator, the approval digest and the cancellation digest over those shared members
  /// differ, whatever the approval's 32 byte payload and order. An approval signs a recovery
  /// going ahead and a cancellation signs it being stopped, so a proof for one must never
  /// count as the other.
  function check_ApprovalAndCancellationDigestsDiffer(RequestMembers calldata _m, bytes32 _separator, uint256 _place)
    external
    view
  {
    assert(
      _harness.approvalDigest(_separator, _approval(_m), _place)
        != _harness.cancelDigest(_separator, _cancel(_m), _place)
    );
  }

  /*///////////////////////////////////////////////////////////////
                     APPROVAL DIGEST, PER MEMBER
  ///////////////////////////////////////////////////////////////*/

  /// Two approvals that differ only in the account give different digests, so a proof
  /// approving a recovery of one account never recovers another.
  function check_ApprovalDigestBindsAccount(
    RequestMembers memory _m,
    bytes32 _separator,
    uint256 _place,
    address _other
  ) external view {
    if (_other == _m.account) return;
    bytes32 _base = _harness.approvalDigest(_separator, _approval(_m), _place);
    _m.account = _other;
    assert(_harness.approvalDigest(_separator, _approval(_m), _place) != _base);
  }

  /// Two approvals that differ only in the action give different digests, so a proof
  /// approving one recovery action never runs another action on the same account.
  function check_ApprovalDigestBindsAction(RequestMembers memory _m, bytes32 _separator, uint256 _place, address _other)
    external
    view
  {
    if (_other == _m.action) return;
    bytes32 _base = _harness.approvalDigest(_separator, _approval(_m), _place);
    _m.action = _other;
    assert(_harness.approvalDigest(_separator, _approval(_m), _place) != _base);
  }

  /// Two approvals that differ only in the attempt id give different digests, so a proof
  /// gathered for one attempt never counts for a later one.
  function check_ApprovalDigestBindsAttemptId(
    RequestMembers memory _m,
    bytes32 _separator,
    uint256 _place,
    uint64 _other
  ) external view {
    if (_other == _m.attemptId) return;
    bytes32 _base = _harness.approvalDigest(_separator, _approval(_m), _place);
    _m.attemptId = _other;
    assert(_harness.approvalDigest(_separator, _approval(_m), _place) != _base);
  }

  /// Two approvals that differ only in the setup nonce give different digests, so a proof
  /// signed under a setup the holder has since replaced never counts under the new one.
  function check_ApprovalDigestBindsSetupNonce(
    RequestMembers memory _m,
    bytes32 _separator,
    uint256 _place,
    uint64 _other
  ) external view {
    if (_other == _m.setupNonce) return;
    bytes32 _base = _harness.approvalDigest(_separator, _approval(_m), _place);
    _m.setupNonce = _other;
    assert(_harness.approvalDigest(_separator, _approval(_m), _place) != _base);
  }

  /// Two approvals whose 32 byte setup bodies differ give different digests, so a proof
  /// signed against one rule never counts for a request that writes out another rule.
  function check_ApprovalDigestBindsSetupBody(
    RequestMembers memory _m,
    bytes32 _separator,
    uint256 _place,
    bytes32 _other
  ) external view {
    if (_other == _m.setupBody) return;
    bytes32 _base = _harness.approvalDigest(_separator, _approval(_m), _place);
    _m.setupBody = _other;
    assert(_harness.approvalDigest(_separator, _approval(_m), _place) != _base);
  }

  /// Two approvals whose setup bodies have different lengths, empty against 32 bytes, give
  /// different digests, so a request cannot drop the rule it was signed against.
  function check_ApprovalDigestBindsSetupBodyLength(RequestMembers calldata _m, bytes32 _separator, uint256 _place)
    external
    view
  {
    IPolicyManager.AttemptRequest memory _request = _approval(_m);
    bytes32 _base = _harness.approvalDigest(_separator, _request, _place);
    _request.setupBody = '';
    assert(_harness.approvalDigest(_separator, _request, _place) != _base);
  }

  /// Two approvals whose 32 byte payloads differ give different digests. The payload is the
  /// outcome being approved, such as the new owner key, so a proof approving one outcome
  /// never installs another.
  function check_ApprovalDigestBindsPayload(
    RequestMembers memory _m,
    bytes32 _separator,
    uint256 _place,
    bytes32 _other
  ) external view {
    if (_other == _m.payload) return;
    bytes32 _base = _harness.approvalDigest(_separator, _approval(_m), _place);
    _m.payload = _other;
    assert(_harness.approvalDigest(_separator, _approval(_m), _place) != _base);
  }

  /// Two approvals whose payloads have different lengths, empty against 32 bytes, give
  /// different digests, so an approved outcome cannot be swapped for an empty one.
  function check_ApprovalDigestBindsPayloadLength(RequestMembers calldata _m, bytes32 _separator, uint256 _place)
    external
    view
  {
    IPolicyManager.AttemptRequest memory _request = _approval(_m);
    bytes32 _base = _harness.approvalDigest(_separator, _request, _place);
    _request.payload = '';
    assert(_harness.approvalDigest(_separator, _request, _place) != _base);
  }

  /// Two approvals that differ only in the payment order's token give different digests, so
  /// the account never pays in a token its guardians did not approve.
  function check_ApprovalDigestBindsOrderToken(
    RequestMembers memory _m,
    bytes32 _separator,
    uint256 _place,
    address _other
  ) external view {
    if (_other == _m.token) return;
    bytes32 _base = _harness.approvalDigest(_separator, _approval(_m), _place);
    _m.token = _other;
    assert(_harness.approvalDigest(_separator, _approval(_m), _place) != _base);
  }

  /// Two approvals that differ only in the payment order's amount give different digests, so
  /// whoever submits the recovery never raises the price the guardians approved.
  function check_ApprovalDigestBindsOrderAmount(
    RequestMembers memory _m,
    bytes32 _separator,
    uint256 _place,
    uint256 _other
  ) external view {
    if (_other == _m.amount) return;
    bytes32 _base = _harness.approvalDigest(_separator, _approval(_m), _place);
    _m.amount = _other;
    assert(_harness.approvalDigest(_separator, _approval(_m), _place) != _base);
  }

  /// Two approvals that differ only in the payment order's payee give different digests, so
  /// whoever submits the recovery never redirects the payment to themselves.
  function check_ApprovalDigestBindsOrderPayee(
    RequestMembers memory _m,
    bytes32 _separator,
    uint256 _place,
    address _other
  ) external view {
    if (_other == _m.payee) return;
    bytes32 _base = _harness.approvalDigest(_separator, _approval(_m), _place);
    _m.payee = _other;
    assert(_harness.approvalDigest(_separator, _approval(_m), _place) != _base);
  }

  /// Two approvals that differ only in the validity window's end give different digests, so
  /// an expired approval cannot be revived by moving its deadline.
  function check_ApprovalDigestBindsValidUntil(
    RequestMembers memory _m,
    bytes32 _separator,
    uint256 _place,
    uint48 _other
  ) external view {
    if (_other == _m.validUntil) return;
    bytes32 _base = _harness.approvalDigest(_separator, _approval(_m), _place);
    _m.validUntil = _other;
    assert(_harness.approvalDigest(_separator, _approval(_m), _place) != _base);
  }

  /// Two approvals that differ only in the place give different digests, so a proof signed
  /// for one credential in the rule never fills another credential's place.
  function check_ApprovalDigestBindsPlace(
    RequestMembers calldata _m,
    bytes32 _separator,
    uint256 _place,
    uint256 _other
  ) external view {
    if (_other == _place) return;
    IPolicyManager.AttemptRequest memory _request = _approval(_m);
    assert(
      _harness.approvalDigest(_separator, _request, _other) != _harness.approvalDigest(_separator, _request, _place)
    );
  }

  /// Two approvals that differ only in the separator give different digests, so a proof
  /// signed for one chain or one manager deployment never counts on another.
  function check_ApprovalDigestBindsSeparator(
    RequestMembers calldata _m,
    bytes32 _separator,
    uint256 _place,
    bytes32 _other
  ) external view {
    if (_other == _separator) return;
    IPolicyManager.AttemptRequest memory _request = _approval(_m);
    assert(_harness.approvalDigest(_other, _request, _place) != _harness.approvalDigest(_separator, _request, _place));
  }

  /*///////////////////////////////////////////////////////////////
                   CANCELLATION DIGEST, PER MEMBER
  ///////////////////////////////////////////////////////////////*/

  /// Two cancellations that differ only in the account give different digests, so a cancel
  /// for one account never stops a recovery of another.
  function check_CancelDigestBindsAccount(RequestMembers memory _m, bytes32 _separator, uint256 _place, address _other)
    external
    view
  {
    if (_other == _m.account) return;
    bytes32 _base = _harness.cancelDigest(_separator, _cancel(_m), _place);
    _m.account = _other;
    assert(_harness.cancelDigest(_separator, _cancel(_m), _place) != _base);
  }

  /// Two cancellations that differ only in the action give different digests, so a cancel
  /// for one action never stops an attempt under another.
  function check_CancelDigestBindsAction(RequestMembers memory _m, bytes32 _separator, uint256 _place, address _other)
    external
    view
  {
    if (_other == _m.action) return;
    bytes32 _base = _harness.cancelDigest(_separator, _cancel(_m), _place);
    _m.action = _other;
    assert(_harness.cancelDigest(_separator, _cancel(_m), _place) != _base);
  }

  /// Two cancellations that differ only in the attempt id give different digests, so a
  /// cancel signed for one attempt never stops a later legitimate one.
  function check_CancelDigestBindsAttemptId(RequestMembers memory _m, bytes32 _separator, uint256 _place, uint64 _other)
    external
    view
  {
    if (_other == _m.attemptId) return;
    bytes32 _base = _harness.cancelDigest(_separator, _cancel(_m), _place);
    _m.attemptId = _other;
    assert(_harness.cancelDigest(_separator, _cancel(_m), _place) != _base);
  }

  /// Two cancellations that differ only in the setup nonce give different digests, so a
  /// cancel signed under a replaced setup never counts under the new one.
  function check_CancelDigestBindsSetupNonce(
    RequestMembers memory _m,
    bytes32 _separator,
    uint256 _place,
    uint64 _other
  ) external view {
    if (_other == _m.setupNonce) return;
    bytes32 _base = _harness.cancelDigest(_separator, _cancel(_m), _place);
    _m.setupNonce = _other;
    assert(_harness.cancelDigest(_separator, _cancel(_m), _place) != _base);
  }

  /// Two cancellations whose 32 byte setup bodies differ give different digests, so a cancel
  /// signed against one rule never counts for a request that writes out another rule.
  function check_CancelDigestBindsSetupBody(
    RequestMembers memory _m,
    bytes32 _separator,
    uint256 _place,
    bytes32 _other
  ) external view {
    if (_other == _m.setupBody) return;
    bytes32 _base = _harness.cancelDigest(_separator, _cancel(_m), _place);
    _m.setupBody = _other;
    assert(_harness.cancelDigest(_separator, _cancel(_m), _place) != _base);
  }

  /// Two cancellations whose setup bodies have different lengths, empty against 32 bytes, give
  /// different digests, so a cancel cannot drop the rule it was signed against.
  function check_CancelDigestBindsSetupBodyLength(RequestMembers calldata _m, bytes32 _separator, uint256 _place)
    external
    view
  {
    IPolicyManager.CancelRequest memory _request = _cancel(_m);
    bytes32 _base = _harness.cancelDigest(_separator, _request, _place);
    _request.setupBody = '';
    assert(_harness.cancelDigest(_separator, _request, _place) != _base);
  }

  /// Two cancellations that differ only in the validity window's end give different
  /// digests, so an expired cancel cannot be revived by moving its deadline.
  function check_CancelDigestBindsValidUntil(
    RequestMembers memory _m,
    bytes32 _separator,
    uint256 _place,
    uint48 _other
  ) external view {
    if (_other == _m.validUntil) return;
    bytes32 _base = _harness.cancelDigest(_separator, _cancel(_m), _place);
    _m.validUntil = _other;
    assert(_harness.cancelDigest(_separator, _cancel(_m), _place) != _base);
  }

  /// Two cancellations that differ only in the place give different digests, so a cancel
  /// signed for one credential in the rule never fills another credential's place.
  function check_CancelDigestBindsPlace(RequestMembers calldata _m, bytes32 _separator, uint256 _place, uint256 _other)
    external
    view
  {
    if (_other == _place) return;
    IPolicyManager.CancelRequest memory _request = _cancel(_m);
    assert(_harness.cancelDigest(_separator, _request, _other) != _harness.cancelDigest(_separator, _request, _place));
  }

  /// Two cancellations that differ only in the separator give different digests, so a cancel
  /// signed for one chain or one manager deployment never counts on another.
  function check_CancelDigestBindsSeparator(
    RequestMembers calldata _m,
    bytes32 _separator,
    uint256 _place,
    bytes32 _other
  ) external view {
    if (_other == _separator) return;
    IPolicyManager.CancelRequest memory _request = _cancel(_m);
    assert(_harness.cancelDigest(_other, _request, _place) != _harness.cancelDigest(_separator, _request, _place));
  }

  /*///////////////////////////////////////////////////////////////
                     PROOFS NEVER ENTER A DIGEST
  ///////////////////////////////////////////////////////////////*/

  /// Two approvals equal in every member but their proofs give the same digest. One carries
  /// a single proof entry with a symbolic place, method, salt and 32 byte config and proof
  /// bytes, the other carries none. A proof signs the digest, so the digest must be
  /// computable before any proof exists and cannot depend on the proofs.
  function check_ApprovalDigestIgnoresProofs(
    RequestMembers calldata _m,
    bytes32 _separator,
    uint256 _place,
    ProofWords calldata _proof
  ) external view {
    IPolicyManager.AttemptRequest memory _request = _approval(_m);
    bytes32 _base = _harness.approvalDigest(_separator, _request, _place);
    _request.proofs = _oneProof(_proof);
    assert(_harness.approvalDigest(_separator, _request, _place) == _base);
  }

  /// Two cancellations equal in every member but their proofs give the same digest. One
  /// carries a single proof entry with a symbolic place, method, salt and 32 byte config and
  /// proof bytes, the other carries none. A cancel's proofs sign its digest, so the digest
  /// cannot depend on them.
  function check_CancelDigestIgnoresProofs(
    RequestMembers calldata _m,
    bytes32 _separator,
    uint256 _place,
    ProofWords calldata _proof
  ) external view {
    IPolicyManager.CancelRequest memory _request = _cancel(_m);
    bytes32 _base = _harness.cancelDigest(_separator, _request, _place);
    _request.proofs = _oneProof(_proof);
    assert(_harness.cancelDigest(_separator, _request, _place) == _base);
  }

  /*///////////////////////////////////////////////////////////////
                          DOMAIN SEPARATOR
  ///////////////////////////////////////////////////////////////*/

  /// Two separators computed on two different chains for the same manager differ, so an approval gathered on one
  /// chain is never replayed on another chain where the same manager address exists. The library reads the chain id
  /// of the chain running the call, so the check moves the chain with `vm.chainId` to each symbolic chain id.
  function check_DomainSeparatorBindsChainId(uint256 _chainId, uint256 _other, address _manager) external {
    if (_other == _chainId) return;
    vm.chainId(_chainId);
    bytes32 _first = _harness.domainSeparator(_manager);
    vm.chainId(_other);
    assert(_harness.domainSeparator(_manager) != _first);
  }

  /// Two separators computed on the same symbolic chain for two different manager addresses differ, so an approval
  /// gathered for one manager deployment is never replayed against another.
  function check_DomainSeparatorBindsManager(uint256 _chainId, address _manager, address _other) external {
    if (_other == _manager) return;
    vm.chainId(_chainId);
    assert(_harness.domainSeparator(_manager) != _harness.domainSeparator(_other));
  }

  /*///////////////////////////////////////////////////////////////
                          SETUP COMMITMENT
  ///////////////////////////////////////////////////////////////*/

  /// Two setup commitments that differ only in the account differ, for a 32 byte body. The
  /// commitment is the only record of the holder's rule, so a rule committed for one account
  /// never verifies for another.
  function check_SetupCommitmentBindsAccount(
    address _account,
    address _action,
    uint64 _nonce,
    bytes32 _body,
    address _other
  ) external view {
    if (_other == _account) return;
    bytes memory _b = abi.encodePacked(_body);
    assert(
      _harness.setupCommitment(_account, _action, _nonce, _b) != _harness.setupCommitment(_other, _action, _nonce, _b)
    );
  }

  /// Two setup commitments that differ only in the action differ, for a 32 byte body, so a
  /// rule committed under one action never authorizes another action.
  function check_SetupCommitmentBindsAction(
    address _account,
    address _action,
    uint64 _nonce,
    bytes32 _body,
    address _other
  ) external view {
    if (_other == _action) return;
    bytes memory _b = abi.encodePacked(_body);
    assert(
      _harness.setupCommitment(_account, _action, _nonce, _b) != _harness.setupCommitment(_account, _other, _nonce, _b)
    );
  }

  /// Two setup commitments that differ only in the nonce differ, for a 32 byte body, so a
  /// rule the holder replaced never verifies again under the new nonce.
  function check_SetupCommitmentBindsNonce(
    address _account,
    address _action,
    uint64 _nonce,
    bytes32 _body,
    uint64 _other
  ) external view {
    if (_other == _nonce) return;
    bytes memory _b = abi.encodePacked(_body);
    assert(
      _harness.setupCommitment(_account, _action, _nonce, _b) != _harness.setupCommitment(_account, _action, _other, _b)
    );
  }

  /// Two setup commitments that differ only in their 32 byte bodies differ, so a request can
  /// never write out a rule other than the one committed.
  function check_SetupCommitmentBindsBody(
    address _account,
    address _action,
    uint64 _nonce,
    bytes32 _body,
    bytes32 _other
  ) external view {
    if (_other == _body) return;
    assert(
      _harness.setupCommitment(_account, _action, _nonce, abi.encodePacked(_body))
        != _harness.setupCommitment(_account, _action, _nonce, abi.encodePacked(_other))
    );
  }

  /// Two setup commitments whose bodies differ in length, 32 bytes against 64 bytes that
  /// start with the same word, differ, so a committed rule cannot be extended with more
  /// bytes after the fact.
  function check_SetupCommitmentBindsBodyLength(
    address _account,
    address _action,
    uint64 _nonce,
    bytes32 _body,
    bytes32 _tail
  ) external view {
    assert(
      _harness.setupCommitment(_account, _action, _nonce, abi.encodePacked(_body))
        != _harness.setupCommitment(_account, _action, _nonce, abi.encodePacked(_body, _tail))
    );
  }

  /*///////////////////////////////////////////////////////////////
                        CREDENTIAL COMMITMENT
  ///////////////////////////////////////////////////////////////*/

  /// Two credential commitments that differ only in the method differ, for a 32 byte config.
  /// The method is the module that verifies the credential, so a proof routed to another
  /// method never fills a committed place.
  function check_CredentialCommitmentBindsMethod(address _method, bytes32 _config, bytes32 _salt, address _other)
    external
    view
  {
    if (_other == _method) return;
    bytes memory _c = abi.encodePacked(_config);
    assert(_harness.credentialCommitment(_method, _c, _salt) != _harness.credentialCommitment(_other, _c, _salt));
  }

  /// Two credential commitments that differ only in their 32 byte configs differ. The config
  /// names the guardian's key or identity, so a proof from anyone else never fills the place.
  function check_CredentialCommitmentBindsConfig(address _method, bytes32 _config, bytes32 _salt, bytes32 _other)
    external
    view
  {
    if (_other == _config) return;
    assert(
      _harness.credentialCommitment(_method, abi.encodePacked(_config), _salt)
        != _harness.credentialCommitment(_method, abi.encodePacked(_other), _salt)
    );
  }

  /// Two credential commitments whose configs differ in length, 32 bytes against empty,
  /// differ, so an empty config never fills a place committed to a real one.
  function check_CredentialCommitmentBindsConfigLength(address _method, bytes32 _config, bytes32 _salt) external view {
    assert(
      _harness.credentialCommitment(_method, abi.encodePacked(_config), _salt)
        != _harness.credentialCommitment(_method, '', _salt)
    );
  }

  /// Two credential commitments that differ only in the salt differ, for a 32 byte config.
  /// The salt hides the credential inside the stored rule, so a place committed with one salt
  /// only opens with that salt.
  function check_CredentialCommitmentBindsSalt(address _method, bytes32 _config, bytes32 _salt, bytes32 _other)
    external
    view
  {
    if (_other == _salt) return;
    bytes memory _c = abi.encodePacked(_config);
    assert(_harness.credentialCommitment(_method, _c, _salt) != _harness.credentialCommitment(_method, _c, _other));
  }

  /*///////////////////////////////////////////////////////////////
                               HELPERS
  ///////////////////////////////////////////////////////////////*/

  /// @dev The approval carrying the given members, each bytes member 32 bytes long, and no proofs.
  function _approval(RequestMembers memory _m) internal pure returns (IPolicyManager.AttemptRequest memory _request) {
    _request.account = _m.account;
    _request.action = _m.action;
    _request.attemptId = _m.attemptId;
    _request.setupNonce = _m.setupNonce;
    _request.setupBody = abi.encodePacked(_m.setupBody);
    _request.payload = abi.encodePacked(_m.payload);
    _request.order = IPolicyManager.PaymentOrder({token: _m.token, amount: _m.amount, payee: _m.payee});
    _request.validUntil = _m.validUntil;
  }

  /// @dev The cancellation carrying the members it shares with the approval, and no proofs.
  function _cancel(RequestMembers memory _m) internal pure returns (IPolicyManager.CancelRequest memory _request) {
    _request.account = _m.account;
    _request.action = _m.action;
    _request.attemptId = _m.attemptId;
    _request.setupNonce = _m.setupNonce;
    _request.setupBody = abi.encodePacked(_m.setupBody);
    _request.validUntil = _m.validUntil;
  }

  /// @dev A proof list of one entry built from the given words, its config and proof 32 bytes long.
  function _oneProof(ProofWords memory _w) internal pure returns (IPolicyManager.ProofPlace[] memory _proofs) {
    _proofs = new IPolicyManager.ProofPlace[](1);
    _proofs[0] = IPolicyManager.ProofPlace({
      place: _w.place,
      method: _w.method,
      config: abi.encodePacked(_w.config),
      salt: _w.salt,
      proof: abi.encodePacked(_w.proof)
    });
  }
}

/// @notice One proof entry with each bytes member reduced to one 32 byte word.
/// @param place The place the entry fills.
/// @param method The module that verifies the credential.
/// @param config The 32 byte content of the credential's config.
/// @param salt The credential's salt.
/// @param proof The 32 byte content of the method's proof.
struct ProofWords {
  uint256 place;
  address method;
  bytes32 config;
  bytes32 salt;
  bytes32 proof;
}
