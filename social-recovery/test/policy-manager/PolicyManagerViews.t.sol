// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {IERC165} from 'forge-std/interfaces/IERC165.sol';
import {IERC20} from 'forge-std/interfaces/IERC20.sol';
import {IERC721} from 'forge-std/interfaces/IERC721.sol';
import {IPolicyAction} from 'interfaces/IPolicyAction.sol';
import {IPolicyManager} from 'interfaces/IPolicyManager.sol';
import {IPolicyMethod} from 'interfaces/IPolicyMethod.sol';
import {IPolicyMethodAdmin} from 'interfaces/IPolicyMethodAdmin.sol';
import {IPolicyMethodPause} from 'interfaces/IPolicyMethodPause.sol';
import {IRecoveryAction} from 'interfaces/IRecoveryAction.sol';
import {PolicyManager} from 'contracts/manager/PolicyManager.sol';
import {PolicyManagerDigestProbe} from 'test/utils/PolicyManagerDigestProbe.sol';
import {PolicyManagerTestBase} from 'test/utils/PolicyManagerTestBase.sol';

/// @notice The manager's views and introspection. Clients read the state view to build requests and
///         cross-check their own digest bytes against the two digest views, so the views must return
///         exactly what the binding digest library computes under this deployment's live domain.
contract PolicyManagerViewsTest is PolicyManagerTestBase {
  /// @notice The request fields a test fuzzes, bundled to keep the fuzz signatures short.
  struct Fields {
    address account;
    address action;
    uint64 attemptId;
    uint64 setupNonce;
    uint48 validUntil;
    address token;
    uint256 amount;
    address payee;
  }

  /// @notice The manager as deployed, without the harness door.
  PolicyManager internal _plain;
  /// @notice Calls the binding digest library, the shared encoder of the two signed message types,
  ///         with the request in calldata, the way the manager receives it, under the live chain id.
  PolicyManagerDigestProbe internal _probe;

  /// @dev Deploys a plain manager and the digest probe beside the harness the base deploys.
  function setUp() public override {
    super.setUp();
    _plain = new PolicyManager();
    _probe = new PolicyManagerDigestProbe();
  }

  /*///////////////////////////////////////////////////////////////
                             TREE TESTS
  ///////////////////////////////////////////////////////////////*/

  /// @notice A pair nobody wrote reads as no setup, nonce zero, no attempt, and next attempt id one,
  ///         the id the first request must carry. `_anyAccount` and `_anyAction` are any pair.
  function test_WhenNothingWasEverWrittenForThePair(address _anyAccount, address _anyAction) external view {
    // it should return a zero state whose next attempt id is one
    IPolicyManager.ActionState memory _actionState = _manager.stateOf(_anyAccount, _anyAction);
    assertEq(_actionState.setupCommitment, bytes32(0), 'commitment');
    assertEq(_actionState.setupNonce, 0, 'nonce');
    assertEq(_actionState.nextAttemptId, 1, 'nextAttemptId');
    assertEq(_actionState.setupCommittedAtBlock, 0, 'setupCommittedAtBlock');
    IPolicyManager.Attempt memory _empty;
    assertEq(abi.encode(_actionState.attempt), abi.encode(_empty), 'no attempt record');
  }

  /// @notice One read returns the stored commitment, nonce, write block and attempt record, so a
  ///         client needs no second call. `_blockNumber` sets the write's block.
  function test_WhenASetupAndAnAttemptAreStored(uint48 _blockNumber, uint64 _attemptId) external {
    // it should return both from stateOf in one read
    vm.roll(_blockNumber);
    (uint64 _nonce, bytes32 _commitment) = _commit(_account, _action);
    IPolicyManager.Attempt memory _planted = _plantWaiting(_account, _action, _attemptId, true);

    IPolicyManager.ActionState memory _actionState = _manager.stateOf(_account, _action);
    assertEq(_actionState.setupCommitment, _commitment, 'commitment');
    assertEq(_actionState.setupNonce, _nonce, 'nonce');
    assertEq(_actionState.nextAttemptId, 1, 'nextAttemptId: the attempt counter never moves here');
    assertEq(_actionState.setupCommittedAtBlock, _blockNumber, 'setupCommittedAtBlock');
    assertEq(abi.encode(_actionState.attempt), abi.encode(_planted), 'attempt');
  }

  /// @notice The approval view equals the library's approval digest under this deployment's chain id
  ///         and address, for any request fields, body, payload and place, so the view a client
  ///         checks against and the digest a proof must sign cannot disagree.
  function test_WhenAnApprovalRequestIsHashed(
    Fields calldata _fields,
    bytes calldata _setupBody,
    bytes calldata _payload,
    uint256 _place
  ) external view {
    // it should return the digest the binding digest library computes
    IPolicyManager.AttemptRequest memory _request = _approvalRequest(_fields, _setupBody, _payload, 0);
    assertEq(
      _plain.hashApproval(_request, _place),
      _probe.approval(address(_plain), _request, _place),
      'hashApproval equals the library'
    );
  }

  /// @notice The approval digest does not depend on the proofs, since a proof cannot sign itself.
  ///         `_proofCount` attaches 1 to 5 proofs to an otherwise identical request.
  function test_WhenProofsAreAttachedToAnApprovalRequest(Fields calldata _fields, uint8 _proofCount, uint256 _place)
    external
    view
  {
    // it should leave the approval digest unchanged
    IPolicyManager.AttemptRequest memory _bare = _approvalRequest(_fields, 'body', 'payload', 0);
    IPolicyManager.AttemptRequest memory _loaded =
      _approvalRequest(_fields, 'body', 'payload', bound(_proofCount, 1, 5));
    assertEq(_plain.hashApproval(_loaded, _place), _plain.hashApproval(_bare, _place), 'proofs ignored');
  }

  /// @notice The cancellation view equals the library's cancellation digest under this deployment's
  ///         chain id and address, for any request fields, body and place.
  function test_WhenACancelRequestIsHashed(Fields calldata _fields, bytes calldata _setupBody, uint256 _place)
    external
    view
  {
    // it should return the digest the binding digest library computes
    IPolicyManager.CancelRequest memory _request = _cancelRequest(_fields, _setupBody, 0);
    assertEq(
      _plain.hashCancel(_request, _place),
      _probe.cancellation(address(_plain), _request, _place),
      'hashCancel equals the library'
    );
  }

  /// @notice The cancellation digest does not depend on the proofs. `_proofCount` attaches 1 to 5.
  function test_WhenProofsAreAttachedToACancelRequest(Fields calldata _fields, uint8 _proofCount, uint256 _place)
    external
    view
  {
    // it should leave the cancellation digest unchanged
    IPolicyManager.CancelRequest memory _bare = _cancelRequest(_fields, 'body', 0);
    IPolicyManager.CancelRequest memory _loaded = _cancelRequest(_fields, 'body', bound(_proofCount, 1, 5));
    assertEq(_plain.hashCancel(_loaded, _place), _plain.hashCancel(_bare, _place), 'proofs ignored');
  }

  /// @notice After a chain id change both digests and the published domain follow the new id, so a
  ///         proof signed for one side of a chain split never verifies on the other.
  ///         `_chainIdSeed` builds a chain id greater than the current one.
  function test_WhenTheChainIdChanges(uint64 _chainIdSeed, Fields calldata _fields, uint256 _place) external {
    uint256 _chainId = bound(_chainIdSeed, block.chainid + 1, type(uint64).max);
    IPolicyManager.AttemptRequest memory _approval = _approvalRequest(_fields, 'body', 'payload', 1);
    IPolicyManager.CancelRequest memory _cancellation = _cancelRequest(_fields, 'body', 1);
    bytes32 _approvalBefore = _plain.hashApproval(_approval, _place);
    bytes32 _cancelBefore = _plain.hashCancel(_cancellation, _place);

    vm.chainId(_chainId);

    // it should compute both digests under the new chain id
    assertEq(_plain.hashApproval(_approval, _place), _probe.approval(address(_plain), _approval, _place), 'approval');
    assertEq(
      _plain.hashCancel(_cancellation, _place),
      _probe.cancellation(address(_plain), _cancellation, _place),
      'cancellation'
    );
    assertTrue(_plain.hashApproval(_approval, _place) != _approvalBefore, 'approval digest moved with the chain');
    assertTrue(_plain.hashCancel(_cancellation, _place) != _cancelBefore, 'cancel digest moved with the chain');
    // it should report the new chain id from eip712Domain
    (,,, uint256 _reported, address _verifyingContract,,) = _plain.eip712Domain();
    assertEq(_reported, _chainId, 'eip712Domain chainId');
    assertEq(_verifyingContract, address(_plain), 'verifyingContract');
  }

  /// @notice The ERC-5267 domain lists name, version, chain id and this address, with no salt and
  ///         no extensions, and hashes to the separator the digests use, so the SDK can rebuild them.
  function test_WhenTheDomainIsRead() external view {
    // it should return the ERC-5267 domain with the four fields in use
    (
      bytes1 _domainFields,
      string memory _name,
      string memory _version,
      uint256 _chainId,
      address _verifyingContract,
      bytes32 _salt,
      uint256[] memory _extensions
    ) = _plain.eip712Domain();
    assertEq(_domainFields, bytes1(0x0f), 'fields: name, version, chain id, verifying contract');
    assertEq(_name, _probe.domainName(), 'name from the binding digest library');
    assertEq(_name, 'PolicyManager', 'name');
    assertEq(_version, _probe.digestVersion(), 'version from the binding digest library');
    assertEq(_version, '1', 'DIGEST_VERSION');
    assertEq(_chainId, block.chainid, 'chainId');
    assertEq(_verifyingContract, address(_plain), 'verifyingContract');
    assertEq(_salt, bytes32(0), 'salt unused');
    assertEq(_extensions.length, 0, 'extensions unused');
    // The domain the view publishes is the one the digests are computed under.
    bytes32 _separator = keccak256(
      abi.encode(
        keccak256('EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)'),
        keccak256(bytes(_name)),
        keccak256(bytes(_version)),
        _chainId,
        _verifyingContract
      )
    );
    assertEq(_separator, _probe.separator(address(_plain)), 'published domain hashes to the separator');
  }

  /// @notice The manager answers ERC-165 for its own interface and for ERC-165 itself, so wallets can
  ///         identify it.
  function test_WhenAskedForTheIPolicyManagerOrTheERC165InterfaceId() external view {
    // it should answer true
    assertTrue(_plain.supportsInterface(type(IPolicyManager).interfaceId), 'IPolicyManager');
    assertTrue(_plain.supportsInterface(type(IERC165).interfaceId), 'ERC-165');
  }

  /// @notice The manager denies the ids of the kit's other interfaces and of common token standards,
  ///         so a wallet probing it never mistakes it for a method, an action or a token. It also
  ///         denies 0xffffffff, the id ERC-165 requires every contract to deny.
  function test_WhenAskedForTheIdOfAnotherKnownInterface() external view {
    // it should answer false
    assertFalse(_plain.supportsInterface(type(IPolicyMethod).interfaceId), 'IPolicyMethod');
    assertFalse(_plain.supportsInterface(type(IPolicyMethodAdmin).interfaceId), 'IPolicyMethodAdmin');
    assertFalse(_plain.supportsInterface(type(IPolicyMethodPause).interfaceId), 'IPolicyMethodPause');
    assertFalse(_plain.supportsInterface(type(IPolicyAction).interfaceId), 'IPolicyAction');
    assertFalse(_plain.supportsInterface(type(IRecoveryAction).interfaceId), 'IRecoveryAction');
    assertFalse(_plain.supportsInterface(type(IERC20).interfaceId), 'ERC-20');
    assertFalse(_plain.supportsInterface(type(IERC721).interfaceId), 'ERC-721');
    assertFalse(_plain.supportsInterface(bytes4(0)), 'zero id');
    assertFalse(_plain.supportsInterface(bytes4(0xffffffff)), '0xffffffff');
  }

  /// @notice The manager denies every interface id but its own two, so it never claims an interface
  ///         it does not implement. `_seed` is any id; where it happens to be one of the two supported
  ///         ids, flipping its lowest bits turns it into an id next to it that is neither, which keeps
  ///         every run on the refusing path.
  function test_WhenAskedForAnyOtherInterfaceId(bytes4 _seed) external view {
    // it should answer false
    bytes4 _id = _unsupportedId(_seed);
    assertFalse(_plain.supportsInterface(_id), 'an unsupported id');
  }

  /// @notice The deployment has a human-readable name and a version for wallets to show.
  function test_WhenTheNameAndVersionAreRead() external view {
    // it should return a nonempty name and version
    assertGt(bytes(_plain.name()).length, 0, 'name');
    assertGt(bytes(_plain.version()).length, 0, 'version');
  }

  /*///////////////////////////////////////////////////////////////
                              BUILDERS
  ///////////////////////////////////////////////////////////////*/

  /// @notice `_seed` when it is neither IPolicyManager's id nor ERC-165's, and otherwise `_seed` with
  ///         its lowest bit, then if needed its two lowest bits, flipped. Two supported ids cannot fill
  ///         all three of seed, seed ^ 1 and seed ^ 3, so the result is always unsupported.
  function _unsupportedId(bytes4 _seed) private pure returns (bytes4 _id) {
    _id = _seed;
    if (_isSupportedId(_id)) _id = _seed ^ bytes4(uint32(1));
    if (_isSupportedId(_id)) _id = _seed ^ bytes4(uint32(3));
  }

  /// @notice Whether `_id` is one of the two ids the manager answers true for.
  function _isSupportedId(bytes4 _id) private pure returns (bool _supported) {
    _supported = _id == type(IPolicyManager).interfaceId || _id == type(IERC165).interfaceId;
  }

  /// @notice An approval request with the given fields and `_proofCount` placeholder proofs.
  function _approvalRequest(
    Fields calldata _fields,
    bytes memory _setupBody,
    bytes memory _payload,
    uint256 _proofCount
  ) private pure returns (IPolicyManager.AttemptRequest memory _request) {
    _request = IPolicyManager.AttemptRequest({
      account: _fields.account,
      action: _fields.action,
      attemptId: _fields.attemptId,
      setupNonce: _fields.setupNonce,
      setupBody: _setupBody,
      payload: _payload,
      order: IPolicyManager.PaymentOrder({token: _fields.token, amount: _fields.amount, payee: _fields.payee}),
      validUntil: _fields.validUntil,
      proofs: _proofs(_proofCount)
    });
  }

  /// @notice A cancellation request with the given fields and `_proofCount` placeholder proofs.
  function _cancelRequest(Fields calldata _fields, bytes memory _setupBody, uint256 _proofCount)
    private
    pure
    returns (IPolicyManager.CancelRequest memory _request)
  {
    _request = IPolicyManager.CancelRequest({
      account: _fields.account,
      action: _fields.action,
      attemptId: _fields.attemptId,
      setupNonce: _fields.setupNonce,
      setupBody: _setupBody,
      validUntil: _fields.validUntil,
      proofs: _proofs(_proofCount)
    });
  }

  /// @notice `_count` placeholder proofs at places 0 upward, with distinct methods, configs and salts.
  function _proofs(uint256 _count) private pure returns (IPolicyManager.ProofPlace[] memory _proofList) {
    _proofList = new IPolicyManager.ProofPlace[](_count);
    for (uint256 _i; _i < _count; ++_i) {
      _proofList[_i] = IPolicyManager.ProofPlace({
        place: _i,
        // casting to 'uint160' is safe because count stays below ten
        // forge-lint: disable-next-line(unsafe-typecast)
        method: address(uint160(0xBEEF + _i)),
        config: abi.encode(_i),
        salt: keccak256(abi.encode('salt', _i)),
        proof: abi.encodePacked('proof', _i)
      });
    }
  }
}
