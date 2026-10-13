// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {Vm, VmSafe} from 'forge-std/Vm.sol';
import {SetupBody} from 'libraries/SetupBody.sol';
import {IPolicyManager} from 'interfaces/IPolicyManager.sol';
import {IPolicyMethod} from 'interfaces/IPolicyMethod.sol';
import {IPolicyMethodPause} from 'interfaces/IPolicyMethodPause.sol';
import {AadhaarMethod} from 'contracts/methods/aadhaar/AadhaarMethod.sol';
import {ZkPassportMethod} from 'contracts/methods/zkpassport/ZkPassportMethod.sol';
import {MethodAadhaarVerifierMock} from 'test/mocks/MethodAadhaarVerifierMock.sol';
import {
  MethodZkPassportProofVerificationData,
  MethodZkPassportProofVerificationParams,
  MethodZkPassportRootVerifierMock,
  MethodZkPassportServiceConfig,
  MethodZkPassportVerifierHelperMock
} from 'test/mocks/MethodZkPassportMocks.sol';
import {IntegrationDemoKitTestBase} from 'test/utils/IntegrationDemoKitTestBase.sol';

/// @notice The demo kit with the identity pair beside it, for the end-to-end walks over the identity methods.
///         The policy manager, the wallet and passkey methods, the recovery action and the account are the demo
///         kit's. The zkPassport method and the Aadhaar method are the real contracts, built with the identity
///         deployment script's constructor arguments: one Safe as both pause holder and key admin, the eight
///         zkPassport words and the one Aadhaar issuer key with its verifier.
/// @dev The identity methods' outside verifiers are deterministic project-owned mocks: zkPassport's root verifier
///      and verifier helper, and Anon Aadhaar's Groth16 verifier. Each mock accepts exactly the proof it was last
///      told about, so a guardian's device "produces" a proof by building its bytes and telling the mock to accept
///      exactly them. The method's own checks still run in full on every proof.
///      The holder's identity rule has two clauses and six places. Clause zero needs two of the three wallet
///      friends (places 0, 1 and 2). Clause one needs one of three: the passkey on the holder's phone (place 3), a
///      zkPassport credential (place 4) or an Aadhaar credential (place 5).
// The walks share one deployed kit with two more methods and their outside verifiers, past the default limit.
// solhint-disable-next-line max-states-count
abstract contract IntegrationIdentityKitTestBase is IntegrationDemoKitTestBase {
  /// @notice The place of the zkPassport credential.
  uint256 internal constant _ZKPASSPORT = 4;
  /// @notice The place of the Aadhaar credential.
  uint256 internal constant _AADHAAR = 5;
  /// @notice zkPassport 0.21.0 as a version word: major, minor and patch as three big-endian uint16 values,
  ///         followed by zero bytes. It is the version the deployment accepts.
  bytes32 internal constant _ZK_VERSION_0_21_0 = 0x0000001500000000000000000000000000000000000000000000000000000000;
  /// @notice The Aadhaar issuer's public-key hash the deployment stores on Sepolia.
  bytes32 internal constant _AADHAAR_KEY = bytes32(
    uint256(19_770_349_258_225_098_911_243_612_275_321_727_303_641_256_718_510_179_842_211_794_623_059_325_011_884)
  );
  /// @notice The identifier the zkPassport guardian's document derives under the holder's domain and scope.
  bytes32 internal constant _ZK_IDENTIFIER = bytes32(uint256(0x1d3471f13));
  /// @notice The zkPassport service's domain.
  string internal constant _ZK_DOMAIN = 'recover.example';
  /// @notice The zkPassport service's scope.
  string internal constant _ZK_SCOPE = 'social-recovery';
  /// @notice How long a zkPassport proof's document check stays valid, in seconds.
  uint256 internal constant _ZK_VALIDITY = 7 days;
  /// @notice The Aadhaar guardian's nullifier.
  uint256 internal constant _AADHAAR_NULLIFIER = 0x0a11ad;
  /// @notice The Aadhaar guardian's nullifier seed.
  uint256 internal constant _AADHAAR_SEED = 0x5eed;
  /// @notice The Aadhaar guardian's freshness window, the 75 minutes the SDK proposes: the most seconds the QR's
  ///         signing time may lie before the block that verifies the proof.
  uint256 internal constant _AADHAAR_WINDOW = 75 minutes;
  /// @notice How many public inputs a zkPassport proof carries in these walks. The nullifier type sits third from
  ///         the end.
  uint256 internal constant _ZK_PUBLIC_INPUTS = 8;

  /// @notice The Safe that holds both roles of both identity methods.
  address internal _identitySafe;
  /// @notice The zkPassport method.
  ZkPassportMethod internal _zkPassport;
  /// @notice The Aadhaar method.
  AadhaarMethod internal _aadhaar;
  /// @notice The mock of zkPassport's root verifier the zkPassport method routes through.
  MethodZkPassportRootVerifierMock internal _zkRoot;
  /// @notice The mock of zkPassport's verifier helper, stored in the zkPassport method's trusted keys.
  MethodZkPassportVerifierHelperMock internal _zkVerifierHelper;
  /// @notice The mock of Anon Aadhaar's Groth16 verifier the Aadhaar method calls.
  MethodAadhaarVerifierMock internal _aadhaarVerifier;

  function setUp() public virtual override {
    super.setUp();
    _identitySafe = makeAddr('identitySafe');
    _zkRoot = new MethodZkPassportRootVerifierMock();
    _zkVerifierHelper = new MethodZkPassportVerifierHelperMock();
    _aadhaarVerifier = new MethodAadhaarVerifierMock();
    _zkPassport =
      new ZkPassportMethod(_identitySafe, _identitySafe, _zkWords(address(_zkRoot), address(_zkVerifierHelper)));
    _aadhaar = new AadhaarMethod(_identitySafe, _identitySafe, _oneWord(_AADHAAR_KEY), address(_aadhaarVerifier));

    // The signal function the guardian's device uses must turn the frozen vector's digest into the vector's signal.
    string memory _vector = vm.readFile('test/fixtures/kats/method-aadhaar-proof.json');
    bytes32 _frozenDigest = vm.parseJsonBytes32(_vector, '.vectors[0].input.digest');
    uint256 _frozenSignal = vm.parseUint(vm.parseJsonString(_vector, '.vectors[0].expected.signalHash'));
    assertEq(_aadhaarSignal(_frozenDigest), _frozenSignal, 'fixture: the signal function disagrees with the vector');
  }

  /*///////////////////////////////////////////////////////////////
                          THE ROLES' OWN CALLS
  ///////////////////////////////////////////////////////////////*/

  /// @notice The eight zkPassport trusted-key words in the method's order: the accepted version, the root verifier,
  ///         the reviewed sub-verifier, the verifier helper, the root registry, the root admin, the root guardian
  ///         and the sub-verifier admin, each address left-padded to one word.
  function _zkWords(address _root, address _verifierHelper) internal returns (bytes32[] memory _words) {
    _words = new bytes32[](8);
    _words[0] = _ZK_VERSION_0_21_0;
    _words[1] = _word(_root);
    _words[2] = _word(makeAddr('zkSubVerifier'));
    _words[3] = _word(_verifierHelper);
    _words[4] = _word(makeAddr('zkRootRegistry'));
    _words[5] = _word(makeAddr('zkRootAdmin'));
    _words[6] = _word(makeAddr('zkRootGuardian'));
    _words[7] = _word(makeAddr('zkSubVerifierAdmin'));
  }

  /// @notice An address left-padded to one word.
  function _word(address _addr) internal pure returns (bytes32 _padded) {
    _padded = bytes32(uint256(uint160(_addr)));
  }

  /// @notice A list of one word.
  function _oneWord(bytes32 _value) internal pure returns (bytes32[] memory _list) {
    _list = new bytes32[](1);
    _list[0] = _value;
  }

  /// @notice The Safe stops `_method` through the method's own pause call.
  function _stopMethod(address _method) internal {
    vm.prank(_identitySafe);
    IPolicyMethodPause(_method).pause();
  }

  /// @notice The Safe unpauses `_method` through the method's own unpause call, so the method no longer answers
  ///         that it is stopped.
  function _unpauseMethod(address _method) internal {
    vm.prank(_identitySafe);
    IPolicyMethodPause(_method).unpause();
  }

  /// @notice The identity method that judges the credential at `_place`.
  function _identityMethodAt(uint256 _place) internal view returns (address _method) {
    _method = _place == _ZKPASSPORT ? address(_zkPassport) : address(_aadhaar);
  }

  /*///////////////////////////////////////////////////////////////
                          THE HOLDER'S RULE
  ///////////////////////////////////////////////////////////////*/

  /// @notice The method, config and salt committed at a place of the identity rule. Places 0 to 3 are the demo
  ///         rule's friends and phone. The zkPassport config is abi.encode(identifier, domain, scope, validity) and
  ///         the Aadhaar config abi.encode(nullifier, seed, freshness window).
  function _idCredential(uint256 _place) internal view returns (address _method, bytes memory _config, bytes32 _salt) {
    if (_place < _ZKPASSPORT) return _credential(_place);
    _salt = keccak256(abi.encode('salt', _place));
    _method = _identityMethodAt(_place);
    _config = _place == _ZKPASSPORT
      ? abi.encode(_ZK_IDENTIFIER, _ZK_DOMAIN, _ZK_SCOPE, _ZK_VALIDITY)
      : abi.encode(_AADHAAR_NULLIFIER, _AADHAAR_SEED, _AADHAAR_WINDOW);
  }

  /// @notice A credential hash of the identity rule: keccak256(abi.encode(method, config, salt)).
  function _idCredentialHash(uint256 _place) internal view returns (bytes32 _hash) {
    (address _method, bytes memory _config, bytes32 _salt) = _idCredential(_place);
    _hash = keccak256(abi.encode(_method, _config, _salt));
  }

  /// @notice The identity rule with the demo wait and the given pause choice: two of the three friends, and one
  ///         of the phone, the zkPassport credential and the Aadhaar credential.
  function _idRule(bool _ignoresPause) internal view returns (bytes memory _setupBody) {
    IPolicyManager.Clause[] memory _clauses = new IPolicyManager.Clause[](2);
    _clauses[0].threshold = 2;
    _clauses[0].credentials = new bytes32[](3);
    _clauses[0].credentials[0] = _idCredentialHash(_ALICE);
    _clauses[0].credentials[1] = _idCredentialHash(_BOB);
    _clauses[0].credentials[2] = _idCredentialHash(_CAROL);
    _clauses[1].threshold = 1;
    _clauses[1].credentials = new bytes32[](3);
    _clauses[1].credentials[0] = _idCredentialHash(_PHONE);
    _clauses[1].credentials[1] = _idCredentialHash(_ZKPASSPORT);
    _clauses[1].credentials[2] = _idCredentialHash(_AADHAAR);
    _setupBody = SetupBody.encode(_WAIT, _ignoresPause, _clauses);
  }

  /// @notice Sets up recovery in one batch under the holder's key: the action authorized under the kit slot, then
  ///         `_setupBody` committed at nonce one.
  function _authorizeAndCommitBody(bytes memory _setupBody) internal {
    _asHolder(_two(_authorizeCall(), _commitCall(1, _commitmentOf(1, _setupBody))));
  }

  /*///////////////////////////////////////////////////////////////
                      THE GUARDIANS' DEVICES
  ///////////////////////////////////////////////////////////////*/

  /// @notice The proof the credential at `_place` gives for `_digest`. Friends and the phone sign as in the demo
  ///         kit, and each identity guardian's device produces a proof that carries the digest as its own outside
  ///         signal.
  function _idProve(uint256 _place, bytes32 _digest) internal returns (bytes memory _proof) {
    if (_place < _ZKPASSPORT) return _prove(_place, _digest);
    _proof = _place == _ZKPASSPORT ? _zkProve(_digest) : _aadhaarProve(_AADHAAR_KEY, _digest);
  }

  /// @notice The zkPassport proof data `_prover` produces for `_digest`: a non-salted nullifier, that is a zero third
  ///         public input from the end, and proof bytes that differ per prover.
  function _zkProofData(bytes32 _digest, string memory _prover)
    internal
    pure
    returns (MethodZkPassportProofVerificationData memory _data)
  {
    bytes32[] memory _inputs = new bytes32[](_ZK_PUBLIC_INPUTS);
    for (uint256 _i; _i < _ZK_PUBLIC_INPUTS; ++_i) {
      _inputs[_i] = keccak256(abi.encode('public input', _i, _digest));
    }
    _inputs[_ZK_PUBLIC_INPUTS - 3] = bytes32(0);
    _data = MethodZkPassportProofVerificationData({
      vkeyHash: keccak256('zkpassport 0.21.0 outer circuit'), proof: abi.encode(_prover, _digest), publicInputs: _inputs
    });
  }

  /// @notice The committed inputs of the guardian's zkPassport proof for `_digest`. The verifier helper reads the
  ///         bound custom data out of them.
  function _zkCommittedInputs(bytes32 _digest) internal pure returns (bytes memory _committed) {
    _committed = abi.encode('committed inputs', _digest);
  }

  /// @notice The parameters the zkPassport method must hand the root verifier for `_prover`'s proof over `_digest`:
  ///         the accepted 0.21.0 version, the proof data, the committed inputs and the holder's service configuration
  ///         with development proofs refused.
  function _zkParams(bytes32 _digest, string memory _prover)
    internal
    pure
    returns (MethodZkPassportProofVerificationParams memory _params)
  {
    _params = MethodZkPassportProofVerificationParams({
      version: _ZK_VERSION_0_21_0,
      proofVerificationData: _zkProofData(_digest, _prover),
      committedInputs: _zkCommittedInputs(_digest),
      serviceConfig: MethodZkPassportServiceConfig({
        validityPeriodInSeconds: _ZK_VALIDITY, domain: _ZK_DOMAIN, scope: _ZK_SCOPE, devMode: false
      })
    });
  }

  /// @notice `_prover` proves `_digest` through the root verifier `_root` and the verifier helper `_verifierHelper`.
  ///         The proof binds the digest as its custom data, rendered as 0x and sixty four lowercase hexadecimal
  ///         characters, which is forge's own rendering of a bytes32. For exactly these parameters the root verifier
  ///         answers valid, with the guardian's identifier and the address of `_verifierHelper`.
  function _zkProveThrough(
    MethodZkPassportRootVerifierMock _root,
    MethodZkPassportVerifierHelperMock _verifierHelper,
    bytes32 _digest,
    string memory _prover
  ) internal returns (bytes memory _proof) {
    MethodZkPassportProofVerificationParams memory _params = _zkParams(_digest, _prover);
    _root.setAnswer(keccak256(abi.encode(_params)), true, _ZK_IDENTIFIER, address(_verifierHelper));
    _verifierHelper.setAnswer(keccak256(_params.committedInputs), vm.toString(_digest));
    _proof = abi.encode(_params.proofVerificationData, _params.committedInputs);
  }

  /// @notice The zkPassport guardian's device proves `_digest` through the deployment's root verifier and verifier
  ///         helper.
  function _zkProve(bytes32 _digest) internal returns (bytes memory _proof) {
    _proof = _zkProveThrough(_zkRoot, _zkVerifierHelper, _digest, 'guardian');
  }

  /// @notice The Aadhaar signal for `_digest`: keccak256 of the digest as one word, shifted right by three bits.
  ///         setUp checks it against the frozen Aadhaar proof vector.
  function _aadhaarSignal(bytes32 _digest) internal pure returns (uint256 _signal) {
    _signal = uint256(keccak256(abi.encodePacked(uint256(_digest)))) >> 3;
  }

  /// @notice The nine public inputs of an Aadhaar proof under the issuer key `_key` for the guardian over
  ///         `_digest`: input zero the key, one the nullifier, two the QR's signing time, seven the seed and eight the
  ///         signal. The QR is signed in the current block, as when the guardian downloads a fresh QR to prove, so
  ///         the proof is fresh when it is submitted in that block. Inputs three to six are disclosures the method
  ///         does not read.
  function _aadhaarInputs(bytes32 _key, bytes32 _digest) internal view returns (uint256[9] memory _inputs) {
    _inputs[0] = uint256(_key);
    _inputs[1] = _AADHAAR_NULLIFIER;
    _inputs[2] = block.timestamp;
    _inputs[3] = 1;
    _inputs[4] = 1;
    _inputs[5] = 1;
    _inputs[6] = 1;
    _inputs[7] = _AADHAAR_SEED;
    _inputs[8] = _aadhaarSignal(_digest);
  }

  /// @notice An Aadhaar proof under the issuer key `_key` over `_digest`, which the Groth16 verifier mock is told
  ///         to accept as a valid proof. The proof bytes are abi.encode(a, b, c, inputs), with points derived from
  ///         the digest so each proof differs.
  function _aadhaarProve(bytes32 _key, bytes32 _digest) internal returns (bytes memory _proof) {
    uint256 _seed = uint256(keccak256(abi.encode('points', _key, _digest))) >> 8;
    uint256[2] memory _a = [_seed, _seed + 1];
    uint256[2][2] memory _b = [[_seed + 2, _seed + 3], [_seed + 4, _seed + 5]];
    uint256[2] memory _c = [_seed + 6, _seed + 7];
    uint256[9] memory _inputs = _aadhaarInputs(_key, _digest);
    _aadhaarVerifier.expectExact(_a, _b, _c, _inputs);
    _proof = abi.encode(_a, _b, _c, _inputs);
  }

  /*///////////////////////////////////////////////////////////////
                              REQUESTS
  ///////////////////////////////////////////////////////////////*/

  /// @notice The places of `_placeList` in the identity rule, each holding its committed credential and no proof.
  function _idUnsignedPlaces(uint256[] memory _placeList)
    internal
    view
    returns (IPolicyManager.ProofPlace[] memory _proofs)
  {
    _proofs = new IPolicyManager.ProofPlace[](_placeList.length);
    for (uint256 _i; _i < _placeList.length; ++_i) {
      (address _method, bytes memory _config, bytes32 _salt) = _idCredential(_placeList[_i]);
      _proofs[_i] =
        IPolicyManager.ProofPlace({place: _placeList[_i], method: _method, config: _config, salt: _salt, proof: ''});
    }
  }

  /// @notice An opening request over `_setupBody` for the next attempt under the stored nonce, with the demo
  ///         payload, order and window. Each guardian's device proves the approval digest of its own place.
  function _idRequest(bytes memory _setupBody, uint256[] memory _placeList)
    internal
    returns (IPolicyManager.AttemptRequest memory _req)
  {
    IPolicyManager.ActionState memory _now = _state();
    _req = IPolicyManager.AttemptRequest({
      account: _account,
      action: address(_action),
      attemptId: _now.nextAttemptId,
      setupNonce: _now.setupNonce,
      setupBody: _setupBody,
      payload: _payload(),
      order: _order(),
      validUntil: _window(),
      proofs: _idUnsignedPlaces(_placeList)
    });
    for (uint256 _i; _i < _placeList.length; ++_i) {
      _req.proofs[_i].proof = _idProve(_placeList[_i], _manager.hashApproval(_req, _placeList[_i]));
    }
  }

  /// @notice A cancellation of the live attempt over `_setupBody`, each place proving its cancellation digest.
  function _idCancelRequest(bytes memory _setupBody, uint256[] memory _placeList)
    internal
    returns (IPolicyManager.CancelRequest memory _req)
  {
    IPolicyManager.ActionState memory _now = _state();
    _req = IPolicyManager.CancelRequest({
      account: _account,
      action: address(_action),
      attemptId: _now.attempt.attemptId,
      setupNonce: _now.setupNonce,
      setupBody: _setupBody,
      validUntil: _window(),
      proofs: _idUnsignedPlaces(_placeList)
    });
    for (uint256 _i; _i < _placeList.length; ++_i) {
      _req.proofs[_i].proof = _idProve(_placeList[_i], _manager.hashCancel(_req, _placeList[_i]));
    }
  }

  /// @notice Alice, Bob and the identity credential at `_place`.
  function _friendsAnd(uint256 _place) internal pure returns (uint256[] memory _list) {
    _list = _places(_ALICE, _BOB, _place);
  }

  /*///////////////////////////////////////////////////////////////
                          WHAT A CALL TOUCHED
  ///////////////////////////////////////////////////////////////*/

  /// @notice How many pause reads `_accesses` holds, that is calls to any address whose calldata is exactly the
  ///         selector of paused().
  function _pauseReads(Vm.AccountAccess[] memory _accesses) internal pure returns (uint256 _count) {
    for (uint256 _i; _i < _accesses.length; ++_i) {
      if (_isPauseRead(_accesses[_i])) ++_count;
    }
  }

  /// @notice Whether one access is a pause read: a call whose calldata is exactly the selector of paused().
  function _isPauseRead(Vm.AccountAccess memory _access) internal pure returns (bool _read) {
    _read = _isCall(_access) && keccak256(_access.data) == keccak256(abi.encodeCall(IPolicyMethodPause.paused, ()));
  }

  /// @notice Whether one access is a verify call: a call whose calldata starts with the selector of verify.
  function _isVerify(Vm.AccountAccess memory _access) internal pure returns (bool _verify) {
    _verify = _isCall(_access) && _access.data.length > 3 && bytes4(_access.data) == IPolicyMethod.verify.selector;
  }

  /// @notice Whether one access is a message call, plain or static.
  function _isCall(Vm.AccountAccess memory _access) internal pure returns (bool _call) {
    _call = _access.kind == VmSafe.AccountAccessKind.Call || _access.kind == VmSafe.AccountAccessKind.StaticCall;
  }

  /// @notice The calls to `_method` in `_accesses`, in the order they ran, each written as 1 for a pause read, 2 for
  ///         a verify call and 3 for anything else.
  function _callsTo(Vm.AccountAccess[] memory _accesses, address _method)
    internal
    pure
    returns (uint256[] memory _kinds)
  {
    uint256 _count;
    for (uint256 _i; _i < _accesses.length; ++_i) {
      if (_accesses[_i].account == _method && _isCall(_accesses[_i])) ++_count;
    }
    _kinds = new uint256[](_count);
    uint256 _at;
    for (uint256 _i; _i < _accesses.length; ++_i) {
      if (_accesses[_i].account != _method || !_isCall(_accesses[_i])) continue;
      _kinds[_at++] = _isPauseRead(_accesses[_i]) ? 1 : _isVerify(_accesses[_i]) ? 2 : 3;
    }
  }

  /// @notice Whether any access in `_accesses` reached `_target` with a call.
  function _reached(Vm.AccountAccess[] memory _accesses, address _target) internal pure returns (bool _found) {
    for (uint256 _i; _i < _accesses.length; ++_i) {
      if (_accesses[_i].account == _target && _isCall(_accesses[_i])) return true;
    }
  }

  /// @notice Asserts the setup the holder committed is still the one `_before` recorded: the same commitment,
  ///         nonce and block of the last setup write.
  function _assertSetupUnchanged(IPolicyManager.ActionState memory _before) internal view {
    IPolicyManager.ActionState memory _now = _state();
    assertEq(_now.setupCommitment, _before.setupCommitment, 'the setup commitment changed');
    assertEq(_now.setupNonce, _before.setupNonce, 'the setup nonce changed');
    assertEq(_now.setupCommittedAtBlock, _before.setupCommittedAtBlock, 'a setup write happened');
  }

  /// @notice Asserts the recovery ran: the attempt is spent, the new key holds the account and the lost key not.
  function _assertHandedOver() internal view {
    assertEq(uint256(_state().attempt.state), uint256(IPolicyManager.AttemptState.Consumed), 'nothing was spent');
    assertEq(_privilege(_newKey), _KEY_VALUE, 'the new key holds no key value');
    assertEq(_privilege(_holderKey), bytes32(0), 'the lost key still holds a privilege');
  }

  /// @notice Asserts no key moved: the lost key still holds the account and the new key holds nothing.
  function _assertNoKeyMoved() internal view {
    assertEq(_privilege(_holderKey), _SIGNER_VALUE, 'the lost key was removed');
    assertEq(_privilege(_newKey), bytes32(0), 'the new key was installed');
  }
}
