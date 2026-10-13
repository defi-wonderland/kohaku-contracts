// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {Test} from 'forge-std/Test.sol';
import {IPolicyMethod} from 'interfaces/IPolicyMethod.sol';
import {AadhaarMethod} from 'contracts/methods/aadhaar/AadhaarMethod.sol';
import {MethodAadhaarVerifierMock} from 'test/mocks/MethodAadhaarVerifierMock.sol';

/// @notice Shared fixture of the Aadhaar method tests. Every deployment of the method goes through _aadhaarDeploy.
///         The constructor's argument order is written in one place.
abstract contract MethodAadhaarTestBase is Test {
  /*///////////////////////////////////////////////////////////////
                              STRUCTS
  ///////////////////////////////////////////////////////////////*/

  /// @notice One Aadhaar proof: the three Groth16 points a, b and c, then the nine public inputs.
  struct AadhaarProof {
    uint256[2] a;
    uint256[2][2] b;
    uint256[2] c;
    uint256[9] inputs;
  }

  /*///////////////////////////////////////////////////////////////
                          STATE VARIABLES
  ///////////////////////////////////////////////////////////////*/

  address internal _owner = makeAddr('pauseHolder');
  address internal _admin = makeAddr('keyAdmin');
  bytes32 internal _issuerKey = bytes32(uint256(0xa11ce));

  uint256 internal _nullifier = 0x0b0b;
  uint256 internal _nullifierSeed = 0x5eed;
  /// @notice The freshness window the fixture's guardian commits in the config, the 75 minutes the SDK proposes.
  uint256 internal _freshnessWindow = 75 minutes;
  /// @notice The block time setUp moves to, late enough that a signing time a whole window earlier is still positive.
  uint256 internal _now = 1_700_000_000;
  bytes32 internal _digest = keccak256('aadhaar digest');

  MethodAadhaarVerifierMock internal _verifier;
  AadhaarMethod internal _method;

  /*///////////////////////////////////////////////////////////////
                              SETUP
  ///////////////////////////////////////////////////////////////*/

  function setUp() public virtual {
    vm.warp(_now);
    _verifier = new MethodAadhaarVerifierMock();
    _method = _aadhaarDeploy(_owner, _admin, _aadhaarOneKey(_issuerKey), address(_verifier));
  }

  /*///////////////////////////////////////////////////////////////
                              HELPERS
  ///////////////////////////////////////////////////////////////*/

  /// @notice Deploys the method. The arguments are the pause holder, the key admin, the initial trusted-key list
  ///         and the address of the raw verifier the method calls. A valid list holds one word, the issuer key.
  function _aadhaarDeploy(
    address _initialOwner,
    address _initialAdmin,
    bytes32[] memory _initialKeys,
    address _verifierAddress
  ) internal returns (AadhaarMethod _deployed) {
    _deployed = new AadhaarMethod(_initialOwner, _initialAdmin, _initialKeys, _verifierAddress);
  }

  /// @notice A one-word trusted-key list.
  function _aadhaarOneKey(bytes32 _key) internal pure returns (bytes32[] memory _keys) {
    _keys = new bytes32[](1);
    _keys[0] = _key;
  }

  /// @notice The signal input eight must carry for a digest. It is keccak256 of the digest as one uint256 word,
  ///         shifted right by three bits. The vector replay checks this value against the frozen file.
  function _aadhaarSignal(bytes32 _forDigest) internal pure returns (uint256 _signal) {
    _signal = uint256(keccak256(abi.encodePacked(uint256(_forDigest)))) >> 3;
  }

  /// @notice The guardian's config, abi.encode(uint256 nullifier, uint256 nullifierSeed, uint256 freshnessWindow),
  ///         96 bytes. The window is the most seconds the QR's signing time may lie before the verifying block. The
  ///         vector replay checks these bytes against the frozen file.
  function _aadhaarConfig(uint256 _configNullifier, uint256 _configNullifierSeed, uint256 _configWindow)
    internal
    pure
    returns (bytes memory _config)
  {
    _config = abi.encode(_configNullifier, _configNullifierSeed, _configWindow);
  }

  /// @notice The fixture guardian's config: the fixture's nullifier, seed and freshness window.
  function _aadhaarDefaultConfig() internal view returns (bytes memory _config) {
    _config = _aadhaarConfig(_nullifier, _nullifierSeed, _freshnessWindow);
  }

  /// @notice A proof whose public inputs match this issuer key, config and digest. Input zero is the key, one the
  ///         nullifier, seven the seed and eight the signal. Input two, the QR's signing time, is the current block
  ///         time, so the proof is fresh under any window in this block. The points are distinct small integers.
  ///         Inputs three to six hold made-up disclosure values the method does not read.
  function _aadhaarValidProof(bytes32 _key, uint256 _proofNullifier, uint256 _proofNullifierSeed, bytes32 _forDigest)
    internal
    view
    returns (AadhaarProof memory _proof)
  {
    _proof.a = [uint256(11), uint256(12)];
    _proof.b = [[uint256(21), uint256(22)], [uint256(23), uint256(24)]];
    _proof.c = [uint256(31), uint256(32)];
    _proof.inputs[0] = uint256(_key);
    _proof.inputs[1] = _proofNullifier;
    _proof.inputs[2] = block.timestamp;
    _proof.inputs[3] = 18;
    _proof.inputs[4] = 1;
    _proof.inputs[5] = 110_001;
    _proof.inputs[6] = 7;
    _proof.inputs[7] = _proofNullifierSeed;
    _proof.inputs[8] = _aadhaarSignal(_forDigest);
  }

  /// @notice The fixture's valid proof under the fixture's key, config and digest.
  function _aadhaarDefaultProof() internal view returns (AadhaarProof memory _proof) {
    _proof = _aadhaarValidProof(_issuerKey, _nullifier, _nullifierSeed, _digest);
  }

  /// @notice The proof bytes, abi.encode(a, b, c, inputs), which are 544 bytes long. The vector replay checks these
  ///         bytes against the frozen file.
  function _aadhaarEncode(AadhaarProof memory _proof) internal pure returns (bytes memory _encoded) {
    _encoded = abi.encode(_proof.a, _proof.b, _proof.c, _proof.inputs);
  }

  /// @notice The first `_length` bytes of `_source`, padded with zero bytes when `_length` is longer.
  function _aadhaarResize(bytes memory _source, uint256 _length) internal pure returns (bytes memory _resized) {
    _resized = new bytes(_length);
    uint256 _copied = _length < _source.length ? _length : _source.length;
    for (uint256 _i; _i < _copied; ++_i) {
      _resized[_i] = _source[_i];
    }
  }

  /// @notice Make the mock accept exactly this proof's verifier calldata and nothing else.
  function _aadhaarExpect(AadhaarProof memory _proof) internal {
    _verifier.expectExact(_proof.a, _proof.b, _proof.c, _proof.inputs);
  }

  /// @notice Whether the method accepts the proof, read the way the policy manager reads a verdict. A proof is
  ///         accepted only when a static call to verify succeeds and returns exactly one word holding its selector.
  ///         Any other answer is a refusal, a revert included.
  function _aadhaarAccepts(address _target, bytes memory _config, bytes32 _forDigest, bytes memory _proof)
    internal
    view
    returns (bool _accepted)
  {
    (bool _ok, bytes memory _ret) =
      _target.staticcall(abi.encodeCall(IPolicyMethod.verify, (_config, _forDigest, _proof)));
    _accepted = _ok && _ret.length == 32 && abi.decode(_ret, (bytes32)) == bytes32(IPolicyMethod.verify.selector);
  }

  /// @notice _aadhaarAccepts against the fixture's method.
  function _aadhaarAccepts(bytes memory _config, bytes32 _forDigest, bytes memory _proof)
    internal
    view
    returns (bool _accepted)
  {
    _accepted = _aadhaarAccepts(address(_method), _config, _forDigest, _proof);
  }

  /// @notice Asserts the method refuses as a plain value. A static call to verify succeeds and returns exactly one
  ///         word, and that word is zero. A refusal never reverts.
  function _aadhaarAssertZeroWord(bytes memory _config, bytes32 _forDigest, bytes memory _proof, string memory _label)
    internal
    view
  {
    (bool _ok, bytes memory _ret) =
      address(_method).staticcall(abi.encodeCall(IPolicyMethod.verify, (_config, _forDigest, _proof)));
    assertTrue(_ok, string.concat(_label, ': the call succeeds'));
    assertEq(_ret.length, 32, string.concat(_label, ': one word'));
    assertEq(abi.decode(_ret, (bytes32)), bytes32(0), string.concat(_label, ': the zero word'));
  }

  /// @notice The fixture method's direct answer to verify for the fixture's config and digest with this proof.
  function _aadhaarAnswer(AadhaarProof memory _proof) internal view returns (bytes4 _answer) {
    _answer = _method.verify(_aadhaarDefaultConfig(), _digest, _aadhaarEncode(_proof));
  }

  /// @notice _aadhaarAccepts for the fixture's config and digest with this proof.
  function _aadhaarAccepts(AadhaarProof memory _proof) internal view returns (bool _accepted) {
    _accepted = _aadhaarAccepts(_aadhaarDefaultConfig(), _digest, _aadhaarEncode(_proof));
  }
}
