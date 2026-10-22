// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {Test} from 'forge-std/Test.sol';
import {IPolicyMethod} from 'interfaces/IPolicyMethod.sol';
import {ZkPassportMethod} from 'contracts/methods/zkpassport/ZkPassportMethod.sol';
import {
  MethodZkPassportVerifierHelperMock,
  MethodZkPassportProofVerificationData,
  MethodZkPassportProofVerificationParams,
  MethodZkPassportRootVerifierMock,
  MethodZkPassportServiceConfig
} from 'test/mocks/MethodZkPassportMocks.sol';

/// @notice Shared fixture for the zkPassport method tests. It deploys the method with eight trusted-key words that
///         point its root verifier and verifier helper at mocks with fixed answers. It also builds configs and proofs
///         in the layouts the SDK writes.
abstract contract MethodZkPassportFixture is Test {
  /// @notice zkPassport 0.21.0 as a version word: major, minor and patch as three big-endian uint16 values,
  ///         right-padded with zeroes. It is the version the method accepts at deployment.
  bytes32 internal constant _ZK_VERSION_0_21_0 = 0x0000001500000000000000000000000000000000000000000000000000000000;

  /// @notice The position of each trusted-key word. The method reads the version, root verifier and verifier helper
  ///         words during a proof. The other five are for a watcher to compare with zkPassport's live contracts.
  uint256 internal constant _WORD_VERSION = 0;
  uint256 internal constant _WORD_ROOT = 1;
  uint256 internal constant _WORD_SUB_VERIFIER = 2;
  uint256 internal constant _WORD_VERIFIER_HELPER = 3;
  uint256 internal constant _WORD_REGISTRY = 4;
  uint256 internal constant _WORD_ROOT_ADMIN = 5;
  uint256 internal constant _WORD_ROOT_GUARDIAN = 6;
  uint256 internal constant _WORD_SUB_VERIFIER_ADMIN = 7;
  uint256 internal constant _KEY_COUNT = 8;

  address internal _pauseHolder = makeAddr('pauseHolder');
  address internal _keyAdmin = makeAddr('keyAdmin');
  address internal constant _SUB_VERIFIER = address(0x5B01);
  address internal constant _REGISTRY = address(0x5B02);
  address internal constant _ROOT_ADMIN = address(0x5B03);
  address internal constant _ROOT_GUARDIAN = address(0x5B04);
  address internal constant _SUB_VERIFIER_ADMIN = address(0x5B05);

  MethodZkPassportRootVerifierMock internal _rootMock;
  MethodZkPassportVerifierHelperMock internal _verifierHelperMock;
  ZkPassportMethod internal _method;

  bytes32 internal _defaultIdentifier = bytes32(uint256(0x7b));
  string internal _defaultDomain = 'recover.example';
  string internal _defaultScope = 'social-recovery';
  uint256 internal _defaultValidity = 86_400;
  bytes32 internal _defaultDigest = keccak256('zkpassport digest');
  bytes internal _defaultCommittedInputs = hex'1234';

  function setUp() public virtual {
    _rootMock = new MethodZkPassportRootVerifierMock();
    _verifierHelperMock = new MethodZkPassportVerifierHelperMock();
    _method = new ZkPassportMethod(_pauseHolder, _keyAdmin, _zkKeys(address(_rootMock), address(_verifierHelperMock)));
  }

  /*///////////////////////////////////////////////////////////////
                               KEYS
  ///////////////////////////////////////////////////////////////*/

  /// @notice The eight trusted-key words in the method's order, each address left-padded to one word.
  function _zkKeys(address _root, address _verifierHelper) internal pure returns (bytes32[] memory _keys) {
    _keys = new bytes32[](_KEY_COUNT);
    _keys[_WORD_VERSION] = _ZK_VERSION_0_21_0;
    _keys[_WORD_ROOT] = _zkWord(_root);
    _keys[_WORD_SUB_VERIFIER] = _zkWord(_SUB_VERIFIER);
    _keys[_WORD_VERIFIER_HELPER] = _zkWord(_verifierHelper);
    _keys[_WORD_REGISTRY] = _zkWord(_REGISTRY);
    _keys[_WORD_ROOT_ADMIN] = _zkWord(_ROOT_ADMIN);
    _keys[_WORD_ROOT_GUARDIAN] = _zkWord(_ROOT_GUARDIAN);
    _keys[_WORD_SUB_VERIFIER_ADMIN] = _zkWord(_SUB_VERIFIER_ADMIN);
  }

  /// @notice An address left-padded to one word.
  function _zkWord(address _account) internal pure returns (bytes32 _word) {
    _word = bytes32(uint256(uint160(_account)));
  }

  /// @notice A valid eight-word set cut or extended to the given length. Every word is nonzero. Only the length can
  ///         make the set invalid.
  function _zkResized(uint256 _length) internal view returns (bytes32[] memory _keys) {
    bytes32[] memory _valid = _zkKeys(address(_rootMock), address(_verifierHelperMock));
    _keys = new bytes32[](_length);
    for (uint256 _i; _i < _length; ++_i) {
      _keys[_i] = _i < _KEY_COUNT ? _valid[_i] : bytes32(uint256(0xdead + _i));
    }
  }

  /// @notice The given word with a nonzero value in its upper twelve bytes, the bytes an address does not use. The
  ///         upper part is bounded to one through the largest twelve-byte value. The result always has a set bit
  ///         outside the address.
  function _zkDirty(bytes32 _word, uint256 _upper) internal pure returns (bytes32 _dirty) {
    _upper = bound(_upper, 1, type(uint96).max);
    _dirty = bytes32((_upper << 160) | uint256(uint160(uint256(_word))));
  }

  /// @notice The given version word with a nonzero value in its twenty six low bytes, after the six bytes of major,
  ///         minor and patch. The padding is bounded to one through the largest twenty-six-byte value. The result
  ///         always has a set bit in the padding.
  function _zkDirtyVersion(bytes32 _version, uint256 _padding) internal pure returns (bytes32 _dirty) {
    _padding = bound(_padding, 1, type(uint208).max);
    _dirty = bytes32(((uint256(_version) >> 208) << 208) | _padding);
  }

  /// @notice Asserts the stored words are still the eight words the fixture deployed with.
  function _zkAssertKeysUnchanged() internal view {
    (,, bytes32[] memory _stored,,) = _method.trustedParties();
    bytes32[] memory _expected = _zkKeys(address(_rootMock), address(_verifierHelperMock));
    assertEq(_stored.length, _KEY_COUNT, 'length changed');
    for (uint256 _i; _i < _KEY_COUNT; ++_i) {
      assertEq(_stored[_i], _expected[_i], 'word changed');
    }
  }

  /*///////////////////////////////////////////////////////////////
                         CONFIG AND PROOF
  ///////////////////////////////////////////////////////////////*/

  /// @notice abi.encode(bytes32 uniqueIdentifier, string domain, string scope, uint256 validityPeriodInSeconds).
  ///         The config names no zkPassport version. The method routes every proof with the version it accepts.
  function _zkConfig(bytes32 _uniqueIdentifier, string memory _domain, string memory _scope, uint256 _validity)
    internal
    pure
    returns (bytes memory _config)
  {
    _config = abi.encode(_uniqueIdentifier, _domain, _scope, _validity);
  }

  /// @notice The default config: the fixture identifier, domain, scope and validity.
  function _zkDefaultConfig() internal view returns (bytes memory _config) {
    _config = _zkConfig(_defaultIdentifier, _defaultDomain, _defaultScope, _defaultValidity);
  }

  /// @notice A public-input array of the given length, every entry nonzero except the one at length - 3.
  function _zkPublicInputs(uint256 _length) internal pure returns (bytes32[] memory _inputs) {
    _inputs = new bytes32[](_length);
    for (uint256 _i; _i < _length; ++_i) {
      _inputs[_i] = bytes32(uint256(0xa0 + _i));
    }
    if (_length > 2) _inputs[_length - 3] = bytes32(0);
  }

  /// @notice Proof data carrying the given public inputs.
  function _zkProofData(bytes32[] memory _publicInputs)
    internal
    pure
    returns (MethodZkPassportProofVerificationData memory _data)
  {
    _data = MethodZkPassportProofVerificationData({
      vkeyHash: bytes32(uint256(0x63)), proof: hex'123456', publicInputs: _publicInputs
    });
  }

  /// @notice abi.encode(IZkPassportRootVerifier.ProofVerificationData proofVerificationData, bytes committedInputs).
  function _zkProof(MethodZkPassportProofVerificationData memory _data, bytes memory _committedInputs)
    internal
    pure
    returns (bytes memory _proof)
  {
    _proof = abi.encode(_data, _committedInputs);
  }

  /// @notice The params the method must hand the root verifier: the accepted version, the proof data, the
  ///         committed inputs and IZkPassportRootVerifier.ServiceConfig(validity, domain, scope, devMode).
  function _zkParams(
    bytes32 _version,
    MethodZkPassportProofVerificationData memory _data,
    bytes memory _committedInputs,
    uint256 _validity,
    string memory _domain,
    string memory _scope,
    bool _devMode
  ) internal pure returns (MethodZkPassportProofVerificationParams memory _params) {
    _params = MethodZkPassportProofVerificationParams({
      version: _version,
      proofVerificationData: _data,
      committedInputs: _committedInputs,
      serviceConfig: MethodZkPassportServiceConfig({
        validityPeriodInSeconds: _validity, domain: _domain, scope: _scope, devMode: _devMode
      })
    });
  }

  /// @notice The root verifier's calldata for the given params.
  function _zkRootCall(MethodZkPassportProofVerificationParams memory _params)
    internal
    pure
    returns (bytes memory _data)
  {
    _data = abi.encodeCall(MethodZkPassportRootVerifierMock.verify, (_params));
  }

  /// @notice Sets the root verifier mock to return (valid, identifier, verifier helper) for exactly these params. Sets
  ///         the verifier helper mock to return customData for exactly these committed inputs.
  function _zkSetAnswers(
    MethodZkPassportRootVerifierMock _root,
    MethodZkPassportVerifierHelperMock _verifierHelper,
    MethodZkPassportProofVerificationParams memory _params,
    bool _valid,
    bytes32 _returnedIdentifier,
    address _returnedVerifierHelper,
    string memory _customData
  ) internal {
    _root.setAnswer(keccak256(abi.encode(_params)), _valid, _returnedIdentifier, _returnedVerifierHelper);
    _verifierHelper.setAnswer(keccak256(_params.committedInputs), _customData);
  }

  /// @notice Sets up the fixture mocks for an honest proof over the default config, the given proof data and
  ///         digest. Every mock answer lets an honest proof through. Any refusal then comes from the method itself.
  function _zkSetHonestAnswers(MethodZkPassportProofVerificationData memory _data, bytes32 _digest) internal {
    _zkSetAnswers(
      _rootMock,
      _verifierHelperMock,
      _zkParams(
        _ZK_VERSION_0_21_0, _data, _defaultCommittedInputs, _defaultValidity, _defaultDomain, _defaultScope, false
      ),
      true,
      _defaultIdentifier,
      address(_verifierHelperMock),
      _zkRender(_digest)
    );
  }

  /// @notice The default honest proof, with the mocks set up for it: eight public inputs with the nullifier type at
  ///         length - 3.
  function _zkDefaultHonestProof() internal returns (bytes memory _proof) {
    MethodZkPassportProofVerificationData memory _data = _zkProofData(_zkPublicInputs(8));
    _zkSetHonestAnswers(_data, _defaultDigest);
    _proof = _zkProof(_data, _defaultCommittedInputs);
  }

  /*///////////////////////////////////////////////////////////////
                         DIGEST RENDERINGS
  ///////////////////////////////////////////////////////////////*/

  /// @notice The one text rendering of a digest the verifier helper must bind: 0x followed by sixty four lowercase
  ///         hexadecimal characters. The zkPassport vector file freezes this rendering. A kat test checks this
  ///         function against it.
  function _zkRender(bytes32 _digest) internal pure returns (string memory _rendered) {
    _rendered = string(abi.encodePacked('0x', _zkHex(_digest, false)));
  }

  /// @notice 0x followed by sixty four uppercase hexadecimal characters.
  function _zkRenderUpper(bytes32 _digest) internal pure returns (string memory _rendered) {
    _rendered = string(abi.encodePacked('0x', _zkHex(_digest, true)));
  }

  /// @notice Sixty four lowercase hexadecimal characters with no prefix.
  function _zkRenderUnprefixed(bytes32 _digest) internal pure returns (string memory _rendered) {
    _rendered = string(_zkHex(_digest, false));
  }

  function _zkHex(bytes32 _digest, bool _upper) internal pure returns (bytes memory _out) {
    bytes memory _alphabet = _upper ? bytes('0123456789ABCDEF') : bytes('0123456789abcdef');
    _out = new bytes(64);
    for (uint256 _i; _i < 32; ++_i) {
      uint8 _b = uint8(_digest[_i]);
      _out[2 * _i] = _alphabet[_b >> 4];
      _out[2 * _i + 1] = _alphabet[_b & 0x0f];
    }
  }

  /*///////////////////////////////////////////////////////////////
                             VERDICTS
  ///////////////////////////////////////////////////////////////*/

  /// @notice Calls verify the way the manager does, as a static call.
  function _zkCall(bytes memory _config, bytes32 _digest, bytes memory _proof)
    internal
    view
    returns (bool _success, bytes memory _returned)
  {
    (_success, _returned) =
      address(_method).staticcall(abi.encodeCall(IPolicyMethod.verify, (_config, _digest, _proof)));
  }

  /// @notice True when verify accepts the proof: the static call succeeds and returns exactly the verify selector.
  ///         The manager reads any other answer as a refusal.
  function _zkAccepts(bytes memory _config, bytes32 _digest, bytes memory _proof)
    internal
    view
    returns (bool _accepts)
  {
    (bool _success, bytes memory _returned) = _zkCall(_config, _digest, _proof);
    _accepts =
      _success && _returned.length == 32 && abi.decode(_returned, (bytes32)) == bytes32(IPolicyMethod.verify.selector);
  }

  function _zkAssertAccepted(bytes memory _config, bytes32 _digest, bytes memory _proof) internal view {
    (bool _success, bytes memory _returned) = _zkCall(_config, _digest, _proof);
    assertTrue(_success, 'verify reverted on an honest proof');
    assertEq(_returned.length, 32, 'verify returned other than one word');
    assertEq(
      abi.decode(_returned, (bytes32)), bytes32(IPolicyMethod.verify.selector), 'verify did not return the magic value'
    );
  }

  function _zkAssertRefused(bytes memory _config, bytes32 _digest, bytes memory _proof) internal view {
    assertFalse(_zkAccepts(_config, _digest, _proof), 'a failing proof was accepted');
  }
}
