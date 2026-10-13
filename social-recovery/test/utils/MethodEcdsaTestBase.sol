// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {Test} from 'forge-std/Test.sol';
import {IPolicyMethod} from 'interfaces/IPolicyMethod.sol';
import {EcdsaMethod} from 'contracts/methods/ecdsa/EcdsaMethod.sol';

/// @notice Holds the setup and the helpers that every wallet method test shares. The test files build their
///         configs, proofs and verdict checks here, so all of them test the same formats.
/// @dev The wallet method checks that one guardian approved the digest of a recovery. The config names that
///      guardian. It is abi.encode(guardian address), one 32-byte word. The proof is the guardian's raw 65-byte
///      signature: r, then s, then the recovery byte v. Verify answers the magic value when the guardian approved.
///      The magic value is the selector of verify itself. Any other answer is a refusal.
abstract contract MethodEcdsaTestBase is Test {
  /*///////////////////////////////////////////////////////////////
                          STATE VARIABLES
  ///////////////////////////////////////////////////////////////*/

  /// @dev The one verdict the manager accepts: the selector of verify itself. Anything else is a rejection.
  bytes4 internal constant _MAGIC = IPolicyMethod.verify.selector;
  /// @dev The order of secp256k1, the bound on a private key and on the signature halves.
  uint256 internal constant _SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
  /// @dev The largest low signature half, n / 2. A signature whose s exceeds it is the malleated twin.
  uint256 internal constant _HALF_N = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0;

  IPolicyMethod internal _method;

  uint256 internal _guardianKey = 0xA11CE;
  address internal _guardian;
  uint256 internal _strangerKey = 0xB0B;
  bytes32 internal _digest = keccak256('an approval digest');

  /*///////////////////////////////////////////////////////////////
                              SETUP
  ///////////////////////////////////////////////////////////////*/

  /// @dev Deploys the wallet method and derives the guardian address from its key.
  function setUp() public virtual {
    _method = IPolicyMethod(address(new EcdsaMethod()));
    _guardian = vm.addr(_guardianKey);
    vm.label(address(_method), 'EcdsaMethod');
    vm.label(_guardian, 'guardian');
  }

  /*///////////////////////////////////////////////////////////////
                              HELPERS
  ///////////////////////////////////////////////////////////////*/

  /// @dev The wallet method's config: abi.encode(address guardian), one ABI word.
  function _config(address _account) internal pure returns (bytes memory _encoded) {
    _encoded = abi.encode(_account);
  }

  /// @dev The wallet method's proof: the raw 65-byte r || s || v signature of `_key` over `_hash`.
  function _sign(uint256 _key, bytes32 _hash) internal pure returns (bytes memory _proof) {
    (uint8 _v, bytes32 _r, bytes32 _s) = vm.sign(_key, _hash);
    _proof = abi.encodePacked(_r, _s, _v);
  }

  /// @dev A personal-message signature (EIP-191 version 0x45) over the 32 digest bytes, the form a wallet
  ///      produces for a login prompt. A phisher can harvest it, so the method must never accept it.
  function _signPersonal(uint256 _key, bytes32 _hash) internal pure returns (bytes memory _proof) {
    _proof = _sign(_key, keccak256(abi.encodePacked('\x19Ethereum Signed Message:\n32', _hash)));
  }

  /// @dev Calls verify with the one-word config naming `_account`, and returns its verdict.
  function _verify(address _account, bytes32 _hash, bytes memory _proof) internal view returns (bytes4 _verdict) {
    _verdict = _method.verify(_config(_account), _hash, _proof);
  }

  /// @dev Asserts a refusal. With a well-formed config, verify must return a word that is not the magic value.
  ///      It must not revert.
  function _assertRefused(address _account, bytes32 _hash, bytes memory _proof) internal view {
    assertTrue(_verify(_account, _hash, _proof) != _MAGIC, 'verify returned the magic value');
  }

  /// @dev Asserts an acceptance: verify returns exactly the magic value.
  function _assertAccepted(address _account, bytes32 _hash, bytes memory _proof) internal view {
    assertEq(_verify(_account, _hash, _proof), _MAGIC, 'verify did not return the magic value');
  }

  /// @dev Calls verify with the raw config bytes `_rawConfig` and asserts that it answers without reverting.
  ///      The answer must be exactly one ABI word, and that word must not be the magic value.
  function _assertAnsweredNotMagic(bytes memory _rawConfig, bytes32 _hash, bytes memory _proof) internal view {
    (bool _ok, bytes memory _ret) =
      address(_method).staticcall(abi.encodeCall(_method.verify, (_rawConfig, _hash, _proof)));
    assertTrue(_ok, 'verify reverted instead of answering a word');
    assertEq(_ret.length, 32, 'verify did not answer exactly one word');
    assertTrue(keccak256(_ret) != keccak256(abi.encode(_MAGIC)), 'verify returned the magic value');
  }

  /// @dev Asserts the call does not produce the magic value, whether it reverts or returns another word.
  ///      Both read as false to the manager, so this is the check where either outcome is allowed.
  function _assertNotMagic(bytes memory _rawConfig, bytes32 _hash, bytes memory _proof) internal view {
    (bool _ok, bytes memory _ret) =
      address(_method).staticcall(abi.encodeCall(_method.verify, (_rawConfig, _hash, _proof)));
    assertFalse(_ok && keccak256(_ret) == keccak256(abi.encode(_MAGIC)), 'verify returned the magic value');
  }

  /// @dev A private key in the legal secp256k1 range [1, n - 1], built from a fuzzed seed.
  function _boundKey(uint256 _seed) internal pure returns (uint256 _key) {
    _key = bound(_seed, 1, _SECP256K1_N - 1);
  }

  /// @dev A private key in the legal range that differs from `_key`, built from a fuzzed seed.
  function _otherKey(uint256 _key, uint256 _seed) internal pure returns (uint256 _other) {
    _other = bound(_seed, 1, _SECP256K1_N - 2);
    if (_other > _key - 1) _other++;
  }

  /// @dev Builds a second hash from `_hash` and a fuzzed seed. ECDSA reads a hash modulo the curve order n, so
  ///      two hashes that are equal modulo n share every signature. The helper adds a nonzero offset below n and
  ///      reduces the sum modulo n. The result is a different number from `_hash` even after that reduction.
  function _otherHash(bytes32 _hash, uint256 _offsetSeed) internal pure returns (bytes32 _other) {
    uint256 _offset = bound(_offsetSeed, 1, _SECP256K1_N - 1);
    _other = bytes32(addmod(uint256(_hash) % _SECP256K1_N, _offset, _SECP256K1_N));
  }

  /// @dev The EIP-7702 delegation designator pointing at `_target`, the code an address carries while it delegates.
  function _delegationCode(address _target) internal pure returns (bytes memory _code) {
    _code = abi.encodePacked(hex'ef0100', _target);
  }
}
