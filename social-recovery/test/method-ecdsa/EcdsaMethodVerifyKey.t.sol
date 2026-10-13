// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {MethodEcdsaTestBase} from 'test/utils/MethodEcdsaTestBase.sol';

/// @notice Tests the wallet method when the guardian is a plain wallet with a private key. The method must accept
///         that key's signature over the exact digest and refuse every other signature and every malformed config,
///         because each extra form it accepted would let someone forge or replay a guardian's approval.
/// @dev The method takes the key path when the guardian address has no code. On that path it recovers the signer
///      from the proof and compares it with the guardian.
///      The proof is the raw 65-byte signature: r, then s, then the recovery byte v.
///      A proof counts only when its s is at most half the curve order n and its v is 27 or 28.
///      The config is abi.encode(guardian address), exactly one 32-byte word.
///      The magic value is the selector of verify. Verify returns it only when the guardian signed the digest.
///      A refusal is a returned word other than the magic value. One test also allows a revert, because the
///      manager reads a revert as a refusal too.
///      In the fuzz tests `_keySeed` and `_otherSeed` each build a private key in the legal secp256k1 range.
///      `_offsetSeed` builds a second digest that is a different number from the first even after the curve's
///      arithmetic, so a signature over one never counts for the other.
contract EcdsaMethodVerifyKeyTest is MethodEcdsaTestBase {
  /// @notice A guardian key's signature over exactly the digest fills the place.
  /// @dev The one success case of the key path: without it no plain wallet could ever help a recovery.
  function test_WhenTheGuardianKeySignsTheDigest() external view {
    assertEq(_guardian.code.length, 0);
    _assertAccepted(_guardian, _digest, _sign(_guardianKey, _digest));
  }

  /// @notice A personal-message signature over the digest bytes is refused.
  /// @dev A page can ask for that form as a login, so accepting it would let a phisher harvest approvals.
  function test_WhenTheGuardianKeySignsAPersonalMessageOfTheDigest() external view {
    _assertRefused(_guardian, _digest, _signPersonal(_guardianKey, _digest));
  }

  /// @notice A signature over another digest is refused here and accepted for the digest it was made over.
  /// @dev An approval of one recovery must never count toward a different one.
  function test_WhenTheGuardianKeySignsAnotherDigest() external view {
    bytes32 _anotherDigest = keccak256('another digest');
    _assertRefused(_guardian, _digest, _sign(_guardianKey, _anotherDigest));
    _assertAccepted(_guardian, _anotherDigest, _sign(_guardianKey, _anotherDigest));
  }

  /// @notice A valid signature by a key other than the guardian's is refused.
  /// @dev Otherwise anyone could fill a guardian's place with their own wallet.
  function test_WhenAnotherKeySignsTheDigest() external view {
    _assertRefused(_guardian, _digest, _sign(_strangerKey, _digest));
  }

  /// @notice The malleated twin of a valid signature is refused. The twin replaces s with n minus s and flips the
  ///         recovery byte, and a bare ecrecover still returns the guardian for it.
  /// @dev One approval must have one proof, so a relayer cannot mint a second valid proof from the first.
  function test_WhenTheSignatureCarriesTheHighSHalf() external view {
    (uint8 _v, bytes32 _r, bytes32 _s) = vm.sign(_guardianKey, _digest);
    uint256 _highS = _SECP256K1_N - uint256(_s);
    uint8 _flippedV = _v == 27 ? 28 : 27;
    assertEq(ecrecover(_digest, _flippedV, _r, bytes32(_highS)), _guardian);
    _assertRefused(_guardian, _digest, abi.encodePacked(_r, bytes32(_highS), _flippedV));
  }

  /// @notice A recovery byte other than 27 or 28 is refused, including the 0 and 1 forms some signers emit.
  /// @dev The raw proof format admits exactly two recovery bytes, so any other one is not a proof.
  function test_WhenTheRecoveryByteIsOutsideItsTwoLegalValues() external view {
    (uint8 _v, bytes32 _r, bytes32 _s) = vm.sign(_guardianKey, _digest);
    _assertRefused(_guardian, _digest, abi.encodePacked(_r, _s, uint8(_v - 27)));
    _assertRefused(_guardian, _digest, abi.encodePacked(_r, _s, uint8(0)));
    _assertRefused(_guardian, _digest, abi.encodePacked(_r, _s, uint8(1)));
    _assertRefused(_guardian, _digest, abi.encodePacked(_r, _s, uint8(29)));
    _assertRefused(_guardian, _digest, abi.encodePacked(_r, _s, uint8(_v + 35)));
    _assertRefused(_guardian, _digest, abi.encodePacked(_r, _s, type(uint8).max));
  }

  /// @notice A signature whose r and s are both zero is refused.
  /// @dev ecrecover answers the zero address for it, which must never read as a guardian's approval.
  function test_WhenTheSignatureHalvesAreZero() external view {
    _assertRefused(_guardian, _digest, abi.encodePacked(bytes32(0), bytes32(0), uint8(27)));
    _assertRefused(_guardian, _digest, abi.encodePacked(bytes32(0), bytes32(0), uint8(28)));
  }

  /// @notice The ABI-encoded form abi.encode(bytes signature) is refused while the raw 65 bytes pass.
  /// @dev The proof layout is frozen as raw r || s || v, and the SDK writes exactly that.
  function test_WhenTheProofIsTheAbiEncodedSignature() external view {
    bytes memory _raw = _sign(_guardianKey, _digest);
    _assertAccepted(_guardian, _digest, _raw);
    _assertRefused(_guardian, _digest, abi.encode(_raw));
  }

  /// @notice The 64-byte compact r || vs signature is refused.
  /// @dev The proof layout is the raw 65-byte signature, so a second encoding of the same approval is not a proof.
  function test_WhenTheProofIsTheCompactSignature() external view {
    (bytes32 _r, bytes32 _vs) = vm.signCompact(_guardianKey, _digest);
    _assertRefused(_guardian, _digest, abi.encodePacked(_r, _vs));
  }

  /// @notice A valid signature with bytes appended after it is refused.
  /// @dev The proof is exactly 65 bytes, so appended bytes cannot ride along with a valid approval.
  function test_WhenTheProofCarriesATrailingByte() external view {
    bytes memory _raw = _sign(_guardianKey, _digest);
    _assertRefused(_guardian, _digest, abi.encodePacked(_raw, uint8(0)));
    _assertRefused(_guardian, _digest, abi.encodePacked(_raw, _raw));
  }

  /// @notice An empty proof is refused without reverting.
  /// @dev An empty proof is what a careless or hostile caller sends first, and it must never fill a place.
  function test_WhenTheProofIsEmpty() external view {
    _assertRefused(_guardian, _digest, '');
  }

  /// @notice A credential naming the zero address is refused whatever the proof.
  /// @dev ecrecover answers the zero address for many malformed signatures, so a zero guardian must match none.
  function test_WhenTheConfigIsTheZeroAddress() external view {
    _assertRefused(address(0), _digest, abi.encodePacked(bytes32(0), bytes32(0), uint8(27)));
    _assertRefused(address(0), _digest, abi.encodePacked(bytes32(uint256(1)), bytes32(uint256(1)), uint8(27)));
    _assertRefused(address(0), _digest, _sign(_guardianKey, _digest));
    _assertRefused(address(0), _digest, '');
    _assertRefused(address(0), bytes32(0), '');
  }

  /// @notice A config of two ABI words is answered with one word that is not the magic value. This holds even
  ///         when the proof is the guardian's valid signature.
  /// @dev The config is one ABI word, so the guardian's word followed by anything else must never fill a place.
  function test_WhenTheConfigCarriesATrailingWord() external view {
    bytes memory _proof = _sign(_guardianKey, _digest);
    _assertAccepted(_guardian, _digest, _proof);
    _assertAnsweredNotMagic(abi.encode(_guardian, uint256(1)), _digest, _proof);
  }

  /// @notice A config shorter than one word is answered with one word that is not the magic value. The test tries
  ///         a config of 31 bytes and an empty config.
  /// @dev A config of any length other than one word is answered with a non-magic word, never a revert.
  function test_WhenTheConfigIsShorterThanOneWord() external view {
    bytes memory _proof = _sign(_guardianKey, _digest);
    bytes memory _full = abi.encode(_guardian);
    bytes memory _shortConfig = new bytes(31);
    for (uint256 _i = 0; _i < 31; _i++) {
      _shortConfig[_i] = _full[_i];
    }
    _assertAnsweredNotMagic(_shortConfig, _digest, _proof);
    _assertAnsweredNotMagic('', _digest, _proof);
  }

  /// @notice A config word with nonzero upper bytes never yields the magic value. This holds even when its low
  ///         20 bytes name the guardian and the guardian's valid signature comes with it.
  /// @dev Such a word is not abi.encode of any address, so it is not the committed credential. The method may
  ///      answer a word or revert here. A revert reads as a rejected proof, so the test accepts either outcome.
  function test_WhenTheConfigWordCarriesNonzeroUpperBytes() external view {
    bytes memory _proof = _sign(_guardianKey, _digest);
    uint256 _low = uint256(uint160(_guardian));
    _assertNotMagic(abi.encode(bytes32((uint256(1) << 160) | _low)), _digest, _proof);
    _assertNotMagic(abi.encode(bytes32((uint256(type(uint96).max) << 160) | _low)), _digest, _proof);
  }

  /// @notice Any legal key's signature over any digest fills that key's place.
  /// @dev The acceptance path must hold for every key and digest, not only the fixed guardian key and digest.
  function testFuzz_AcceptsAnyKeysSignatureOverAnyDigest(uint256 _keySeed, bytes32 _anyDigest) external view {
    uint256 _key = _boundKey(_keySeed);
    _assertAccepted(vm.addr(_key), _anyDigest, _sign(_key, _anyDigest));
  }

  /// @notice A signature over any hash other than the digest is refused.
  /// @dev The digest is the only signed form the method accepts.
  function testFuzz_RefusesASignatureOverAnyOtherHash(uint256 _keySeed, bytes32 _anyDigest, uint256 _offsetSeed)
    external
    view
  {
    uint256 _key = _boundKey(_keySeed);
    _assertRefused(vm.addr(_key), _anyDigest, _sign(_key, _otherHash(_anyDigest, _offsetSeed)));
  }

  /// @notice A personal-message signature over any digest is refused.
  /// @dev The login-prompt form must never count as an approval, for any key or digest.
  function testFuzz_RefusesAPersonalMessageOfTheDigest(uint256 _keySeed, bytes32 _anyDigest) external view {
    uint256 _key = _boundKey(_keySeed);
    _assertRefused(vm.addr(_key), _anyDigest, _signPersonal(_key, _anyDigest));
  }

  /// @notice Any other key's signature over the digest is refused.
  /// @dev Only the committed guardian can fill its place.
  function testFuzz_RefusesAnotherKeysSignature(uint256 _keySeed, uint256 _otherSeed, bytes32 _anyDigest)
    external
    view
  {
    uint256 _key = _boundKey(_keySeed);
    uint256 _wrongKey = _otherKey(_key, _otherSeed);
    _assertRefused(vm.addr(_key), _anyDigest, _sign(_wrongKey, _anyDigest));
  }

  /// @notice The high-s twin of any valid signature is refused.
  /// @dev A valid signature has exactly one accepted encoding.
  function testFuzz_RefusesTheHighSTwin(uint256 _keySeed, bytes32 _anyDigest) external view {
    uint256 _key = _boundKey(_keySeed);
    (uint8 _v, bytes32 _r, bytes32 _s) = vm.sign(_key, _anyDigest);
    assertLe(uint256(_s), _HALF_N);
    _assertRefused(
      vm.addr(_key), _anyDigest, abi.encodePacked(_r, bytes32(_SECP256K1_N - uint256(_s)), _v == 27 ? 28 : 27)
    );
  }

  /// @notice A valid r and s with any recovery byte other than 27 or 28 are refused.
  /// @dev `_vSeed` builds a byte in [0, 26] or [29, 255], every illegal recovery byte.
  function testFuzz_RefusesAnIllegalRecoveryByte(uint256 _keySeed, bytes32 _anyDigest, uint256 _vSeed) external view {
    uint256 _key = _boundKey(_keySeed);
    uint8 _v = uint8(bound(_vSeed, 0, 253));
    if (_v > 26) _v += 2;
    (, bytes32 _r, bytes32 _s) = vm.sign(_key, _anyDigest);
    _assertRefused(vm.addr(_key), _anyDigest, abi.encodePacked(_r, _s, _v));
  }

  /// @notice A valid signature followed by any nonempty tail is refused.
  /// @dev `_tail` plus `_lastByte` build a suffix of at least one byte, so the proof is always longer than 65.
  function testFuzz_RefusesAProofLongerThanOneSignature(
    uint256 _keySeed,
    bytes32 _anyDigest,
    bytes calldata _tail,
    uint8 _lastByte
  ) external view {
    uint256 _key = _boundKey(_keySeed);
    _assertRefused(vm.addr(_key), _anyDigest, abi.encodePacked(_sign(_key, _anyDigest), _tail, _lastByte));
  }

  /// @notice Any strict prefix of a valid signature is refused.
  /// @dev `_cutSeed` builds a length in [0, 64], so the proof is always shorter than 65 bytes.
  function testFuzz_RefusesAProofShorterThanOneSignature(uint256 _keySeed, bytes32 _anyDigest, uint256 _cutSeed)
    external
    view
  {
    uint256 _key = _boundKey(_keySeed);
    bytes memory _raw = _sign(_key, _anyDigest);
    uint256 _cut = bound(_cutSeed, 0, 64);
    bytes memory _prefix = new bytes(_cut);
    for (uint256 _i = 0; _i < _cut; _i++) {
      _prefix[_i] = _raw[_i];
    }
    _assertRefused(vm.addr(_key), _anyDigest, _prefix);
  }

  /// @notice No 65-byte proof fills a credential naming the zero address.
  /// @dev A zero guardian is a mistake at setup, and it must never become a place anyone can fill.
  function testFuzz_RefusesEveryProofForTheZeroAddress(bytes32 _anyDigest, bytes32 _r, bytes32 _s, uint8 _v)
    external
    view
  {
    _assertRefused(address(0), _anyDigest, abi.encodePacked(_r, _s, _v));
  }

  /// @notice A valid config word followed by any nonempty tail is answered with one word that is not the magic
  ///         value.
  /// @dev `_extra` plus `_lastByte` build a tail of at least one byte, so the config is always longer than 32.
  function testFuzz_RefusesAConfigLongerThanOneWord(
    uint256 _keySeed,
    bytes32 _anyDigest,
    bytes calldata _extra,
    uint8 _lastByte
  ) external view {
    uint256 _key = _boundKey(_keySeed);
    bytes memory _longConfig = abi.encodePacked(abi.encode(vm.addr(_key)), _extra, _lastByte);
    _assertAnsweredNotMagic(_longConfig, _anyDigest, _sign(_key, _anyDigest));
  }

  /// @notice Any strict prefix of a valid config word is answered with one word that is not the magic value.
  /// @dev `_cutSeed` builds a length in [0, 31], so the config is always shorter than one word.
  function testFuzz_RefusesAConfigShorterThanOneWord(uint256 _keySeed, bytes32 _anyDigest, uint256 _cutSeed)
    external
    view
  {
    uint256 _key = _boundKey(_keySeed);
    bytes memory _full = abi.encode(vm.addr(_key));
    uint256 _cut = bound(_cutSeed, 0, 31);
    bytes memory _prefix = new bytes(_cut);
    for (uint256 _i = 0; _i < _cut; _i++) {
      _prefix[_i] = _full[_i];
    }
    _assertAnsweredNotMagic(_prefix, _anyDigest, _sign(_key, _anyDigest));
  }
}
