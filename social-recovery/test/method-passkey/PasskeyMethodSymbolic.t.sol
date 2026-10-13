// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {IPolicyMethod} from 'interfaces/IPolicyMethod.sol';
import {PasskeyMethodHarness} from 'test/utils/PasskeyMethodHarness.sol';
import {PasskeyMethodHelpers} from 'test/utils/PasskeyMethodHelpers.sol';

/// @notice Symbolic proofs, run by Halmos, that the passkey method refuses every assertion failing a
///         check that does not depend on the P-256 math: the fixed client data prefix, the challenge,
///         the closing quote, the relying party hash, the two required flags and the minimum lengths.
///         Every parameter is symbolic, so a passing check holds for every value of it.
/// @dev Halmos does not model the P256VERIFY precompile at 0x100, so `setUp` installs a stand-in there
///      that answers valid, one word equal to 1, for every input. Each refusal therefore comes from the
///      field under test and never from the signature. The real precompile is exercised by the unit
///      and fuzz suites. The acceptance side is proven there too, because every accepting path hashes
///      with SHA-256, and Halmos 0.3.3 models SHA-256 as one function per input size and errors when one
///      run meets it at two sizes. A check with a symbolic field can reach that hashing whenever the
///      solver cannot rule a branch out in time, since Halmos then walks the branch. So the checks on
///      the head, the relying party hash and the flags call one check alone through the harness, and
///      never reach the signature. The two length checks call the full `verify`, since a concrete
///      short length fails its check on the only path there is. The client data prefix is the 36
///      bytes {"type":"webauthn.get","challenge":" and the challenge is the digest in unpadded
///      base64url, 43 characters, so the prefix, the challenge and the closing quote take the first
///      80 bytes, called the head below.
contract PasskeyMethodSymbolicTest is PasskeyMethodHelpers {
  /// @dev A stand-in for P256VERIFY that returns one word equal to 1, the precompile's valid answer.
  bytes internal constant _STUB_VALID = hex'600160005260206000f3';
  /// @dev The fixed client data prefix, type first and challenge second, with no whitespace.
  bytes internal constant _PREFIX = '{"type":"webauthn.get","challenge":"';
  /// @dev The digest the checks ask about, the one the frozen passkey vectors sign. Its rendering
  ///      carries the url safe character `_`.
  bytes32 internal constant _DIGEST = 0x17498ba208aefe001e6e2f2adec41cd16d0285e23660df6e310d3daac040c339;
  /// @dev The relying party hash the checks commit, sha256 of `recover.example` as the frozen config
  ///      vector carries it.
  bytes32 internal constant _RP_ID_HASH = 0x1f4228a6a013a3f630b909758979b417fe85c904352c0bb7ca7fa5bcfe8f91c4;

  /// @dev The method under test, with its checks exposed one by one.
  PasskeyMethodHarness internal _method;

  function setUp() public {
    _method = new PasskeyMethodHarness();
    vm.etch(_P256_VERIFY, _STUB_VALID);
  }

  /*///////////////////////////////////////////////////////////////
                            CLIENT DATA
  ///////////////////////////////////////////////////////////////*/

  /// Client data whose first 32 bytes differ from the head's fails the client data check, whatever
  /// follows them. `_delta` is a nonzero word XORed into those bytes, and `_head1` and `_head2` are
  /// the next 48 bytes. A document with another type, member order or leading whitespace approves
  /// nothing. The check runs alone, so no path reaches the signature.
  function check_RefusesAnyChangeInTheFirstWordOfTheHead(uint256 _delta, bytes32 _head1, bytes16 _head2) external view {
    bytes32 _head0 = _word(_expectedHead(), 0) ^ bytes32(bound(_delta, 1, type(uint256).max));
    assert(!_clientDataPasses(abi.encodePacked(_head0, _head1, _head2, _ORIGIN_FIELDS, '}')));
  }

  /// Client data whose first 32 bytes match the head but whose next 32 differ fails the client data
  /// check, whatever follows. `_delta` is a nonzero word XORed into those bytes and `_head2` the last
  /// 16 head bytes. A challenge that renders another digest, or no digest, approves nothing. The
  /// check runs alone, so no path reaches the signature.
  function check_RefusesAnyChangeInTheSecondWordOfTheHead(uint256 _delta, bytes16 _head2) external view {
    bytes memory _head = _expectedHead();
    bytes32 _head1 = _word(_head, 32) ^ bytes32(bound(_delta, 1, type(uint256).max));
    assert(!_clientDataPasses(abi.encodePacked(_word(_head, 0), _head1, _head2, _ORIGIN_FIELDS, '}')));
  }

  /// Client data whose first 64 bytes match the head but whose last 16 head bytes differ fails the
  /// client data check. `_delta` is a nonzero value XORed into those bytes, which hold the end of the
  /// challenge and the closing quote. A challenge that is longer, padded or unterminated approves
  /// nothing. The check runs alone, so no path reaches the signature.
  function check_RefusesAnyChangeInTheLastBytesOfTheHead(uint128 _delta) external view {
    bytes memory _head = _expectedHead();
    bytes16 _head2 = bytes16(_word(_head, 64)) ^ bytes16(uint128(bound(_delta, 1, type(uint128).max)));
    assert(!_clientDataPasses(abi.encodePacked(_word(_head, 0), _word(_head, 32), _head2, _ORIGIN_FIELDS, '}')));
  }

  /// Every client data document shorter than the 80 byte head is refused, whatever its bytes. Each
  /// length from 0 to 79 keeps that many leading bytes of `_head0`, `_head1` and `_head2`. A truncated
  /// document is not an assertion over the digest, and reading past its end must not approve it.
  function check_RefusesClientDataShorterThanTheHead(bytes32 _head0, bytes32 _head1, bytes16 _head2) external view {
    bytes memory _full = abi.encodePacked(_head0, _head1, _head2);
    for (uint256 _length = 0; _length < 80; ++_length) {
      assert(!_acceptsClientData(_truncate(_full, _length)));
    }
  }

  /*///////////////////////////////////////////////////////////////
                         AUTHENTICATOR DATA
  ///////////////////////////////////////////////////////////////*/

  /// Authenticator data carrying any relying party hash other than the committed one fails the
  /// authenticator data check. `_committed` is the config's hash and `_delta` a nonzero word XORed
  /// into it to make the carried one. A passkey enrolled under another site cannot fill a place, even
  /// with a valid signature. The check runs alone, so no path reaches the signature.
  function check_RefusesAnyOtherRelyingPartyHash(bytes32 _committed, uint256 _delta) external view {
    bytes32 _carried = _committed ^ bytes32(bound(_delta, 1, type(uint256).max));
    bytes memory _authenticatorData = _buildAuthenticatorData(_carried, _FLAGS_UP_UV);
    assert(!_method.harnessAuthenticatorDataValid(_authenticatorData, _committed));
  }

  /// Any flags byte without the user present bit fails the authenticator data check, whatever its
  /// other bits and the counter. `_flags` has that bit cleared. An assertion made without a person
  /// touching the authenticator approves nothing. The check runs alone, so no path reaches the
  /// signature.
  function check_RefusesWithoutUserPresent(bytes1 _flags, bytes4 _counter) external view {
    bytes memory _authenticatorData = abi.encodePacked(_RP_ID_HASH, _flags & ~_FLAG_UP, _counter);
    assert(!_method.harnessAuthenticatorDataValid(_authenticatorData, _RP_ID_HASH));
  }

  /// Any flags byte without the user verified bit fails the authenticator data check, whatever its
  /// other bits and the counter. `_flags` has that bit cleared. An assertion made without the
  /// guardian's PIN or biometric approves nothing, so a stolen unlocked authenticator cannot fill a
  /// place. The check runs alone, so no path reaches the signature.
  function check_RefusesWithoutUserVerified(bytes1 _flags, bytes4 _counter) external view {
    bytes memory _authenticatorData = abi.encodePacked(_RP_ID_HASH, _flags & ~_FLAG_UV, _counter);
    assert(!_method.harnessAuthenticatorDataValid(_authenticatorData, _RP_ID_HASH));
  }

  /// Every authenticator data shorter than 37 bytes is refused with a returned value, not a revert.
  /// Each length from 0 to 36 keeps that many leading bytes of `_rpIdHash`, `_flags` and `_counter`,
  /// the relying party hash, flags and signature counter. A short assertion reads as one more failed
  /// check, and no field is read past its end.
  function check_RefusesShortAuthenticatorDataWithoutReverting(bytes32 _rpIdHash, bytes1 _flags, bytes4 _counter)
    external
    view
  {
    bytes memory _full = abi.encodePacked(_rpIdHash, _flags, _counter);
    for (uint256 _length = 0; _length < 37; ++_length) {
      (bool _success, bytes memory _returned) = address(_method)
        .staticcall(
          abi.encodeCall(IPolicyMethod.verify, (_config(_rpIdHash), _DIGEST, _proof(_truncate(_full, _length))))
        );
      assert(_success && _returned.length == 32);
      assert(abi.decode(_returned, (bytes32)) != bytes32(IPolicyMethod.verify.selector));
    }
  }

  /*///////////////////////////////////////////////////////////////
                              HELPERS
  ///////////////////////////////////////////////////////////////*/

  /// @notice A config with a fixed key and the given relying party hash.
  function _config(bytes32 _rpIdHash) internal pure returns (bytes memory _configBytes) {
    _configBytes = abi.encode(uint256(1), uint256(2), _rpIdHash);
  }

  /// @notice A proof over the valid client data with fixed signature scalars, which the stand-in accepts.
  function _proof(bytes memory _authenticatorData) internal pure returns (bytes memory _proofBytes) {
    _proofBytes = _encodeProof(_authenticatorData, _standardClientData(_DIGEST), 1, 1);
  }

  /// @notice The client data check's answer on `_clientDataJSON` for the digest, run alone.
  function _clientDataPasses(bytes memory _clientDataJSON) internal view returns (bool _passes) {
    _passes = _method.harnessClientDataValid(_clientDataJSON, _DIGEST);
  }

  /// @notice The verdict on client data under the committed relying party hash and both flags.
  function _acceptsClientData(bytes memory _clientDataJSON) internal view returns (bool _accepted) {
    bytes memory _authenticatorData = _buildAuthenticatorData(_RP_ID_HASH, _FLAGS_UP_UV);
    _accepted = _verdict(
      address(_method), _config(_RP_ID_HASH), _DIGEST, _encodeProof(_authenticatorData, _clientDataJSON, 1, 1)
    );
  }

  /// @notice The 80 byte head valid client data carries: the prefix, the challenge and a closing quote.
  function _expectedHead() internal pure returns (bytes memory _head) {
    _head = abi.encodePacked(_PREFIX, _renderChallenge(_DIGEST), '"');
  }

  /// @notice The first `_length` bytes of `_data`.
  function _truncate(bytes memory _data, uint256 _length) internal pure returns (bytes memory _prefix) {
    _prefix = new bytes(_length);
    for (uint256 _i = 0; _i < _length; ++_i) {
      _prefix[_i] = _data[_i];
    }
  }

  /// @notice The 32 bytes of memory starting at byte `_offset` of `_data`. Bytes past its end are
  ///         whatever memory follows, so callers keep only the bytes inside `_data`.
  function _word(bytes memory _data, uint256 _offset) internal pure returns (bytes32 _value) {
    assembly ('memory-safe') {
      _value := mload(add(add(_data, 0x20), _offset))
    }
  }
}
