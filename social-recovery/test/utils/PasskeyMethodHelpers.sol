// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {Test} from 'forge-std/Test.sol';
import {IPolicyMethod} from 'interfaces/IPolicyMethod.sol';

/// @notice Builders for WebAuthn assertions in the shape the frozen passkey vectors carry: a 37 byte
///         authenticator data of rpIdHash, flags and a four byte signature counter, a client data JSON
///         document, and a P-256 signature over sha256(authenticatorData || sha256(clientDataJSON)).
/// @dev The base64url renderer here is written independently of the method under test and is
///      checked against the RFC 4648 examples in PasskeyMethodBase64UrlTest. None of these helpers
///      decides a verdict: each test states the verdict it expects.
abstract contract PasskeyMethodHelpers is Test {
  /// @dev The order of the P-256 group.
  uint256 internal constant _P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551;
  /// @dev The P256VERIFY precompile the method calls (EIP-7951, active under osaka).
  address internal constant _P256_VERIFY = address(0x100);
  /// @dev The user-present flag bit of the authenticator data.
  bytes1 internal constant _FLAG_UP = 0x01;
  /// @dev The user-verified flag bit of the authenticator data.
  bytes1 internal constant _FLAG_UV = 0x04;
  /// @dev The backup eligibility flag bit: the credential may be synced to other devices.
  bytes1 internal constant _FLAG_BE = 0x08;
  /// @dev The backup state flag bit: the credential is synced today. WebAuthn allows it only beside backup eligibility.
  bytes1 internal constant _FLAG_BS = 0x10;
  /// @dev The flags byte a valid assertion carries in the vectors.
  bytes1 internal constant _FLAGS_UP_UV = 0x05;
  /// @dev The client data fields after the challenge in a browser-made assertion.
  string internal constant _ORIGIN_FIELDS = ',"origin":"https://recover.example","crossOrigin":false';
  /// @dev The trailing extra field the valid vector carries.
  string internal constant _EXTRA_FIELD = ',"extra":"kept"';

  /// @dev The WebAuthn base64url alphabet, RFC 4648 section 5.
  bytes internal constant _BASE64URL_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
  /// @dev The standard base64 alphabet, RFC 4648 section 4.
  bytes internal constant _BASE64_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

  /// @notice Render bytes in base64 with the given alphabet and no padding.
  function _base64NoPad(bytes memory _data, bytes memory _alphabet) internal pure returns (string memory _encoded) {
    uint256 _bits = _data.length * 8;
    uint256 _outLength = (_bits + 5) / 6;
    bytes memory _out = new bytes(_outLength);
    for (uint256 _i = 0; _i < _outLength; ++_i) {
      uint256 _position = _i * 6;
      uint256 _byteIndex = _position / 8;
      uint256 _offset = _position % 8;
      uint256 _window = uint256(uint8(_data[_byteIndex])) << 8;
      if (_byteIndex + 1 < _data.length) _window |= uint256(uint8(_data[_byteIndex + 1]));
      uint256 _sextet = (_window >> (10 - _offset)) & 0x3f;
      _out[_i] = _alphabet[_sextet];
    }
    _encoded = string(_out);
  }

  /// @notice WebAuthn's base64url rendering without padding.
  function _base64Url(bytes memory _data) internal pure returns (string memory _encoded) {
    _encoded = _base64NoPad(_data, _BASE64URL_ALPHABET);
  }

  /// @notice The challenge text a client data document carries for a digest.
  function _renderChallenge(bytes32 _digest) internal pure returns (string memory _challenge) {
    _challenge = _base64Url(abi.encodePacked(_digest));
  }

  /// @notice A client data document with the fields in the order browsers write them.
  function _clientData(string memory _clientType, string memory _challenge, string memory _tail)
    internal
    pure
    returns (bytes memory _clientDataJSON)
  {
    _clientDataJSON = bytes(string.concat('{"type":"', _clientType, '","challenge":"', _challenge, '"', _tail, '}'));
  }

  /// @notice The standard assertion client data for a digest, no extra field.
  function _standardClientData(bytes32 _digest) internal pure returns (bytes memory _clientDataJSON) {
    _clientDataJSON = _clientData('webauthn.get', _renderChallenge(_digest), _ORIGIN_FIELDS);
  }

  /// @notice The client data of the valid vector's shape, with a trailing extra field.
  function _extraFieldClientData(bytes32 _digest) internal pure returns (bytes memory _clientDataJSON) {
    _clientDataJSON =
      _clientData('webauthn.get', _renderChallenge(_digest), string.concat(_ORIGIN_FIELDS, _EXTRA_FIELD));
  }

  /// @notice Authenticator data: rpIdHash, flags and a zero four-byte signature counter.
  function _buildAuthenticatorData(bytes32 _rpIdHash, bytes1 _flags)
    internal
    pure
    returns (bytes memory _authenticatorData)
  {
    _authenticatorData = _buildAuthenticatorData(_rpIdHash, _flags, bytes4(0));
  }

  /// @notice Authenticator data: rpIdHash, flags and the given four-byte signature counter.
  function _buildAuthenticatorData(bytes32 _rpIdHash, bytes1 _flags, bytes4 _counter)
    internal
    pure
    returns (bytes memory _authenticatorData)
  {
    _authenticatorData = abi.encodePacked(_rpIdHash, _flags, _counter);
  }

  /// @notice The message a passkey signs: sha256(authenticatorData || sha256(clientDataJSON)).
  function _hashAssertion(bytes memory _authenticatorData, bytes memory _clientDataJSON)
    internal
    pure
    returns (bytes32 _signedHash)
  {
    _signedHash = sha256(abi.encodePacked(_authenticatorData, sha256(_clientDataJSON)));
  }

  /// @notice Sign a message hash with a P-256 key, returning the low signature half.
  function _signLow(uint256 _privateKey, bytes32 _messageHash) internal pure returns (uint256 _r, uint256 _s) {
    (bytes32 _rWord, bytes32 _sWord) = vm.signP256(_privateKey, _messageHash);
    _r = uint256(_rWord);
    _s = uint256(_sWord);
    if (_s > _P256_N / 2) _s = _P256_N - _s;
  }

  /// @notice Sign an assertion with a P-256 key, returning the low signature half.
  function _signAssertion(uint256 _privateKey, bytes memory _authenticatorData, bytes memory _clientDataJSON)
    internal
    pure
    returns (uint256 _r, uint256 _s)
  {
    (_r, _s) = _signLow(_privateKey, _hashAssertion(_authenticatorData, _clientDataJSON));
  }

  /// @notice The config of a passkey credential: abi.encode(uint256 x, uint256 y, bytes32 rpIdHash).
  function _buildConfig(uint256 _privateKey, bytes32 _rpIdHash) internal pure returns (bytes memory _config) {
    (uint256 _x, uint256 _y) = vm.publicKeyP256(_privateKey);
    _config = abi.encode(_x, _y, _rpIdHash);
  }

  /// @notice The proof of a passkey credential:
  ///         abi.encode(bytes authenticatorData, bytes clientDataJSON, uint256 r, uint256 s).
  function _encodeProof(bytes memory _authenticatorData, bytes memory _clientDataJSON, uint256 _r, uint256 _s)
    internal
    pure
    returns (bytes memory _proof)
  {
    _proof = abi.encode(_authenticatorData, _clientDataJSON, _r, _s);
  }

  /// @notice Sign and encode a proof in one step, with the low signature half.
  function _signedProof(uint256 _privateKey, bytes memory _authenticatorData, bytes memory _clientDataJSON)
    internal
    pure
    returns (bytes memory _proof)
  {
    (uint256 _r, uint256 _s) = _signAssertion(_privateKey, _authenticatorData, _clientDataJSON);
    _proof = _encodeProof(_authenticatorData, _clientDataJSON, _r, _s);
  }

  /// @notice Read a verdict the way the policy manager reads it: a successful static call returning
  ///         exactly one word that is the verify selector is an approval, and anything else, a revert
  ///         or an empty return included, is a refusal.
  function _verdict(address _methodAddress, bytes memory _config, bytes32 _digest, bytes memory _proof)
    internal
    view
    returns (bool _accepted)
  {
    (bool _success, bytes memory _returned) =
      _methodAddress.staticcall(abi.encodeCall(IPolicyMethod.verify, (_config, _digest, _proof)));
    _accepted =
      _success && _returned.length == 32 && abi.decode(_returned, (bytes32)) == bytes32(IPolicyMethod.verify.selector);
  }

  /// @notice A string of `_length` copies of the letter a.
  function _letterRun(uint256 _length) internal pure returns (string memory _letters) {
    bytes memory _out = new bytes(_length);
    for (uint256 _i = 0; _i < _length; ++_i) {
      _out[_i] = 'a';
    }
    _letters = string(_out);
  }

  /// @notice A valid P-256 private key, between 1 and the group order minus 1, built from any seed.
  function _boundKey(uint256 _seed) internal pure returns (uint256 _privateKey) {
    _privateKey = bound(_seed, 1, _P256_N - 1);
  }
}
