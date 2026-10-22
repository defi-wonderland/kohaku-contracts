// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {Base64} from '@openzeppelin/contracts/utils/Base64.sol';
import {ERC165} from '@openzeppelin/contracts/utils/introspection/ERC165.sol';
import {IPolicyMethod} from 'interfaces/IPolicyMethod.sol';

/// @title PasskeyMethod
/// @author defi-wonderland
/// @notice The passkey method lets a guardian approve a recovery step with a passkey. A passkey is a
///         P-256 key pair kept by the guardian's device or password manager. The device uses the
///         private key only after the guardian unlocks it, and the key never leaves the device.
///         This contract checks that the guardian's passkey signed the digest it is given.
/// @dev The config is `abi.encode(uint256 x, uint256 y, bytes32 rpIdHash)`. The words x and y are
///      the passkey's public key, so only that passkey can produce a valid signature. The word
///      rpIdHash is the sha256 hash of the domain the passkey was created for. A passkey created
///      for another site reports another hash, so it never counts here.
///
///      The proof is `abi.encode(bytes authenticatorData, bytes clientDataJSON, uint256 r, uint256 s)`,
///      a WebAuthn assertion. The authenticator, the device part that holds the key, writes the
///      authenticatorData. The browser writes the clientDataJSON. The words r and s are the
///      signature.
///
///      The authenticator never signs the digest directly. It signs
///      sha256(authenticatorData || sha256(clientDataJSON)). The digest travels inside
///      clientDataJSON as the challenge, so this contract checks the challenge and then the
///      signature over both pieces.
///
///      The signature counter in authenticatorData is not checked. Synced passkeys, such as the
///      ones iCloud or Google keep, always report zero, so a counter check would refuse them.
///
///      The method holds no storage, trusts no key and has no pause. It does not check the origin.
contract PasskeyMethod is IPolicyMethod, ERC165 {
  /*///////////////////////////////////////////////////////////////
                              CONSTANTS
  ///////////////////////////////////////////////////////////////*/

  /// @notice The address of the P256VERIFY precompile, which checks P-256 signatures.
  address private constant _P256_VERIFY = address(0x100);

  /// @notice The two flag bits every assertion must set. Bit 0, user present, says someone was
  ///         there and confirmed. Bit 2, user verified, says that person also unlocked the passkey
  ///         with biometrics or a PIN. The method requires both, since presence alone could be a
  ///         stranger touching a security key.
  bytes1 private constant _REQUIRED_FLAGS = 0x05;

  /// @notice Bit 3, backup eligible. The authenticator sets it when the passkey may be synced or
  ///         backed up, as iCloud and Google passkeys are.
  bytes1 private constant _BACKUP_ELIGIBLE_FLAG = 0x08;

  /// @notice Bit 4, backup state. The authenticator sets it when the passkey is currently backed
  ///         up. An authenticator that says backed up but not eligible contradicts itself, so the
  ///         method refuses that answer.
  bytes1 private constant _BACKUP_STATE_FLAG = 0x10;

  /// @notice The exact config length in bytes: three words, the key's x and y and the domain hash.
  uint256 private constant _CONFIG_LENGTH = 96;

  /// @notice Where the flags byte sits in authenticatorData. It comes right after the 32-byte
  ///         domain hash.
  uint256 private constant _FLAGS_OFFSET = 32;

  /// @notice The shortest authenticatorData that holds its three fixed fields: the 32-byte domain
  ///         hash, the flags byte and the four-byte signature counter.
  uint256 private constant _MIN_AUTHENTICATOR_DATA_LENGTH = 37;

  /// @notice The bytes clientDataJSON must begin with. The browser writes the type first and the
  ///         challenge second. The type webauthn.get marks a use of the passkey, not its creation.
  ///         These bytes stop at the opening quote of the challenge value.
  bytes private constant _CLIENT_DATA_PREFIX = '{"type":"webauthn.get","challenge":"';

  /*///////////////////////////////////////////////////////////////
                          EXTERNAL FUNCTIONS
  ///////////////////////////////////////////////////////////////*/

  /// @inheritdoc IPolicyMethod
  /// @dev The checks run cheapest first and the signature last. Each part of the proof binds
  ///      something different.
  ///
  ///      1. The config must be exactly 96 bytes. Any other length gets a word other than the magic
  ///         value before anything is decoded.
  ///      2. authenticatorData binds the site and a verified person. It must start with the
  ///         committed rpIdHash, and its flags must say a person was present and unlocked the
  ///         passkey.
  ///      3. clientDataJSON binds this exact request. Its challenge must be this digest, and its
  ///         type must be webauthn.get, which marks a use of the passkey and not its creation.
  ///      4. The signature binds the two together. It covers authenticatorData and the hash of
  ///         clientDataJSON, so changing either one breaks it.
  ///
  ///      A malformed config, too short authenticatorData or clientDataJSON, and any failed check
  ///      all get a word other than the magic value, never a revert. Only a proof that does not
  ///      decode as its four fields reverts, and a caller reads that revert as a refusal too.
  function verify(bytes calldata _config, bytes32 _digest, bytes calldata _proof)
    external
    view
    returns (bytes4 _magicValue)
  {
    if (_config.length != _CONFIG_LENGTH) return bytes4(0);
    (uint256 _x, uint256 _y, bytes32 _rpIdHash) = abi.decode(_config, (uint256, uint256, bytes32));
    (bytes memory _authenticatorData, bytes memory _clientDataJSON, uint256 _r, uint256 _s) =
      abi.decode(_proof, (bytes, bytes, uint256, uint256));

    if (!_authenticatorDataValid(_authenticatorData, _rpIdHash) || !_clientDataValid(_clientDataJSON, _digest)) {
      return bytes4(0);
    }
    // Only a successful call that returns exactly one word equal to 1 counts. On a chain without
    // the P256VERIFY precompile, the call to its empty address succeeds and returns nothing, so
    // success alone would approve any signature. Both halves of s are accepted, since many
    // authenticators sign with either, and the digest ties every signature to one request.
    bytes32 _hash = sha256(abi.encodePacked(_authenticatorData, sha256(_clientDataJSON)));
    (bool _success, bytes memory _result) = _P256_VERIFY.staticcall(abi.encode(_hash, _r, _s, _x, _y));
    bool _approved = _success && _result.length == 32 && abi.decode(_result, (uint256)) == 1;

    _magicValue = _approved ? IPolicyMethod.verify.selector : bytes4(0);
  }

  /// @inheritdoc IPolicyMethod
  function trustedParties()
    external
    pure
    returns (
      address _admin,
      address _pendingAdmin,
      bytes32[] memory _trustedKeys,
      address _pauseHolder,
      address _pendingPauseHolder
    )
  {
    _trustedKeys = new bytes32[](0);
    (_admin, _pendingAdmin, _pauseHolder, _pendingPauseHolder) = (address(0), address(0), address(0), address(0));
  }

  /// @inheritdoc IPolicyMethod
  function name() external pure returns (string memory _moduleName) {
    _moduleName = 'method-passkey';
  }

  /// @inheritdoc IPolicyMethod
  function version() external pure returns (string memory _moduleVersion) {
    _moduleVersion = '1.0.0';
  }

  /*///////////////////////////////////////////////////////////////
                           PUBLIC FUNCTIONS
  ///////////////////////////////////////////////////////////////*/

  /// @inheritdoc IPolicyMethod
  function supportsInterface(bytes4 _interfaceId)
    public
    view
    override(ERC165, IPolicyMethod)
    returns (bool _supported)
  {
    _supported =
      _interfaceId == type(IPolicyMethod).interfaceId || super.supportsInterface(_interfaceId);
  }

  /*///////////////////////////////////////////////////////////////
                          INTERNAL FUNCTIONS
  ///////////////////////////////////////////////////////////////*/

  /// @notice Checks that authenticatorData names the right site and a verified person.
  /// @dev The data must be long enough to hold its three fixed fields, or the check fails. Its
  ///      first 32 bytes must equal the committed domain hash, so an assertion made for another
  ///      site fails. In its flags byte, the user present and user verified bits must both be set,
  ///      so a stranger touching a security key does not count. The backup state bit must not be
  ///      set while the backup eligible bit is clear, since a passkey cannot be backed up when it
  ///      may not be.
  /// @param _authenticatorData The authenticatorData from the assertion.
  /// @param _rpIdHash The domain hash the config commits.
  /// @return _valid True when all three checks pass.
  function _authenticatorDataValid(bytes memory _authenticatorData, bytes32 _rpIdHash)
    internal
    pure
    returns (bool _valid)
  {
    if (_authenticatorData.length < _MIN_AUTHENTICATOR_DATA_LENGTH || _leadingWord(_authenticatorData) != _rpIdHash) {
      return _valid;
    }
    bytes1 _flags = _authenticatorData[_FLAGS_OFFSET];
    _valid = _flags & _REQUIRED_FLAGS == _REQUIRED_FLAGS
      && (_flags & _BACKUP_ELIGIBLE_FLAG == _BACKUP_ELIGIBLE_FLAG || _flags & _BACKUP_STATE_FLAG == 0);
  }

  /// @notice Checks that clientDataJSON is a use of the passkey whose challenge is this digest.
  /// @dev The check builds the exact start the browser writes for this digest: the type
  ///      webauthn.get, then the challenge, which is the digest in base64url without padding,
  ///      then its closing quote. clientDataJSON must begin with exactly those bytes. The start
  ///      must be exact because it pins both the type and the challenge. The bytes after it, such
  ///      as the origin, are signed but not checked. Data shorter than the start fails.
  /// @param _clientDataJSON The clientDataJSON from the assertion, in the exact bytes the
  ///        authenticator hashed and signed.
  /// @param _digest The digest the proof must approve.
  /// @return _valid True when clientDataJSON begins with the expected bytes.
  function _clientDataValid(bytes memory _clientDataJSON, bytes32 _digest) internal pure returns (bool _valid) {
    bytes memory _expected = abi.encodePacked(_CLIENT_DATA_PREFIX, Base64.encodeURL(abi.encodePacked(_digest)), '"');
    _valid = !(_clientDataJSON.length < _expected.length)
      && _leadingHash(_clientDataJSON, _expected.length) == keccak256(_expected);
  }

  /*///////////////////////////////////////////////////////////////
                          PRIVATE FUNCTIONS
  ///////////////////////////////////////////////////////////////*/

  /// @notice Reads the first 32 bytes of a byte string as one word.
  /// @dev The caller checks that the byte string holds at least 32 bytes. Shorter data would read
  ///      past its end.
  /// @param _data The byte string.
  /// @return _word The first 32 bytes of `_data`.
  function _leadingWord(bytes memory _data) private pure returns (bytes32 _word) {
    assembly ('memory-safe') {
      _word := mload(add(_data, 0x20))
    }
  }

  /// @notice Hashes the first bytes of a byte string.
  /// @dev The caller checks that the byte string holds at least `_length` bytes.
  /// @param _data The byte string.
  /// @param _length The number of leading bytes to hash.
  /// @return _hash The keccak256 hash of the first `_length` bytes of `_data`.
  function _leadingHash(bytes memory _data, uint256 _length) private pure returns (bytes32 _hash) {
    assembly ('memory-safe') {
      _hash := keccak256(add(_data, 0x20), _length)
    }
  }
}
