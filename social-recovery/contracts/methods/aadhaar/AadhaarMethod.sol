// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {IPolicyMethod} from 'interfaces/IPolicyMethod.sol';
import {IAadhaarMethod} from 'contracts/methods/aadhaar/IAadhaarMethod.sol';
import {IAnonAadhaarGroth16Verifier} from 'contracts/methods/aadhaar/IAnonAadhaarGroth16Verifier.sol';
import {PolicyMethodRoles} from 'contracts/methods/roles/PolicyMethodRoles.sol';

/// @title AadhaarMethod
/// @author defi-wonderland
/// @notice This method approves a recovery with an Anon Aadhaar proof. The proof shows that the guardian holds one
///         specific Aadhaar identity. It also commits to the binding digest of the recovery.
/// @dev The config is `abi.encode(uint256 nullifier, uint256 nullifierSeed, uint256 freshnessWindow)`. It names
///      one Aadhaar identity under one seed and the longest age, in seconds, of a QR the method accepts. The holder
///      chooses the window when committing the guardian, so it is fixed in the commitment. Nobody who builds a
///      request later can change it. The proof is
///      `abi.encode(uint256[2] a, uint256[2][2] b, uint256[2] c, uint256[9] inputs)`, which is 544 bytes. The method
///      reads five of the nine inputs. They are the public-key hash at index 0, the nullifier at 1, the QR's signing
///      time at 2, the nullifier seed at 7 and the signal hash at 8. The method does not interpret inputs three
///      through six, the four disclosures. It makes no claim about what the guardian disclosed.
///      The one trusted key is the issuer's public-key hash. The key admin replaces it when the issuer rotates its
///      key. Anon Aadhaar's wrapper contract stores one public-key hash that never changes. So the method calls the
///      raw Groth16 verifier instead.
contract AadhaarMethod is PolicyMethodRoles, IAadhaarMethod {
  /*///////////////////////////////////////////////////////////////
                          STATE VARIABLES
  ///////////////////////////////////////////////////////////////*/

  /// @notice The byte length of a well-formed config. It holds three words: the nullifier, the nullifier seed and
  ///         the freshness window.
  uint256 private constant _CONFIG_LENGTH = 96;

  /// @notice The shortest freshness window a config may name, one hour in seconds. The circuit truncates the QR's
  ///         signing time to the hour, so a shorter window would refuse a QR in the hour it was signed.
  uint256 private constant _MIN_FRESHNESS_WINDOW = 1 hours;

  /// @notice The byte length of a well-formed proof. It holds seventeen words, the three points and nine inputs.
  uint256 private constant _PROOF_LENGTH = 544;

  /// @notice The position of the issuer's public-key hash in the trusted keys, the only word stored there.
  uint256 private constant _PUBKEY_HASH_KEY = 0;

  /// @notice The position of the issuer's public-key hash in the proof's public inputs.
  uint256 private constant _PUBKEY_HASH_INPUT = 0;

  /// @notice The position of the nullifier in the proof's public inputs. It names the guardian's identity
  ///         under the seed.
  uint256 private constant _NULLIFIER_INPUT = 1;

  /// @notice The position of the QR's signing time in the proof's public inputs, truncated to the hour.
  uint256 private constant _SIGNED_AT_INPUT = 2;

  /// @notice The position of the nullifier seed in the proof's public inputs.
  uint256 private constant _NULLIFIER_SEED_INPUT = 7;

  /// @notice The position of the signal hash in the proof's public inputs. It commits the proof to the
  ///         recovery's digest.
  uint256 private constant _SIGNAL_HASH_INPUT = 8;

  /// @notice The Anon Aadhaar Groth16 verifier this method calls. It is stateless code fixed by its address.
  ///         It is not a trusted party and not a trusted-key word.
  address private immutable _VERIFIER;

  /*///////////////////////////////////////////////////////////////
                             CONSTRUCTOR
  ///////////////////////////////////////////////////////////////*/

  /// @notice The constructor sets the two roles, the issuer's public-key hash and the verifier.
  /// @dev The keys go through the same check `setTrustedKeys` runs. A method never starts with keys the admin
  ///      could not set later. The constructor stores the verifier as given. The deployment checks that the
  ///      verifier is the expected contract.
  /// @param _initialOwner The pause holder.
  /// @param _initialAdmin The key admin.
  /// @param _initialKeys The trusted keys: exactly one nonzero word, the issuer's public-key hash. The check
  ///        refuses any other list.
  /// @param _verifier The Anon Aadhaar Groth16 verifier's address.
  constructor(address _initialOwner, address _initialAdmin, bytes32[] memory _initialKeys, address _verifier)
    PolicyMethodRoles(_initialOwner, _initialAdmin, _initialKeys, 'method-aadhaar', '1.0.0')
  {
    _VERIFIER = _verifier;
  }

  /*///////////////////////////////////////////////////////////////
                          EXTERNAL FUNCTIONS
  ///////////////////////////////////////////////////////////////*/

  /// @inheritdoc IPolicyMethod
  /// @dev The method answers the magic value only when three things hold. The proof's public inputs name the
  ///      stored public-key hash, the config's nullifier and seed, and this digest's signal hash. The QR's signing
  ///      time, input 2, is at most the config's freshness window before this block's timestamp. A signing time in
  ///      the future counts as fresh. The verifier answers exactly true. These checks tie a valid proof to this
  ///      issuer, this guardian, this recovery and a recently downloaded QR.
  ///      Every other case answers the zero word. That includes a config that is not 96 bytes, a proof that is not
  ///      544 bytes, and a freshness window under one hour. The circuit sets the minutes of the signing time to
  ///      zero, so a QR signed at 11:59 reads as 11:00, and a window under an hour would refuse a QR in the hour it
  ///      was signed. The method checks both lengths before it decodes either, and runs every cheap check before it
  ///      calls the verifier. The manager reads the zero word as a refusal. The method never reverts on any input.
  ///      The proof is a Groth16 proof: three curve points `a`, `b` and `c`, then the nine public inputs. `b` is a
  ///      point on the second curve, written as two pairs of coordinates. The proof bytes go to the verifier
  ///      unchanged. Their layout is already the argument encoding of `verifyProof`, with each pair of `b`
  ///      reversed, as Anon Aadhaar's packing produces it. The call carries nine inputs and no tenth.
  ///      The method never reads its own stop. Only the manager acts on it.
  function verify(bytes calldata _config, bytes32 _digest, bytes calldata _proof)
    external
    view
    returns (bytes4 _magicValue)
  {
    if (_config.length != _CONFIG_LENGTH || _proof.length != _PROOF_LENGTH) return _magicValue;
    (uint256 _nullifier, uint256 _nullifierSeed, uint256 _freshnessWindow) =
      abi.decode(_config, (uint256, uint256, uint256));
    if (_freshnessWindow < _MIN_FRESHNESS_WINDOW) return _magicValue;
    (,,, uint256[9] memory _inputs) = abi.decode(_proof, (uint256[2], uint256[2][2], uint256[2], uint256[9]));
    // A QR is stale when it is more than the window old. The test cannot overflow, since the window is any word
    // the config holds, and a signing time in the future counts as fresh.
    uint256 _signedAt = _inputs[_SIGNED_AT_INPUT];
    uint256 _now = block.timestamp;
    if (
      _inputs[_PUBKEY_HASH_INPUT] != uint256(_trustedKey(_PUBKEY_HASH_KEY)) || _inputs[_NULLIFIER_INPUT] != _nullifier
        || _inputs[_NULLIFIER_SEED_INPUT] != _nullifierSeed
        || _inputs[_SIGNAL_HASH_INPUT] != uint256(keccak256(abi.encodePacked(uint256(_digest)))) >> 3
        || (_signedAt < _now && _now - _signedAt > _freshnessWindow)
    ) return _magicValue;
    (bool _success, bytes memory _answer) =
      _VERIFIER.staticcall(abi.encodePacked(IAnonAadhaarGroth16Verifier.verifyProof.selector, _proof));
    if (_success && _answer.length == 32 && abi.decode(_answer, (uint256)) == 1) {
      _magicValue = IPolicyMethod.verify.selector;
    }
  }

  /// @inheritdoc IAadhaarMethod
  function verifier() external view returns (address _verifier) {
    _verifier = _VERIFIER;
  }

  /*///////////////////////////////////////////////////////////////
                          INTERNAL FUNCTIONS
  ///////////////////////////////////////////////////////////////*/

  /// @notice Accept only a list of one nonzero word, the issuer's public-key hash.
  /// @dev The issuer signs with one key at a time, so the method holds exactly one hash. A zero word never matches
  ///      a real proof's public-key hash. Storing it would quietly stop the method from approving anything.
  /// @param _keys The candidate trusted keys.
  function _validateTrustedKeys(bytes32[] memory _keys) internal pure override {
    require(_keys.length == 1, AadhaarMethod_InvalidTrustedKeysLength(_keys.length));
    require(_keys[_PUBKEY_HASH_KEY] != bytes32(0), AadhaarMethod_ZeroTrustedKey(_PUBKEY_HASH_KEY));
  }
}
