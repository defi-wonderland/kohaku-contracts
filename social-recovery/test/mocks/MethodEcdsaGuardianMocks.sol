// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

// Raw-return guardians need assembly to answer shapes Solidity's ABI encoder never produces.

// Contract guardians for the wallet method's ERC-1271 path, the path it takes when the guardian address has code.
// Every mock is stateless, so its runtime code can be etched at an arbitrary address or
// reached through an EIP-7702 delegation designator and still answer the same way.

/// @dev ERC-1271's magic value, `isValidSignature(bytes32,bytes)`.
bytes4 constant METHOD_ECDSA_ERC1271_MAGIC = 0x1626ba7e;

/// @notice A smart account guardian that says yes to everything. It answers exactly one word holding ERC-1271's
///         magic value, whatever digest and signature it is asked about.
contract MethodEcdsaMagic1271 {
  function isValidSignature(bytes32, bytes calldata) external pure returns (bytes4 _magicValue) {
    _magicValue = METHOD_ECDSA_ERC1271_MAGIC;
  }
}

/// @notice A smart account guardian that says yes and then adds a second word. The first word holds ERC-1271's
///         magic value, so the answer still counts as a yes.
contract MethodEcdsaMagicTrailing1271 {
  fallback() external {
    assembly ('memory-safe') {
      mstore(0x00, shl(224, 0x1626ba7e))
      mstore(0x20, 0x1234)
      return(0x00, 0x40)
    }
  }
}

/// @notice A smart account guardian that says no. It answers one word that is not ERC-1271's magic value.
contract MethodEcdsaWrongValue1271 {
  function isValidSignature(bytes32, bytes calldata) external pure returns (bytes4 _magicValue) {
    _magicValue = 0xffffffff;
  }
}

/// @notice A smart account guardian that answers the ABI encoding of `true`. A plain true is not ERC-1271's
///         magic value, so the answer is a no.
contract MethodEcdsaTrue1271 {
  fallback() external {
    assembly ('memory-safe') {
      mstore(0x00, 1)
      return(0x00, 0x20)
    }
  }
}

/// @notice A smart account guardian whose answer only starts like a yes. Its one word begins with the four magic
///         bytes, but its last byte is not zero, so the word is not ERC-1271's magic value.
contract MethodEcdsaDirtyMagic1271 {
  fallback() external {
    assembly ('memory-safe') {
      mstore(0x00, or(shl(224, 0x1626ba7e), 1))
      return(0x00, 0x20)
    }
  }
}

/// @notice A smart account guardian that answers only the four magic bytes. Four bytes are less than one word,
///         so the answer is a no.
contract MethodEcdsaShortMagic1271 {
  fallback() external {
    assembly ('memory-safe') {
      mstore(0x00, shl(224, 0x1626ba7e))
      return(0x00, 0x04)
    }
  }
}

/// @notice A smart account guardian that answers the first 31 bytes of the word that holds
///         ERC-1271's magic value. The answer is one byte short of a word, so it is a no.
contract MethodEcdsaThirtyOneBytes1271 {
  fallback() external {
    assembly ('memory-safe') {
      mstore(0x00, shl(224, 0x1626ba7e))
      return(0x00, 0x1f)
    }
  }
}

/// @notice A smart account guardian whose call succeeds but returns no bytes. An empty answer is a no.
contract MethodEcdsaEmpty1271 {
  fallback() external {
    assembly ('memory-safe') {
      return(0x00, 0x00)
    }
  }
}

/// @notice A smart account guardian that reverts on every call. Its revert data holds ERC-1271's magic value,
///         and the method must still read the revert as a no.
contract MethodEcdsaReverting1271 {
  fallback() external {
    assembly ('memory-safe') {
      mstore(0x00, shl(224, 0x1626ba7e))
      revert(0x00, 0x20)
    }
  }
}

/// @notice A smart account guardian controlled by one owner key. It says yes only when the owner signed exactly
///         the hash it is asked about.
/// @dev The signature must be the raw 65 bytes r, then s, then v. Its s must be at most half the curve order,
///      and v must be 27 or 28. Any other signature gets a word that is not ERC-1271's magic value.
contract MethodEcdsaOwner1271 {
  uint256 internal constant _HALF_N = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0;

  /// @notice The owner key's address.
  address public immutable OWNER;

  constructor(address _owner) {
    OWNER = _owner;
  }

  function isValidSignature(bytes32 _hash, bytes calldata _signature) external view returns (bytes4 _magicValue) {
    _magicValue = 0xffffffff;
    if (_signature.length == 65) {
      bytes32 _r = bytes32(_signature[0:32]);
      bytes32 _s = bytes32(_signature[32:64]);
      uint8 _v = uint8(_signature[64]);
      if (uint256(_s) < _HALF_N + 1 && (_v == 27 || _v == 28)) {
        address _recovered = ecrecover(_hash, _v, _r, _s);
        if (_recovered != address(0) && _recovered == OWNER) _magicValue = METHOD_ECDSA_ERC1271_MAGIC;
      }
    }
  }
}

/// @notice A smart account guardian that says yes to one hash and one signature only. Both are fixed when it is
///         deployed, so a yes proves the method passed the digest and the proof through unchanged.
contract MethodEcdsaExactArgs1271 {
  /// @notice The only hash this guardian approves.
  bytes32 public immutable EXPECTED_HASH;
  /// @notice The keccak256 of the only signature bytes this guardian approves.
  bytes32 public immutable EXPECTED_SIGNATURE_HASH;

  constructor(bytes32 _expectedHash, bytes memory _expectedSignature) {
    EXPECTED_HASH = _expectedHash;
    EXPECTED_SIGNATURE_HASH = keccak256(_expectedSignature);
  }

  function isValidSignature(bytes32 _hash, bytes calldata _signature) external view returns (bytes4 _magicValue) {
    _magicValue = 0xffffffff;
    if (_hash == EXPECTED_HASH && keccak256(_signature) == EXPECTED_SIGNATURE_HASH) {
      _magicValue = METHOD_ECDSA_ERC1271_MAGIC;
    }
  }
}
