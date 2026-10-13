// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

/// @notice A guardian that is a smart wallet, not a key. It answers ERC-1271 for a 65-byte signature
///         r || s || v by its current owner over the exact hash asked about. Its owner can hand the
///         wallet to another key, and from then on the wallet answers for the new owner.
contract IntegrationSmartWalletGuardian {
  /*///////////////////////////////////////////////////////////////
                          STATE VARIABLES
  ///////////////////////////////////////////////////////////////*/

  /// @notice ERC-1271's magic value, the selector of isValidSignature(bytes32,bytes).
  bytes4 public constant MAGIC_VALUE = 0x1626ba7e;
  /// @notice The key that signs for the wallet today.
  address public owner;

  /*///////////////////////////////////////////////////////////////
                              EVENTS
  ///////////////////////////////////////////////////////////////*/

  /// @notice The wallet changed hands.
  event OwnerChanged(address indexed _previousOwner, address indexed _newOwner);

  /*///////////////////////////////////////////////////////////////
                              ERRORS
  ///////////////////////////////////////////////////////////////*/

  /// @notice A caller other than the owner tried to hand the wallet on.
  error IntegrationSmartWalletGuardian_NotOwner(address _caller);

  /*///////////////////////////////////////////////////////////////
                            CONSTRUCTOR
  ///////////////////////////////////////////////////////////////*/

  constructor(address _owner) {
    owner = _owner;
  }

  /*///////////////////////////////////////////////////////////////
                        EXTERNAL FUNCTIONS
  ///////////////////////////////////////////////////////////////*/

  /// @notice Hands the wallet to `_newOwner`. Only the current owner may call it.
  function setOwner(address _newOwner) external {
    require(msg.sender == owner, IntegrationSmartWalletGuardian_NotOwner(msg.sender));
    emit OwnerChanged(owner, _newOwner);
    owner = _newOwner;
  }

  /// @notice Answers the magic value when the current owner signed `_hash`, and zero otherwise.
  function isValidSignature(bytes32 _hash, bytes calldata _signature) external view returns (bytes4 _magicValue) {
    if (_signature.length != 65) return _magicValue;
    (bytes32 _r, bytes32 _s) = (bytes32(_signature[0:32]), bytes32(_signature[32:64]));
    address _signer = ecrecover(_hash, uint8(_signature[64]), _r, _s);
    if (_signer != address(0) && _signer == owner) _magicValue = MAGIC_VALUE;
  }
}
