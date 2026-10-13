// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {PolicyMethodRoles} from 'contracts/methods/roles/PolicyMethodRoles.sol';

/// @notice A subclass of the roles base for tests only. The base leaves its key validation hook to each
///         method, so this subclass supplies a hook the tests can observe. The hook refuses one marker word
///         at any position of the key list. When the test arms it, the hook also reverts unless the keys
///         already in storage hash to a value the test fixed beforehand. This shows whether setTrustedKeys
///         stored the new keys before it asked the hook.
contract MethodRolesHarness is PolicyMethodRoles {
  /*///////////////////////////////////////////////////////////////
                          STATE VARIABLES
  ///////////////////////////////////////////////////////////////*/

  /// @notice The one word this hook refuses.
  bytes32 public constant MARKER = keccak256('method-roles.harness.marker');

  /// @notice Whether the hook checks the stored keys against `_probeExpectedHash`.
  bool internal _probeArmed;

  /// @notice The hash the stored keys must have while the armed hook runs.
  bytes32 internal _probeExpectedHash;

  /*///////////////////////////////////////////////////////////////
                               ERRORS
  ///////////////////////////////////////////////////////////////*/

  /// @notice The hook met the marker at this position of the key list.
  error MethodRolesHarness_MarkerKeyRefused(uint256 _index, bytes32 _key);

  /// @notice The hook found keys in storage other than the ones the test expected there.
  error MethodRolesHarness_HookSawStoredKeys(bytes32 _storedHash, bytes32 _expectedHash);

  /*///////////////////////////////////////////////////////////////
                            CONSTRUCTOR
  ///////////////////////////////////////////////////////////////*/

  /// @dev Hands every argument to the roles base unchanged.
  constructor(
    address _initialOwner,
    address _initialAdmin,
    bytes32[] memory _initialKeys,
    string memory _moduleName,
    string memory _moduleVersion
  ) PolicyMethodRoles(_initialOwner, _initialAdmin, _initialKeys, _moduleName, _moduleVersion) {}

  /*///////////////////////////////////////////////////////////////
                         EXTERNAL FUNCTIONS
  ///////////////////////////////////////////////////////////////*/

  /// @notice Arm the stored-keys probe with the hash of the keys expected in storage when the
  ///         hook runs. The hash is keccak256 over the tightly packed key words.
  function armProbe(bytes32 _expectedStoredHash) external {
    _probeArmed = true;
    _probeExpectedHash = _expectedStoredHash;
  }

  /// @notice Returns the stored trusted key at `_index` through the base's internal getter. The getter
  ///         reverts with the array bounds panic when `_index` is at or past the end of the list.
  function trustedKey(uint256 _index) external view returns (bytes32 _key) {
    _key = _trustedKey(_index);
  }

  /// @notice A verifier that approves nothing, since the roles base leaves verify to each method.
  function verify(bytes calldata, bytes32, bytes calldata) external pure override returns (bytes4 _magicValue) {
    _magicValue = bytes4(0);
  }

  /*///////////////////////////////////////////////////////////////
                         INTERNAL FUNCTIONS
  ///////////////////////////////////////////////////////////////*/

  /// @dev Refuses the marker word at any position of `_keys`, naming the position. When the probe is
  ///      armed, it also refuses unless the keys already in storage hash to the value the test fixed.
  function _validateTrustedKeys(bytes32[] memory _keys) internal view override {
    for (uint256 _i = 0; _i < _keys.length; _i++) {
      require(_keys[_i] != MARKER, MethodRolesHarness_MarkerKeyRefused(_i, _keys[_i]));
    }
    if (_probeArmed) {
      (,, bytes32[] memory _stored,,) = this.trustedParties();
      bytes32 _storedHash = keccak256(abi.encodePacked(_stored));
      require(_storedHash == _probeExpectedHash, MethodRolesHarness_HookSawStoredKeys(_storedHash, _probeExpectedHash));
    }
  }
}
