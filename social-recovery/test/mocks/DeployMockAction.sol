// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

/// @notice A stand-in for the recovery action that the deployment's checks read, with each answer
///         set by the test. It answers MANAGER, AMBIRE_IMPLEMENTATION and KIT_SLOT, and ERC-165 with
///         true for every interface id except the ones the test refuses.
contract DeployMockAction {
  /// @notice The manager MANAGER answers.
  address public immutable MANAGER;
  /// @notice The implementation AMBIRE_IMPLEMENTATION answers.
  address public immutable AMBIRE_IMPLEMENTATION;
  /// @notice Whether KIT_SLOT answers the slot Ambire's helper derives for this contract's own
  ///         binding instead of the kit's own derivation.
  bool public immutable COLLIDES;

  /// @notice The interface ids supportsInterface answers false for.
  mapping(bytes4 _interfaceId => bool _refused) public refused;

  /// @param _manager The manager MANAGER answers.
  /// @param _ambireImplementation The implementation AMBIRE_IMPLEMENTATION answers.
  /// @param _collides Whether KIT_SLOT answers the slot Ambire's helper would derive.
  constructor(address _manager, address _ambireImplementation, bool _collides) {
    MANAGER = _manager;
    AMBIRE_IMPLEMENTATION = _ambireImplementation;
    COLLIDES = _collides;
  }

  /// @notice Makes supportsInterface answer false for `_interfaceId`.
  function refuse(bytes4 _interfaceId) external {
    refused[_interfaceId] = true;
  }

  /// @notice When COLLIDES is set, the low twenty bytes of keccak256(abi.encode(this, bytes(""))),
  ///         the slot Ambire's helper derives for this contract's binding. Otherwise the low twenty
  ///         bytes of keccak256(abi.encode("kit", this)), the kit's own derivation.
  function KIT_SLOT() external view returns (address _kitSlot) {
    string memory _kit = 'kit';
    _kitSlot = COLLIDES
      ? address(uint160(uint256(keccak256(abi.encode(address(this), bytes(''))))))
      : address(uint160(uint256(keccak256(abi.encode(_kit, address(this))))));
  }

  /// @notice True for every interface id the test has not refused.
  function supportsInterface(bytes4 _interfaceId) external view returns (bool _supported) {
    _supported = !refused[_interfaceId];
  }
}
