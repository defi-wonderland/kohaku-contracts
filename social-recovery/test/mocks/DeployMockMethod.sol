// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

/// @notice A stand-in for a method whose trustedParties answer the test sets field by field, and
///         which answers ERC-165 with true for every interface id except the ones the test refuses.
///         Every field starts empty, the answer of a method that declares no role and no key. Its
///         name answers what the test sets, empty by default, and reverts once the test asks it to.
contract DeployMockMethod {
  string internal _name;
  bool internal _nameReverts;
  address internal _admin;
  address internal _pendingAdmin;
  bytes32[] internal _trustedKeys;
  address internal _pauseHolder;
  address internal _pendingPauseHolder;

  /// @notice The interface ids supportsInterface answers false for.
  mapping(bytes4 _interfaceId => bool _refused) public refused;

  /// @notice The revert name gives once revertName was called.
  error DeployMockMethod_NameReverts();

  /// @notice Makes name answer `_newName`.
  function setName(string calldata _newName) external {
    _name = _newName;
  }

  /// @notice Makes name revert.
  function revertName() external {
    _nameReverts = true;
  }

  /// @notice Declares `_newAdmin` as the key admin.
  function setAdmin(address _newAdmin) external {
    _admin = _newAdmin;
  }

  /// @notice Declares `_newPendingAdmin` as the pending key admin.
  function setPendingAdmin(address _newPendingAdmin) external {
    _pendingAdmin = _newPendingAdmin;
  }

  /// @notice Adds `_key` to the trusted key list.
  function addTrustedKey(bytes32 _key) external {
    _trustedKeys.push(_key);
  }

  /// @notice Declares `_newPauseHolder` as the pause holder.
  function setPauseHolder(address _newPauseHolder) external {
    _pauseHolder = _newPauseHolder;
  }

  /// @notice Declares `_newPendingPauseHolder` as the pending pause holder.
  function setPendingPauseHolder(address _newPendingPauseHolder) external {
    _pendingPauseHolder = _newPendingPauseHolder;
  }

  /// @notice Makes supportsInterface answer false for `_interfaceId`.
  function refuse(bytes4 _interfaceId) external {
    refused[_interfaceId] = true;
  }

  /// @notice The name the test set, or a revert once revertName was called.
  function name() external view returns (string memory _answer) {
    require(!_nameReverts, DeployMockMethod_NameReverts());
    _answer = _name;
  }

  /// @notice The five values the test set, in the order of IPolicyMethod.trustedParties.
  function trustedParties()
    external
    view
    returns (
      address _declaredAdmin,
      address _declaredPendingAdmin,
      bytes32[] memory _declaredKeys,
      address _declaredPauseHolder,
      address _declaredPendingPauseHolder
    )
  {
    _declaredAdmin = _admin;
    _declaredPendingAdmin = _pendingAdmin;
    _declaredKeys = _trustedKeys;
    _declaredPauseHolder = _pauseHolder;
    _declaredPendingPauseHolder = _pendingPauseHolder;
  }

  /// @notice True for every interface id the test has not refused.
  function supportsInterface(bytes4 _interfaceId) external view returns (bool _supported) {
    _supported = !refused[_interfaceId];
  }
}
