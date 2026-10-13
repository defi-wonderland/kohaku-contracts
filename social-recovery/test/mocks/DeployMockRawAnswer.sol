// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

/// @notice A contract with no function of its own that answers every call with the same raw return
///         data the test sets, unencoded: no bytes, one word with bits above an address, or any other
///         bytes. It stands for an address that holds a contract which does not answer the views the
///         deployment checks read the way the kit's contract does.
contract DeployMockRawAnswer {
  /// @notice The raw return data every call answers.
  bytes internal _answer;

  /// @param _rawAnswer The raw return data every call answers.
  constructor(bytes memory _rawAnswer) {
    _answer = _rawAnswer;
  }

  /// @notice Returns the raw answer for any calldata.
  fallback(bytes calldata) external returns (bytes memory _result) {
    _result = _answer;
  }
}
