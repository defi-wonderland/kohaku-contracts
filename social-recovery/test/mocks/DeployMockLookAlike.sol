// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

/// @notice A look-alike of a kit contract: a different contract that passes every call on to the real one and
///         returns its answer, so it answers every view the deployment checks read exactly as the real contract
///         does, except for the selectors the test gives an answer of its own. Its code is not the kit's code,
///         which only a code hash comparison can tell.
contract DeployMockLookAlike {
  /// @notice The contract every call is passed on to.
  address public immutable TARGET;

  /// @notice The raw return data a selector answers instead of the target's answer.
  mapping(bytes4 _selector => bytes _answer) internal _answers;
  /// @notice Whether a selector answers its own return data.
  mapping(bytes4 _selector => bool _set) internal _answered;

  /// @param _target The contract every call is passed on to.
  constructor(address _target) {
    TARGET = _target;
  }

  /// @notice Makes calls with `_selector` return `_answer` as raw return data instead of the target's answer.
  function setAnswer(bytes4 _selector, bytes calldata _answer) external {
    _answers[_selector] = _answer;
    _answered[_selector] = true;
  }

  /// @notice Returns the answer set for the call's selector, or passes the call on to the target and returns or
  ///         reverts with exactly what the target gave.
  fallback(bytes calldata _data) external returns (bytes memory _result) {
    _result = _answerOrForward(_data);
  }

  /// @notice The answer set for `_data`'s selector, or the target's answer to `_data`, bubbling its revert.
  function _answerOrForward(bytes calldata _data) internal returns (bytes memory _result) {
    if (_data.length > 3 && _answered[bytes4(_data[:4])]) return _answers[bytes4(_data[:4])];
    bool _success;
    (_success, _result) = TARGET.call(_data);
    if (!_success) {
      assembly {
        revert(add(_result, 32), mload(_result))
      }
    }
  }
}
