// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

/// @notice A stand-in for a zkPassport contract the identity script reads. Each read the test configures answers
///         with an address, or fails in one of four ways: it reverts, answers nothing, answers a word with a bit
///         set above the twenty address bytes, or answers the address followed by a second word. A read the test
///         did not configure reverts. The two version-keyed reads answer only for the version the test names, and
///         answer the zero word for any other.
abstract contract DeployIdentityMockLiveReads {
  /// @notice How a read answers.
  enum Mode {
    Unset,
    Value,
    Revert,
    Empty,
    DirtyWord,
    TwoWords
  }

  /// @notice A configured answer: the mode and the address it carries.
  struct Answer {
    Mode mode;
    address value;
  }

  /// @notice The version the version-keyed reads answer for.
  bytes32 public version;

  /// @notice The configured answer of each read, by its selector.
  mapping(bytes4 _selector => Answer _answer) public answers;

  /// @notice The revert a read raises when it is configured to revert or not configured at all.
  error DeployIdentityMockLiveReads_Refused(bytes4 _selector);

  /// @notice Sets the version the version-keyed reads answer for.
  function setVersion(bytes32 _version) external {
    version = _version;
  }

  /// @notice Makes the read `_selector` answer `_value` in mode `_mode`.
  function setAnswer(bytes4 _selector, Mode _mode, address _value) external {
    answers[_selector] = Answer({mode: _mode, value: _value});
  }

  /// @notice Answers any read as configured.
  fallback() external {
    _giveAnswer();
  }

  /// @notice Reverts, or returns the configured answer, for the read the calldata names.
  function _giveAnswer() internal view {
    Answer memory _answer = answers[msg.sig];
    require(_answer.mode != Mode.Unset && _answer.mode != Mode.Revert, DeployIdentityMockLiveReads_Refused(msg.sig));
    uint256 _word = uint256(uint160(_answer.value));
    if (msg.data.length == 36 && _isKeyedByVersion(msg.sig) && bytes32(msg.data[4:36]) != version) _word = 0;
    if (_answer.mode == Mode.Empty) {
      assembly {
        return(0, 0)
      }
    }
    if (_answer.mode == Mode.DirtyWord) _word |= uint256(1) << 160;
    uint256 _size = _answer.mode == Mode.TwoWords ? 64 : 32;
    assembly {
      mstore(0, _word)
      mstore(32, 0)
      return(0, _size)
    }
  }

  /// @notice Whether a read takes the version as its argument.
  function _isKeyedByVersion(bytes4 _selector) internal pure virtual returns (bool _keyed);
}

/// @notice A stand-in for zkPassport's root verifier, with the five reads the identity script makes:
///         getSubVerifier(bytes32), getHelper(bytes32), rootRegistry(), admin() and guardian().
contract DeployIdentityMockRootVerifier is DeployIdentityMockLiveReads {
  /// @notice getSubVerifier(bytes32) and getHelper(bytes32) take the version.
  function _isKeyedByVersion(bytes4 _selector) internal pure override returns (bool _keyed) {
    _keyed =
      _selector == bytes4(keccak256('getSubVerifier(bytes32)')) || _selector == bytes4(keccak256('getHelper(bytes32)'));
  }
}

/// @notice A stand-in for a zkPassport sub-verifier, with the one read the identity script makes: admin().
contract DeployIdentityMockSubVerifier is DeployIdentityMockLiveReads {
  /// @notice No read of a sub-verifier takes the version.
  function _isKeyedByVersion(bytes4) internal pure override returns (bool _keyed) {
    _keyed = false;
  }
}
