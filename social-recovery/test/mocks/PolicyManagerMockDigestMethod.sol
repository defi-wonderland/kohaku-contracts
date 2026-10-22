// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {IPolicyMethod} from 'interfaces/IPolicyMethod.sol';

/// @notice Mock of an honest method for the invariant suite. It approves a proof only when the
///         proof is the seal of this exact config and this exact digest, the way a real method
///         binds its verdict to both, and anyone may choose how it answers the pause read. The seal
///         is keccak256(abi.encode(config, digest)), so any instance accepts the seal any other
///         instance accepts: only the manager's check that the committed method runs keeps a
///         swapped-in instance from counting.
/// @dev The pause answers cover the shapes a manager must tell apart: exactly one word holding the
///      encoding of true is a stop, and every other answer, a false word, a revert, a revert
///      carrying the encoding of true, nothing, less than a word, another word or true followed by
///      more bytes, is not.
contract PolicyManagerMockDigestMethod {
  /*///////////////////////////////////////////////////////////////
                              CONSTANTS
  ///////////////////////////////////////////////////////////////*/

  /// @notice The pause read returns one word holding the encoding of false.
  uint8 public constant ANSWER_FALSE = 0;
  /// @notice The pause read returns exactly one word holding the encoding of true: a stop.
  uint8 public constant ANSWER_TRUE = 1;
  /// @notice The pause read reverts with no data.
  uint8 public constant ANSWER_REVERT = 2;
  /// @notice The pause read reverts carrying the encoding of true.
  uint8 public constant ANSWER_REVERT_WITH_TRUE = 3;
  /// @notice The pause read succeeds and returns nothing.
  uint8 public constant ANSWER_EMPTY = 4;
  /// @notice The pause read returns 31 bytes, the last of them 0x01.
  uint8 public constant ANSWER_SHORT = 5;
  /// @notice The pause read returns one word holding 2, which is neither true nor false.
  uint8 public constant ANSWER_OTHER_WORD = 6;
  /// @notice The pause read returns the encoding of true followed by one more byte.
  uint8 public constant ANSWER_TRUE_AND_MORE = 7;

  /*///////////////////////////////////////////////////////////////
                          STATE VARIABLES
  ///////////////////////////////////////////////////////////////*/

  /// @notice How the pause read answers, one of the ANSWER_ constants.
  uint8 public pauseAnswer;

  /*///////////////////////////////////////////////////////////////
                        EXTERNAL FUNCTIONS
  ///////////////////////////////////////////////////////////////*/

  /// @notice Turns the stop on, as exactly true, or off, as a false word.
  /// @param _stopped The new stop.
  function setStopped(bool _stopped) external {
    pauseAnswer = _stopped ? ANSWER_TRUE : ANSWER_FALSE;
  }

  /// @notice Chooses how the pause read answers.
  /// @param _answer One of the ANSWER_ constants.
  function setPauseAnswer(uint8 _answer) external {
    pauseAnswer = _answer;
  }

  /// @notice Whether the pause read answers exactly true, the one answer that is a stop.
  /// @return _isStopped True when the pause read returns exactly the encoding of true.
  function stopped() external view returns (bool _isStopped) {
    _isStopped = pauseAnswer == ANSWER_TRUE;
  }

  /// @notice Returns the magic value when `_proof` is the seal of `_config` and `_digest`, and zero
  ///         otherwise.
  /// @param _config The credential's config.
  /// @param _digest The digest the proof must approve.
  /// @param _proof The proof bytes.
  /// @return _magicValue The verify selector, or zero.
  function verify(bytes calldata _config, bytes32 _digest, bytes calldata _proof)
    external
    pure
    returns (bytes4 _magicValue)
  {
    if (keccak256(_proof) == keccak256(seal(_config, _digest))) _magicValue = IPolicyMethod.verify.selector;
  }

  /// @notice Answers the pause read in the shape `pauseAnswer` names, returning or reverting with
  ///         raw bytes, so shapes a bool cannot hold reach the caller.
  /// @return _isPaused Whether the answer is a stop. The raw return below replaces it.
  function paused() external view returns (bool _isPaused) {
    uint8 _answer = pauseAnswer;
    _isPaused = _answer == ANSWER_TRUE;
    assembly {
      mstore(0x00, 0)
      mstore(0x20, 0)
      switch _answer
      case 0 { return(0x00, 0x20) }
      case 1 {
        mstore(0x00, 1)
        return(0x00, 0x20)
      }
      case 2 { revert(0x00, 0x00) }
      case 3 {
        mstore(0x00, 1)
        revert(0x00, 0x20)
      }
      case 4 { return(0x00, 0x00) }
      case 5 {
        mstore8(0x1e, 1)
        return(0x00, 0x1f)
      }
      case 6 {
        mstore(0x00, 2)
        return(0x00, 0x20)
      }
      default {
        mstore(0x00, 1)
        mstore8(0x20, 1)
        return(0x00, 0x21)
      }
    }
  }

  /// @notice The proof this mock approves for `_config` and `_digest`.
  /// @param _config The credential's config.
  /// @param _digest The digest to approve.
  /// @return _proof abi.encode(keccak256(abi.encode(_config, _digest))).
  function seal(bytes memory _config, bytes32 _digest) public pure returns (bytes memory _proof) {
    _proof = abi.encode(keccak256(abi.encode(_config, _digest)));
  }
}
