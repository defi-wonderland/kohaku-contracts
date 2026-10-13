// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

/// @notice A contract that answers supportsInterface and trustedParties with something other than a
///         well-formed answer: a plain revert, no bytes, the one word 2, the word 1 followed by a
///         second word, a revert whose data is the
///         word 1, or a revert whose data is the encoding of an empty declaration of parties.
contract DeployMockMalformedAnswer {
  /// @notice The answers the mock can give.
  enum Answer {
    Revert,
    Empty,
    WordTwo,
    WordOneThenMore,
    RevertWithWordOne,
    RevertWithEmptyDeclaration
  }

  /// @notice The answer this mock gives to both functions.
  Answer public immutable ANSWER;

  /// @notice The revert the mock raises in the Revert mode.
  error DeployMockMalformedAnswer_Refused();

  /// @param _answer The answer this mock gives to both functions.
  constructor(Answer _answer) {
    ANSWER = _answer;
  }

  /// @notice Gives ANSWER. It declares no return value, so the Empty mode answers no bytes.
  function supportsInterface(bytes4) external view {
    _giveAnswer();
  }

  /// @notice Gives ANSWER. It declares no return value, so the Empty mode answers no bytes.
  function trustedParties() external view {
    _giveAnswer();
  }

  /// @notice Reverts, returns, or falls through to an empty return, as ANSWER says.
  function _giveAnswer() internal view {
    require(ANSWER != Answer.Revert, DeployMockMalformedAnswer_Refused());
    if (ANSWER == Answer.WordTwo) {
      assembly {
        mstore(0, 2)
        return(0, 32)
      }
    }
    if (ANSWER == Answer.WordOneThenMore) {
      assembly {
        mstore(0, 1)
        mstore(32, 0)
        return(0, 64)
      }
    }
    if (ANSWER == Answer.RevertWithWordOne) {
      assembly {
        mstore(0, 1)
        revert(0, 32)
      }
    }
    if (ANSWER == Answer.RevertWithEmptyDeclaration) {
      bytes memory _declaration = abi.encode(address(0), address(0), new bytes32[](0), address(0), address(0));
      assembly {
        revert(add(_declaration, 0x20), mload(_declaration))
      }
    }
  }
}
