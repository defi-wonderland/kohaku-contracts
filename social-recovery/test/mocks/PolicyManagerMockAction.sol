// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {IPolicyManager} from 'interfaces/IPolicyManager.sol';

/// @notice Mock of an action as the manager sees it at commitSetup: a contract whose supportsAccount
///         gives a configurable answer. Its storage starts at the Serves answer, so its runtime code
///         etched at any address is an action that serves every account.
contract PolicyManagerMockAction {
  /// @notice The answers the mock can give to supportsAccount.
  /// @dev Serves is the zero value, so etched code with empty storage serves every account.
  enum Answer {
    Serves,
    AnswersFalse,
    Reverts,
    RawBytes,
    WritesState,
    ServesWhileUnwritten
  }

  /*///////////////////////////////////////////////////////////////
                          STATE VARIABLES
  ///////////////////////////////////////////////////////////////*/

  /// @notice The answer supportsAccount gives.
  Answer public answer;
  /// @notice How many answers wrote storage. It stays zero while every call is static.
  uint256 public writes;
  /// @notice The exact bytes supportsAccount returns in the RawBytes answer.
  bytes internal _rawAnswer;
  /// @notice The manager the ServesWhileUnwritten answer reads.
  IPolicyManager internal _watchedManager;
  /// @notice The hash of the account's state for this action that the ServesWhileUnwritten answer
  ///         expects to read.
  bytes32 internal _expectedStateHash;

  /*///////////////////////////////////////////////////////////////
                              ERRORS
  ///////////////////////////////////////////////////////////////*/

  /// @notice The revert supportsAccount raises in the Reverts answer.
  error PolicyManagerMockAction_Refused();

  /*///////////////////////////////////////////////////////////////
                        EXTERNAL FUNCTIONS
  ///////////////////////////////////////////////////////////////*/

  /// @notice Sets the answer supportsAccount gives.
  /// @param _answer The new answer.
  function setAnswer(Answer _answer) external {
    answer = _answer;
  }

  /// @notice Makes supportsAccount return exactly `_bytes`, whatever their length.
  /// @param _bytes The bytes returned.
  function setRawAnswer(bytes calldata _bytes) external {
    answer = Answer.RawBytes;
    _rawAnswer = _bytes;
  }

  /// @notice Makes supportsAccount answer true only while `_manager` still reports, for the asked
  ///         account and this action, the state whose abi encoding hashes to `_stateHash`, and false
  ///         once anything in it changed.
  /// @param _manager The manager read.
  /// @param _stateHash The hash of the abi-encoded state expected.
  function setServesWhileUnwritten(IPolicyManager _manager, bytes32 _stateHash) external {
    answer = Answer.ServesWhileUnwritten;
    _watchedManager = _manager;
    _expectedStateHash = _stateHash;
  }

  /// @notice Answers as `answer` says. It declares no return value, so it can return any bytes: the
  ///         word true, the word false, a revert, the raw bytes, or a storage write followed by the
  ///         word true.
  ///         In the ServesWhileUnwritten answer it returns the word true only while the manager's
  ///         state for the asked account is still the expected one.
  /// @param _account The account asked about.
  function supportsAccount(address _account) external {
    require(answer != Answer.Reverts, PolicyManagerMockAction_Refused());
    if (answer == Answer.WritesState) ++writes;
    bool _serves = answer == Answer.Serves || answer == Answer.WritesState;
    if (answer == Answer.ServesWhileUnwritten) {
      _serves = keccak256(abi.encode(_watchedManager.stateOf(_account, address(this)))) == _expectedStateHash;
    }
    bytes memory _returned = answer == Answer.RawBytes ? _rawAnswer : abi.encode(_serves);
    assembly ('memory-safe') {
      return(add(_returned, 32), mload(_returned))
    }
  }
}
