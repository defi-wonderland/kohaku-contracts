// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

/// @notice A stand-in for an identity method that declares the parties the test gives it and names the verifier
///         the test gives it, and answers ERC-165 with a clean true for every interface id except one the test
///         singles out, which gets the answer the test picks.
contract DeployIdentityMockMethod {
  /// @notice The answers supportsInterface can give the singled-out interface id.
  enum Answer {
    False,
    Revert,
    Empty,
    WordTwo,
    TrueThenMore
  }

  address internal immutable _ADMIN;
  address internal immutable _PAUSE_HOLDER;
  address internal immutable _VERIFIER;
  bytes32[] internal _keys;

  /// @notice The interface id that gets `refusal` instead of true.
  bytes4 public refusedId;
  /// @notice The answer the singled-out interface id gets.
  Answer public refusal;

  /// @notice The revert the mock raises in the Revert mode.
  error DeployIdentityMockMethod_Refused();

  /// @param _admin The key admin the mock declares.
  /// @param _pauseHolder The pause holder the mock declares.
  /// @param _trustedKeys The trusted keys the mock declares.
  /// @param _verifier The verifier the mock names.
  constructor(address _admin, address _pauseHolder, bytes32[] memory _trustedKeys, address _verifier) {
    _ADMIN = _admin;
    _PAUSE_HOLDER = _pauseHolder;
    _keys = _trustedKeys;
    _VERIFIER = _verifier;
  }

  /// @notice Makes supportsInterface give `_answer` for `_interfaceId`.
  function refuse(bytes4 _interfaceId, Answer _answer) external {
    refusedId = _interfaceId;
    refusal = _answer;
  }

  /// @notice The declared admin and pause holder, no pending holder, and the declared keys.
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
    _declaredAdmin = _ADMIN;
    _declaredPendingAdmin = address(0);
    _declaredKeys = _keys;
    _declaredPauseHolder = _PAUSE_HOLDER;
    _declaredPendingPauseHolder = address(0);
  }

  /// @notice The verifier the mock names.
  function verifier() external view returns (address _verifier) {
    _verifier = _VERIFIER;
  }

  /// @notice A clean true, except for the singled-out id, which gets the picked answer. It declares no return
  ///         value so each answer can be written raw.
  function supportsInterface(bytes4 _interfaceId) external view {
    if (_interfaceId != refusedId) {
      assembly {
        mstore(0, 1)
        return(0, 32)
      }
    }
    Answer _answer = refusal;
    require(_answer != Answer.Revert, DeployIdentityMockMethod_Refused());
    if (_answer == Answer.False) {
      assembly {
        mstore(0, 0)
        return(0, 32)
      }
    }
    if (_answer == Answer.WordTwo) {
      assembly {
        mstore(0, 2)
        return(0, 32)
      }
    }
    if (_answer == Answer.TrueThenMore) {
      assembly {
        mstore(0, 1)
        mstore(32, 0)
        return(0, 64)
      }
    }
  }
}
