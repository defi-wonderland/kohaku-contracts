// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

/// @notice A stand-in for Anon Aadhaar's raw Groth16 verifier. Unit tests set its answer without a real proof. It
///         answers every call through its fallback. A test can make it return true, false or any raw bytes. It can
///         also revert, with or without the word true as its revert data.
/// @dev In Exact mode it answers true only for one exact calldata. That calldata is the selector of
///      verifyProof(uint256[2],uint256[2][2],uint256[2],uint256[9]) followed by the words the test expects. It
///      catches a reversed b, a reordered point, a missing input or an extra tenth word. A prefix match such as
///      vm.mockCall or vm.expectCall would let those through.
contract MethodAadhaarVerifierMock {
  /*///////////////////////////////////////////////////////////////
                                ENUMS
  ///////////////////////////////////////////////////////////////*/

  /// @notice How the mock answers.
  enum Mode {
    Exact,
    AlwaysTrue,
    AlwaysFalse,
    Revert,
    RevertWithTrue,
    Raw
  }

  /*///////////////////////////////////////////////////////////////
                          STATE VARIABLES
  ///////////////////////////////////////////////////////////////*/

  /// @notice The selector of the raw verifier the method calls.
  bytes4 public constant VERIFY_PROOF_SELECTOR =
    bytes4(keccak256('verifyProof(uint256[2],uint256[2][2],uint256[2],uint256[9])'));

  /// @notice The current answering mode.
  Mode public mode;

  /// @notice The keccak of the one calldata Exact mode accepts.
  bytes32 public expectedCalldataHash;

  /// @notice The bytes Raw mode returns verbatim.
  bytes public rawAnswer;

  /*///////////////////////////////////////////////////////////////
                               ERRORS
  ///////////////////////////////////////////////////////////////*/

  /// @notice The verifier the mock plays refused the call.
  error MethodAadhaarVerifierMock_Reverted();

  /*///////////////////////////////////////////////////////////////
                              FALLBACK
  ///////////////////////////////////////////////////////////////*/

  /// @notice Answers every call per the current mode.
  // solhint-disable-next-line no-complex-fallback
  fallback(bytes calldata _data) external returns (bytes memory _answer) {
    Mode _current = mode;
    require(_current != Mode.Revert, MethodAadhaarVerifierMock_Reverted());
    if (_current == Mode.RevertWithTrue) {
      // A revert whose data is exactly the one word a successful true answer would carry.
      bytes memory _trueWord = abi.encode(true);
      assembly ('memory-safe') {
        revert(add(_trueWord, 32), mload(_trueWord))
      }
    }
    if (_current == Mode.Raw) return rawAnswer;
    if (_current == Mode.AlwaysFalse) return abi.encode(false);
    if (_current == Mode.AlwaysTrue) return abi.encode(true);
    _answer = abi.encode(keccak256(_data) == expectedCalldataHash);
  }

  /*///////////////////////////////////////////////////////////////
                          EXTERNAL FUNCTIONS
  ///////////////////////////////////////////////////////////////*/

  /// @notice Set the answering mode.
  function setMode(Mode _mode) external {
    mode = _mode;
  }

  /// @notice Enter Exact mode, accepting only verifyProof(a, b, c, inputs) with exactly these words.
  function expectExact(
    uint256[2] calldata _a,
    uint256[2][2] calldata _b,
    uint256[2] calldata _c,
    uint256[9] calldata _inputs
  ) external {
    mode = Mode.Exact;
    expectedCalldataHash = keccak256(abi.encodeWithSelector(VERIFY_PROOF_SELECTOR, _a, _b, _c, _inputs));
  }

  /// @notice Enter Raw mode, returning these exact bytes to every call.
  function setRawAnswer(bytes calldata _rawAnswer) external {
    mode = Mode.Raw;
    rawAnswer = _rawAnswer;
  }
}
