// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

/// @notice The upstream ServiceConfig, in the upstream field order: (validityPeriodInSeconds, domain, scope, devMode).
struct MethodZkPassportServiceConfig {
  uint256 validityPeriodInSeconds;
  string domain;
  string scope;
  bool devMode;
}

/// @notice The upstream ProofVerificationData, in the upstream field order: (vkeyHash, proof, publicInputs).
struct MethodZkPassportProofVerificationData {
  bytes32 vkeyHash;
  bytes proof;
  bytes32[] publicInputs;
}

/// @notice The upstream ProofVerificationParams the root verifier's verify takes, in the upstream field order:
///         (version, proofVerificationData, committedInputs, serviceConfig). It matches the zkPassport packages
///         source at commit 5f7b5c5, and the fork test proves it against the live root verifier on Sepolia.
struct MethodZkPassportProofVerificationParams {
  bytes32 version;
  MethodZkPassportProofVerificationData proofVerificationData;
  bytes committedInputs;
  MethodZkPassportServiceConfig serviceConfig;
}

/// @notice The struct the verifier helper's getBoundData returns, carrying customData. Its layout (senderAddress,
///         chainId, customData) matches upstream and the live verifier helper on the Sepolia fork. It matches the SDK's
///         BoundData (user_address, chain, custom_data).
struct MethodZkPassportBoundData {
  address senderAddress;
  uint256 chainId;
  string customData;
}

/// @notice How a mock answers a call.
enum MethodZkPassportMockMode {
  Answer,
  Revert,
  ReturnNothing,
  ReturnOneWord,
  ReturnGarbage
}

/// @notice Stands in for zkPassport's root verifier with fixed answers, so each unit test chooses exactly what the
///         verifier answers. It returns its set answer only for exactly the expected params, and (false, 0, 0) for
///         any other params.
contract MethodZkPassportRootVerifierMock {
  /// @notice The mock's refusal in Revert mode.
  error MethodZkPassportRootVerifierMock_Refused();

  /// @notice How the mock answers.
  MethodZkPassportMockMode public mode;
  /// @notice keccak256(abi.encode(params)) of the only params that get the mock's set answer.
  bytes32 public expectedParamsHash;
  /// @notice The valid flag the mock returns.
  bool public answerValid;
  /// @notice The uniqueIdentifier the mock returns.
  bytes32 public answerIdentifier;
  /// @notice The verifier helper address the mock returns.
  address public answerVerifierHelper;

  /// @notice Sets how the mock answers.
  function setMode(MethodZkPassportMockMode _mode) external {
    mode = _mode;
  }

  /// @notice Sets the params the mock expects and the answer it returns for them.
  function setAnswer(bytes32 _paramsHash, bool _valid, bytes32 _uniqueIdentifier, address _verifierHelper) external {
    expectedParamsHash = _paramsHash;
    answerValid = _valid;
    answerIdentifier = _uniqueIdentifier;
    answerVerifierHelper = _verifierHelper;
  }

  /// @notice The upstream root verifier's verify, answering deterministically.
  function verify(MethodZkPassportProofVerificationParams calldata _params)
    external
    view
    returns (bool _valid, bytes32 _uniqueIdentifier, address _verifierHelper)
  {
    MethodZkPassportMockMode _mode = mode;
    require(_mode != MethodZkPassportMockMode.Revert, MethodZkPassportRootVerifierMock_Refused());
    if (_mode == MethodZkPassportMockMode.ReturnNothing) {
      assembly {
        return(0, 0)
      }
    }
    if (_mode == MethodZkPassportMockMode.ReturnOneWord) {
      assembly {
        mstore(0, 1)
        return(0, 32)
      }
    }
    if (_mode == MethodZkPassportMockMode.ReturnGarbage) {
      // Eight words of 0xff. The answer is longer than any honest one, and every offset and length is out of range.
      assembly {
        let p := mload(0x40)
        for { let i := 0 } lt(i, 0x100) { i := add(i, 0x20) } { mstore(add(p, i), not(0)) }
        return(p, 0x100)
      }
    }
    if (keccak256(abi.encode(_params)) != expectedParamsHash) return (false, bytes32(0), address(0));
    _valid = answerValid;
    _uniqueIdentifier = answerIdentifier;
    _verifierHelper = answerVerifierHelper;
  }
}

/// @notice Stands in for zkPassport's verifier helper with fixed answers, for the same reason as the root verifier
///         mock. It returns its set customData only for the expected committed inputs, and an empty customData for any
///         others.
contract MethodZkPassportVerifierHelperMock {
  /// @notice The mock's refusal in Revert mode.
  error MethodZkPassportVerifierHelperMock_Refused();

  /// @notice How the mock answers.
  MethodZkPassportMockMode public mode;
  /// @notice keccak256 of the only committed inputs that get the mock's set customData.
  bytes32 public expectedCommittedInputsHash;
  /// @notice The customData the mock returns.
  string public answerCustomData;

  /// @notice Sets how the mock answers.
  function setMode(MethodZkPassportMockMode _mode) external {
    mode = _mode;
  }

  /// @notice Sets the committed inputs the mock expects and the customData it returns for them.
  function setAnswer(bytes32 _committedInputsHash, string calldata _customData) external {
    expectedCommittedInputsHash = _committedInputsHash;
    answerCustomData = _customData;
  }

  /// @notice The upstream verifier helper's getBoundData, answering deterministically.
  function getBoundData(bytes calldata _committedInputs)
    external
    view
    returns (MethodZkPassportBoundData memory _data)
  {
    MethodZkPassportMockMode _mode = mode;
    require(_mode != MethodZkPassportMockMode.Revert, MethodZkPassportVerifierHelperMock_Refused());
    if (_mode == MethodZkPassportMockMode.ReturnNothing) {
      assembly {
        return(0, 0)
      }
    }
    if (_mode == MethodZkPassportMockMode.ReturnOneWord) {
      assembly {
        mstore(0, 1)
        return(0, 32)
      }
    }
    if (_mode == MethodZkPassportMockMode.ReturnGarbage) {
      // Eight words of 0xff. The answer is longer than any honest one, and every offset and length is out of range.
      assembly {
        let p := mload(0x40)
        for { let i := 0 } lt(i, 0x100) { i := add(i, 0x20) } { mstore(add(p, i), not(0)) }
        return(p, 0x100)
      }
    }
    _data.senderAddress = address(0xB0b);
    _data.chainId = block.chainid;
    if (keccak256(_committedInputs) == expectedCommittedInputsHash) _data.customData = answerCustomData;
  }
}
