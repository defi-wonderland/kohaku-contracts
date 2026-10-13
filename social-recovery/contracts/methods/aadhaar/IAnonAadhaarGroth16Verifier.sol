// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

/// @title IAnonAadhaarGroth16Verifier
/// @author defi-wonderland
/// @notice The one function of Anon Aadhaar's raw Groth16 verifier that the Aadhaar method calls.
/// @dev The verifier is stateless generated code, reached by its address. It checks the pairing of one proof
///      over nine public inputs and holds no key of its own, so it accepts whatever public-key hash the inputs
///      carry. The declaration mirrors the generated verifier's ABI and keeps its parameter names; the return
///      carries a name the generated code leaves out, which changes nothing in the ABI.
interface IAnonAadhaarGroth16Verifier {
  /*///////////////////////////////////////////////////////////////
                              LOGIC
  ///////////////////////////////////////////////////////////////*/

  /// @notice Check one Groth16 proof against its nine public inputs.
  /// @param _pA The proof's first point.
  /// @param _pB The proof's second point, each coordinate pair already in the order the verifier expects.
  /// @param _pC The proof's third point.
  /// @param _pubSignals The nine public inputs: the public-key hash, the nullifier, the timestamp, the age,
  ///        gender, postcode and state disclosures, the nullifier seed and the signal hash.
  /// @return _valid True when the proof verifies against those inputs.
  function verifyProof(
    uint256[2] calldata _pA,
    uint256[2][2] calldata _pB,
    uint256[2] calldata _pC,
    uint256[9] calldata _pubSignals
  ) external view returns (bool _valid);
}
