// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

/// @title IAadhaarMethod
/// @author defi-wonderland
/// @notice This interface declares what the Aadhaar method adds beside its policy-method interfaces. It holds the
///         errors for a bad trusted key and the read that names the verifier the method calls.
/// @dev It is not a policy-method interface, so the method does not report it through `supportsInterface`.
interface IAadhaarMethod {
  /*///////////////////////////////////////////////////////////////
                               ERRORS
  ///////////////////////////////////////////////////////////////*/

  /// @notice The key admin offered a trusted-key list whose length is not one.
  /// @param _length The refused list's length.
  error AadhaarMethod_InvalidTrustedKeysLength(uint256 _length);

  /// @notice The key admin offered a zero word as a trusted key.
  /// @param _index The position of the zero word in the refused list.
  error AadhaarMethod_ZeroTrustedKey(uint256 _index);

  /*///////////////////////////////////////////////////////////////
                              LOGIC
  ///////////////////////////////////////////////////////////////*/

  /// @notice The address of the Anon Aadhaar Groth16 verifier this method calls, fixed at deployment.
  /// @dev A deployment check reads it to confirm which verifier the method calls.
  /// @return _verifier The verifier's address.
  function verifier() external view returns (address _verifier);
}
