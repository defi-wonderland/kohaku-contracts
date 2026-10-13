// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {PasskeyMethod} from 'contracts/methods/passkey/PasskeyMethod.sol';

/// @notice Test harness. It is the passkey method with two extra doors that run one of its checks
///         alone: the authenticator data check and the client data check. A test can then ask about
///         one field without reaching the signature check and its SHA-256 calls. It adds no behavior
///         to the method's own functions.
contract PasskeyMethodHarness is PasskeyMethod {
  /*///////////////////////////////////////////////////////////////
                        EXTERNAL FUNCTIONS
  ///////////////////////////////////////////////////////////////*/

  /// @notice Runs the authenticator data check alone.
  /// @param _authenticatorData The authenticatorData from the assertion.
  /// @param _rpIdHash The relying party hash the config commits.
  /// @return _valid The check's answer.
  function harnessAuthenticatorDataValid(bytes calldata _authenticatorData, bytes32 _rpIdHash)
    external
    pure
    returns (bool _valid)
  {
    _valid = _authenticatorDataValid(_authenticatorData, _rpIdHash);
  }

  /// @notice Runs the client data check alone.
  /// @param _clientDataJSON The clientDataJSON from the assertion.
  /// @param _digest The digest the proof must approve.
  /// @return _valid The check's answer.
  function harnessClientDataValid(bytes calldata _clientDataJSON, bytes32 _digest) external pure returns (bool _valid) {
    _valid = _clientDataValid(_clientDataJSON, _digest);
  }
}
