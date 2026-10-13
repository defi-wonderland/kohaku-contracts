// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {IPolicyManager} from 'interfaces/IPolicyManager.sol';

// Every narrowing cast below truncates on purpose. The change only has to be nonzero, and `_seed | 1`
// sets the lowest bit, so the change is nonzero at every width.
// forge-lint: disable-start(unsafe-typecast)

/// @notice Changes exactly one member of what the binding digest or a commitment hashes. A test compares the hash
///         before and after, so a member the encoder ignores shows up as two different inputs sharing one hash.
///         `_which` picks the member and `_seed` builds the change: a fixed-width member is XORed with `_seed | 1`,
///         and a bytes member gains one trailing byte.
library BindingDigestMemberChanges {
  /// @dev Members of an approval: account, action, attempt id, setup nonce, setup body, payload, the order's token,
  ///      amount and payee, validUntil, place, then the domain separator.
  uint256 internal constant APPROVAL_MEMBERS = 12;
  /// @dev Members of a cancellation: account, action, attempt id, setup nonce, setup body, validUntil, place, then
  ///      the domain separator.
  uint256 internal constant CANCEL_MEMBERS = 8;
  /// @dev Members of the setup commitment: account, action, nonce, body.
  uint256 internal constant SETUP_MEMBERS = 4;
  /// @dev Members of the credential commitment: method, config, salt.
  uint256 internal constant CREDENTIAL_MEMBERS = 3;

  /// @dev Changes member `_which` of the approval in place and returns the separator and place to use.
  function changeApproval(
    bytes32 _separator,
    IPolicyManager.AttemptRequest memory _request,
    uint256 _place,
    uint256 _which,
    uint256 _seed
  ) internal pure returns (bytes32 _newSeparator, uint256 _newPlace) {
    _newSeparator = _separator;
    _newPlace = _place;
    uint256 _nonzero = _seed | 1;
    if (_which == 0) _request.account = address(uint160(_request.account) ^ uint160(_nonzero));
    else if (_which == 1) _request.action = address(uint160(_request.action) ^ uint160(_nonzero));
    else if (_which == 2) _request.attemptId ^= uint64(_nonzero);
    else if (_which == 3) _request.setupNonce ^= uint64(_nonzero);
    else if (_which == 4) _request.setupBody = abi.encodePacked(_request.setupBody, bytes1(uint8(_seed)));
    else if (_which == 5) _request.payload = abi.encodePacked(_request.payload, bytes1(uint8(_seed)));
    else if (_which == 6) _request.order.token = address(uint160(_request.order.token) ^ uint160(_nonzero));
    else if (_which == 7) _request.order.amount ^= _nonzero;
    else if (_which == 8) _request.order.payee = address(uint160(_request.order.payee) ^ uint160(_nonzero));
    else if (_which == 9) _request.validUntil ^= uint48(_nonzero);
    else if (_which == 10) _newPlace ^= _nonzero;
    else _newSeparator ^= bytes32(_nonzero);
  }

  /// @dev Changes member `_which` of the cancellation in place and returns the separator and place to use.
  function changeCancel(
    bytes32 _separator,
    IPolicyManager.CancelRequest memory _request,
    uint256 _place,
    uint256 _which,
    uint256 _seed
  ) internal pure returns (bytes32 _newSeparator, uint256 _newPlace) {
    _newSeparator = _separator;
    _newPlace = _place;
    uint256 _nonzero = _seed | 1;
    if (_which == 0) _request.account = address(uint160(_request.account) ^ uint160(_nonzero));
    else if (_which == 1) _request.action = address(uint160(_request.action) ^ uint160(_nonzero));
    else if (_which == 2) _request.attemptId ^= uint64(_nonzero);
    else if (_which == 3) _request.setupNonce ^= uint64(_nonzero);
    else if (_which == 4) _request.setupBody = abi.encodePacked(_request.setupBody, bytes1(uint8(_seed)));
    else if (_which == 5) _request.validUntil ^= uint48(_nonzero);
    else if (_which == 6) _newPlace ^= _nonzero;
    else _newSeparator ^= bytes32(_nonzero);
  }

  /// @dev Changes member `_which` of a setup commitment's inputs and returns all four.
  function changeSetup(
    address _account,
    address _action,
    uint64 _nonce,
    bytes memory _body,
    uint256 _which,
    uint256 _seed
  ) internal pure returns (address _newAccount, address _newAction, uint64 _newNonce, bytes memory _newBody) {
    (_newAccount, _newAction, _newNonce, _newBody) = (_account, _action, _nonce, _body);
    uint256 _nonzero = _seed | 1;
    if (_which == 0) _newAccount = address(uint160(_account) ^ uint160(_nonzero));
    else if (_which == 1) _newAction = address(uint160(_action) ^ uint160(_nonzero));
    else if (_which == 2) _newNonce = _nonce ^ uint64(_nonzero);
    else _newBody = abi.encodePacked(_body, bytes1(uint8(_seed)));
  }

  /// @dev Changes member `_which` of a credential commitment's inputs and returns all three.
  function changeCredential(address _method, bytes memory _config, bytes32 _salt, uint256 _which, uint256 _seed)
    internal
    pure
    returns (address _newMethod, bytes memory _newConfig, bytes32 _newSalt)
  {
    (_newMethod, _newConfig, _newSalt) = (_method, _config, _salt);
    uint256 _nonzero = _seed | 1;
    if (_which == 0) _newMethod = address(uint160(_method) ^ uint160(_nonzero));
    else if (_which == 1) _newConfig = abi.encodePacked(_config, bytes1(uint8(_seed)));
    else _newSalt = _salt ^ bytes32(_nonzero);
  }
}
// forge-lint: disable-end(unsafe-typecast)
