// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {IPolicyManager} from 'interfaces/IPolicyManager.sol';

/// @title BindingDigest
/// @author defi-wonderland
/// @notice This library computes the EIP-712 digest a guardian's proof signs. It also computes the
///         setup commitment and the credential commitment.
/// @dev An approval and a cancellation are signed under different EIP-712 type names. The type
///      name goes into the signed hash, so a signature for one never verifies as the other. The
///      domain holds the chain id and the manager's address, so each digest belongs to one chain
///      and one manager deployment. Every hash is keccak256 over abi.encode of its values in a
///      fixed order. abi.encode writes the length of each bytes value, so two different inputs
///      never produce the same bytes. encodePacked could, by shifting bytes from the end of one
///      value into the start of the next. The only packed step is the 0x1901 prefix that EIP-712
///      requires. It is safe because its three parts have fixed widths. The library chooses no
///      salt. It hashes the salt each request supplies.
library BindingDigest {
  /*///////////////////////////////////////////////////////////////
                              CONSTANTS
  ///////////////////////////////////////////////////////////////*/

  /// @notice The name in the EIP-712 domain. Every manager deployment uses the same name.
  string internal constant DOMAIN_NAME = 'PolicyManager';

  /// @notice The version in the EIP-712 domain. It is the version of the signed format, not a
  ///         release number. It changes only when the signed types or their meaning change.
  string internal constant DIGEST_VERSION = '1';

  /// @notice The type hash of the EIP-712 domain. The domain lists the name, the version, the
  ///         chain id and the manager's address, in the order ERC-5267 uses. It has no salt and
  ///         no extensions.
  bytes32 internal constant DOMAIN_TYPEHASH =
    keccak256('EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)');

  /// @notice The type hash of the payment order, which the Approval message nests.
  bytes32 internal constant PAYMENT_ORDER_TYPEHASH =
    keccak256('PaymentOrder(address token,uint256 amount,address payee)');

  /// @notice The type hash of the Approval message. EIP-712 requires the nested PaymentOrder
  ///         type to follow the main type in the string that is hashed.
  bytes32 internal constant APPROVAL_TYPEHASH = keccak256(
    'Approval(address account,address action,uint64 attemptId,uint64 setupNonce,bytes32 setupBodyHash,'
    'bytes payload,PaymentOrder order,uint48 validUntil,uint256 place)'
    'PaymentOrder(address token,uint256 amount,address payee)'
  );

  /// @notice The type hash of the Cancellation message. A cancellation names an attempt and
  ///         carries no outcome, so it has no payload and no order.
  bytes32 internal constant CANCELLATION_TYPEHASH = keccak256(
    'Cancellation(address account,address action,uint64 attemptId,uint64 setupNonce,bytes32 setupBodyHash,'
    'uint48 validUntil,uint256 place)'
  );

  /*///////////////////////////////////////////////////////////////
                          INTERNAL FUNCTIONS
  ///////////////////////////////////////////////////////////////*/

  /// @notice Computes the EIP-712 domain separator of one manager deployment on the chain that
  ///         runs the call.
  /// @dev It reads block.chainid on every call instead of taking a chain id or a stored
  ///      separator. A stored or passed-in separator keeps the old chain id after a chain split
  ///      changes it, so an approval signed on one branch would also verify on the other.
  /// @param _verifyingContract The manager's address.
  /// @return _separator keccak256 of abi.encode of the domain type hash, the hashed name, the
  ///         hashed DIGEST_VERSION, block.chainid and the manager's address.
  function domainSeparator(address _verifyingContract) internal view returns (bytes32 _separator) {
    _separator = keccak256(
      abi.encode(
        DOMAIN_TYPEHASH,
        keccak256(bytes(DOMAIN_NAME)),
        keccak256(bytes(DIGEST_VERSION)),
        block.chainid,
        _verifyingContract
      )
    );
  }

  /// @notice Computes the EIP-712 struct hash of a payment order.
  /// @param _order The order the guardians approve and the attempt stores.
  /// @return _structHash keccak256 of abi.encode of the type hash, the token, the amount and
  ///         the payee.
  function hashPaymentOrder(IPolicyManager.PaymentOrder calldata _order) internal pure returns (bytes32 _structHash) {
    _structHash = keccak256(abi.encode(PAYMENT_ORDER_TYPEHASH, _order.token, _order.amount, _order.payee));
  }

  /// @notice Computes the digest that the proof at one place of an opening request must sign.
  /// @dev The setup body and the payload enter as the keccak256 of their bytes, which is how
  ///      EIP-712 hashes a bytes value. The order enters as its own struct hash. Each member is
  ///      read from calldata, so the proofs are never hashed or copied.
  /// @param _separator The domain separator of the manager deployment.
  /// @param _request The request the digest covers.
  /// @param _place The place in the rule that the signing credential fills.
  /// @return _digest The EIP-712 hash of the Approval message.
  function approvalDigest(bytes32 _separator, IPolicyManager.AttemptRequest calldata _request, uint256 _place)
    internal
    pure
    returns (bytes32 _digest)
  {
    bytes32 _structHash = keccak256(
      abi.encode(
        APPROVAL_TYPEHASH,
        _request.account,
        _request.action,
        _request.attemptId,
        _request.setupNonce,
        keccak256(_request.setupBody),
        keccak256(_request.payload),
        hashPaymentOrder(_request.order),
        _request.validUntil,
        _place
      )
    );
    _digest = _typedDataHash(_separator, _structHash);
  }

  /// @notice Computes the digest that the proof at one place of a cancellation must sign.
  /// @dev The Cancellation message has no payload and no order. Its type name differs from the
  ///      Approval type name, so an approval over the same values gives a different digest. Each
  ///      member is read from calldata, so the proofs are never hashed or copied.
  /// @param _separator The domain separator of the manager deployment.
  /// @param _request The cancellation the digest covers.
  /// @param _place The place in the rule that the signing credential fills.
  /// @return _digest The EIP-712 hash of the Cancellation message.
  function cancelDigest(bytes32 _separator, IPolicyManager.CancelRequest calldata _request, uint256 _place)
    internal
    pure
    returns (bytes32 _digest)
  {
    bytes32 _structHash = keccak256(
      abi.encode(
        CANCELLATION_TYPEHASH,
        _request.account,
        _request.action,
        _request.attemptId,
        _request.setupNonce,
        keccak256(_request.setupBody),
        _request.validUntil,
        _place
      )
    );
    _digest = _typedDataHash(_separator, _structHash);
  }

  /// @notice Computes the setup commitment, keccak256(abi.encode(account, action, nonce, body)).
  /// @param _account The account the setup belongs to.
  /// @param _action The action the setup governs.
  /// @param _nonce The setup nonce the write stores.
  /// @param _body The setup body's bytes.
  /// @return _commitment The hash the manager stores and checks again at every request.
  function setupCommitment(address _account, address _action, uint64 _nonce, bytes memory _body)
    internal
    pure
    returns (bytes32 _commitment)
  {
    _commitment = keccak256(abi.encode(_account, _action, _nonce, _body));
  }

  /// @notice Computes the credential commitment, keccak256(abi.encode(method, config, salt)).
  ///         The setup body lists this hash, not the credential, so a setup hides who the guardians
  ///         are until a request reveals the config.
  /// @dev The salt is hashed as given. The library never picks one, so the holder or their
  ///      client chooses it off chain.
  /// @param _method The method module that verifies the credential.
  /// @param _config The credential's public data, abi-encoded in the layout its method defines, for
  ///        example a guardian's address for a wallet method or a passkey's public key. Only the
  ///        method decodes it; this library only hashes it.
  /// @param _salt The salt that comes with the credential.
  /// @return _commitment The credential hash a setup body lists at the credential's place.
  function credentialCommitment(address _method, bytes memory _config, bytes32 _salt)
    internal
    pure
    returns (bytes32 _commitment)
  {
    _commitment = keccak256(abi.encode(_method, _config, _salt));
  }

  /*///////////////////////////////////////////////////////////////
                          PRIVATE FUNCTIONS
  ///////////////////////////////////////////////////////////////*/

  /// @notice Computes the EIP-712 hash of a struct hash under a domain.
  /// @dev EIP-712 hashes the 0x1901 prefix, the domain separator and the struct hash packed
  ///      together. All three have fixed widths, so the packed bytes can be read only one way.
  /// @param _separator The domain separator.
  /// @param _structHash The message's struct hash.
  /// @return _digest keccak256 of 0x1901, the separator and the struct hash.
  function _typedDataHash(bytes32 _separator, bytes32 _structHash) private pure returns (bytes32 _digest) {
    _digest = keccak256(bytes.concat(hex'1901', _separator, _structHash));
  }
}
