// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {IPolicyManager} from 'interfaces/IPolicyManager.sol';
import {InterfacesArtifacts} from 'test/utils/InterfacesArtifacts.sol';

/// @notice Checks the field types, field names and encoding order of the policy manager's shared
///         structs, and the numbering of the attempt states.
contract PolicyManagerTypesTest is InterfacesArtifacts {
  /// Builds a PaymentOrder with named fields and distinct values. Each _exactly helper compiles only when
  /// the field has exactly that type, and the encoding must equal the fields encoded in order.
  /// Clients and the manager exchange these bytes, so a moved or resized field breaks every request.
  function test_WhenThePaymentOrderStructIsEncoded() external pure {
    // it should hold the specified fields types and order
    IPolicyManager.PaymentOrder memory _subject =
      IPolicyManager.PaymentOrder({token: address(0x1001), amount: uint256(2), payee: address(0x1003)});
    _subject.token = _exactlyAddress(_subject.token);
    _subject.amount = _exactlyUint256(_subject.amount);
    _subject.payee = _exactlyAddress(_subject.payee);
    assertEq(abi.encode(_subject), abi.encode(_subject.token, _subject.amount, _subject.payee));
  }

  /// Builds a ProofPlace with named fields and distinct values. Each _exactly helper compiles only when
  /// the field has exactly that type, and the encoding must equal the fields encoded in order.
  /// Clients and the manager exchange these bytes, so a moved or resized field breaks every request.
  function test_WhenTheProofPlaceStructIsEncoded() external pure {
    // it should hold the specified fields types and order
    IPolicyManager.ProofPlace memory _subject = IPolicyManager.ProofPlace({
      place: uint256(1),
      method: address(0x1002),
      config: bytes('config-3'),
      salt: bytes32(uint256(0xb004)),
      proof: bytes('proof-5')
    });
    _subject.place = _exactlyUint256(_subject.place);
    _subject.method = _exactlyAddress(_subject.method);
    _subject.config = _exactlyBytes(_subject.config);
    _subject.salt = _exactlyBytes32(_subject.salt);
    _subject.proof = _exactlyBytes(_subject.proof);
    assertEq(
      abi.encode(_subject),
      bytes.concat(
        bytes32(uint256(0x20)),
        abi.encode(_subject.place, _subject.method, _subject.config, _subject.salt, _subject.proof)
      )
    );
  }

  /// Builds an AttemptRequest with named fields and distinct values. Each _exactly helper compiles only when
  /// the field has exactly that type, and the encoding must equal the fields encoded in order.
  /// Clients and the manager exchange these bytes, so a moved or resized field breaks every request.
  function test_WhenTheAttemptRequestStructIsEncoded() external pure {
    // it should hold the specified fields types and order
    IPolicyManager.ProofPlace[] memory _proofs = new IPolicyManager.ProofPlace[](1);
    _proofs[0] = IPolicyManager.ProofPlace({
      place: uint256(14),
      method: address(0x100f),
      config: bytes('config-16'),
      salt: bytes32(uint256(0xb011)),
      proof: bytes('proof-18')
    });
    IPolicyManager.AttemptRequest memory _subject = IPolicyManager.AttemptRequest({
      account: address(0x1001),
      action: address(0x1002),
      attemptId: uint64(3),
      setupNonce: uint64(4),
      setupBody: bytes('setupBody-5'),
      payload: bytes('payload-6'),
      order: IPolicyManager.PaymentOrder({token: address(0x1008), amount: uint256(9), payee: address(0x100a)}),
      validUntil: uint48(11),
      proofs: _proofs
    });
    _subject.account = _exactlyAddress(_subject.account);
    _subject.action = _exactlyAddress(_subject.action);
    _subject.attemptId = _exactlyUint64(_subject.attemptId);
    _subject.setupNonce = _exactlyUint64(_subject.setupNonce);
    _subject.setupBody = _exactlyBytes(_subject.setupBody);
    _subject.payload = _exactlyBytes(_subject.payload);
    _subject.order = _exactlyPaymentOrder(_subject.order);
    _subject.validUntil = _exactlyUint48(_subject.validUntil);
    _subject.proofs = _exactlyProofPlaceArray(_subject.proofs);
    assertEq(
      abi.encode(_subject),
      bytes.concat(
        bytes32(uint256(0x20)),
        abi.encode(
          _subject.account,
          _subject.action,
          _subject.attemptId,
          _subject.setupNonce,
          _subject.setupBody,
          _subject.payload,
          _subject.order,
          _subject.validUntil,
          _subject.proofs
        )
      )
    );
  }

  /// Builds a CancelRequest with named fields and distinct values. Each _exactly helper compiles only when
  /// the field has exactly that type, and the encoding must equal the fields encoded in order.
  /// Clients and the manager exchange these bytes, so a moved or resized field breaks every request.
  function test_WhenTheCancelRequestStructIsEncoded() external pure {
    // it should hold the specified fields types and order
    IPolicyManager.ProofPlace[] memory _proofs = new IPolicyManager.ProofPlace[](1);
    _proofs[0] = IPolicyManager.ProofPlace({
      place: uint256(9),
      method: address(0x100a),
      config: bytes('config-11'),
      salt: bytes32(uint256(0xb00c)),
      proof: bytes('proof-13')
    });
    IPolicyManager.CancelRequest memory _subject = IPolicyManager.CancelRequest({
      account: address(0x1001),
      action: address(0x1002),
      attemptId: uint64(3),
      setupNonce: uint64(4),
      setupBody: bytes('setupBody-5'),
      validUntil: uint48(6),
      proofs: _proofs
    });
    _subject.account = _exactlyAddress(_subject.account);
    _subject.action = _exactlyAddress(_subject.action);
    _subject.attemptId = _exactlyUint64(_subject.attemptId);
    _subject.setupNonce = _exactlyUint64(_subject.setupNonce);
    _subject.setupBody = _exactlyBytes(_subject.setupBody);
    _subject.validUntil = _exactlyUint48(_subject.validUntil);
    _subject.proofs = _exactlyProofPlaceArray(_subject.proofs);
    assertEq(
      abi.encode(_subject),
      bytes.concat(
        bytes32(uint256(0x20)),
        abi.encode(
          _subject.account,
          _subject.action,
          _subject.attemptId,
          _subject.setupNonce,
          _subject.setupBody,
          _subject.validUntil,
          _subject.proofs
        )
      )
    );
  }

  /// Builds an Attempt with named fields and distinct values, with ignoresPause right after state.
  /// Each _exactly helper compiles only when the field has exactly that type, and the encoding must
  /// equal the fields encoded in order. stateOf returns these bytes, so a moved field misreads an attempt.
  function test_WhenTheAttemptStructIsEncoded() external pure {
    // it should hold the specified fields types and order
    address[] memory _usedMethods = new address[](1);
    _usedMethods[0] = address(0x100c);
    IPolicyManager.Attempt memory _subject = IPolicyManager.Attempt({
      attemptId: uint64(1),
      setupNonce: uint64(2),
      consumableAfter: uint48(3),
      state: IPolicyManager.AttemptState.Cancelled,
      ignoresPause: true,
      payloadHash: bytes32(uint256(0xb006)),
      order: IPolicyManager.PaymentOrder({token: address(0x1008), amount: uint256(9), payee: address(0x100a)}),
      usedMethods: _usedMethods
    });
    _subject.attemptId = _exactlyUint64(_subject.attemptId);
    _subject.setupNonce = _exactlyUint64(_subject.setupNonce);
    _subject.consumableAfter = _exactlyUint48(_subject.consumableAfter);
    _subject.state = _exactlyAttemptState(_subject.state);
    _subject.ignoresPause = _exactlyBool(_subject.ignoresPause);
    _subject.payloadHash = _exactlyBytes32(_subject.payloadHash);
    _subject.order = _exactlyPaymentOrder(_subject.order);
    _subject.usedMethods = _exactlyAddressArray(_subject.usedMethods);
    assertEq(
      abi.encode(_subject),
      bytes.concat(
        bytes32(uint256(0x20)),
        abi.encode(
          _subject.attemptId,
          _subject.setupNonce,
          _subject.consumableAfter,
          _subject.state,
          _subject.ignoresPause,
          _subject.payloadHash,
          _subject.order,
          _subject.usedMethods
        )
      )
    );
  }

  /// Builds an ActionState with named fields and distinct values. Each _exactly helper compiles only when
  /// the field has exactly that type, and the encoding must equal the fields encoded in order.
  /// Clients and the manager exchange these bytes, so a moved or resized field breaks every request.
  function test_WhenTheActionStateStructIsEncoded() external pure {
    // it should hold the specified fields types and order
    address[] memory _usedMethods = new address[](1);
    _usedMethods[0] = address(0x1011);
    IPolicyManager.ActionState memory _subject = IPolicyManager.ActionState({
      setupCommitment: bytes32(uint256(0xb001)),
      setupNonce: uint64(2),
      nextAttemptId: uint64(3),
      setupCommittedAtBlock: uint48(4),
      attempt: IPolicyManager.Attempt({
        attemptId: uint64(6),
        setupNonce: uint64(7),
        consumableAfter: uint48(8),
        state: IPolicyManager.AttemptState.Cancelled,
        ignoresPause: true,
        payloadHash: bytes32(uint256(0xb00b)),
        order: IPolicyManager.PaymentOrder({token: address(0x100d), amount: uint256(14), payee: address(0x100f)}),
        usedMethods: _usedMethods
      })
    });
    _subject.setupCommitment = _exactlyBytes32(_subject.setupCommitment);
    _subject.setupNonce = _exactlyUint64(_subject.setupNonce);
    _subject.nextAttemptId = _exactlyUint64(_subject.nextAttemptId);
    _subject.setupCommittedAtBlock = _exactlyUint48(_subject.setupCommittedAtBlock);
    _subject.attempt = _exactlyAttempt(_subject.attempt);
    assertEq(
      abi.encode(_subject),
      bytes.concat(
        bytes32(uint256(0x20)),
        abi.encode(
          _subject.setupCommitment,
          _subject.setupNonce,
          _subject.nextAttemptId,
          _subject.setupCommittedAtBlock,
          _subject.attempt
        )
      )
    );
  }

  /// Builds a Setup with named fields and distinct values. Each _exactly helper compiles only when the field has
  /// exactly that type, and the encoding must equal the fields encoded in order. The manager keeps one Setup per
  /// account and action, so a moved or resized field misplaces the commitment, the nonce or the attempt counter.
  function test_WhenTheSetupStructIsEncoded() external pure {
    // it should hold the specified fields types and order
    IPolicyManager.Setup memory _subject = IPolicyManager.Setup({
      commitment: bytes32(uint256(0xb001)),
      nonce: uint64(2),
      attemptCounter: uint64(3),
      setupCommittedAtBlock: uint48(4)
    });
    _subject.commitment = _exactlyBytes32(_subject.commitment);
    _subject.nonce = _exactlyUint64(_subject.nonce);
    _subject.attemptCounter = _exactlyUint64(_subject.attemptCounter);
    _subject.setupCommittedAtBlock = _exactlyUint48(_subject.setupCommittedAtBlock);
    assertEq(
      abi.encode(_subject),
      abi.encode(_subject.commitment, _subject.nonce, _subject.attemptCounter, _subject.setupCommittedAtBlock)
    );
  }

  /// Builds a Clause with named fields and distinct values. Each _exactly helper compiles only when the field has
  /// exactly that type, and the encoding must equal the fields encoded in order. A setup body is abi.encode over a
  /// list of these, so a moved or resized field makes the manager read a rule other than the one a client wrote.
  function test_WhenTheClauseStructIsEncoded() external pure {
    // it should hold the specified fields types and order
    bytes32[] memory _credentials = new bytes32[](2);
    _credentials[0] = bytes32(uint256(0xb002));
    _credentials[1] = bytes32(uint256(0xb003));
    IPolicyManager.Clause memory _subject = IPolicyManager.Clause({threshold: uint8(1), credentials: _credentials});
    _subject.threshold = _exactlyUint8(_subject.threshold);
    _subject.credentials = _exactlyBytes32Array(_subject.credentials);
    assertEq(
      abi.encode(_subject), bytes.concat(bytes32(uint256(0x20)), abi.encode(_subject.threshold, _subject.credentials))
    );
  }

  /// Reads Setup from the compiled artifact of IPolicyManager and checks its members are commitment, nonce,
  /// attemptCounter and setupCommittedAtBlock, in that order, with their types. No function or event carries Setup,
  /// so the ABI never lists it, and the artifact is the one place its declared names can be read.
  function test_WhenTheSetupMembersAreReadFromTheArtifact() external {
    // it should declare the specified names and types in order
    string memory _json = _interfacesLoad('IPolicyManager');
    _interfacesAssertStruct(
      _json, 'Setup', 'bytes32 commitment,uint64 nonce,uint64 attemptCounter,uint48 setupCommittedAtBlock'
    );
  }

  /// Reads Clause from the compiled artifact of IPolicyManager and checks its members are threshold and credentials,
  /// in that order, with their types. No function or event carries Clause, so the ABI never lists it, and the
  /// artifact is the one place its declared names can be read.
  function test_WhenTheClauseMembersAreReadFromTheArtifact() external {
    // it should declare the specified names and types in order
    string memory _json = _interfacesLoad('IPolicyManager');
    _interfacesAssertStruct(_json, 'Clause', 'uint8 threshold,bytes32[] credentials');
  }

  /// Checks the attempt states are numbered None 0, Waiting 1, Cancelled 2 and Consumed 3, with nothing
  /// after Consumed. stateOf returns this number, so a reorder makes a client misread an attempt.
  function test_WhenTheAttemptStatesAreCastToIntegers() external pure {
    // it should number them None Waiting Cancelled Consumed
    assertEq(uint8(IPolicyManager.AttemptState.None), 0);
    assertEq(uint8(IPolicyManager.AttemptState.Waiting), 1);
    assertEq(uint8(IPolicyManager.AttemptState.Cancelled), 2);
    assertEq(uint8(IPolicyManager.AttemptState.Consumed), 3);
    assertEq(uint8(type(IPolicyManager.AttemptState).min), uint8(IPolicyManager.AttemptState.None));
    assertEq(uint8(type(IPolicyManager.AttemptState).max), uint8(IPolicyManager.AttemptState.Consumed));
  }

  /// @notice Compiles only when the field is exactly Attempt: the argument converts implicitly
  ///         from the field, and the result converts implicitly back into it.
  function _exactlyAttempt(IPolicyManager.Attempt memory _input)
    private
    pure
    returns (IPolicyManager.Attempt memory _output)
  {
    _output = _input;
  }

  /// @notice Compiles only when the field is exactly AttemptState: the argument converts implicitly
  ///         from the field, and the result converts implicitly back into it.
  function _exactlyAttemptState(IPolicyManager.AttemptState _input)
    private
    pure
    returns (IPolicyManager.AttemptState _output)
  {
    _output = _input;
  }

  /// @notice Compiles only when the field is exactly PaymentOrder: the argument converts implicitly
  ///         from the field, and the result converts implicitly back into it.
  function _exactlyPaymentOrder(IPolicyManager.PaymentOrder memory _input)
    private
    pure
    returns (IPolicyManager.PaymentOrder memory _output)
  {
    _output = _input;
  }

  /// @notice Compiles only when the field is exactly ProofPlace[]: the argument converts implicitly
  ///         from the field, and the result converts implicitly back into it.
  function _exactlyProofPlaceArray(IPolicyManager.ProofPlace[] memory _input)
    private
    pure
    returns (IPolicyManager.ProofPlace[] memory _output)
  {
    _output = _input;
  }

  /// @notice Compiles only when the field is exactly address: the argument converts implicitly
  ///         from the field, and the result converts implicitly back into it.
  function _exactlyAddress(address _input) private pure returns (address _output) {
    _output = _input;
  }

  /// @notice Compiles only when the field is exactly address[]: the argument converts implicitly
  ///         from the field, and the result converts implicitly back into it.
  function _exactlyAddressArray(address[] memory _input) private pure returns (address[] memory _output) {
    _output = _input;
  }

  /// @notice Compiles only when the field is exactly bool: the argument converts implicitly
  ///         from the field, and the result converts implicitly back into it.
  function _exactlyBool(bool _input) private pure returns (bool _output) {
    _output = _input;
  }

  /// @notice Compiles only when the field is exactly bytes: the argument converts implicitly
  ///         from the field, and the result converts implicitly back into it.
  function _exactlyBytes(bytes memory _input) private pure returns (bytes memory _output) {
    _output = _input;
  }

  /// @notice Compiles only when the field is exactly bytes32[]: the argument converts implicitly
  ///         from the field, and the result converts implicitly back into it.
  function _exactlyBytes32Array(bytes32[] memory _input) private pure returns (bytes32[] memory _output) {
    _output = _input;
  }

  /// @notice Compiles only when the field is exactly bytes32: the argument converts implicitly
  ///         from the field, and the result converts implicitly back into it.
  function _exactlyBytes32(bytes32 _input) private pure returns (bytes32 _output) {
    _output = _input;
  }

  /// @notice Compiles only when the field is exactly uint256: the argument converts implicitly
  ///         from the field, and the result converts implicitly back into it.
  function _exactlyUint256(uint256 _input) private pure returns (uint256 _output) {
    _output = _input;
  }

  /// @notice Compiles only when the field is exactly uint8: the argument converts implicitly
  ///         from the field, and the result converts implicitly back into it.
  function _exactlyUint8(uint8 _input) private pure returns (uint8 _output) {
    _output = _input;
  }

  /// @notice Compiles only when the field is exactly uint48: the argument converts implicitly
  ///         from the field, and the result converts implicitly back into it.
  function _exactlyUint48(uint48 _input) private pure returns (uint48 _output) {
    _output = _input;
  }

  /// @notice Compiles only when the field is exactly uint64: the argument converts implicitly
  ///         from the field, and the result converts implicitly back into it.
  function _exactlyUint64(uint64 _input) private pure returns (uint64 _output) {
    _output = _input;
  }
}
