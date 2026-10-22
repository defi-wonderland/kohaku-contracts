// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {
  MethodZkPassportProofVerificationData,
  MethodZkPassportProofVerificationParams
} from 'test/mocks/MethodZkPassportMocks.sol';
import {MethodZkPassportFixture} from 'test/utils/MethodZkPassportFixture.sol';

/// @notice Replays the frozen zkPassport vector files. The SDK writes these bytes and the method reads them. Both
///         sides replay the same files, and a change on either side fails a test. The proof vector is synthetic. It
///         fixes the outer encoding, the nullifier type position and the text rendering of the digest. Its replay
///         checks those against the mocks, not against a live proof. Every value is read from the files at run time,
///         and a file with no row fails.
contract ZkPassportMethodKatTest is MethodZkPassportFixture {
  string internal constant _ZK_KAT_CONFIG_FILE = 'test/fixtures/kats/method-zkpassport-config.json';
  string internal constant _ZK_KAT_PROOF_FILE = 'test/fixtures/kats/method-zkpassport-proof.json';
  /// @notice The config layout this replay reads: four fields and no version. A file in another layout fails.
  string internal constant _ZK_KAT_CONFIG_FORMAT = 'method-zkpassport-config-v2';

  /// @notice One row of the config vector file.
  struct ZkPassportKatConfigRow {
    bytes32 uniqueIdentifier;
    string domain;
    string scope;
    uint256 validity;
    bytes encoded;
  }

  /// @notice One row of the proof vector file.
  struct ZkPassportKatProofRow {
    MethodZkPassportProofVerificationData data;
    bytes committedInputs;
    bytes32 digest;
    bytes encoded;
    string requiredCustomData;
    uint256 nullifierIndexFromEnd;
  }

  /*///////////////////////////////////////////////////////////////
                          CONFIG VECTORS
  ///////////////////////////////////////////////////////////////*/

  /// Encoding each frozen config row's identifier, domain, scope and validity in the config layout gives the frozen
  /// bytes. The fixture's encoder therefore writes what the SDK writes, and the config carries no version.
  function test_WhenReplayingTheConfigVectorEncodings() external view {
    string memory _json = vm.readFile(_ZK_KAT_CONFIG_FILE);
    // it should read a file in the four field layout
    assertEq(vm.parseJsonString(_json, '.format'), _ZK_KAT_CONFIG_FORMAT, 'format');
    // it should reproduce every frozen config encoding
    uint256 _count = _zkKatRowCount(_json);
    for (uint256 _i; _i < _count; ++_i) {
      ZkPassportKatConfigRow memory _row = _zkKatConfigRow(_json, _i);
      assertEq(_zkConfig(_row.uniqueIdentifier, _row.domain, _row.scope, _row.validity), _row.encoded, 'encoding');
    }
  }

  /// The method decodes each frozen config into exactly the root verifier call its fields describe, under the version
  /// the method accepts, and accepts the proof. A config the SDK wrote is read the way the SDK meant it.
  function test_WhenReplayingTheConfigVectorsThroughVerify() external {
    // it should call the root verifier with each rows fields and the accepted version, and accept the proof
    string memory _json = vm.readFile(_ZK_KAT_CONFIG_FILE);
    uint256 _count = _zkKatRowCount(_json);
    for (uint256 _i; _i < _count; ++_i) {
      ZkPassportKatConfigRow memory _row = _zkKatConfigRow(_json, _i);
      MethodZkPassportProofVerificationData memory _data = _zkProofData(_zkPublicInputs(8));
      MethodZkPassportProofVerificationParams memory _params = _zkKatAcceptRow(_row, _data, _row.uniqueIdentifier);
      vm.expectCall(address(_rootMock), _zkRootCall(_params), 1);
      _zkAssertAccepted(_row.encoded, _defaultDigest, _zkProof(_data, _defaultCommittedInputs));
    }
  }

  /// Each frozen config is refused when the root verifier returns an identifier one bit away from the row's. The
  /// method compares the returned identifier with the one it decoded from the config.
  function test_WhenReplayingTheConfigVectorsWithAnotherReturnedIdentifier() external {
    // it should refuse the proof
    string memory _json = vm.readFile(_ZK_KAT_CONFIG_FILE);
    uint256 _count = _zkKatRowCount(_json);
    for (uint256 _i; _i < _count; ++_i) {
      ZkPassportKatConfigRow memory _row = _zkKatConfigRow(_json, _i);
      MethodZkPassportProofVerificationData memory _data = _zkProofData(_zkPublicInputs(8));
      _zkKatAcceptRow(_row, _data, bytes32(uint256(_row.uniqueIdentifier) ^ 1));
      _zkAssertRefused(_row.encoded, _defaultDigest, _zkProof(_data, _defaultCommittedInputs));
    }
  }

  /*///////////////////////////////////////////////////////////////
                           PROOF VECTORS
  ///////////////////////////////////////////////////////////////*/

  /// Encoding each frozen proof row's inputs in the proof layout gives the frozen bytes.
  function test_WhenReplayingTheProofVectorEncodings() external view {
    // it should reproduce every frozen proof encoding
    string memory _json = vm.readFile(_ZK_KAT_PROOF_FILE);
    uint256 _count = _zkKatRowCount(_json);
    for (uint256 _i; _i < _count; ++_i) {
      ZkPassportKatProofRow memory _row = _zkKatProofRow(_json, _i);
      assertEq(_zkProof(_row.data, _row.committedInputs), _row.encoded, 'encoding');
    }
  }

  /// The fixture's digest renderer turns each frozen digest into the frozen custom data. The unit tests use that
  /// renderer for the expected custom data. This replay is what checks the renderer.
  function test_WhenReplayingTheProofVectorRenderings() external view {
    // it should render every frozen digest as the required custom data
    string memory _json = vm.readFile(_ZK_KAT_PROOF_FILE);
    uint256 _count = _zkKatRowCount(_json);
    for (uint256 _i; _i < _count; ++_i) {
      ZkPassportKatProofRow memory _row = _zkKatProofRow(_json, _i);
      assertEq(_row.requiredCustomData, _zkRender(_row.digest), 'rendering');
    }
  }

  /// Each frozen proof is accepted under its frozen digest when the verifier helper answers the frozen custom data. Its
  /// decoded fields reach the root verifier unchanged.
  function test_WhenReplayingTheProofVectorsThroughVerify() external {
    // it should pass the decoded fields to the root verifier and accept the proof
    string memory _json = vm.readFile(_ZK_KAT_PROOF_FILE);
    uint256 _count = _zkKatRowCount(_json);
    for (uint256 _i; _i < _count; ++_i) {
      ZkPassportKatProofRow memory _row = _zkKatProofRow(_json, _i);
      _zkKatSetAnswers(_row.data, _row.committedInputs, _row.requiredCustomData);
      vm.expectCall(
        address(_rootMock),
        _zkRootCall(
          _zkParams(
            _ZK_VERSION_0_21_0, _row.data, _row.committedInputs, _defaultValidity, _defaultDomain, _defaultScope, false
          )
        ),
        1
      );
      _zkAssertAccepted(_zkDefaultConfig(), _row.digest, _row.encoded);
    }
  }

  /// The frozen custom data with its hexadecimal letters in uppercase is refused.
  function test_WhenReplayingTheProofVectorsWithUppercaseCustomData() external {
    // it should refuse the proof
    string memory _json = vm.readFile(_ZK_KAT_PROOF_FILE);
    uint256 _count = _zkKatRowCount(_json);
    for (uint256 _i; _i < _count; ++_i) {
      ZkPassportKatProofRow memory _row = _zkKatProofRow(_json, _i);
      string memory _upper = _zkKatUpper(_row.requiredCustomData);
      assertTrue(keccak256(bytes(_upper)) != keccak256(bytes(_row.requiredCustomData)), 'the row holds no letter');
      _zkKatSetAnswers(_row.data, _row.committedInputs, _upper);
      _zkAssertRefused(_zkDefaultConfig(), _row.digest, _row.encoded);
    }
  }

  /// The frozen custom data without its 0x prefix is refused.
  function test_WhenReplayingTheProofVectorsWithUnprefixedCustomData() external {
    // it should refuse the proof
    string memory _json = vm.readFile(_ZK_KAT_PROOF_FILE);
    uint256 _count = _zkKatRowCount(_json);
    for (uint256 _i; _i < _count; ++_i) {
      ZkPassportKatProofRow memory _row = _zkKatProofRow(_json, _i);
      _zkKatSetAnswers(_row.data, _row.committedInputs, _zkKatStripPrefix(_row.requiredCustomData));
      _zkAssertRefused(_zkDefaultConfig(), _row.digest, _row.encoded);
    }
  }

  /// Each frozen proof carries zero at the frozen nullifier type position, counted from the end. Flipping that input
  /// gets the proof refused. The method reads the nullifier type where the SDK writes it.
  function test_WhenReplayingTheProofVectorsWithTheNullifierInputChanged() external {
    // it should refuse the proof
    string memory _json = vm.readFile(_ZK_KAT_PROOF_FILE);
    uint256 _count = _zkKatRowCount(_json);
    for (uint256 _i; _i < _count; ++_i) {
      ZkPassportKatProofRow memory _row = _zkKatProofRow(_json, _i);
      uint256 _position = _row.data.publicInputs.length - _row.nullifierIndexFromEnd;
      assertEq(_row.data.publicInputs[_position], bytes32(0), 'the frozen row carries the unsalted nullifier type');
      MethodZkPassportProofVerificationData memory _data = _zkKatFlip(_row.data, _position);
      _zkKatSetAnswers(_data, _row.committedInputs, _row.requiredCustomData);
      _zkAssertRefused(_zkDefaultConfig(), _row.digest, _zkProof(_data, _row.committedInputs));
    }
  }

  /// Flipping any other public input of a frozen proof still gets it accepted. No other position is read as the
  /// nullifier type.
  function test_WhenReplayingTheProofVectorsWithAnotherInputChanged() external {
    // it should accept the proof
    string memory _json = vm.readFile(_ZK_KAT_PROOF_FILE);
    uint256 _count = _zkKatRowCount(_json);
    for (uint256 _i; _i < _count; ++_i) {
      ZkPassportKatProofRow memory _row = _zkKatProofRow(_json, _i);
      uint256 _length = _row.data.publicInputs.length;
      uint256 _position = _length - _row.nullifierIndexFromEnd;
      for (uint256 _j; _j < _length; ++_j) {
        if (_j == _position) continue;
        MethodZkPassportProofVerificationData memory _data = _zkKatFlip(_row.data, _j);
        _zkKatSetAnswers(_data, _row.committedInputs, _row.requiredCustomData);
        _zkAssertAccepted(_zkDefaultConfig(), _row.digest, _zkProof(_data, _row.committedInputs));
      }
    }
  }

  /// Each frozen proof is refused under a digest one bit away from its own. A proof made for one recovery cannot
  /// approve another.
  function test_WhenReplayingTheProofVectorsUnderAnotherDigest() external {
    // it should refuse the proof
    string memory _json = vm.readFile(_ZK_KAT_PROOF_FILE);
    uint256 _count = _zkKatRowCount(_json);
    for (uint256 _i; _i < _count; ++_i) {
      ZkPassportKatProofRow memory _row = _zkKatProofRow(_json, _i);
      _zkKatSetAnswers(_row.data, _row.committedInputs, _row.requiredCustomData);
      _zkAssertRefused(_zkDefaultConfig(), bytes32(uint256(_row.digest) ^ 1), _row.encoded);
    }
  }

  /*///////////////////////////////////////////////////////////////
                       INTERNAL FUNCTIONS
  ///////////////////////////////////////////////////////////////*/

  /// @notice The number of rows under .vectors. The test fails when there is none.
  function _zkKatRowCount(string memory _json) internal view returns (uint256 _count) {
    while (vm.keyExistsJson(_json, _zkKatRow(_count, ''))) {
      ++_count;
    }
    assertGt(_count, 0, 'the vector file holds no row');
  }

  /// @notice The JSON path of a field of row i.
  function _zkKatRow(uint256 _i, string memory _field) internal pure returns (string memory _path) {
    _path = string.concat('.vectors[', vm.toString(_i), ']', _field);
  }

  function _zkKatConfigRow(string memory _json, uint256 _i) internal pure returns (ZkPassportKatConfigRow memory _row) {
    _row.uniqueIdentifier = vm.parseJsonBytes32(_json, _zkKatRow(_i, '.input.uniqueIdentifier'));
    _row.domain = vm.parseJsonString(_json, _zkKatRow(_i, '.input.domain'));
    _row.scope = vm.parseJsonString(_json, _zkKatRow(_i, '.input.scope'));
    _row.validity = vm.parseJsonUint(_json, _zkKatRow(_i, '.input.validityPeriodInSeconds'));
    _row.encoded = vm.parseJsonBytes(_json, _zkKatRow(_i, '.expected.encoded'));
  }

  function _zkKatProofRow(string memory _json, uint256 _i) internal pure returns (ZkPassportKatProofRow memory _row) {
    _row.data = MethodZkPassportProofVerificationData({
      vkeyHash: vm.parseJsonBytes32(_json, _zkKatRow(_i, '.input.proofVerificationData.vkeyHash')),
      proof: vm.parseJsonBytes(_json, _zkKatRow(_i, '.input.proofVerificationData.proof')),
      publicInputs: vm.parseJsonBytes32Array(_json, _zkKatRow(_i, '.input.proofVerificationData.publicInputs'))
    });
    _row.committedInputs = vm.parseJsonBytes(_json, _zkKatRow(_i, '.input.committedInputs'));
    _row.digest = vm.parseJsonBytes32(_json, _zkKatRow(_i, '.input.digest'));
    _row.encoded = vm.parseJsonBytes(_json, _zkKatRow(_i, '.expected.encoded'));
    _row.requiredCustomData = vm.parseJsonString(_json, _zkKatRow(_i, '.expected.requiredCustomData'));
    _row.nullifierIndexFromEnd = vm.parseJsonUint(_json, _zkKatRow(_i, '.expected.nullifierTypeIndexFromEnd'));
  }

  /// @notice Sets the root mock to answer valid with the given identifier for exactly the call the config row
  ///         describes under the accepted version, and the verifier helper mock to bind the fixture digest. Returns the
  ///         params that call carries.
  function _zkKatAcceptRow(
    ZkPassportKatConfigRow memory _row,
    MethodZkPassportProofVerificationData memory _data,
    bytes32 _returnedIdentifier
  ) internal returns (MethodZkPassportProofVerificationParams memory _params) {
    _params = _zkParams(
      _ZK_VERSION_0_21_0, _data, _defaultCommittedInputs, _row.validity, _row.domain, _row.scope, false
    );
    _zkSetAnswers(
      _rootMock,
      _verifierHelperMock,
      _params,
      true,
      _returnedIdentifier,
      address(_verifierHelperMock),
      _zkRender(_defaultDigest)
    );
  }

  /// @notice Sets the root mock to accept this proof data under the default config, and the verifier helper mock to
  ///         answer the given custom data.
  function _zkKatSetAnswers(
    MethodZkPassportProofVerificationData memory _data,
    bytes memory _committedInputs,
    string memory _customData
  ) internal {
    _zkSetAnswers(
      _rootMock,
      _verifierHelperMock,
      _zkParams(_ZK_VERSION_0_21_0, _data, _committedInputs, _defaultValidity, _defaultDomain, _defaultScope, false),
      true,
      _defaultIdentifier,
      address(_verifierHelperMock),
      _customData
    );
  }

  /// @notice A copy of the proof data with the lowest bit of one public input flipped.
  function _zkKatFlip(MethodZkPassportProofVerificationData memory _data, uint256 _index)
    internal
    pure
    returns (MethodZkPassportProofVerificationData memory _copy)
  {
    bytes32[] memory _inputs = new bytes32[](_data.publicInputs.length);
    for (uint256 _i; _i < _inputs.length; ++_i) {
      _inputs[_i] = _data.publicInputs[_i];
    }
    _inputs[_index] = bytes32(uint256(_inputs[_index]) ^ 1);
    _copy.vkeyHash = _data.vkeyHash;
    _copy.proof = _data.proof;
    _copy.publicInputs = _inputs;
  }

  /// @notice The same text with the letters a to f raised to A to F. The first two characters, the 0x prefix, stay
  ///         as they are.
  function _zkKatUpper(string memory _text) internal pure returns (string memory _upper) {
    bytes memory _b = bytes(_text);
    bytes memory _out = new bytes(_b.length);
    for (uint256 _i; _i < _b.length; ++_i) {
      bytes1 _c = _b[_i];
      _out[_i] = (_i > 1 && uint8(_c) > 0x60 && uint8(_c) < 0x67) ? bytes1(uint8(_c) - 32) : _c;
    }
    _upper = string(_out);
  }

  /// @notice The same text without its first two characters.
  function _zkKatStripPrefix(string memory _text) internal pure returns (string memory _stripped) {
    bytes memory _b = bytes(_text);
    bytes memory _out = new bytes(_b.length - 2);
    for (uint256 _i; _i < _out.length; ++_i) {
      _out[_i] = _b[_i + 2];
    }
    _stripped = string(_out);
  }
}
