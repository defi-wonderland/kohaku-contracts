// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {IPolicyMethod} from 'interfaces/IPolicyMethod.sol';
import {AadhaarMethod} from 'contracts/methods/aadhaar/AadhaarMethod.sol';
import {MethodAadhaarTestBase} from 'test/utils/MethodAadhaarTestBase.sol';

/// @notice Replays the two frozen Aadhaar vector files, one for the config and one for the proof. It reads both files
///         at run time and embeds no vector value. The SDK replays the same files. A byte drift between the SDK and
///         the method fails here. The proof vector's points are small made-up integers, and a mock plays the verifier.
contract AadhaarMethodKatTest is MethodAadhaarTestBase {
  /*///////////////////////////////////////////////////////////////
                              STRUCTS
  ///////////////////////////////////////////////////////////////*/

  /// @notice One row of the proof vector file, as read.
  struct AadhaarKatProofRow {
    string path;
    uint256[2] piA;
    uint256[2][2] piB;
    uint256[2] piC;
    bytes32 digest;
    uint256[9] inputs;
    uint256[2] a;
    uint256[2][2] b;
    uint256[2] c;
    uint256 signalHash;
    bytes encoded;
    uint256 byteLength;
  }

  /// @notice One row of the config vector file, as read.
  struct AadhaarKatConfigRow {
    string path;
    uint256 nullifier;
    uint256 nullifierSeed;
    uint256 freshnessWindow;
    bytes encoded;
  }

  /*///////////////////////////////////////////////////////////////
                          STATE VARIABLES
  ///////////////////////////////////////////////////////////////*/

  string internal constant _AADHAAR_KAT_CONFIG_PATH = 'test/fixtures/kats/method-aadhaar-config.json';
  string internal constant _AADHAAR_KAT_PROOF_PATH = 'test/fixtures/kats/method-aadhaar-proof.json';

  /*///////////////////////////////////////////////////////////////
                               TESTS
  ///////////////////////////////////////////////////////////////*/

  /// The frozen config bytes are accepted with a proof carrying that row's nullifier and seed. A config the SDK
  /// writes is one the method reads.
  function test_WhenReplayingTheConfigVectorsAgainstMatchingInputs() external {
    // it should accept the proof for every row.
    string memory _json = vm.readFile(_AADHAAR_KAT_CONFIG_PATH);
    uint256 _count = _aadhaarKatCount(_json);
    for (uint256 _i; _i < _count; ++_i) {
      AadhaarKatConfigRow memory _row = _aadhaarKatConfigRow(_json, _i);
      AadhaarProof memory _proof = _aadhaarValidProof(_issuerKey, _row.nullifier, _row.nullifierSeed, _digest);
      _aadhaarExpect(_proof);
      assertTrue(_aadhaarAccepts(_row.encoded, _digest, _aadhaarEncode(_proof)), _row.path);
    }
  }

  /// The frozen config bytes accept a proof signed exactly the row's window before the verifying block and refuse
  /// one signed a second earlier. The method reads the third config word as the freshness window, so the window the
  /// SDK writes is the one that bounds a copied QR.
  function test_WhenReplayingTheConfigVectorsAtTheEdgeOfTheirWindow() external {
    // it should accept a proof signed the window before and refuse one signed a second earlier, for every row.
    string memory _json = vm.readFile(_AADHAAR_KAT_CONFIG_PATH);
    uint256 _count = _aadhaarKatCount(_json);
    for (uint256 _i; _i < _count; ++_i) {
      AadhaarKatConfigRow memory _row = _aadhaarKatConfigRow(_json, _i);
      AadhaarProof memory _proof = _aadhaarValidProof(_issuerKey, _row.nullifier, _row.nullifierSeed, _digest);
      _proof.inputs[2] = block.timestamp - _row.freshnessWindow;
      _aadhaarExpect(_proof);
      assertTrue(_aadhaarAccepts(_row.encoded, _digest, _aadhaarEncode(_proof)), string.concat(_row.path, ' edge'));
      _proof.inputs[2] -= 1;
      _aadhaarExpect(_proof);
      assertFalse(_aadhaarAccepts(_row.encoded, _digest, _aadhaarEncode(_proof)), string.concat(_row.path, ' past'));
    }
  }

  /// The frozen config bytes are refused with a proof that swaps the row's nullifier and seed. The method reads the
  /// nullifier and seed config words in their frozen order.
  function test_WhenReplayingTheConfigVectorsAgainstSwappedInputs() external {
    // it should refuse the proof for any row.
    string memory _json = vm.readFile(_AADHAAR_KAT_CONFIG_PATH);
    uint256 _count = _aadhaarKatCount(_json);
    for (uint256 _i; _i < _count; ++_i) {
      AadhaarKatConfigRow memory _row = _aadhaarKatConfigRow(_json, _i);
      assertTrue(_row.nullifier != _row.nullifierSeed, string.concat(_row.path, ' distinct words'));
      AadhaarProof memory _proof = _aadhaarValidProof(_issuerKey, _row.nullifierSeed, _row.nullifier, _digest);
      _aadhaarExpect(_proof);
      assertFalse(_aadhaarAccepts(_row.encoded, _digest, _aadhaarEncode(_proof)), _row.path);
    }
  }

  /// The frozen 544 proof bytes and the frozen digest are accepted in a block at the proof's signing time, input
  /// two. The verifier receives exactly the frozen a, b, c and nine inputs. A proof the SDK packs is decoded the same
  /// way by the method, with b passed as packed.
  function test_WhenReplayingTheProofVectors() external {
    // it should pass the frozen fields to the verifier and return the verify selector for every row.
    string memory _json = vm.readFile(_AADHAAR_KAT_PROOF_PATH);
    uint256 _count = _aadhaarKatCount(_json);
    for (uint256 _i; _i < _count; ++_i) {
      AadhaarKatProofRow memory _row = _aadhaarKatProofRow(_json, _i);
      assertEq(_row.encoded.length, _row.byteLength, string.concat(_row.path, ' byte length'));
      AadhaarMethod _deployed = _aadhaarKatMethodFor(_row);
      vm.warp(_row.inputs[2]);
      bytes memory _config = _aadhaarConfig(_row.inputs[1], _row.inputs[7], _freshnessWindow);
      bytes4 _answer = _deployed.verify(_config, _row.digest, _row.encoded);
      assertEq(_answer, IPolicyMethod.verify.selector, string.concat(_row.path, ' magic value'));
    }
  }

  /// The frozen proof is refused when verify is asked about any digest but the frozen one. The frozen signal hash
  /// approves exactly that digest.
  function test_WhenReplayingTheProofVectorsForAnotherDigest() external {
    // it should refuse the proof for any row.
    string memory _json = vm.readFile(_AADHAAR_KAT_PROOF_PATH);
    uint256 _count = _aadhaarKatCount(_json);
    for (uint256 _i; _i < _count; ++_i) {
      AadhaarKatProofRow memory _row = _aadhaarKatProofRow(_json, _i);
      AadhaarMethod _deployed = _aadhaarKatMethodFor(_row);
      vm.warp(_row.inputs[2]);
      bytes memory _config = _aadhaarConfig(_row.inputs[1], _row.inputs[7], _freshnessWindow);
      bytes32 _other = _row.digest ^ bytes32(uint256(1));
      assertFalse(_aadhaarAccepts(address(_deployed), _config, _other, _row.encoded), _row.path);
    }
  }

  /// The test base's proof, config and signal builders reproduce the frozen bytes and signal hash. Packing the
  /// upstream proof in the client's order gives the frozen a, b and c. The unit tests built on them therefore test
  /// the frozen format.
  function test_WhenReplayingTheVectorsThroughTheTestBuilders() external view {
    // it should reproduce every frozen byte and signal hash.
    string memory _proofJson = vm.readFile(_AADHAAR_KAT_PROOF_PATH);
    uint256 _proofCount = _aadhaarKatCount(_proofJson);
    for (uint256 _i; _i < _proofCount; ++_i) {
      AadhaarKatProofRow memory _row = _aadhaarKatProofRow(_proofJson, _i);
      uint256[2][2] memory _packedB = [[_row.piB[0][1], _row.piB[0][0]], [_row.piB[1][1], _row.piB[1][0]]];
      for (uint256 _k; _k < 2; ++_k) {
        assertEq(_row.a[_k], _row.piA[_k], string.concat(_row.path, ' packed a'));
        assertEq(_row.c[_k], _row.piC[_k], string.concat(_row.path, ' packed c'));
        assertEq(_packedB[_k][0], _row.b[_k][0], string.concat(_row.path, ' packed b, first coordinate'));
        assertEq(_packedB[_k][1], _row.b[_k][1], string.concat(_row.path, ' packed b, second coordinate'));
      }
      AadhaarProof memory _proof = AadhaarProof({a: _row.a, b: _row.b, c: _row.c, inputs: _row.inputs});
      assertEq(_aadhaarEncode(_proof), _row.encoded, string.concat(_row.path, ' proof bytes'));
      assertEq(_aadhaarSignal(_row.digest), _row.signalHash, string.concat(_row.path, ' signal'));
      assertEq(_row.inputs[8], _row.signalHash, string.concat(_row.path, ' input eight'));
    }
    string memory _configJson = vm.readFile(_AADHAAR_KAT_CONFIG_PATH);
    uint256 _configCount = _aadhaarKatCount(_configJson);
    for (uint256 _i; _i < _configCount; ++_i) {
      AadhaarKatConfigRow memory _row = _aadhaarKatConfigRow(_configJson, _i);
      assertEq(
        _aadhaarConfig(_row.nullifier, _row.nullifierSeed, _row.freshnessWindow),
        _row.encoded,
        string.concat(_row.path, ' config')
      );
    }
  }

  /*///////////////////////////////////////////////////////////////
                              HELPERS
  ///////////////////////////////////////////////////////////////*/

  /// @notice A method trusting the row's input zero as its issuer key, with the mock verifier accepting exactly
  ///         the row's expected points and inputs.
  function _aadhaarKatMethodFor(AadhaarKatProofRow memory _row) internal returns (AadhaarMethod _deployed) {
    assertTrue(_row.inputs[0] != 0, string.concat(_row.path, ' a nonzero key'));
    _deployed = _aadhaarDeploy(_owner, _admin, _aadhaarOneKey(bytes32(_row.inputs[0])), address(_verifier));
    _verifier.expectExact(_row.a, _row.b, _row.c, _row.inputs);
  }

  /// @notice The number of rows under `.vectors` in a vector file.
  function _aadhaarKatCount(string memory _json) internal view returns (uint256 _count) {
    while (vm.keyExistsJson(_json, string.concat('.vectors[', vm.toString(_count), ']'))) ++_count;
    assertGt(_count, 0, 'the file holds vectors');
  }

  /// @notice A decimal string field of a vector file, as a uint256.
  function _aadhaarKatUint(string memory _json, string memory _key) internal pure returns (uint256 _value) {
    _value = vm.parseUint(vm.parseJsonString(_json, _key));
  }

  /// @notice A two-element array of decimal strings, as a uint256 pair.
  function _aadhaarKatPair(string memory _json, string memory _key) internal pure returns (uint256[2] memory _pair) {
    string[] memory _words = vm.parseJsonStringArray(_json, _key);
    assertEq(_words.length, 2, _key);
    _pair[0] = vm.parseUint(_words[0]);
    _pair[1] = vm.parseUint(_words[1]);
  }

  /// @notice Reads config row `_i`.
  function _aadhaarKatConfigRow(string memory _json, uint256 _i)
    internal
    pure
    returns (AadhaarKatConfigRow memory _row)
  {
    _row.path = string.concat('.vectors[', vm.toString(_i), ']');
    _row.nullifier = _aadhaarKatUint(_json, string.concat(_row.path, '.input.nullifier'));
    _row.nullifierSeed = _aadhaarKatUint(_json, string.concat(_row.path, '.input.nullifierSeed'));
    _row.freshnessWindow = _aadhaarKatUint(_json, string.concat(_row.path, '.input.freshnessWindow'));
    _row.encoded = vm.parseJsonBytes(_json, string.concat(_row.path, '.expected.encoded'));
  }

  /// @notice Reads proof row `_i`.
  function _aadhaarKatProofRow(string memory _json, uint256 _i) internal pure returns (AadhaarKatProofRow memory _row) {
    _row.path = string.concat('.vectors[', vm.toString(_i), ']');
    string memory _input = string.concat(_row.path, '.input');
    string memory _expected = string.concat(_row.path, '.expected');
    _row.piA = _aadhaarKatPair(_json, string.concat(_input, '.upstreamProof.pi_a'));
    _row.piB[0] = _aadhaarKatPair(_json, string.concat(_input, '.upstreamProof.pi_b[0]'));
    _row.piB[1] = _aadhaarKatPair(_json, string.concat(_input, '.upstreamProof.pi_b[1]'));
    _row.piC = _aadhaarKatPair(_json, string.concat(_input, '.upstreamProof.pi_c'));
    _row.digest = vm.parseJsonBytes32(_json, string.concat(_input, '.digest'));
    string[] memory _inputs = vm.parseJsonStringArray(_json, string.concat(_input, '.inputs'));
    assertEq(_inputs.length, 9, 'nine public inputs');
    for (uint256 _k; _k < 9; ++_k) {
      _row.inputs[_k] = vm.parseUint(_inputs[_k]);
    }
    _row.a = _aadhaarKatPair(_json, string.concat(_expected, '.a'));
    _row.b[0] = _aadhaarKatPair(_json, string.concat(_expected, '.b[0]'));
    _row.b[1] = _aadhaarKatPair(_json, string.concat(_expected, '.b[1]'));
    _row.c = _aadhaarKatPair(_json, string.concat(_expected, '.c'));
    _row.signalHash = _aadhaarKatUint(_json, string.concat(_expected, '.signalHash'));
    _row.encoded = vm.parseJsonBytes(_json, string.concat(_expected, '.encoded'));
    _row.byteLength = vm.parseJsonUint(_json, string.concat(_expected, '.byteLength'));
  }
}
