// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {IPolicyMethod} from 'interfaces/IPolicyMethod.sol';
import {AadhaarMethod} from 'contracts/methods/aadhaar/AadhaarMethod.sol';
import {IAnonAadhaarGroth16Verifier} from 'contracts/methods/aadhaar/IAnonAadhaarGroth16Verifier.sol';
import {AadhaarRealProofFixture} from 'test/fixtures/aadhaar/AadhaarRealProofFixture.sol';
import {MethodAadhaarTestBase} from 'test/utils/MethodAadhaarTestBase.sol';

/// @notice Sepolia fork tests that run one real Anon Aadhaar proof through the live verifier and through the method.
///         The proof proves upstream's sample identity under upstream's published test key, so the method here is
///         deployed with that test key hash, inside the test only. The tests skip when SEPOLIA_RPC_URL is empty.
contract AadhaarMethodForkTest is MethodAadhaarTestBase, AadhaarRealProofFixture {
  /// @dev The Groth16 verifier published on Sepolia.
  address internal constant _SEPOLIA_VERIFIER = 0xCBd85cd69C4779aA9a7AB9B6D6A9f6FEd61504F0;
  /// @dev A pinned Sepolia block at which the verifier's code is the published one.
  uint256 internal constant _SEPOLIA_BLOCK = 11_831_100;
  /// @dev The issuer public-key hash a deployment trusts, the hash of UIDAI's current signing key, in force since
  ///      2026-02-03.
  uint256 internal constant _PRODUCTION_KEY =
    19_770_349_258_225_098_911_243_612_275_321_727_303_641_256_718_510_179_842_211_794_623_059_325_011_884;
  /// @dev The gas a call that may meet a malformed point is given, well above a valid proof's cost of about 300,000.
  uint256 internal constant _GAS_CAP = 5_000_000;
  /// @dev How long after the real proof's signing time the tests verify it, a few minutes as when a guardian downloads
  ///      a QR and proves at once.
  uint256 internal constant _PROVED_AFTER = 5 minutes;

  /// @dev The method deployed with the test key hash and the live verifier.
  AadhaarMethod internal _testKeyMethod;

  /// @dev Selects a Sepolia fork at the pinned block and deploys the method with the test key hash, or skips every
  ///      test when no endpoint is configured. The real proof's QR was signed in 2019, so the block time then moves
  ///      to a few minutes after that signing time. The verifier is stateless, so its answer does not depend on it.
  function setUp() public override {
    string memory _rpc = vm.envOr('SEPOLIA_RPC_URL', string(''));
    if (bytes(_rpc).length == 0) {
      vm.skip(true, 'SEPOLIA_RPC_URL is empty');
      return;
    }
    vm.createSelectFork(_rpc, _SEPOLIA_BLOCK);
    _testKeyMethod =
      _aadhaarDeploy(_owner, _admin, _aadhaarOneKey(bytes32(_AADHAAR_REAL_TEST_KEY_HASH)), _SEPOLIA_VERIFIER);
    vm.warp(_AADHAAR_REAL_INPUT_2 + _PROVED_AFTER);
  }

  /// The live verifier answers true for the real proof, called through the interface the method uses. This shows
  /// the copied selector and argument layout, and the fixture's b order, match the deployed verifier.
  function test_WhenTheLiveVerifierChecksTheRealProof() external view {
    (uint256[2] memory _a, uint256[2][2] memory _b, uint256[2] memory _c, uint256[9] memory _inputs) =
      _aadhaarRealProof();
    // it should answer true
    assertTrue(IAnonAadhaarGroth16Verifier(_SEPOLIA_VERIFIER).verifyProof(_a, _b, _c, _inputs), 'verifier accepts');
  }

  /// The method trusting the test key answers the magic value for the real proof, the guardian's config (the
  /// proof's nullifier, seed 77 and a 75-minute window) and the digest the proof binds, a few minutes after the
  /// QR was signed. This is the whole proof path working against
  /// a real pairing check, under the test key only.
  function test_WhenTheMethodWithTheTestKeyChecksTheRealProof() external view {
    bytes memory _proof = _realProofBytes(_AADHAAR_REAL_INPUT_2, false);
    assertEq(_proof.length, 544, 'the proof is 544 bytes');
    // it should answer the magic value
    bytes4 _answer = _testKeyMethod.verify(_realConfig(), _AADHAAR_REAL_DIGEST, _proof);
    assertEq(_answer, IPolicyMethod.verify.selector, 'the magic value');
  }

  /// The same proof offered for a different digest answers zero, because the proof's signal binds one digest and
  /// cannot be replayed to approve another recovery.
  function test_WhenTheDigestDiffers() external view {
    // it should answer zero
    _assertZero(
      _testKeyMethod, _realConfig(), keccak256('another digest'), _realProofBytes(_AADHAAR_REAL_INPUT_2, false)
    );
  }

  /// A method that trusts the production key answers zero for the same valid proof, because input 0 carries the
  /// test key. The verifier accepts any key, so this comparison is what makes the issuer's key matter.
  function test_WhenTheMethodHoldsTheProductionKey() external {
    AadhaarMethod _productionKeyMethod =
      _aadhaarDeploy(_owner, _admin, _aadhaarOneKey(bytes32(_PRODUCTION_KEY)), _SEPOLIA_VERIFIER);
    // it should answer zero
    _assertZero(
      _productionKeyMethod, _realConfig(), _AADHAAR_REAL_DIGEST, _realProofBytes(_AADHAAR_REAL_INPUT_2, false)
    );
  }

  /// A guardian config whose nullifier is one more than the proof's answers zero, so a proof of one person's
  /// identity cannot approve for a guardian set up as another person.
  function test_WhenTheConfigNullifierDiffers() external view {
    // it should answer zero
    _assertZero(
      _testKeyMethod,
      _aadhaarConfig(_AADHAAR_REAL_INPUT_1 + 1, _AADHAAR_REAL_NULLIFIER_SEED, _freshnessWindow),
      _AADHAAR_REAL_DIGEST,
      _realProofBytes(_AADHAAR_REAL_INPUT_2, false)
    );
  }

  /// A guardian config whose nullifier seed is one more than the proof's answers zero, because a nullifier names
  /// a person only under the seed it was derived with.
  function test_WhenTheConfigSeedDiffers() external view {
    // it should answer zero
    _assertZero(
      _testKeyMethod,
      _aadhaarConfig(_AADHAAR_REAL_INPUT_1, _AADHAAR_REAL_NULLIFIER_SEED + 1, _freshnessWindow),
      _AADHAAR_REAL_DIGEST,
      _realProofBytes(_AADHAAR_REAL_INPUT_2, false)
    );
  }

  /// A proof whose timestamp input was raised by one answers zero. The changed signing time is still fresh, so the
  /// method's own freshness check lets it through and only the real pairing check catches the change, which shows
  /// the method hands the verifier all nine inputs.
  function test_WhenTheTimestampInputIsTampered() external view {
    // it should answer zero
    _assertZero(_testKeyMethod, _realConfig(), _AADHAAR_REAL_DIGEST, _realProofBytes(_AADHAAR_REAL_INPUT_2 + 1, false));
  }

  /// The proof with b in snarkjs's order, each pair not swapped, answers zero, so a client must send b as packed.
  /// That b is not a valid curve point and the pairing precompile then consumes all the gas it is given, so the
  /// call here is capped at 5,000,000 gas. A real submitter pays that gas, which is why the SDK simulates first.
  function test_WhenPointBIsInSnarkjsOrder() external view {
    // it should answer zero
    _assertZero(_testKeyMethod, _realConfig(), _AADHAAR_REAL_DIGEST, _realProofBytes(_AADHAAR_REAL_INPUT_2, true));
  }

  /// The real proof, untouched, answers zero one second after its window has passed. The proof is valid, but a QR
  /// signed more than the guardian's window ago no longer approves a recovery, so an old copy of it is useless.
  function test_WhenTheRealProofIsOneSecondPastTheWindow() external {
    vm.warp(_AADHAAR_REAL_INPUT_2 + _freshnessWindow + 1);
    // it should answer zero
    _assertZero(_testKeyMethod, _realConfig(), _AADHAAR_REAL_DIGEST, _realProofBytes(_AADHAAR_REAL_INPUT_2, false));
  }

  /// @dev The guardian's config for the real proof: the proof's nullifier, seed 77 and the fixture's 75-minute
  ///      window.
  function _realConfig() internal view returns (bytes memory _config) {
    _config = _aadhaarConfig(_AADHAAR_REAL_INPUT_1, _AADHAAR_REAL_NULLIFIER_SEED, _freshnessWindow);
  }

  /// @dev The real proof's 544 bytes, with input 2 replaced by `_timestamp` and, when `_rawB`, b in snarkjs's order.
  function _realProofBytes(uint256 _timestamp, bool _rawB) internal pure returns (bytes memory _encoded) {
    AadhaarProof memory _proof;
    (_proof.a, _proof.b, _proof.c, _proof.inputs) = _aadhaarRealProof();
    _proof.inputs[2] = _timestamp;
    if (_rawB) _proof.b = _aadhaarRealRawB();
    _encoded = _aadhaarEncode(_proof);
  }

  /// @dev Asserts a static call to verify, given at most the gas cap, succeeds and returns exactly the zero word.
  function _assertZero(AadhaarMethod _target, bytes memory _config, bytes32 _forDigest, bytes memory _proof)
    internal
    view
  {
    (bool _ok, bytes memory _ret) = address(_target).staticcall{gas: _GAS_CAP}(
      abi.encodeCall(IPolicyMethod.verify, (_config, _forDigest, _proof))
    );
    assertTrue(_ok, 'the call succeeds');
    assertEq(_ret.length, 32, 'one word');
    assertEq(abi.decode(_ret, (bytes32)), bytes32(0), 'the zero word');
  }
}
