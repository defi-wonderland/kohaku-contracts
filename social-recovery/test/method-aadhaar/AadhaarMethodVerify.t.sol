// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {IPolicyMethod} from 'interfaces/IPolicyMethod.sol';
import {AadhaarMethod} from 'contracts/methods/aadhaar/AadhaarMethod.sol';
import {MethodAadhaarVerifierMock} from 'test/mocks/MethodAadhaarVerifierMock.sol';
import {MethodAadhaarTestBase} from 'test/utils/MethodAadhaarTestBase.sol';

/// @notice The Aadhaar method's verify. A proof is accepted only when every bound input matches and the raw verifier
///         answers exactly true. Input zero must be the stored issuer key. Inputs one and seven must be the config's
///         nullifier and seed. Input eight must be the digest's signal. Input two, the QR's signing time, must lie at
///         most the config's freshness window before the verifying block. A mock stands in for the verifier.
contract AadhaarMethodVerifyTest is MethodAadhaarTestBase {
  /// @dev The BN254 scalar field order, the modulus a circuit field reduction would use.
  uint256 internal constant _SNARK_SCALAR_FIELD =
    21_888_242_871_839_275_222_246_405_745_257_275_088_548_364_400_416_034_343_698_204_186_575_808_495_617;

  /// A proof that matches every bound input and that the verifier accepts returns the verify selector. This is the
  /// one answer that lets an Aadhaar guardian approve a recovery.
  function test_WhenEveryCheckHolds() external {
    // it should return the verify selector
    AadhaarProof memory _proof = _aadhaarDefaultProof();
    _aadhaarExpect(_proof);
    bytes4 _answer = _method.verify(_aadhaarDefaultConfig(), _digest, _aadhaarEncode(_proof));
    assertEq(_answer, IPolicyMethod.verify.selector, 'magic value');
    assertTrue(_aadhaarAccepts(_proof), 'accepted as a static call');
  }

  /// The verifier receives the decoded points and exactly the nine inputs, with no tenth word. The real verifier
  /// reads one word past its array as zero. An extra word would change what it checks.
  function test_WhenTheVerifierIsCalled() external {
    // it should pass the decoded points and exactly the nine inputs
    AadhaarProof memory _proof = _aadhaarDefaultProof();
    _aadhaarExpect(_proof);
    bytes memory _callData = abi.encodeWithSelector(
      bytes4(keccak256('verifyProof(uint256[2],uint256[2][2],uint256[2],uint256[9])')),
      _proof.a,
      _proof.b,
      _proof.c,
      _proof.inputs
    );
    assertEq(_callData.length, 4 + 544, 'selector plus seventeen words, no tenth input');
    vm.expectCall(address(_verifier), _callData, 1);
    assertTrue(_aadhaarAccepts(_proof), 'the mock accepts only the exact calldata');
  }

  /// The method passes b as decoded. The client already reversed each coordinate pair when packing the proof. A
  /// second reversal would make every real proof fail.
  function test_WhenTheVerifierAcceptsOnlyAReversedB() external {
    // it should refuse the proof
    AadhaarProof memory _proof = _aadhaarDefaultProof();
    AadhaarProof memory _reversed = _aadhaarDefaultProof();
    _reversed.b = [[_proof.b[0][1], _proof.b[0][0]], [_proof.b[1][1], _proof.b[1][0]]];
    _aadhaarExpect(_reversed);
    assertFalse(_aadhaarAccepts(_proof), 'the method reversed b again');
  }

  /// A proof under any issuer key other than the stored one is refused, even when the verifier accepts. The verifier
  /// accepts any key. This check is all that ties a proof to the real issuer. `_delta` is any nonzero offset added
  /// to the stored key.
  function test_WhenInputZeroIsAnotherIssuerKey(uint256 _delta) external {
    // it should answer the zero word
    _delta = bound(_delta, 1, type(uint256).max);
    _verifier.setMode(MethodAadhaarVerifierMock.Mode.AlwaysTrue);
    AadhaarProof memory _proof = _aadhaarDefaultProof();
    unchecked {
      _proof.inputs[0] += _delta;
    }
    assertEq(_aadhaarAnswer(_proof), bytes4(0), 'the direct answer is the zero word');
    assertFalse(_aadhaarAccepts(_proof));
  }

  /// A proof whose input one differs from the config's nullifier is refused. A proof from another person cannot
  /// stand in for this guardian. `_delta` is any nonzero offset.
  function test_WhenInputOneIsNotTheConfigNullifier(uint256 _delta) external {
    // it should refuse the proof
    _delta = bound(_delta, 1, type(uint256).max);
    _verifier.setMode(MethodAadhaarVerifierMock.Mode.AlwaysTrue);
    AadhaarProof memory _proof = _aadhaarDefaultProof();
    unchecked {
      _proof.inputs[1] += _delta;
    }
    assertFalse(_aadhaarAccepts(_proof));
  }

  /// A proof whose input seven differs from the config's nullifier seed is refused. A proof made for another
  /// application's seed cannot be reused here. `_delta` is any nonzero offset.
  function test_WhenInputSevenIsNotTheConfigNullifierSeed(uint256 _delta) external {
    // it should refuse the proof
    _delta = bound(_delta, 1, type(uint256).max);
    _verifier.setMode(MethodAadhaarVerifierMock.Mode.AlwaysTrue);
    AadhaarProof memory _proof = _aadhaarDefaultProof();
    unchecked {
      _proof.inputs[7] += _delta;
    }
    assertFalse(_aadhaarAccepts(_proof));
  }

  /// A config that swaps the nullifier and the seed is refused. The method reads the two config fields in their
  /// fixed order.
  function test_WhenTheConfigSwapsNullifierAndSeed() external {
    // it should refuse the proof
    _verifier.setMode(MethodAadhaarVerifierMock.Mode.AlwaysTrue);
    AadhaarProof memory _proof = _aadhaarDefaultProof();
    assertFalse(
      _aadhaarAccepts(_aadhaarConfig(_nullifierSeed, _nullifier, _freshnessWindow), _digest, _aadhaarEncode(_proof))
    );
  }

  /// A proof whose input eight differs from the digest's signal is refused. A proof approves one digest and no
  /// other. `_delta` is any nonzero offset added to the correct signal.
  function test_WhenInputEightIsNotTheSignalOfTheDigest(uint256 _delta) external {
    // it should refuse the proof
    _delta = bound(_delta, 1, type(uint256).max);
    _verifier.setMode(MethodAadhaarVerifierMock.Mode.AlwaysTrue);
    AadhaarProof memory _proof = _aadhaarDefaultProof();
    unchecked {
      _proof.inputs[8] += _delta;
    }
    assertFalse(_aadhaarAccepts(_proof));
  }

  /// Input eight carrying any other plausible signal for the digest is refused. The test tries seven: the raw digest,
  /// the digest shifted, three keccak shifts, the keccak modulo the BN254 field and a shifted sha256. Only the one
  /// signal clients produce may count.
  function test_WhenInputEightIsAnyOtherReductionOfTheDigest() external {
    // it should refuse the proof
    _verifier.setMode(MethodAadhaarVerifierMock.Mode.AlwaysTrue);
    uint256 _hashed = uint256(keccak256(abi.encodePacked(uint256(_digest))));
    uint256[7] memory _others = [
      uint256(_digest),
      uint256(_digest) >> 3,
      _hashed,
      _hashed >> 2,
      _hashed >> 4,
      _hashed % _SNARK_SCALAR_FIELD,
      uint256(sha256(abi.encodePacked(uint256(_digest)))) >> 3
    ];
    for (uint256 _i; _i < _others.length; ++_i) {
      assertTrue(_others[_i] != _aadhaarSignal(_digest), 'the alternative differs from the correct reduction');
      AadhaarProof memory _proof = _aadhaarDefaultProof();
      _proof.inputs[8] = _others[_i];
      assertFalse(_aadhaarAccepts(_proof), vm.toString(_i));
    }
  }

  /// A proof bound to the fixture digest is refused when verify is asked about another digest. `_seed` is any
  /// nonzero word XORed into the fixture digest to build that other digest.
  function test_WhenVerifyIsAskedAboutAnotherDigest(uint256 _seed) external {
    // it should refuse the proof
    bytes32 _other = _digest ^ bytes32(bound(_seed, 1, type(uint256).max));
    AadhaarProof memory _proof = _aadhaarDefaultProof();
    _aadhaarExpect(_proof);
    assertFalse(
      _aadhaarAccepts(_aadhaarDefaultConfig(), _other, _aadhaarEncode(_proof)),
      'the proof carries the signal of the fixture digest'
    );
  }

  /// When the verifier reverts, the method answers the zero word and does not pass the revert on. A broken verifier
  /// never approves a recovery.
  function test_WhenTheVerifierReverts() external {
    // it should answer the zero word
    _verifier.setMode(MethodAadhaarVerifierMock.Mode.Revert);
    assertEq(_aadhaarAnswer(_aadhaarDefaultProof()), bytes4(0), 'the direct answer is the zero word');
    assertFalse(_aadhaarAccepts(_aadhaarDefaultProof()));
  }

  /// A verifier that reverts with the word true as its revert data is refused. That data looks exactly like a true
  /// answer. Only a method that checks the call succeeded refuses it.
  function test_WhenTheVerifierRevertsWithTheWordTrue() external {
    // it should answer the zero word
    _verifier.setMode(MethodAadhaarVerifierMock.Mode.RevertWithTrue);
    assertEq(_aadhaarAnswer(_aadhaarDefaultProof()), bytes4(0), 'the direct answer is the zero word');
    assertFalse(_aadhaarAccepts(_aadhaarDefaultProof()));
  }

  /// A verifier that answers false is refused. A proof the verifier rejects never approves a recovery.
  function test_WhenTheVerifierAnswersFalse() external {
    // it should answer the zero word
    _verifier.setMode(MethodAadhaarVerifierMock.Mode.AlwaysFalse);
    assertEq(_aadhaarAnswer(_aadhaarDefaultProof()), bytes4(0), 'the direct answer is the zero word');
    assertFalse(_aadhaarAccepts(_aadhaarDefaultProof()));
  }

  /// A verifier that returns no bytes gets the zero word as a plain answer, not a revert. Only an exact true answer
  /// counts, and a refusal never reverts the manager's read.
  function test_WhenTheVerifierReturnsNothing() external {
    // it should answer the zero word
    _verifier.setRawAnswer('');
    assertEq(_aadhaarAnswer(_aadhaarDefaultProof()), bytes4(0), 'the direct answer is the zero word');
  }

  /// A verifier answer shorter or longer than one word gets the zero word as a plain answer, even when its first word
  /// is true. A malformed answer never approves a recovery and never reverts the manager's read.
  function test_WhenTheVerifierReturnsAShortOrALongAnswer() external {
    // it should answer the zero word
    _verifier.setRawAnswer(hex'01');
    assertEq(_aadhaarAnswer(_aadhaarDefaultProof()), bytes4(0), 'one byte');
    _verifier.setRawAnswer(abi.encodePacked(bytes30(0), bytes1(0x01)));
    assertEq(_aadhaarAnswer(_aadhaarDefaultProof()), bytes4(0), 'thirty-one bytes');
    _verifier.setRawAnswer(abi.encodePacked(abi.encode(uint256(1)), bytes1(0)));
    assertEq(_aadhaarAnswer(_aadhaarDefaultProof()), bytes4(0), 'thirty-three bytes, first word true');
    _verifier.setRawAnswer(abi.encode(uint256(1), uint256(0)));
    assertEq(_aadhaarAnswer(_aadhaarDefaultProof()), bytes4(0), 'sixty-four bytes, first word true');
  }

  /// A verifier word other than one is refused. The test tries zero, two, 257, the maximum, the top bit alone and the
  /// top bit plus one. 257 and the top bit plus one end in the byte 0x01, so a method that read only the last byte
  /// would take them for true.
  function test_WhenTheVerifierReturnsAWordOtherThanTrue() external {
    // it should answer the zero word
    uint256[6] memory _words =
      [uint256(0), uint256(2), uint256(257), type(uint256).max, uint256(1) << 255, (uint256(1) << 255) | 1];
    for (uint256 _i; _i < _words.length; ++_i) {
      _verifier.setRawAnswer(abi.encode(_words[_i]));
      assertEq(_aadhaarAnswer(_aadhaarDefaultProof()), bytes4(0), vm.toString(_words[_i]));
      assertFalse(_aadhaarAccepts(_aadhaarDefaultProof()), vm.toString(_words[_i]));
    }
  }

  /// A proof of 543 bytes, of 545 bytes or of no bytes gets the zero word, even when the verifier accepts. The method
  /// reads a proof of exactly 544 bytes. A malformed proof gets a plain refusal and never reverts the manager's read.
  function test_WhenTheProofIsNot544Bytes() external {
    // it should answer the zero word
    _verifier.setMode(MethodAadhaarVerifierMock.Mode.AlwaysTrue);
    bytes memory _encoded = _aadhaarEncode(_aadhaarDefaultProof());
    assertEq(_encoded.length, 544, 'the proof is 544 bytes');
    bytes memory _config = _aadhaarDefaultConfig();
    assertEq(_method.verify(_config, _digest, _aadhaarResize(_encoded, 543)), bytes4(0), '543 bytes, direct');
    _aadhaarAssertZeroWord(_config, _digest, _aadhaarResize(_encoded, 543), '543 bytes');
    _aadhaarAssertZeroWord(_config, _digest, abi.encodePacked(_encoded, bytes1(0)), '545 bytes');
    _aadhaarAssertZeroWord(_config, _digest, '', 'empty');
  }

  /// A config of any length from zero to 257 bytes other than 96 gets the zero word, even when the verifier accepts.
  /// The method reads a config of exactly three words. `_seed` picks the length. It is bounded to 0..256 and then
  /// moved up by one from 96 on, to skip 96. The config is the valid one cut short or padded with zero bytes.
  function test_WhenTheConfigHasAnyLengthButThreeWords(uint256 _seed) external {
    // it should answer the zero word
    uint256 _length = bound(_seed, 0, 256);
    if (_length > 95) ++_length;
    _verifier.setMode(MethodAadhaarVerifierMock.Mode.AlwaysTrue);
    bytes memory _config = _aadhaarResize(_aadhaarDefaultConfig(), _length);
    _aadhaarAssertZeroWord(_config, _digest, _aadhaarEncode(_aadhaarDefaultProof()), vm.toString(_length));
  }

  /// Inputs three through six never change the verdict. They hold the four disclosures. The method makes no claim
  /// about them, and a proof with any values there is still accepted.
  function test_WhenInputsThreeThroughSixCarryAnyValues(uint256 _i3, uint256 _i4, uint256 _i5, uint256 _i6) external {
    // it should return the verify selector
    AadhaarProof memory _proof = _aadhaarDefaultProof();
    _proof.inputs[3] = _i3;
    _proof.inputs[4] = _i4;
    _proof.inputs[5] = _i5;
    _proof.inputs[6] = _i6;
    _aadhaarExpect(_proof);
    assertTrue(_aadhaarAccepts(_proof));
  }

  /// A config whose freshness window is under an hour gets the zero word, even for a proof signed in this very
  /// block that the verifier accepts. The circuit rounds the signing time down to the hour, so a shorter window
  /// would refuse a QR in the hour it was signed. `_window` is the config's window, bounded to 0..3599 seconds.
  function test_WhenTheFreshnessWindowIsUnderAnHour(uint256 _window) external {
    // it should answer the zero word
    uint256 _shortWindow = bound(_window, 0, 1 hours - 1);
    AadhaarProof memory _proof = _aadhaarDefaultProof();
    _aadhaarExpect(_proof);
    _aadhaarAssertZeroWord(
      _aadhaarConfig(_nullifier, _nullifierSeed, _shortWindow),
      _digest,
      _aadhaarEncode(_proof),
      vm.toString(_shortWindow)
    );
  }

  /// A config whose freshness window is exactly one hour is accepted for a proof signed a full hour before the
  /// verifying block. An hour is the shortest window the method takes, and the floor lets it through.
  function test_WhenTheFreshnessWindowIsExactlyAnHour() external {
    // it should return the verify selector
    AadhaarProof memory _proof = _aadhaarDefaultProof();
    _proof.inputs[2] = block.timestamp - 1 hours;
    _aadhaarExpect(_proof);
    assertEq(
      _method.verify(_aadhaarConfig(_nullifier, _nullifierSeed, 1 hours), _digest, _aadhaarEncode(_proof)),
      IPolicyMethod.verify.selector,
      'an hour old under an hour window'
    );
  }

  /// A proof signed exactly the window before the verifying block, so that the signing time plus the window equals
  /// the block time, is still fresh and accepted. `_window` is the config's window, bounded from an hour up to the
  /// fixture's block time, so the signing time stays a valid time.
  function test_WhenTheSigningTimeIsExactlyTheWindowBeforeTheBlock(uint256 _window) external {
    // it should return the verify selector
    uint256 _anyWindow = bound(_window, 1 hours, block.timestamp);
    AadhaarProof memory _proof = _aadhaarDefaultProof();
    _proof.inputs[2] = block.timestamp - _anyWindow;
    _aadhaarExpect(_proof);
    assertEq(
      _method.verify(_aadhaarConfig(_nullifier, _nullifierSeed, _anyWindow), _digest, _aadhaarEncode(_proof)),
      IPolicyMethod.verify.selector,
      'the signing time plus the window is the block time'
    );
  }

  /// A proof signed one second more than the window before the verifying block is stale and gets the zero word,
  /// even though the verifier accepts it and every other input matches. A copied QR stops working once its window
  /// has passed. `_window` is the config's window, bounded from an hour up to one second under the block time.
  function test_WhenTheSigningTimeIsOneSecondPastTheWindow(uint256 _window) external {
    // it should answer the zero word
    uint256 _anyWindow = bound(_window, 1 hours, block.timestamp - 1);
    AadhaarProof memory _proof = _aadhaarDefaultProof();
    _proof.inputs[2] = block.timestamp - _anyWindow - 1;
    _aadhaarExpect(_proof);
    _aadhaarAssertZeroWord(
      _aadhaarConfig(_nullifier, _nullifierSeed, _anyWindow), _digest, _aadhaarEncode(_proof), 'one second past'
    );
  }

  /// A stale proof is refused when every other input matches and the verifier would accept it. The fixture's
  /// 75-minute window has passed by `_late` seconds, and the method checks freshness against the block. `_late`
  /// is bounded from one second to a year past the window.
  function test_WhenAStaleProofMatchesEveryOtherInput(uint256 _late) external {
    // it should answer the zero word
    AadhaarProof memory _proof = _aadhaarDefaultProof();
    _aadhaarExpect(_proof);
    assertTrue(_aadhaarAccepts(_proof), 'fresh in the block it was signed');
    vm.warp(block.timestamp + _freshnessWindow + bound(_late, 1, 365 days));
    _aadhaarAssertZeroWord(_aadhaarDefaultConfig(), _digest, _aadhaarEncode(_proof), 'stale');
  }

  /// A proof whose signing time lies after the verifying block counts as fresh and is accepted. The method bounds
  /// how old a QR may be, not how new. `_ahead` is how many seconds after the block the QR reads as signed, bounded
  /// from one second to 2**128, far beyond any real time.
  function test_WhenTheSigningTimeIsInTheFuture(uint256 _ahead) external {
    // it should return the verify selector
    AadhaarProof memory _proof = _aadhaarDefaultProof();
    _proof.inputs[2] = block.timestamp + bound(_ahead, 1, 2 ** 128);
    _aadhaarExpect(_proof);
    assertEq(_aadhaarAnswer(_proof), IPolicyMethod.verify.selector, 'a future signing time');
  }

  /// A config whose window is the largest uint256 neither reverts nor refuses. The signing time plus that window
  /// passes the largest number, and the method still answers, here with the verify selector, since the proof is
  /// as fresh as a window can make it. A refusal never reverts the manager's read, and neither does an acceptance.
  function test_WhenTheFreshnessWindowIsTheLargestWord() external {
    // it should return the verify selector
    AadhaarProof memory _proof = _aadhaarDefaultProof();
    _proof.inputs[2] = block.timestamp - 1 hours;
    _aadhaarExpect(_proof);
    bytes memory _config = _aadhaarConfig(_nullifier, _nullifierSeed, type(uint256).max);
    assertEq(_method.verify(_config, _digest, _aadhaarEncode(_proof)), IPolicyMethod.verify.selector, 'direct');
    assertTrue(_aadhaarAccepts(_config, _digest, _aadhaarEncode(_proof)), 'accepted as a static call');
  }

  /// For any nonzero issuer key, config and digest, a fresh proof whose inputs match them is accepted. `_key` is
  /// bounded to a nonzero word, because the method refuses a zero key at deployment. `_window` is the config's
  /// freshness window, bounded to an hour or more, the shortest the method takes. The proof is signed in this block.
  function test_WhenTheInputsMatchAnyKeyConfigAndDigest(
    uint256 _key,
    uint256 _anyNullifier,
    uint256 _anyNullifierSeed,
    uint256 _window,
    bytes32 _anyDigest
  ) external {
    // it should return the verify selector
    bytes32 _anyIssuerKey = bytes32(bound(_key, 1, type(uint256).max));
    uint256 _anyWindow = bound(_window, 1 hours, type(uint256).max);
    AadhaarMethod _deployed = _aadhaarDeploy(_owner, _admin, _aadhaarOneKey(_anyIssuerKey), address(_verifier));
    AadhaarProof memory _proof = _aadhaarValidProof(_anyIssuerKey, _anyNullifier, _anyNullifierSeed, _anyDigest);
    _aadhaarExpect(_proof);
    assertTrue(
      _aadhaarAccepts(
        address(_deployed),
        _aadhaarConfig(_anyNullifier, _anyNullifierSeed, _anyWindow),
        _anyDigest,
        _aadhaarEncode(_proof)
      )
    );
  }

  /// Pausing the method never changes its verdict. A good proof is accepted and a bad one refused before, during and
  /// after a pause. The manager alone decides what a pause blocks.
  function test_WhenTheMethodIsPausedAndUnpaused() external {
    // it should answer the same before, during and after the pause
    AadhaarProof memory _good = _aadhaarDefaultProof();
    AadhaarProof memory _bad = _aadhaarDefaultProof();
    _bad.inputs[1] = _nullifier + 1;
    _aadhaarExpect(_good);

    assertTrue(_aadhaarAccepts(_good), 'before the pause');
    assertFalse(_aadhaarAccepts(_bad), 'bad before the pause');

    vm.prank(_owner);
    _method.pause();
    assertTrue(_method.paused(), 'paused');
    assertTrue(_aadhaarAccepts(_good), 'during the pause');
    assertFalse(_aadhaarAccepts(_bad), 'bad during the pause');

    vm.prank(_owner);
    _method.unpause();
    assertFalse(_method.paused(), 'unpaused');
    assertTrue(_aadhaarAccepts(_good), 'after the unpause');
    assertFalse(_aadhaarAccepts(_bad), 'bad after the unpause');
  }

  /// After the key admin replaces the issuer key, proofs under the old key are refused and proofs under the new key
  /// are accepted. This is how the method keeps working when the issuer changes its key.
  function test_WhenTheKeyAdminRotatesTheKey() external {
    // it should accept the new key and refuse the old one
    bytes32 _rotated = bytes32(uint256(0xb0b));
    AadhaarProof memory _oldProof = _aadhaarDefaultProof();
    AadhaarProof memory _newProof = _aadhaarValidProof(_rotated, _nullifier, _nullifierSeed, _digest);
    _verifier.setMode(MethodAadhaarVerifierMock.Mode.AlwaysTrue);
    assertTrue(_aadhaarAccepts(_oldProof), 'old key before the rotation');
    assertFalse(_aadhaarAccepts(_newProof), 'new key before the rotation');

    vm.prank(_admin);
    _method.setTrustedKeys(_aadhaarOneKey(_rotated));

    assertFalse(_aadhaarAccepts(_oldProof), 'old key after the rotation');
    assertTrue(_aadhaarAccepts(_newProof), 'new key after the rotation');
  }

  /// After the key admin moves to any other nonzero key, a proof under the old key is refused and one under the new
  /// key is accepted. A retired issuer key loses its power at once. `_seed` builds the new key. It is bounded to a
  /// nonzero word below the maximum, then moved up by one from the fixture key on, to never equal that key.
  function test_WhenTheKeyAdminRotatesToAnyNewKey(uint256 _seed) external {
    uint256 _newWord = bound(_seed, 1, type(uint256).max - 1);
    if (_newWord > uint256(_issuerKey) - 1) ++_newWord;
    bytes32 _rotated = bytes32(_newWord);
    AadhaarProof memory _oldProof = _aadhaarDefaultProof();
    AadhaarProof memory _newProof = _aadhaarValidProof(_rotated, _nullifier, _nullifierSeed, _digest);
    _verifier.setMode(MethodAadhaarVerifierMock.Mode.AlwaysTrue);

    vm.prank(_admin);
    _method.setTrustedKeys(_aadhaarOneKey(_rotated));

    // it should accept the new key and refuse the old one
    assertEq(_aadhaarAnswer(_newProof), IPolicyMethod.verify.selector, 'new key after the rotation');
    assertEq(_aadhaarAnswer(_oldProof), bytes4(0), 'old key after the rotation');
  }

  /// A key change made while the method is paused takes effect for verify at once. The new key is accepted and the
  /// old one refused. A pause does not freeze the key that verify reads.
  function test_WhenTheKeyAdminRotatesTheKeyWhileTheMethodIsPaused() external {
    bytes32 _rotated = bytes32(uint256(0xb0b));
    AadhaarProof memory _oldProof = _aadhaarDefaultProof();
    AadhaarProof memory _newProof = _aadhaarValidProof(_rotated, _nullifier, _nullifierSeed, _digest);
    _verifier.setMode(MethodAadhaarVerifierMock.Mode.AlwaysTrue);

    vm.prank(_owner);
    _method.pause();
    vm.prank(_admin);
    _method.setTrustedKeys(_aadhaarOneKey(_rotated));
    assertTrue(_method.paused(), 'still paused');

    // it should accept the new key and refuse the old one
    assertTrue(_aadhaarAccepts(_newProof), 'new key during the pause');
    assertFalse(_aadhaarAccepts(_oldProof), 'old key during the pause');
  }
}
