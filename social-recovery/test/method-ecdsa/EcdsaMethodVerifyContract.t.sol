// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {
  MethodEcdsaDirtyMagic1271,
  MethodEcdsaEmpty1271,
  MethodEcdsaExactArgs1271,
  MethodEcdsaMagic1271,
  MethodEcdsaMagicTrailing1271,
  MethodEcdsaOwner1271,
  MethodEcdsaReverting1271,
  MethodEcdsaShortMagic1271,
  MethodEcdsaThirtyOneBytes1271,
  MethodEcdsaTrue1271,
  MethodEcdsaWrongValue1271
} from 'test/mocks/MethodEcdsaGuardianMocks.sol';
import {MethodEcdsaTestBase} from 'test/utils/MethodEcdsaTestBase.sol';

/// @notice Tests the wallet method when the guardian is a smart account. Such an account approves by answering
///         isValidSignature, so the test checks that the method accepts only the standard yes and nothing that
///         merely looks like it.
/// @dev The method looks at the guardian address each time verify runs. If the address has code, the method takes
///      the ERC-1271 path. If it has no code, the method takes the key path and recovers the signer from the
///      signature. Once it has picked a path, it never tries the other one.
///      An address that delegates to code through EIP-7702 has code, so it takes the ERC-1271 path too.
///      On the ERC-1271 path the method calls isValidSignature(digest, proof) on the guardian.
///      The guardian's answer is a yes when three things hold. The call succeeds. It returns at least one 32-byte
///      word. The first word is 0x1626ba7e followed by 28 zero bytes, which is ERC-1271's magic value.
///      Every other answer is a no, and a revert inside the guardian is a no as well.
///      In the fuzz tests `_keySeed` builds a private key in the legal secp256k1 range.
///      `_offsetSeed` builds a second digest that is a different number from the first even after the curve's
///      arithmetic, so an approval of one never counts for the other.
contract EcdsaMethodVerifyContractTest is MethodEcdsaTestBase {
  /// @notice A contract guardian answering one word holding ERC-1271's magic value fills the place.
  /// @dev A smart account guardian, a Safe for example, approves this way.
  function test_WhenTheGuardianAnswersTheMagicValue() external {
    address _contractGuardian = address(new MethodEcdsaMagic1271());
    _assertAccepted(_contractGuardian, _digest, _sign(_strangerKey, _digest));
  }

  /// @notice The magic value followed by a trailing word still fills the place.
  /// @dev Trailing return bytes do not turn a valid answer into a rejection, so such accounts can still help.
  function test_WhenTheGuardianAnswersTheMagicValueFollowedByTrailingBytes() external {
    address _contractGuardian = address(new MethodEcdsaMagicTrailing1271());
    _assertAccepted(_contractGuardian, _digest, _sign(_strangerKey, _digest));
  }

  /// @notice A contract guardian answering a word other than the magic value is refused.
  /// @dev Only the guardian's explicit approval counts.
  function test_WhenTheGuardianAnswersAnotherValue() external {
    address _contractGuardian = address(new MethodEcdsaWrongValue1271());
    _assertRefused(_contractGuardian, _digest, _sign(_strangerKey, _digest));
  }

  /// @notice A contract guardian answering the ABI encoding of true is refused.
  /// @dev A plain true is easy to produce by accident, so it is not an approval.
  function test_WhenTheGuardianAnswersTrue() external {
    address _contractGuardian = address(new MethodEcdsaTrue1271());
    _assertRefused(_contractGuardian, _digest, _sign(_strangerKey, _digest));
  }

  /// @notice A first word that starts with the magic bytes but has nonzero low bytes is refused.
  /// @dev The first word must be the magic value itself, not merely begin with it.
  function test_WhenTheGuardianAnswersTheMagicValueWithDirtyLowBytes() external {
    address _contractGuardian = address(new MethodEcdsaDirtyMagic1271());
    _assertRefused(_contractGuardian, _digest, _sign(_strangerKey, _digest));
  }

  /// @notice An answer of only the four magic bytes is refused.
  /// @dev The call must return at least one full word before its first word counts.
  function test_WhenTheGuardianAnswersLessThanOneWord() external {
    address _contractGuardian = address(new MethodEcdsaShortMagic1271());
    _assertRefused(_contractGuardian, _digest, _sign(_strangerKey, _digest));
  }

  /// @notice An answer of 31 bytes, the magic word cut by one byte, is refused.
  /// @dev This is the exact boundary of the one-word rule: 31 bytes is not a word, 32 is.
  function test_WhenTheGuardianAnswersOneByteShortOfAWord() external {
    address _contractGuardian = address(new MethodEcdsaThirtyOneBytes1271());
    _assertRefused(_contractGuardian, _digest, _sign(_strangerKey, _digest));
  }

  /// @notice A contract guardian whose call succeeds with no return data is refused.
  /// @dev Silent success is what a code-less or broken account produces, and it approves nothing.
  function test_WhenTheGuardianAnswersNothing() external {
    address _contractGuardian = address(new MethodEcdsaEmpty1271());
    _assertRefused(_contractGuardian, _digest, _sign(_strangerKey, _digest));
  }

  /// @notice A contract guardian that reverts is refused, and verify itself does not revert. This holds even when
  ///         the revert data is the magic value.
  /// @dev A guardian that reverts must cost its own place, never the whole attempt.
  function test_WhenTheGuardianReverts() external {
    address _contractGuardian = address(new MethodEcdsaReverting1271());
    _assertRefused(_contractGuardian, _digest, _sign(_strangerKey, _digest));
  }

  /// @notice The method hands the guardian exactly the digest and the proof it received.
  /// @dev The guardian mock approves one digest and one proof only, so passing proves both arrive unchanged.
  function test_WhenTheGuardianIsAskedAboutTheDigest() external {
    bytes memory _proof = _sign(_strangerKey, _digest);
    address _contractGuardian = address(new MethodEcdsaExactArgs1271(_digest, _proof));
    _assertAccepted(_contractGuardian, _digest, _proof);
    _assertRefused(_contractGuardian, keccak256('another digest'), _proof);
    _assertRefused(_contractGuardian, _digest, _sign(_strangerKey, keccak256('another digest')));
  }

  /// @notice A smart account guardian whose owner key signs the digest fills the place, and a stranger does not.
  /// @dev The holder trusts whoever controls the account at recovery time, and that owner is who approves.
  function test_WhenTheGuardianOwnerSignsTheDigest() external {
    address _contractGuardian = address(new MethodEcdsaOwner1271(_guardian));
    _assertAccepted(_contractGuardian, _digest, _sign(_guardianKey, _digest));
    _assertRefused(_contractGuardian, _digest, _sign(_strangerKey, _digest));
  }

  /// @notice A smart account guardian's owner signing a personal message of the digest is refused.
  /// @dev The digest is the only signed form accepted, whatever kind of guardian is asked.
  function test_WhenTheGuardianOwnerSignsAPersonalMessageOfTheDigest() external {
    address _contractGuardian = address(new MethodEcdsaOwner1271(_guardian));
    _assertRefused(_contractGuardian, _digest, _signPersonal(_guardianKey, _digest));
  }

  /// @notice Once code sits at a keyed address, that address's own key signing the digest is refused.
  /// @dev The method never tries ECDSA recovery for an address with code, so the code alone decides.
  function test_WhenTheKeyOfAnAddressWithCodeSignsTheDigestDirectly() external {
    bytes memory _proof = _sign(_guardianKey, _digest);
    _assertAccepted(_guardian, _digest, _proof);

    vm.etch(_guardian, address(new MethodEcdsaWrongValue1271()).code);
    _assertRefused(_guardian, _digest, _proof);

    vm.etch(_guardian, address(new MethodEcdsaReverting1271()).code);
    _assertRefused(_guardian, _digest, _proof);

    vm.etch(_guardian, address(new MethodEcdsaEmpty1271()).code);
    _assertRefused(_guardian, _digest, _proof);

    vm.etch(_guardian, address(new MethodEcdsaOwner1271(vm.addr(_strangerKey))).code);
    _assertRefused(_guardian, _digest, _proof);
    _assertAccepted(_guardian, _digest, _sign(_strangerKey, _digest));
  }

  /// @notice An address that delegates to code through EIP-7702 stops passing with its bare key signature.
  /// @dev While the delegation remains, the delegated code decides, as for any address with code.
  function test_WhenTheKeyOfADelegatedAddressSignsTheDigestDirectly() external {
    bytes memory _proof = _sign(_guardianKey, _digest);
    _assertAccepted(_guardian, _digest, _proof);

    vm.etch(_guardian, _delegationCode(address(new MethodEcdsaWrongValue1271())));
    assertGt(_guardian.code.length, 0);
    _assertRefused(_guardian, _digest, _proof);

    vm.etch(_guardian, _delegationCode(address(new MethodEcdsaReverting1271())));
    _assertRefused(_guardian, _digest, _proof);
  }

  /// @notice A delegated address whose delegate answers the magic value fills the place with a proof its key
  ///         never made.
  /// @dev This shows the delegated address really takes the ERC-1271 path.
  function test_WhenADelegatedAddressAnswersTheMagicValue() external {
    vm.etch(_guardian, _delegationCode(address(new MethodEcdsaMagic1271())));
    _assertAccepted(_guardian, _digest, _sign(_strangerKey, _digest));
  }

  /// @notice The method picks its path from the code at the address when verify runs. A counterfactual account
  ///         passes only once it is deployed. A keyed address is refused while code sits there, and it passes again
  ///         once the code is gone.
  /// @dev A guardian's kind can change after setup, and the verdict must follow the address as it is now.
  function test_WhenCodeAppearsOrDisappearsAtTheGuardianAddress() external {
    address _counterfactual = makeAddr('counterfactual account');
    bytes memory _accountProof = _sign(_strangerKey, _digest);
    _assertRefused(_counterfactual, _digest, _accountProof);
    vm.etch(_counterfactual, address(new MethodEcdsaMagic1271()).code);
    _assertAccepted(_counterfactual, _digest, _accountProof);

    bytes memory _keyProof = _sign(_guardianKey, _digest);
    _assertAccepted(_guardian, _digest, _keyProof);
    vm.etch(_guardian, address(new MethodEcdsaWrongValue1271()).code);
    _assertRefused(_guardian, _digest, _keyProof);
    vm.etch(_guardian, '');
    _assertAccepted(_guardian, _digest, _keyProof);
  }

  /// @notice For any digest and any proof bytes, the guardian receives exactly those and its approval counts.
  /// @dev The method must not reshape the proof on the way to a contract guardian.
  function testFuzz_ForwardsAnyDigestAndProofUnchanged(bytes32 _anyDigest, bytes calldata _proof) external {
    address _contractGuardian = address(new MethodEcdsaExactArgs1271(_anyDigest, _proof));
    _assertAccepted(_contractGuardian, _anyDigest, _proof);
  }

  /// @notice A guardian that approves only another digest is refused for this one.
  /// @dev The method asks about the place's digest, never a different hash.
  function testFuzz_RefusesWhenTheGuardianIsAskedAboutAnotherDigest(
    bytes32 _anyDigest,
    uint256 _offsetSeed,
    bytes calldata _proof
  ) external {
    address _contractGuardian = address(new MethodEcdsaExactArgs1271(_otherHash(_anyDigest, _offsetSeed), _proof));
    _assertRefused(_contractGuardian, _anyDigest, _proof);
  }

  /// @notice For any key, the key's own signature passes while its address has no code. Once code that says no
  ///         sits at the address, the same signature is refused.
  /// @dev There is no fallback from the ERC-1271 path to the key path, for any key.
  function testFuzz_NeverFallsBackToTheKeyOfAnAddressWithCode(uint256 _keySeed, bytes32 _anyDigest) external {
    uint256 _key = _boundKey(_keySeed);
    address _keyedGuardian = vm.addr(_key);
    bytes memory _proof = _sign(_key, _anyDigest);
    _assertAccepted(_keyedGuardian, _anyDigest, _proof);
    vm.etch(_keyedGuardian, address(new MethodEcdsaWrongValue1271()).code);
    _assertRefused(_keyedGuardian, _anyDigest, _proof);
  }
}
