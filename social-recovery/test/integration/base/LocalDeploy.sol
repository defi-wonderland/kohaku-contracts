// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {Vm} from 'forge-std/Vm.sol';

import {Deploy} from 'script/Deploy.s.sol';
import {DeployIdentity} from 'script/DeployIdentity.s.sol';
import {LocalAmbireAccount} from 'test/integration/base/LocalAmbire.sol';
import {
  LocalAadhaarGroth16Verifier,
  LocalZkPassportHelper,
  LocalZkPassportRegistry,
  LocalZkPassportRootVerifier,
  LocalZkPassportSubVerifier
} from 'test/integration/base/LocalWorld.sol';

/// @notice Where the local chain's stand-ins live and how they get there. Each one is created through the deterministic
///         CREATE2 deployer every local node carries, so its address is known before it exists and a pure chain table
///         can name it, the way the mainnet table names Ambire's implementation.
library LocalChain {
  /// @notice The chain id of the local test chain.
  uint256 internal constant CHAIN_ID = 31_337;
  /// @notice The deterministic CREATE2 deployer.
  address internal constant CREATE2_DEPLOYER = 0x4e59b44847b379578588920cA78FbF26c0B4956C;
  /// @notice The salt every stand-in is created under.
  bytes32 internal constant SALT = keccak256('social-recovery local chain');
  /// @notice The zkPassport version the local chain accepts, 0.21.0 as a version word.
  bytes32 internal constant ZKPASSPORT_VERSION = 0x0000001500000000000000000000000000000000000000000000000000000000;
  /// @notice The identifier derivation zkPassport 0.21.0 uses on the local chain.
  bytes32 internal constant ZKPASSPORT_DERIVATION = keccak256('zkPassport identifier derivation v1');
  /// @notice The hash of the Aadhaar issuer's current signing key on the local chain.
  bytes32 internal constant AADHAAR_ISSUER_KEY = keccak256('UIDAI signing key, local issue 1');

  Vm internal constant VM = Vm(address(uint160(uint256(keccak256('hevm cheat code')))));

  /// @notice The deterministic deployer did not create a stand-in.
  error LocalChain_StandInNotCreated();

  /// @notice The stand-in Ambire implementation's creation code.
  function ambireImplementationCode() internal pure returns (bytes memory _code) {
    _code = type(LocalAmbireAccount).creationCode;
  }

  /// @notice The stand-in Ambire implementation's address.
  function ambireImplementation() internal pure returns (address _implementation) {
    _implementation = _addressOf(ambireImplementationCode());
  }

  /// @notice The zkPassport sub-verifier stand-in's creation code.
  function subVerifierCode() internal pure returns (bytes memory _code) {
    _code = type(LocalZkPassportSubVerifier).creationCode;
  }

  /// @notice The zkPassport verifier helper stand-in's creation code.
  function helperCode() internal pure returns (bytes memory _code) {
    _code = type(LocalZkPassportHelper).creationCode;
  }

  /// @notice The zkPassport registry stand-in's creation code.
  function registryCode() internal pure returns (bytes memory _code) {
    _code = type(LocalZkPassportRegistry).creationCode;
  }

  /// @notice The zkPassport root verifier stand-in's creation code, routing the local version.
  function rootVerifierCode() internal pure returns (bytes memory _code) {
    _code = abi.encodePacked(
      type(LocalZkPassportRootVerifier).creationCode,
      abi.encode(
        ZKPASSPORT_VERSION,
        _addressOf(subVerifierCode()),
        _addressOf(helperCode()),
        _addressOf(registryCode()),
        ZKPASSPORT_DERIVATION
      )
    );
  }

  /// @notice The Aadhaar verifier stand-in's creation code.
  function aadhaarVerifierCode() internal pure returns (bytes memory _code) {
    _code = type(LocalAadhaarGroth16Verifier).creationCode;
  }

  /// @notice The address a creation code gets from the deterministic deployer under SALT.
  function _addressOf(bytes memory _code) internal pure returns (address _deployed) {
    _deployed = VM.computeCreate2Address(SALT, keccak256(_code), CREATE2_DEPLOYER);
  }

  /// @notice Creates every stand-in the local chain lacks.
  function createStandIns() internal {
    _create(ambireImplementationCode());
    _create(subVerifierCode());
    _create(helperCode());
    _create(registryCode());
    _create(rootVerifierCode());
    _create(aadhaarVerifierCode());
  }

  /// @notice Creates one stand-in through the deterministic deployer.
  function _create(bytes memory _code) private {
    (bool _ok,) = CREATE2_DEPLOYER.call(abi.encodePacked(SALT, _code));
    require(_ok && _addressOf(_code).code.length != 0, LocalChain_StandInNotCreated());
  }
}

/// @notice The kit's deployment on the local chain. Mainnet and Sepolia keep the script's own table; the local chain
///         pins the stand-in Ambire implementation and runs the P256VERIFY probe in the local EVM, since a local test
///         chain has no node to send an eth_call to.
contract LocalDeploy is Deploy {
  /// @inheritdoc Deploy
  function _pinsFor(uint256 _chainId) internal pure override returns (Pins memory _pins) {
    if (_chainId != LocalChain.CHAIN_ID) return super._pinsFor(_chainId);
    _pins = Pins({
      ambireImplementation: LocalChain.ambireImplementation(),
      ambireImplementationCodehash: keccak256(type(LocalAmbireAccount).runtimeCode)
    });
  }

  /// @inheritdoc Deploy
  function _checkP256Verify() internal override {
    if (block.chainid != LocalChain.CHAIN_ID) return super._checkP256Verify();
    // A chain without the precompile answers with empty bytes, which the answer check refuses.
    // forge-lint: disable-next-line(unchecked-call)
    (, bytes memory _answer) = address(0x100).staticcall(_p256VerifyInput());
    _checkP256VerifyAnswer(_answer);
  }
}

/// @notice The identity methods' deployment on the local chain. Mainnet and Sepolia keep the script's own table; the
///         local chain pins the zkPassport and Aadhaar stand-ins and an invented issuer key.
contract LocalDeployIdentity is DeployIdentity {
  /// @inheritdoc DeployIdentity
  function _pinsFor(uint256 _chainId) internal pure override returns (Pins memory _pins) {
    if (_chainId != LocalChain.CHAIN_ID) return super._pinsFor(_chainId);
    _pins.acceptedVersion = LocalChain.ZKPASSPORT_VERSION;
    _pins.rootVerifier = LocalChain._addressOf(LocalChain.rootVerifierCode());
    _pins.subVerifier = LocalChain._addressOf(LocalChain.subVerifierCode());
    _pins.verifierHelper = LocalChain._addressOf(LocalChain.helperCode());
    _pins.rootRegistry = LocalChain._addressOf(LocalChain.registryCode());
    _pins.shipsAadhaar = true;
    _pins.aadhaarVerifier = LocalChain._addressOf(LocalChain.aadhaarVerifierCode());
    _pins.aadhaarVerifierCodehash = keccak256(type(LocalAadhaarGroth16Verifier).runtimeCode);
    _pins.aadhaarKey = LocalChain.AADHAAR_ISSUER_KEY;
  }
}
