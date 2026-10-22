// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {IDeployIdentity} from 'script/IDeployIdentity.sol';
import {DeployIdentityTestBase} from 'test/utils/DeployIdentityTestBase.sol';

/// @notice The first assertion: every zkPassport address in the table, and the Aadhaar verifier where the chain
///         ships it, holds code. A call to an address with no code succeeds and returns nothing, so a method wired
///         to a mistyped address would fail only later, in a recovery. Each bad table here replaces one address
///         of a good local table with an address hashed from a label, which holds no code.
contract DeployIdentityCheckCodeTest is DeployIdentityTestBase {
  /// checkCode passes when every table address holds code.
  function test_WhenEveryAddressHoldsCode() external view {
    // it should pass
    _script.checkCode(_pins);
  }

  /// checkCode passes for a table that ships no Aadhaar method and names no Aadhaar verifier, the mainnet shape,
  /// so the zkPassport method still deploys where no Aadhaar verifier is published.
  function test_WhenTheChainShipsNoAadhaarMethod() external view {
    IDeployIdentity.Pins memory _table = _pins;
    _table.shipsAadhaar = false;
    _table.aadhaarVerifier = address(0);
    _table.aadhaarVerifierCodehash = bytes32(0);
    _table.aadhaarKey = bytes32(0);
    // it should pass
    _script.checkCode(_table);
  }

  /// checkCode reverts naming the root verifier when it has no code.
  function test_RevertWhen_TheRootVerifierHasNoCode() external {
    IDeployIdentity.Pins memory _table = _pins;
    _table.rootVerifier = _freshAddress('rootWithoutCode', 0);
    // it should revert
    // it should name the address in the no code error
    _expectNoCode(_table, _table.rootVerifier);
  }

  /// checkCode reverts naming the sub-verifier when it has no code.
  function test_RevertWhen_TheSubVerifierHasNoCode() external {
    IDeployIdentity.Pins memory _table = _pins;
    _table.subVerifier = _freshAddress('subVerifierWithoutCode', 0);
    // it should revert
    // it should name the address in the no code error
    _expectNoCode(_table, _table.subVerifier);
  }

  /// checkCode reverts naming the verifier helper when it has no code.
  function test_RevertWhen_TheVerifierHelperHasNoCode() external {
    IDeployIdentity.Pins memory _table = _pins;
    _table.verifierHelper = _freshAddress('verifierHelperWithoutCode', 0);
    // it should revert
    // it should name the address in the no code error
    _expectNoCode(_table, _table.verifierHelper);
  }

  /// checkCode reverts naming the root registry when it has no code.
  function test_RevertWhen_TheRootRegistryHasNoCode() external {
    IDeployIdentity.Pins memory _table = _pins;
    _table.rootRegistry = _freshAddress('registryWithoutCode', 0);
    // it should revert
    // it should name the address in the no code error
    _expectNoCode(_table, _table.rootRegistry);
  }

  /// checkCode reverts naming the Aadhaar verifier when the chain ships the Aadhaar method and the verifier has
  /// no code. The method's constructor stores the verifier as given, so this is where a wrong one is caught.
  function test_RevertWhen_TheAadhaarVerifierHasNoCode() external {
    IDeployIdentity.Pins memory _table = _pins;
    _table.aadhaarVerifier = _freshAddress('aadhaarVerifierWithoutCode', 0);
    // it should revert
    // it should name the address in the no code error
    _expectNoCode(_table, _table.aadhaarVerifier);
  }

  /// checkCode reverts naming the zero address when the chain ships the Aadhaar method with a zero verifier.
  function test_RevertWhen_TheAadhaarVerifierIsZero() external {
    IDeployIdentity.Pins memory _table = _pins;
    _table.aadhaarVerifier = address(0);
    // it should revert
    // it should name the address in the no code error
    _expectNoCode(_table, address(0));
  }

  /// checkCode reverts naming the verifier, the pinned code hash and the code hash found when the Aadhaar
  /// verifier holds other code than the pinned one. The address holds code, so only the code hash tells a wrong
  /// contract from the reviewed verifier, and the method's constructor stores the verifier as given.
  function test_RevertWhen_TheAadhaarVerifierHoldsOtherCode() external {
    vm.etch(_pins.aadhaarVerifier, hex'01');
    bytes32 _actual = _pins.aadhaarVerifier.codehash;
    // it should revert
    // it should name the verifier and both code hashes
    vm.expectRevert(
      abi.encodeWithSelector(
        IDeployIdentity.DeployIdentity_AadhaarVerifierCodehashMismatch.selector,
        _pins.aadhaarVerifier,
        _pins.aadhaarVerifierCodehash,
        _actual
      )
    );
    _script.checkCode(_pins);
  }

  function _expectNoCode(IDeployIdentity.Pins memory _table, address _missing) internal {
    vm.expectRevert(abi.encodeWithSelector(IDeployIdentity.DeployIdentity_NoCode.selector, _missing));
    _script.checkCode(_table);
  }
}
