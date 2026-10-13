// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {IDeploy} from 'script/IDeploy.sol';
import {DeployTestBase} from 'test/utils/DeployTestBase.sol';

/// @notice The first assertion: the pinned AmbireAccount implementation has code on the target
///         chain, and that code has the pinned codehash. The action takes the pin as given, so a
///         pin with no code, or with code that is not Ambire's implementation, would yield an action
///         that serves no real account, and nothing in the contract would say why.
contract DeployCheckImplementationTest is DeployTestBase {
  /// @notice Pins naming `_implementation` with `_codehash`.
  function _pinsOf(address _implementation, bytes32 _codehash) internal pure returns (IDeploy.Pins memory _p) {
    _p = IDeploy.Pins({ambireImplementation: _implementation, ambireImplementationCodehash: _codehash});
  }

  /// @notice 33 bytes of code drawn from `_label` and `_seed`: a zero byte, then the hash of both.
  ///         The leading zero keeps the code from starting with 0xef01, which the test chain reads
  ///         as an EIP-7702 delegation designator and refuses to place unless it is 23 bytes long.
  function _codeOf(string memory _label, uint256 _seed) internal pure returns (bytes memory _code) {
    _code = abi.encodePacked(bytes1(0x00), keccak256(abi.encode(_label, _seed)));
  }

  /// checkImplementation accepts a pin that holds code whose codehash is the pinned one.
  /// A deployment whose pin is the expected contract must not be blocked.
  function test_WhenThePinHoldsCodeWithThePinnedCodehash() external view {
    // it should pass
    _script.checkImplementation(_pins);
  }

  /// checkImplementation accepts any pin whose code matches its pinned codehash. `_seed` is hashed
  /// into an address no fixture uses and into the code the test places there, built by `_codeOf`.
  function test_WhenAnyPinHoldsCodeWithItsCodehash(uint256 _seed) external {
    address _pin = _freshAddress('implementationWithCode', _seed);
    vm.etch(_pin, _codeOf('implementationCode', _seed));
    // it should pass
    _script.checkImplementation(_pinsOf(_pin, _pin.codehash));
  }

  /// checkImplementation reverts naming the pin when the pin has no code. `_seed` is hashed into
  /// an address no fixture uses and that holds no code, a pin copied wrongly into the table.
  function test_RevertWhen_ThePinHasNoCode(uint256 _seed) external {
    address _pin = _freshAddress('implementationWithoutCode', _seed);
    // it should revert
    // it should name the pin in the no code error
    vm.expectRevert(abi.encodeWithSelector(IDeploy.Deploy_ImplementationHasNoCode.selector, _pin));
    _script.checkImplementation(_pinsOf(_pin, _PINNED_CODEHASH));
  }

  /// checkImplementation reverts for the zero address, a pin left unset in the table.
  /// The action's constructor accepts zero, so this check is the only one that catches it.
  function test_RevertWhen_ThePinIsTheZeroAddress() external {
    // it should revert
    // it should name the pin in the no code error
    vm.expectRevert(abi.encodeWithSelector(IDeploy.Deploy_ImplementationHasNoCode.selector, address(0)));
    _script.checkImplementation(_pinsOf(address(0), _PINNED_CODEHASH));
  }

  /// checkImplementation reverts naming the pin, the pinned codehash and the actual one when the pin
  /// holds code with another codehash, a wrong contract that has code. `_seed` is hashed into the
  /// code the test places at the pin, built by `_codeOf`, so its codehash is not the pinned one.
  function test_RevertWhen_ThePinHoldsCodeWithAnotherCodehash(uint256 _seed) external {
    vm.etch(_implementation, _codeOf('otherCode', _seed));
    bytes32 _actual = _implementation.codehash;
    // it should revert
    // it should name the pin, the pinned codehash and the actual codehash
    vm.expectRevert(
      abi.encodeWithSelector(
        IDeploy.Deploy_ImplementationCodehashMismatch.selector, _implementation, _PINNED_CODEHASH, _actual
      )
    );
    _script.checkImplementation(_pinsOf(_implementation, _PINNED_CODEHASH));
  }

  /// checkImplementation reverts when the pinned codehash is the hash of empty code, which an
  /// address with code never has. A table that pinned that hash would accept nothing.
  function test_RevertWhen_ThePinnedCodehashIsTheEmptyCodeHash() external {
    bytes32 _emptyCodeHash = keccak256('');
    // it should revert
    // it should name the pin, the pinned codehash and the actual codehash
    vm.expectRevert(
      abi.encodeWithSelector(
        IDeploy.Deploy_ImplementationCodehashMismatch.selector,
        _implementation,
        _emptyCodeHash,
        _implementation.codehash
      )
    );
    _script.checkImplementation(_pinsOf(_implementation, _emptyCodeHash));
  }
}
