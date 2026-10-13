// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {IDeploy} from 'script/IDeploy.sol';
import {DeployTestBase} from 'test/utils/DeployTestBase.sol';

/// @notice The rule that names a deployment record under script/deployments, with no environment
///         read. It is the decimal chain id when no label is set, so the SDK finds a chain's record
///         by its id, and the label when one is set, so a rehearsal on a copy of Sepolia never
///         writes over Sepolia's record. A label is 1 to 64 characters of lower-case letters,
///         digits and hyphens, so it can never name a path outside script/deployments, and not
///         digits alone, so it can never take another chain's record name.
contract DeployLabelForTest is DeployTestBase {
  function _expectInvalid(string memory _label) internal {
    vm.expectRevert(abi.encodeWithSelector(IDeploy.Deploy_InvalidLabel.selector, _label));
  }

  /// labelFor answers the decimal chain id when no label is set, so a real deployment writes the
  /// record the SDK looks up by chain id. The value passed alongside is ignored.
  function test_WhenTheLabelIsUnset() external view {
    // it should answer the decimal chain id
    assertEq(_script.labelFor(false, '', _SEPOLIA_CHAIN_ID), '11155111', 'sepolia');
    assertEq(_script.labelFor(false, 'ignored', _MAINNET_CHAIN_ID), '1', 'mainnet');
  }

  /// labelFor answers the decimal rendering of any chain id when no label is set. `_chainId` is
  /// any chain id, and vm.toString renders it in decimal.
  function test_WhenTheLabelIsUnsetOnAnyChain(uint256 _chainId) external view {
    // it should answer the decimal chain id
    assertEq(_script.labelFor(false, '', _chainId), vm.toString(_chainId));
  }

  /// labelFor answers the label when one is set, here 'tenderly-sepolia', whatever the chain id,
  /// so a rehearsal that keeps Sepolia's chain id writes its own record.
  function test_WhenTheLabelIsSet() external view {
    // it should answer the variable's value
    assertEq(_script.labelFor(true, 'tenderly-sepolia', _SEPOLIA_CHAIN_ID), 'tenderly-sepolia');
  }

  /// labelFor accepts a label of one character, the shortest one allowed.
  function test_WhenTheLabelIsOneCharacter() external view {
    // it should answer the variable's value
    assertEq(_script.labelFor(true, 'a', _SEPOLIA_CHAIN_ID), 'a');
  }

  /// labelFor accepts a label of exactly 64 characters, the longest one allowed.
  function test_WhenTheLabelIsSixtyFourCharacters() external view {
    string memory _label = 'abcdefghijklmnopqrstuvwxyz-0123456789-abcdefghijklmnopqrstuvwxyz';
    assertEq(bytes(_label).length, 64, 'length');
    // it should answer the variable's value
    assertEq(_script.labelFor(true, _label, _SEPOLIA_CHAIN_ID), _label);
  }

  /// labelFor accepts a label of digits with one lower-case letter, at the end and at the start, since only a
  /// label of digits alone could take a chain's record name.
  function test_WhenTheLabelHoldsDigitsAndOneLetter() external view {
    // it should answer the variable's value
    assertEq(_script.labelFor(true, '11155111a', _SEPOLIA_CHAIN_ID), '11155111a', 'letter last');
    assertEq(_script.labelFor(true, 'a1', _SEPOLIA_CHAIN_ID), 'a1', 'letter first');
  }

  /// labelFor accepts a label of digits and one hyphen, '1-1', since a hyphen is not a digit and no chain id
  /// holds one, so the label names no chain's record.
  function test_WhenTheLabelHoldsDigitsAndAHyphen() external view {
    // it should answer the variable's value
    assertEq(_script.labelFor(true, '1-1', _SEPOLIA_CHAIN_ID), '1-1');
  }

  /// labelFor reverts naming the label when the label set is the empty string, which
  /// would name a record called only by its extension.
  function test_RevertWhen_TheLabelIsEmpty() external {
    // it should revert
    // it should name the label in the error
    _expectInvalid('');
    _script.labelFor(true, '', _SEPOLIA_CHAIN_ID);
  }

  /// labelFor reverts naming the label when it is 65 characters, one over the limit.
  function test_RevertWhen_TheLabelIsLongerThanSixtyFourCharacters() external {
    string memory _label = 'abcdefghijklmnopqrstuvwxyz-0123456789-abcdefghijklmnopqrstuvwxyza';
    assertEq(bytes(_label).length, 65, 'length');
    // it should revert
    // it should name the label in the error
    _expectInvalid(_label);
    _script.labelFor(true, _label, _SEPOLIA_CHAIN_ID);
  }

  /// labelFor reverts naming the label when it holds a '/', a path separator that would place
  /// the record in another directory. The label here holds no '.', so only the slash is refused.
  function test_RevertWhen_TheLabelHoldsASlash() external {
    // it should revert
    // it should name the label in the error
    _expectInvalid('deployments/sepolia');
    _script.labelFor(true, 'deployments/sepolia', _SEPOLIA_CHAIN_ID);
  }

  /// labelFor reverts naming the label when it holds a '.', which would let a label imitate
  /// another record's file name, such as one ending in .pending.
  function test_RevertWhen_TheLabelHoldsADot() external {
    // it should revert
    // it should name the label in the error
    _expectInvalid('sepolia.pending');
    _script.labelFor(true, 'sepolia.pending', _SEPOLIA_CHAIN_ID);
  }

  /// labelFor reverts naming the label when it holds an upper-case letter, so two labels that
  /// differ only in case never name the same file on a case-insensitive file system.
  function test_RevertWhen_TheLabelHoldsAnUpperCaseLetter() external {
    // it should revert
    // it should name the label in the error
    _expectInvalid('Tenderly-sepolia');
    _script.labelFor(true, 'Tenderly-sepolia', _SEPOLIA_CHAIN_ID);
  }

  /// labelFor reverts naming the label when it is '1', mainnet's chain id, set on Sepolia. A rehearsal with
  /// that label would publish the record the SDK reads as mainnet's.
  function test_RevertWhen_TheLabelIsAChainId() external {
    // it should revert
    // it should name the label in the error
    _expectInvalid('1');
    _script.labelFor(true, '1', _SEPOLIA_CHAIN_ID);
  }

  /// labelFor reverts naming the label for any label of 1 to 64 digits, whatever the chain. `_lengthSeed` picks
  /// the length and `_digitSeed` the digits. A label of digits alone reads as some chain's id, so its record
  /// could be taken for that chain's.
  function test_RevertWhen_TheLabelHoldsOnlyDigits(uint256 _lengthSeed, bytes32 _digitSeed, uint256 _chainId) external {
    uint256 _length = bound(_lengthSeed, 1, 64);
    bytes memory _digits = new bytes(_length);
    for (uint256 _i; _i < _length; ++_i) {
      _digits[_i] = bytes1(uint8(0x30 + uint256(keccak256(abi.encode(_digitSeed, _i))) % 10));
    }
    string memory _label = string(_digits);
    // it should revert
    // it should name the label in the error
    _expectInvalid(_label);
    _script.labelFor(true, _label, _chainId);
  }
}
