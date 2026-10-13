// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {IAmbireRecoveryAction} from 'contracts/actions/ambire/IAmbireRecoveryAction.sol';
import {InterfacesArtifacts} from 'test/utils/InterfacesArtifacts.sol';

/// @notice The Ambire action's own interface, IAmbireRecoveryAction: what it adds to the interface
///         every recovery action shares. That is the callback Ambire's account makes before it runs
///         a batch, the Transaction struct the callback and the account's execute take, and the
///         getters of the action's constant and immutables. The account and the SDK encode against
///         these selectors and this tuple, so a drift breaks the recovery on every Ambire account.
contract AmbireRecoveryActionInterfaceTest is InterfacesArtifacts {
  /// @notice Each selector the interface adds is the first four bytes of keccak256 of the function's
  ///         canonical signature. Ambire's account calls validateSig by that selector, with the batch
  ///         element written as the tuple (address,uint256,bytes), so a drift leaves the account
  ///         unable to ask the action and every recovery fails.
  function test_WhenTheSelectorsAreDerived() external pure {
    // it should match each function's canonical signature
    _interfacesAssertSelector(
      IAmbireRecoveryAction.validateSig.selector,
      string.concat('validateSig(bytes,bytes,', _interfacesTransactionTuple(), '[])')
    );
    _interfacesAssertSelector(IAmbireRecoveryAction.KEY_VALUE.selector, 'KEY_VALUE()');
    _interfacesAssertSelector(IAmbireRecoveryAction.MANAGER.selector, 'MANAGER()');
    _interfacesAssertSelector(IAmbireRecoveryAction.AMBIRE_IMPLEMENTATION.selector, 'AMBIRE_IMPLEMENTATION()');
    _interfacesAssertSelector(IAmbireRecoveryAction.KIT_SLOT.selector, 'KIT_SLOT()');
    _interfacesAssertSelector(IAmbireRecoveryAction.BINDING.selector, 'BINDING()');
  }

  /// @notice The compiled ABI lists exactly the eight functions every recovery action shares plus the
  ///         six this interface adds, no event, and only the six shared refusals. A missing entry
  ///         breaks a caller, and an extra one is surface nobody specified or reviewed.
  function test_WhenTheCompiledAbiIsRead() external {
    string memory _json = _interfacesLoad('IAmbireRecoveryAction');
    string[] memory _signatures = new string[](14);
    _signatures[0] = 'supportsAccount(address)';
    _signatures[1] = 'isAuthority(address,address)';
    _signatures[2] = 'isAuthorized(address)';
    _signatures[3] = 'supportsInterface(bytes4)';
    _signatures[4] = 'name()';
    _signatures[5] = 'version()';
    _signatures[6] = 'holdsAnyPrivilege(address,address)';
    _signatures[7] = 'executeHandover(address,bytes)';
    _signatures[8] = 'validateSig(bytes,bytes,(address,uint256,bytes)[])';
    _signatures[9] = 'KEY_VALUE()';
    _signatures[10] = 'MANAGER()';
    _signatures[11] = 'AMBIRE_IMPLEMENTATION()';
    _signatures[12] = 'KIT_SLOT()';
    _signatures[13] = 'BINDING()';
    // it should list exactly the shared functions and the six it adds
    _interfacesAssertMethodIdentifiers(_json, _signatures);
    assertEq(_interfacesAbiCount(_json, 'function'), 14, 'functions');
    assertEq(_interfacesAbiCount(_json, 'event'), 0, 'events');
    assertEq(_interfacesAbiCount(_json, 'error'), 6, 'errors');
  }

  /// @notice validateSig takes the validator data, the inner signature and the batch as an array of
  ///         Transaction, returns a bool and a timestamp, and is nonpayable. This is the shape of
  ///         Ambire's ExternalSigValidator, which the account decodes the answer against, so any other
  ///         shape makes the account's call revert.
  function test_WhenValidateSigIsRead() external {
    string memory _json = _interfacesLoad('IAmbireRecoveryAction');
    // it should take two byte strings and a transaction array and return a bool and a uint256
    _interfacesAssertFunction(
      _json,
      'validateSig',
      'nonpayable',
      'bytes _data,bytes _innerSignature,struct IAmbireRecoveryAction.Transaction[] _calls',
      'bool _isValidSignature,uint256 _timestampValidAfter'
    );
  }

  /// @notice The five getters are views with no parameters that return the privilege value a grant
  ///         writes, the manager, the pinned implementation, the slot and the binding. A client reads
  ///         them to learn which manager and implementation an action pins before a setup adopts it,
  ///         so each must return the specified type.
  function test_WhenTheGettersAreRead() external {
    string memory _json = _interfacesLoad('IAmbireRecoveryAction');
    // it should declare five views with the specified returns
    _interfacesAssertFunction(_json, 'KEY_VALUE', 'view', '', 'bytes32 _keyValue');
    _interfacesAssertFunction(_json, 'MANAGER', 'view', '', 'contract IPolicyManager _manager');
    _interfacesAssertFunction(_json, 'AMBIRE_IMPLEMENTATION', 'view', '', 'address _implementation');
    _interfacesAssertFunction(_json, 'KIT_SLOT', 'view', '', 'address _kitSlot');
    _interfacesAssertFunction(_json, 'BINDING', 'view', '', 'bytes32 _binding');
  }

  /// @notice A Transaction built with named fields and distinct values encodes as its target, its
  ///         value and its calldata in that order. Each _exactly helper compiles only when the field
  ///         has exactly that type. The account runs batches of this tuple, so a moved or resized
  ///         field makes the action approve a batch other than the one the account runs.
  function test_WhenATransactionIsEncoded() external pure {
    IAmbireRecoveryAction.Transaction memory _subject =
      IAmbireRecoveryAction.Transaction({to: address(0x1001), value: uint256(2), data: bytes('data-3')});
    _subject.to = _exactlyAddress(_subject.to);
    _subject.value = _exactlyUint256(_subject.value);
    _subject.data = _exactlyBytes(_subject.data);
    // it should encode the target, the value and the calldata in that order
    assertEq(
      abi.encode(_subject), bytes.concat(bytes32(uint256(0x20)), abi.encode(_subject.to, _subject.value, _subject.data))
    );
  }

  /// @notice Compiles only when the field is exactly address: the argument converts implicitly
  ///         from the field, and the result converts implicitly back into it.
  function _exactlyAddress(address _input) private pure returns (address _output) {
    _output = _input;
  }

  /// @notice Compiles only when the field is exactly bytes: the argument converts implicitly
  ///         from the field, and the result converts implicitly back into it.
  function _exactlyBytes(bytes memory _input) private pure returns (bytes memory _output) {
    _output = _input;
  }

  /// @notice Compiles only when the field is exactly uint256: the argument converts implicitly
  ///         from the field, and the result converts implicitly back into it.
  function _exactlyUint256(uint256 _input) private pure returns (uint256 _output) {
    _output = _input;
  }
}
