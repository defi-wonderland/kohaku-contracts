// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {IRecoveryAction} from 'interfaces/IRecoveryAction.sol';
import {ActionAmbireProxy, ActionAmbireProxyDeployer} from 'test/utils/ActionAmbireProxy.sol';
import {ActionTestBase} from 'test/utils/ActionTestBase.sol';

/// @notice The fit check `supportsAccount`. The setup screen calls it before a holder commits,
///         so a wrong true lets a holder authorize recovery on an account the action cannot serve and a
///         wrong false turns away a Kohaku account. It must answer true only for Ambire's minimal
///         proxy over the implementation the action was deployed with, pushed at its full twenty
///         bytes, exactly 45 bytes with no padding, and false for any other bytecode. The proxy's
///         suffix jumps to the fixed offset 0x2b, which is a JUMPDEST only when the address push is
///         twenty bytes wide, so a proxy with a shorter push reverts every call that succeeds.
contract AmbireRecoveryActionSupportsAccountTest is ActionTestBase {
  ActionAmbireProxyDeployer internal _deployer;
  address internal _probe;

  function setUp() public override {
    super.setUp();
    _deployer = new ActionAmbireProxyDeployer();
    _probe = makeAddr('probe');
  }

  /// @notice Deploys, with CREATE2 under `_salt`, the creation code Ambire's builder produces for
  ///         `_impl` with one signer key.
  function _proxyFor(address _impl, uint256 _salt) internal returns (address _proxy) {
    _proxy = _deployer.deploy(ActionAmbireProxy.creationCode(_impl, makeAddr('signerKey'), bytes32(uint256(2))), _salt);
  }

  /// @notice The 45-byte proxy runtime over the pinned implementation.
  function _canonical() internal view returns (bytes memory _code) {
    _code = ActionAmbireProxy.runtime(_implementation);
  }

  /// @notice Places `_code` at a fixed probe address and returns that address.
  function _etched(bytes memory _code) internal returns (address _where) {
    vm.etch(_probe, _code);
    _where = _probe;
  }

  /// @notice An address whose top byte is nonzero and whose width is `20 - _zeros` bytes, built
  ///         from `_seed`, so its proxy pushes exactly that many bytes.
  function _implementationWithLeadingZeros(uint256 _seed, uint256 _zeros) internal pure returns (address _impl) {
    uint256 _width = 8 * (20 - _zeros);
    uint256 _raw = _seed & ((uint256(1) << _width) - 1);
    _raw |= uint256(1) << (_width - 1);
    // casting to 'uint160' is safe because _raw is masked to at most twenty bytes
    // forge-lint: disable-next-line(unsafe-typecast)
    _impl = address(uint160(_raw));
  }

  /// @notice A Kohaku account created through the factory over the pinned implementation is
  ///         supported, the one account shape the action exists to serve.
  function test_WhenTheCodeIsTheProxyTheFactoryDeploysForThePinnedImplementation() external {
    address _proxy = _proxyFor(_implementation, 0);
    // it should return true
    assertTrue(_action.supportsAccount(_proxy));
  }

  /// @notice The 45-byte runtime placed directly at an address is supported, whatever deployed it.
  function test_WhenTheCodeIsTheBuilderRuntimeForThePinnedImplementation() external {
    // it should return true
    assertTrue(_action.supportsAccount(_etched(_canonical())));
  }

  /// @notice For an action pinned to an implementation with one to nineteen leading zero bytes,
  ///         the factory's proxy pushes fewer than twenty bytes and is zero padded to 45. Its jump
  ///         to the fixed offset 0x2b then reaches padding, so the account cannot run and is refused.
  function test_WhenThePinnedImplementationHasLeadingZeroBytesAndTheFactoryDeploysItsProxy() external {
    // it should return false
    for (uint256 _zeros = 1; _zeros < 20; ++_zeros) {
      _assertShortenedFactoryProxyRefused(uint256(keccak256(abi.encode('impl', _zeros))), _zeros);
    }
  }

  /// @notice The same refusal for any shortened implementation. `_seed` fills the address bits and
  ///         `_zeros`, bounded to 1 through 19, sets how many leading bytes are zero. The top bit of
  ///         the first nonzero byte is always set, so the address is at least 0x80 and never a
  ///         precompile, and no other address the test runs on has a leading zero byte, so etching
  ///         the implementation's code there never overwrites live code.
  function testFuzz_WhenThePinnedImplementationHasLeadingZeroBytesAndTheFactoryDeploysItsProxy(
    uint256 _seed,
    uint256 _zeros
  ) external {
    // it should return false
    _assertShortenedFactoryProxyRefused(_seed, bound(_zeros, 1, 19));
  }

  /// @notice Deploys an action pinned to a shortened implementation built from `_seed` and
  ///         `_zeros`, and checks that action refuses the factory's proxy over that implementation.
  function _assertShortenedFactoryProxyRefused(uint256 _seed, uint256 _zeros) internal {
    address _impl = _implementationWithLeadingZeros(_seed, _zeros);
    vm.etch(_impl, hex'00');
    IRecoveryAction _other = _deployAction(_manager, _impl);
    assertFalse(_other.supportsAccount(_proxyFor(_impl, _seed)));
  }

  /// @notice For an action pinned to any full-width implementation, the proxy the factory deploys
  ///         over it is supported. `_seed` fills the low sixteen bytes of the address and its top
  ///         four bytes are fixed to 0xfeedface, so the address has no leading zero byte. The fixed
  ///         prefix keeps it off every address the test runs on, the test contract, the action,
  ///         the manager, the pinned implementation, the proxy deployer, the probe and the
  ///         precompiles, none of which starts with it, so etching the implementation's code there
  ///         never overwrites live code whatever seed the fuzzer draws from the state it observes.
  function testFuzz_WhenTheFactoryDeploysAProxyOverAFullWidthPinnedImplementation(uint256 _seed) external {
    // casting to 'uint160' is safe because the value is at most twenty bytes wide
    // forge-lint: disable-next-line(unsafe-typecast)
    address _impl = address(uint160((uint256(0xfeedface) << 128) | (_seed & type(uint128).max)));
    vm.etch(_impl, hex'00');
    IRecoveryAction _other = _deployAction(_manager, _impl);
    // it should return true
    assertTrue(_other.supportsAccount(_proxyFor(_impl, _seed)));
  }

  /// @notice The factory's proxy over any full-width implementation other than the pinned one is
  ///         refused. `_seed` builds an address with its top bit set, and its low bit is flipped when
  ///         it would equal the pinned implementation, so it never does.
  function testFuzz_WhenTheFactoryDeploysAProxyOverAnotherFullWidthImplementation(uint256 _seed) external {
    address _impl = _implementationWithLeadingZeros(_seed, 0);
    if (_impl == _implementation) _impl = address(uint160(_impl) ^ 1);
    // it should return false
    assertFalse(_action.supportsAccount(_proxyFor(_impl, _seed)));
  }

  /// @notice A proxy over a 19-byte address without the factory's zero padding is refused, because
  ///         its jump to the fixed offset 0x2b points past its 44 bytes of code.
  function test_WhenAShortenedProxyIsInItsExactForm() external {
    address _impl = _implementationWithLeadingZeros(uint256(keccak256('exactForm')), 1);
    vm.etch(_impl, hex'00');
    IRecoveryAction _other = _deployAction(_manager, _impl);
    // it should return false
    assertFalse(_other.supportsAccount(_etched(ActionAmbireProxy.runtime(_impl))));
  }

  /// @notice The reason for refusing shortened proxies: over a working implementation at 0x1234,
  ///         which returns 42, the full-width proxy answers but the two-byte push in its exact and
  ///         zero-padded forms reverts, since offset 0x2b is no JUMPDEST. The action refuses both.
  function test_WhenAShortenedProxyWrapsAWorkingImplementation() external {
    address _impl = address(0x1234);
    // runtime that stores 42 in memory and returns that word
    vm.etch(_impl, hex'602a60005260206000f3');
    IRecoveryAction _other = _deployAction(_manager, _impl);
    bytes memory _exact = ActionAmbireProxy.runtime(_impl);
    assertEq(_exact.length, 27, 'a two-byte push');
    bytes memory _padded = abi.encodePacked(_exact, new bytes(45 - _exact.length));
    bytes memory _fullWidth =
      abi.encodePacked(ActionAmbireProxy.RUNTIME_HEAD, bytes1(0x73), _impl, ActionAmbireProxy.RUNTIME_TAIL);

    vm.etch(_probe, _fullWidth);
    (bool _ok, bytes memory _ret) = _probe.call('');
    assertTrue(_ok, 'the full-width proxy runs');
    assertEq(abi.decode(_ret, (uint256)), 42, 'the full-width proxy returns the implementation answer');

    // it should return false
    vm.etch(_probe, _exact);
    (_ok,) = _probe.call('');
    assertFalse(_ok, 'the exact shortened proxy reverts');
    assertFalse(_other.supportsAccount(_probe), 'the exact shortened proxy is refused');

    vm.etch(_probe, _padded);
    (_ok,) = _probe.call('');
    assertFalse(_ok, 'the padded shortened proxy reverts');
    assertFalse(_other.supportsAccount(_probe), 'the padded shortened proxy is refused');
  }

  /// @notice A PUSH0 where the address push belongs carries no address, so the account is refused.
  function test_WhenThePushOpcodeIsPush0() external {
    bytes memory _code = _canonical();
    _code[9] = 0x5f;
    // it should return false
    assertFalse(_action.supportsAccount(_etched(_code)), 'PUSH0 in a 45-byte proxy');
    bytes memory _zeroPush =
      abi.encodePacked(ActionAmbireProxy.RUNTIME_HEAD, bytes1(0x5f), ActionAmbireProxy.RUNTIME_TAIL);
    assertFalse(_action.supportsAccount(_etched(abi.encodePacked(_zeroPush, new bytes(45 - _zeroPush.length)))));
  }

  /// @notice A PUSH19 of the pinned address's low nineteen bytes names a different address, so it
  ///         is refused. A check that compared only the pushed bytes would wrongly accept it.
  function test_WhenAPush19CarriesTheLowBytesOfTheFullWidthPinnedImplementation() external {
    bytes memory _full = abi.encodePacked(_implementation);
    assertTrue(_full[0] != 0, 'the pinned implementation is full width');
    bytes memory _low = new bytes(19);
    for (uint256 _i; _i < 19; ++_i) {
      _low[_i] = _full[_i + 1];
    }
    bytes memory _code =
      abi.encodePacked(ActionAmbireProxy.RUNTIME_HEAD, bytes1(0x72), _low, ActionAmbireProxy.RUNTIME_TAIL);
    // it should return false
    assertFalse(_action.supportsAccount(_etched(abi.encodePacked(_code, hex'00'))));
    assertFalse(_action.supportsAccount(_etched(_code)));
  }

  /// @notice A factory proxy over another implementation is refused, so a Kohaku account on a
  ///         different Ambire implementation takes a different action.
  function test_WhenTheProxyNamesAnotherImplementation() external {
    // it should return false
    assertFalse(_action.supportsAccount(_proxyFor(address(uint160(_implementation) ^ 1), 0)));
    assertFalse(_action.supportsAccount(_proxyFor(address(uint160(_implementation) >> 8), 1)));
  }

  /// @notice The same for any other implementation. `_raw` is mapped onto an address that is
  ///         neither zero nor the pinned implementation.
  function testFuzz_WhenTheProxyNamesAnotherImplementation(uint256 _raw) external {
    address _otherImpl = _addressOtherThan(_raw, _implementation);
    // it should return false
    assertFalse(_action.supportsAccount(_etched(ActionAmbireProxy.runtime(_otherImpl))));
  }

  /// @notice An address delegating through EIP-7702 to the pinned implementation, installed the way
  ///         a real EOA installs it, is refused, because the delegating key could still sign for the
  ///         address after a handover.
  function test_WhenTheAccountIsDelegatedThroughEip7702ToThePinnedImplementation() external {
    (address _eoa, uint256 _pk) = makeAddrAndKey('delegatingEoa');
    vm.signAndAttachDelegation(_implementation, _pk);
    // it should return false
    assertFalse(_action.supportsAccount(_eoa));
  }

  /// @notice An address with no code, a plain key or an account not yet deployed, is refused.
  function test_WhenTheAddressHasNoCode() external {
    // it should return false
    assertFalse(_action.supportsAccount(makeAddr('emptyAccount')));
    assertFalse(_action.supportsAccount(address(0)));
  }

  /// @notice A 46-byte code is not the one accepted length, so it is refused even when its first
  ///         45 bytes are the pinned proxy.
  function test_WhenTheCodeIsOneByteLongerThanTheProxy() external {
    // it should return false
    assertFalse(_action.supportsAccount(_etched(abi.encodePacked(_canonical(), hex'00'))));
    assertFalse(_action.supportsAccount(_etched(abi.encodePacked(_canonical(), hex'5b'))));
  }

  /// @notice The pinned proxy cut to 44 bytes has a truncated suffix, so it is refused.
  function test_WhenTheCodeIsOneByteShorterThanTheProxy() external {
    bytes memory _code = _canonical();
    assembly {
      mstore(_code, 44)
    }
    // it should return false
    assertFalse(_action.supportsAccount(_etched(_code)));
  }

  /// @notice The prefix and the pinned address without the proxy's suffix is refused.
  function test_WhenTheCodeIsThePrefixAndTheAddressWithoutTheTail() external {
    // it should return false
    assertFalse(
      _action.supportsAccount(_etched(abi.encodePacked(ActionAmbireProxy.RUNTIME_HEAD, bytes1(0x73), _implementation)))
    );
  }

  /// @notice The proxy's prefix alone carries no address, so it is refused without reading past it.
  function test_WhenTheCodeIsThePrefixAlone() external {
    // it should return false
    assertFalse(_action.supportsAccount(_etched(abi.encodePacked(ActionAmbireProxy.RUNTIME_HEAD, bytes1(0x73)))));
    assertFalse(_action.supportsAccount(_etched(ActionAmbireProxy.RUNTIME_HEAD)));
  }

  /// @notice Flipping the low bit of any one of the first ten bytes turns the proxy into other
  ///         code, which is refused.
  function test_WhenOnePrefixByteDiffers() external {
    // it should return false
    for (uint256 _i; _i < 10; ++_i) {
      bytes memory _code = _canonical();
      _code[_i] = bytes1(uint8(_code[_i]) ^ 0x01);
      assertFalse(_action.supportsAccount(_etched(_code)));
    }
  }

  /// @notice The same for any change to one of the first ten bytes. `_index` picks the byte and
  ///         `_flip`, bounded to 1 through 255, is XORed into it, so the byte always changes.
  function testFuzz_WhenOnePrefixByteDiffers(uint256 _index, uint256 _flip) external {
    _index = bound(_index, 0, 9);
    bytes memory _code = _canonical();
    _code[_index] = bytes1(uint8(_code[_index]) ^ uint8(bound(_flip, 1, 255)));
    // it should return false
    assertFalse(_action.supportsAccount(_etched(_code)));
  }

  /// @notice Changing any one of the fifteen suffix bytes of the 45-byte proxy over the pinned
  ///         implementation, the code after the address, turns it into code the factory never
  ///         deploys, so it is refused. The low bit of each byte is flipped in turn.
  function test_WhenOneSuffixByteDiffers() external {
    // it should return false
    for (uint256 _i; _i < 15; ++_i) {
      bytes memory _code = _canonical();
      _code[30 + _i] = bytes1(uint8(_code[30 + _i]) ^ 0x01);
      assertFalse(_action.supportsAccount(_etched(_code)), vm.toString(_i));
    }
  }

  /// @notice The same for any change to one suffix byte. `_index`, bounded to 0 through 14, picks
  ///         the suffix byte and `_flip`, bounded to 1 through 255, is XORed into it, so it changes.
  function testFuzz_WhenOneSuffixByteDiffers(uint256 _index, uint256 _flip) external {
    uint256 _at = 30 + bound(_index, 0, 14);
    bytes memory _code = _canonical();
    _code[_at] = bytes1(uint8(_code[_at]) ^ uint8(bound(_flip, 1, 255)));
    // it should return false
    assertFalse(_action.supportsAccount(_etched(_code)));
  }

  /// @notice A PUSH21 of a zero byte and the pinned address, in the exact form, pushes the same
  ///         number but is not code the factory deploys, whose push is twenty bytes wide, and it
  ///         moves the suffix off the fixed jump target, so it is refused.
  function test_WhenAPush21CarriesAZeroByteAndThePinnedImplementation() external {
    bytes memory _code = abi.encodePacked(
      ActionAmbireProxy.RUNTIME_HEAD, bytes1(0x74), bytes1(0x00), _implementation, ActionAmbireProxy.RUNTIME_TAIL
    );
    // it should return false
    assertFalse(_action.supportsAccount(_etched(_code)));
  }

  /// @notice Short codes, a designator to the zero address, and contracts that are not proxies
  ///         are all refused.
  function test_WhenTheCodeIsArbitraryBytes() external {
    // it should return false
    assertFalse(_action.supportsAccount(_etched(hex'00')));
    assertFalse(_action.supportsAccount(_etched(ActionAmbireProxy.designator(address(0)))));
    assertFalse(_action.supportsAccount(address(_account)), 'a contract that is no proxy');
    assertFalse(_action.supportsAccount(address(_action)), 'the action itself');
  }

  /// @notice Any code whose first byte differs from the proxy's is refused. `_lead` is mapped onto
  ///         a first byte that is neither the proxy's 0x36 nor 0xef, which the test chain only
  ///         accepts as a 23-byte designator, and `_tail` is any bytes after it.
  function testFuzz_WhenTheCodeIsArbitraryBytes(uint256 _lead, bytes calldata _tail) external {
    uint256 _first = bound(_lead, 0, 253);
    _first += _first < 0x36 ? 0 : 1;
    _first += _first < 0xef ? 0 : 1;
    // casting to 'uint8' is safe because _first is bounded to 0 through 255
    // forge-lint: disable-next-line(unsafe-typecast)
    bytes1 _firstByte = bytes1(uint8(_first));
    // it should return false
    assertFalse(_action.supportsAccount(_etched(abi.encodePacked(_firstByte, _tail))));
  }

  /// @notice The implementation contract itself is not an account the action serves.
  function test_WhenTheAccountIsThePinnedImplementationItself() external view {
    // it should return false
    assertFalse(_action.supportsAccount(_implementation));
  }
}
