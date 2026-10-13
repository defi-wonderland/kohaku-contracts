// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

/// @notice A Solidity transcription of Ambire's proxy builder, `getProxyDeployBytecode` in
///         kohaku-commons `src/libs/proxyDeploy/deploy.ts` at commit 29227cc (lines 37-62),
///         so the fit check is driven with the exact bytes Ambire's factory deploys.
///         The runtime is `363d3d373d3d3d363d`, a PUSH of the implementation address with
///         its leading zero bytes dropped (deploy.ts line 55), then
///         `5af43d82803e903d91602b57fd5bf3`. The creation code writes each privilege with
///         PUSH32 value, PUSH32 slot, SSTORE (deploy.ts lines 19-30), the slot being
///         `keccak256(abi.encode(uint256(key), uint256(0)))` (deploy.ts lines 14-16, privSlot
///         0 from bytecode.ts line 9), and then returns 0x2d bytes of runtime. The test
///         ActionAmbireProxyBuilderTest checks this transcription against bytes the builder itself
///         produced.
library ActionAmbireProxy {
  /*///////////////////////////////////////////////////////////////
                          STATE VARIABLES
  ///////////////////////////////////////////////////////////////*/

  /// @notice The nine bytes before the PUSH opcode of the runtime.
  bytes internal constant RUNTIME_HEAD = hex'363d3d373d3d3d363d';
  /// @notice The fifteen bytes after the implementation address.
  bytes internal constant RUNTIME_TAIL = hex'5af43d82803e903d91602b57fd5bf3';
  /// @notice The EIP-7702 delegation designator's three-byte prefix.
  bytes internal constant DESIGNATOR_HEAD = hex'ef0100';

  /*///////////////////////////////////////////////////////////////
                              ERRORS
  ///////////////////////////////////////////////////////////////*/

  /// @notice A push of no bytes or of more than a word.
  error ActionAmbireProxy_PushLength(uint256 _length);
  /// @notice More privileges than the builder accepts, or mismatched lists.
  error ActionAmbireProxy_PrivilegeCount(uint256 _keys, uint256 _values);

  /*///////////////////////////////////////////////////////////////
                        INTERNAL FUNCTIONS
  ///////////////////////////////////////////////////////////////*/

  /// @notice The implementation address with its leading zero bytes dropped, as the builder does.
  function strippedAddress(address _impl) internal pure returns (bytes memory _body) {
    bytes memory _full = abi.encodePacked(_impl);
    uint256 _zeros;
    while (_zeros < 20 && _full[_zeros] == 0) {
      ++_zeros;
    }
    _body = new bytes(20 - _zeros);
    for (uint256 _i; _i < _body.length; ++_i) {
      _body[_i] = _full[_zeros + _i];
    }
  }

  /// @notice The builder's evmPush: the PUSHn opcode for the data's length, then the data.
  function evmPush(bytes memory _data) internal pure returns (bytes memory _pushed) {
    require(_data.length != 0 && _data.length < 33, ActionAmbireProxy_PushLength(_data.length));
    _pushed = abi.encodePacked(bytes1(uint8(0x5f + _data.length)), _data);
  }

  /// @notice The runtime the builder emits for an implementation, before any zero padding.
  function runtime(address _impl) internal pure returns (bytes memory _code) {
    _code = abi.encodePacked(RUNTIME_HEAD, evmPush(strippedAddress(_impl)), RUNTIME_TAIL);
  }

  /// @notice The storage slot the builder writes a key's privilege at.
  function privilegeSlot(address _key) internal pure returns (bytes32 _slot) {
    _slot = keccak256(abi.encode(uint256(uint160(_key)), uint256(0)));
  }

  /// @notice The creation code the builder emits for an implementation and its initial privileges.
  function creationCode(address _impl, address[] memory _keys, bytes32[] memory _values)
    internal
    pure
    returns (bytes memory _code)
  {
    require(
      _keys.length == _values.length && _keys.length < 4, ActionAmbireProxy_PrivilegeCount(_keys.length, _values.length)
    );
    bytes memory _writes;
    for (uint256 _i; _i < _keys.length; ++_i) {
      _writes =
        abi.encodePacked(_writes, bytes1(0x7f), _values[_i], bytes1(0x7f), privilegeSlot(_keys[_i]), bytes1(0x55));
    }
    uint256 _offset = _writes.length + 4 + 6;
    // casting to 'uint8' is safe because at most three writes keep the offset at 211
    // forge-lint: disable-next-line(unsafe-typecast)
    _code = abi.encodePacked(_writes, hex'3d602d80', bytes1(0x60), uint8(_offset), hex'3d3981f3', runtime(_impl));
  }

  /// @notice The creation code for one key, the shape the extension's account builder uses.
  function creationCode(address _impl, address _key, bytes32 _value) internal pure returns (bytes memory _code) {
    address[] memory _keys = new address[](1);
    bytes32[] memory _values = new bytes32[](1);
    _keys[0] = _key;
    _values[0] = _value;
    _code = creationCode(_impl, _keys, _values);
  }

  /// @notice The EIP-7702 delegation designator for a target.
  function designator(address _target) internal pure returns (bytes memory _code) {
    _code = abi.encodePacked(DESIGNATOR_HEAD, _target);
  }

  /// @notice The create2 address a factory derives for a code and a salt.
  function create2Address(address _factory, bytes memory _code, uint256 _salt) internal pure returns (address _addr) {
    _addr = address(uint160(uint256(keccak256(abi.encodePacked(bytes1(0xff), _factory, _salt, keccak256(_code))))));
  }
}

/// @notice A local stand-in for Ambire's factory `deploySafe` (AmbireFactory.sol lines 100-119):
///         CREATE2 of the given code under the given salt.
contract ActionAmbireProxyDeployer {
  /*///////////////////////////////////////////////////////////////
                              ERRORS
  ///////////////////////////////////////////////////////////////*/

  /// @notice The create2 returned no address.
  error ActionAmbireProxyDeployer_DeployFailed();

  /*///////////////////////////////////////////////////////////////
                        EXTERNAL FUNCTIONS
  ///////////////////////////////////////////////////////////////*/

  /// @notice Deploys the code under the salt and returns the address.
  function deploy(bytes calldata _code, uint256 _salt) external returns (address _addr) {
    bytes memory _initCode = _code;
    assembly {
      _addr := create2(0, add(_initCode, 0x20), mload(_initCode), _salt)
    }
    require(_addr != address(0), ActionAmbireProxyDeployer_DeployFailed());
  }
}
