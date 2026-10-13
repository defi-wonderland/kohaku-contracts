// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {IPolicyManager} from 'interfaces/IPolicyManager.sol';
import {IPolicyMethod} from 'interfaces/IPolicyMethod.sol';

import {IAmbireRecoveryAction} from 'contracts/actions/ambire/IAmbireRecoveryAction.sol';

/// @title IDeploy
/// @author defi-wonderland
/// @notice The deployment script of the demo path: the policy manager, the wallet and passkey
///         methods, and the recovery action for Ambire's account. The script checks what it is
///         about to deploy on and what it deployed, and a failing check reverts the whole run.
/// @dev The kit's contracts take the addresses their constructors store as given, so a zero
///      address, an address with no code or the wrong contract would only show up later, in a
///      recovery. These checks are where such a mistake is caught, before anything is sent. The
///      checks are internal to the script, and its only entry points are run, confirm and
///      confirmLabel.
interface IDeploy {
  /*///////////////////////////////////////////////////////////////
                              STRUCTS
  ///////////////////////////////////////////////////////////////*/

  /// @notice The per-chain pins. The only constructor argument the kit takes from outside is the
  ///         Ambire implementation the action serves.
  /// @param ambireImplementation The AmbireAccount implementation the action serves on this chain.
  /// @param ambireImplementationCodehash The code hash that implementation must have, so a wrong
  ///        contract at the pinned address is caught even though it has code.
  struct Pins {
    address ambireImplementation;
    bytes32 ambireImplementationCodehash;
  }

  /// @notice What one run deployed.
  /// @param manager The policy manager.
  /// @param ecdsaMethod The wallet method.
  /// @param passkeyMethod The passkey method.
  /// @param action The recovery action for Ambire's account.
  struct Deployment {
    IPolicyManager manager;
    IPolicyMethod ecdsaMethod;
    IPolicyMethod passkeyMethod;
    IAmbireRecoveryAction action;
  }

  /*///////////////////////////////////////////////////////////////
                              ERRORS
  ///////////////////////////////////////////////////////////////*/

  /// @notice The script has no pins for this chain.
  /// @param _chainId The chain id asked about.
  error Deploy_UnsupportedChain(uint256 _chainId);

  /// @notice The chain's P256VERIFY precompile did not accept a known valid signature, so the passkey
  ///         method would refuse every passkey on this chain.
  /// @param _returnData What the call to the precompile returned.
  error Deploy_P256VerifyNotLive(bytes _returnData);

  /// @notice The pinned Ambire implementation has no code on this chain.
  /// @param _implementation The pinned implementation.
  error Deploy_ImplementationHasNoCode(address _implementation);

  /// @notice The pinned Ambire implementation has code, but not the code the pin names, or a
  ///         candidate record holds another code hash than the pin.
  /// @param _implementation The pinned implementation.
  /// @param _expected The pinned code hash.
  /// @param _actual In a deployment, the code hash found on this chain. In confirm's comparison of
  ///        the candidate with the table, the code hash the candidate records.
  error Deploy_ImplementationCodehashMismatch(address _implementation, bytes32 _expected, bytes32 _actual);

  /// @notice The action names a manager other than the one this run deployed.
  /// @param _expected The manager this run deployed.
  /// @param _actual The manager the action names.
  error Deploy_ActionManagerMismatch(address _expected, address _actual);

  /// @notice The action names an Ambire implementation other than the pin, or a candidate record
  ///         holds another implementation than the pin.
  /// @param _expected The pinned implementation.
  /// @param _actual In the action check, the implementation the action names. In confirm's
  ///        comparison of the candidate with the table, the implementation the candidate records.
  error Deploy_ActionImplementationMismatch(address _expected, address _actual);

  /// @notice The action's slot equals the slot Ambire's own helper derives for the action's
  ///         binding, so the two entries would share one place in the account's privilege table.
  /// @param _action The action.
  /// @param _kitSlot The slot the action uses.
  error Deploy_KitSlotCollides(address _action, address _kitSlot);

  /// @notice A method that should carry no role declares a key admin, a trusted key or a stop.
  /// @param _method The method.
  error Deploy_MethodDeclaresRoles(address _method);

  /// @notice A method answers another name than the one its place in the deployment expects, so
  ///         the record may name the wallet method where the passkey method belongs, or the reverse.
  /// @param _method The method asked.
  /// @param _expected The name it must answer: method-ecdsa for the wallet method, method-passkey
  ///        for the passkey method.
  /// @param _actual The name it answered.
  error Deploy_MethodMismatch(address _method, string _expected, string _actual);

  /// @notice A contract of the deployment did not answer one of the reads the checks make: the
  ///         call reverted, or its answer was empty or not the encoding of the value asked for. The
  ///         address may hold another contract than its record key names, for example when the
  ///         broadcast landed out of order.
  /// @param _component The record key that names the address: recoveryAction for the action's
  ///        manager, implementation and slot reads, ecdsaMethod or passkeyMethod for a method's
  ///        name read.
  /// @param _target The address read.
  error Deploy_ReadFailed(string _component, address _target);

  /// @notice A deployed contract does not answer ERC-165 for an interface it must implement.
  /// @param _target The contract asked.
  /// @param _interfaceId The interface id it failed to confirm.
  error Deploy_InterfaceNotSupported(address _target, bytes4 _interfaceId);

  /// @notice A record label is empty, longer than 64 characters, holds a character outside
  ///         lowercase letters, digits and the hyphen, so it could name a file outside
  ///         script/deployments, or holds only digits, so it could take another chain's default
  ///         record name.
  /// @param _label The label refused.
  error Deploy_InvalidLabel(string _label);

  /// @notice The candidate record names another chain than the one confirm runs against.
  /// @param _recorded The chain id the record holds.
  /// @param _current The chain id confirm runs against.
  error Deploy_RecordChainMismatch(uint256 _recorded, uint256 _current);

  /// @notice An address the candidate record names has no code on this chain, so its deployment
  ///         never landed.
  /// @param _target The address with no code.
  error Deploy_NotDeployed(address _target);

  /// @notice An address of the deployment does not run exactly the kit's code, so it may answer
  ///         every other check the way the kit's contract would and still behave differently.
  /// @param _component The record key that names the address: policyManager, ecdsaMethod,
  ///        passkeyMethod or recoveryAction.
  /// @param _target The address checked.
  /// @param _expected The code hash of the kit's code for that address.
  /// @param _actual The code hash found at the address.
  error Deploy_CodeMismatch(string _component, address _target, bytes32 _expected, bytes32 _actual);

  /*///////////////////////////////////////////////////////////////
                              LOGIC
  ///////////////////////////////////////////////////////////////*/

  /// @notice The operator's first step: `forge script script/Deploy.s.sol --rpc-url <chain>
  ///         --broadcast`. It deploys with this chain's pins and writes a candidate record to
  ///         script/deployments/<label>.pending.json. Once the transactions are confirmed on the
  ///         chain, the operator runs confirm, the second step, to publish the record.
  /// @dev It first resolves this chain's pins, then applies the label rule to DEPLOYMENT_LABEL,
  ///      before any check or creation, so a dry run with an invalid label stops with
  ///      Deploy_InvalidLabel. forge executes the whole script, file writes included, before it
  ///      sends any transaction, so what this function writes may name addresses that never land.
  ///      That is why it writes only a candidate and never <label>.json. The candidate is written
  ///      only when forge reports a broadcast or a resumed broadcast, so a dry run or a test writes
  ///      nothing.
  /// @return _deployment What this run deployed.
  function run() external returns (Deployment memory _deployment);

  /// @notice The operator's second step, run after the broadcast's transactions are confirmed:
  ///         `forge script script/Deploy.s.sol --sig 'confirm()' --rpc-url <chain>`, without
  ///         --broadcast. It publishes the candidate record as script/deployments/<label>.json,
  ///         the file the SDK and the screens read, and removes the candidate.
  /// @dev It publishes only what the chain confirms. This chain must have a table entry, the
  ///      chain's P256VERIFY precompile must accept the known valid signature, the record must name
  ///      this chain, each of its four addresses must have code, its pin must equal this chain's
  ///      table entry, and the recorded deployment must pass the same checks a deployment passes
  ///      in run, the last of which requires each address to run exactly the kit's code. The
  ///      published record is rebuilt from the values those checks read, never copied from the
  ///      candidate's text. It broadcasts nothing.
  ///      The label is DEPLOYMENT_LABEL when it is set, else the decimal chain id, by the same
  ///      rule confirmLabel applies to its argument. The chain's table is resolved before the label
  ///      is read, and confirmLabel's checks follow in confirmLabel's order.
  /// @return _deployment The deployment the record names.
  function confirm() external returns (Deployment memory _deployment);

  /// @notice Does everything confirm does, for a label given explicitly rather than read from the
  ///         environment.
  /// @dev The chain's table is resolved first, so on another chain it stops with
  ///      Deploy_UnsupportedChain before anything else. The label must then pass the same rule a
  ///      DEPLOYMENT_LABEL value passes. The P256VERIFY probe runs next, before the candidate is
  ///      read. After the chain id and the checks that each
  ///      recorded address has code, the recorded code hash is compared with the table's first,
  ///      then the recorded implementation address, and in each error the table's value is the
  ///      expected one. The code check runs after every other check of the deployment.
  /// @param _label The label that names the candidate and the published record.
  /// @return _deployment The deployment the record names.
  function confirmLabel(string memory _label) external returns (Deployment memory _deployment);
}
