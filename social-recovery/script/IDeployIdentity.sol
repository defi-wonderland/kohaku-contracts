// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {IPolicyMethod} from 'interfaces/IPolicyMethod.sol';

/// @title IDeployIdentity
/// @author defi-wonderland
/// @notice The deployment script of the two identity methods: the zkPassport method on mainnet and Sepolia, and
///         the Aadhaar method on Sepolia alone. The script checks the chain before it deploys and the methods
///         after, and a failing check reverts the whole run, so nothing is sent.
/// @dev The identity methods store no address of another kit contract, so this script deploys them apart from
///      the demo path's script and can deploy one again on its own. The zkPassport method's trusted keys copy
///      outside contracts and roles that zkPassport can change, and the Aadhaar method stores its verifier as
///      given, so the checks here are where a wrong pin or a stale role is caught. The pure and view checks are
///      public, so a test can call each one with explicit values and an operator can run the trusted-key check
///      or the Aadhaar key check alone before a Safe transaction. deploy is public too, as a test entry point
///      that takes the pins from its caller.
interface IDeployIdentity {
  /*///////////////////////////////////////////////////////////////
                              STRUCTS
  ///////////////////////////////////////////////////////////////*/

  /// @notice The per-chain table. zkPassport ships on mainnet and Sepolia, Aadhaar on Sepolia alone.
  /// @param acceptedVersion The zkPassport version the method accepts, as a canonical version word.
  /// @param rootVerifier zkPassport's root verifier, the router the method calls.
  /// @param subVerifier The reviewed sub-verifier the root routes the accepted version to.
  /// @param verifierHelper The verifier helper the root returns for the accepted version.
  /// @param rootRegistry The root registry the root verifier names.
  /// @param shipsAadhaar Whether this chain gets an Aadhaar method.
  /// @param aadhaarVerifier The Anon Aadhaar Groth16 verifier, or address(0) where Aadhaar does not ship.
  /// @param aadhaarVerifierCodehash The code hash the Aadhaar verifier must have, so a wrong contract at the pinned
  ///        address is caught even though it has code, or zero where Aadhaar does not ship.
  /// @param aadhaarKey The issuer public-key hash the Aadhaar method trusts, or zero where Aadhaar does not ship.
  struct Pins {
    bytes32 acceptedVersion;
    address rootVerifier;
    address subVerifier;
    address verifierHelper;
    address rootRegistry;
    bool shipsAadhaar;
    address aadhaarVerifier;
    bytes32 aadhaarVerifierCodehash;
    bytes32 aadhaarKey;
  }

  /// @notice The operator's inputs. They are not table entries: the two Safes are created outside this repository,
  ///         and the three role words are the values the deployment team reviewed, which the checks compare with
  ///         the live upstream roles and so must never be read from them.
  /// @param zkPassportMethodSafe The pause holder and key admin of the zkPassport method.
  /// @param aadhaarMethodSafe The pause holder and key admin of the Aadhaar method. It may equal the zkPassport
  ///        method's Safe. It is the zero address on a chain that deploys no Aadhaar method.
  /// @param rootAdmin The last reviewed admin of zkPassport's root verifier, the sixth trusted-key word.
  /// @param rootGuardian The last reviewed root guardian of zkPassport's root verifier, the seventh trusted-key word.
  ///        It may be zero, since the root verifier may run without a root guardian.
  /// @param subVerifierAdmin The last reviewed admin of the reviewed sub-verifier, the eighth trusted-key word.
  struct Inputs {
    address zkPassportMethodSafe;
    address aadhaarMethodSafe;
    address rootAdmin;
    address rootGuardian;
    address subVerifierAdmin;
  }

  /// @notice What one run deployed.
  /// @param zkPassportMethod The zkPassport method.
  /// @param aadhaarMethod The Aadhaar method, or address(0) where the chain ships none.
  struct Deployment {
    IPolicyMethod zkPassportMethod;
    IPolicyMethod aadhaarMethod;
  }

  /*///////////////////////////////////////////////////////////////
                              ERRORS
  ///////////////////////////////////////////////////////////////*/

  /// @notice The script has no table entry for this chain.
  /// @param _chainId The chain id asked about.
  error DeployIdentity_UnsupportedChain(uint256 _chainId);

  /// @notice A required environment variable is not set, or is set to the empty string.
  /// @param _name The variable's name.
  error DeployIdentity_MissingInput(string _name);

  /// @notice A Safe input is the zero address. The script never substitutes the operator's key for it.
  /// @param _name The environment variable that holds that Safe.
  error DeployIdentity_ZeroSafe(string _name);

  /// @notice An address the table pins has no code on this chain.
  /// @param _target The address with no code.
  error DeployIdentity_NoCode(address _target);

  /// @notice The Aadhaar verifier has code, but not the code the table pins.
  /// @param _verifier The pinned verifier.
  /// @param _expected The pinned code hash.
  /// @param _actual The code hash found on this chain.
  error DeployIdentity_AadhaarVerifierCodehashMismatch(address _verifier, bytes32 _expected, bytes32 _actual);

  /// @notice A set of zkPassport trusted-key words does not hold exactly eight words.
  /// @param _count The number of words given.
  error DeployIdentity_WordCount(uint256 _count);

  /// @notice A zkPassport word read as an address has a nonzero byte above its low twenty bytes. Calling it would
  ///         call a truncated address rather than the one declared, and a mismatch error would show two equal
  ///         addresses.
  /// @param _index The word's position.
  /// @param _word The word.
  error DeployIdentity_WordNotClean(uint256 _index, bytes32 _word);

  /// @notice A live zkPassport component read differs from the trusted-key word that should match it, or the read
  ///         failed, or a candidate record holds another outside address than the table. A failed read reports
  ///         address(0) as the live value.
  /// @param _component The component: subVerifier, verifierHelper or rootRegistry, and rootVerifier when
  ///        confirm compares a recorded root verifier with the table.
  /// @param _expected The address the trusted-key word holds, or the table's address when confirm compares the
  ///        candidate with the table.
  /// @param _actual The address the live contract answered, or the address the candidate records when confirm
  ///        compares the candidate with the table.
  error DeployIdentity_ComponentMismatch(string _component, address _expected, address _actual);

  /// @notice A live zkPassport role read differs from the reviewed role word, or the read failed. A failed read
  ///         reports address(0) as the live value.
  /// @param _role The role: rootAdmin, rootGuardian or subVerifierAdmin.
  /// @param _expected The address the trusted-key word holds.
  /// @param _actual The address the live contract answered.
  error DeployIdentity_RoleMismatch(string _role, address _expected, address _actual);

  /// @notice The Aadhaar key is the Anon Aadhaar stack's published test key, whose private half is public, so a
  ///         method trusting it would accept a proof anyone can make.
  /// @param _key The key refused.
  error DeployIdentity_AadhaarTestKey(bytes32 _key);

  /// @notice The Aadhaar key is one of UIDAI's two expired production keys. UIDAI no longer signs with it, so a
  ///         method trusting it would accept only proofs over old signed data.
  /// @param _key The key refused.
  error DeployIdentity_AadhaarExpiredKey(bytes32 _key);

  /// @notice The Aadhaar verifier differs from the pin, or could not be read, or a candidate record holds another
  ///         verifier than the pin.
  /// @param _expected The pinned verifier.
  /// @param _actual The verifier the deployed method names, or address(0) when that read failed. When confirm
  ///        compares the candidate with the table, the verifier the candidate records.
  error DeployIdentity_AadhaarVerifierMismatch(address _expected, address _actual);

  /// @notice A method does not declare its Safe as its key admin and pause holder, with no pending holder of
  ///         either role and exactly the trusted keys it was given.
  /// @param _method The method.
  error DeployIdentity_MethodRolesMismatch(address _method);

  /// @notice A deployed method does not answer ERC-165 for an interface it must implement.
  /// @param _target The method asked.
  /// @param _interfaceId The interface id it failed to confirm.
  error DeployIdentity_InterfaceNotSupported(address _target, bytes4 _interfaceId);

  /// @notice A record label is empty, longer than 64 characters, holds a character outside lowercase letters,
  ///         digits and the hyphen, so it could name a file outside script/deployments, or holds only digits, so it
  ///         could take another chain's default record name.
  /// @param _label The label refused.
  error DeployIdentity_InvalidLabel(string _label);

  /// @notice The candidate record names another chain than the one confirm runs against.
  /// @param _recorded The chain id the record holds.
  /// @param _current The chain id confirm runs against.
  error DeployIdentity_RecordChainMismatch(uint256 _recorded, uint256 _current);

  /// @notice A method the candidate record names has no code on this chain, so its deployment never landed, or
  ///         the record names an Aadhaar method on a chain that ships none.
  /// @param _target The recorded address.
  error DeployIdentity_NotDeployed(address _target);

  /// @notice A value the candidate record holds differs from what this chain's table and the recorded inputs give.
  /// @param _field The record key of the value that differs.
  error DeployIdentity_RecordMismatch(string _field);

  /// @notice A deployed method does not run exactly the kit's code, so it may answer every other check the way the
  ///         kit's method would and still behave differently.
  /// @param _component The record key that names the method: zkPassportMethod or aadhaarMethod.
  /// @param _target The address checked.
  /// @param _expected The code hash of the kit's code for that method.
  /// @param _actual The code hash found at the address.
  error DeployIdentity_CodeMismatch(string _component, address _target, bytes32 _expected, bytes32 _actual);

  /*///////////////////////////////////////////////////////////////
                              LOGIC
  ///////////////////////////////////////////////////////////////*/

  /// @notice The operator's first step: `forge script script/DeployIdentity.s.sol --rpc-url <chain> --broadcast`.
  ///         It deploys with this chain's table and the operator's inputs, and writes a candidate record to
  ///         script/deployments/<label>.identity.pending.json.
  /// @dev It first resolves this chain's table, then applies the label rule to DEPLOYMENT_LABEL, then reads the
  ///      inputs, all before any check or creation, so a dry run with an invalid label stops with
  ///      DeployIdentity_InvalidLabel. forge executes the whole script, file writes included, before it sends any
  ///      transaction, so the candidate may name addresses that never land. That is why run writes only a
  ///      candidate, and only when forge reports a broadcast or a resumed broadcast, so a dry run or a test writes
  ///      nothing. The `.identity` part keeps this record apart from the demo path's record on the same chain and
  ///      label, since a label cannot hold a dot.
  /// @return _deployment What this run deployed.
  function run() external returns (Deployment memory _deployment);

  /// @notice The operator's second step, once the broadcast's transactions are confirmed:
  ///         `forge script script/DeployIdentity.s.sol --sig 'confirm()' --rpc-url <chain>`. It publishes the
  ///         candidate record for the label recordLabel gives.
  /// @dev It resolves this chain's table before it reads the label, so on another chain it stops with
  ///      DeployIdentity_UnsupportedChain before anything else. The checks then follow confirmLabel's order.
  /// @return _deployment The deployment the record names.
  function confirm() external returns (Deployment memory _deployment);

  /// @notice Publishes the candidate record a label names, once the chain confirms it, and removes the candidate.
  /// @dev It publishes only what the chain confirms. It first resolves this chain's table, so on another chain it
  ///      stops with DeployIdentity_UnsupportedChain before anything else, and then applies the label rule to its
  ///      argument. It then checks that the record names this chain and holds eight zkPassport words, then that
  ///      the Safe of each method this chain deploys is nonzero, as a deployment's is. On a chain that deploys no
  ///      Aadhaar method the recorded Aadhaar Safe must be the zero address, or it fails with
  ///      DeployIdentity_RecordMismatch and the key aadhaarMethodSafe. Then each method the record names must have
  ///      code, its table values must equal this chain's table, and the recorded deployment must pass again every
  ///      check a deployment passes, with the recorded Safes and role words. The code check runs last: each method
  ///      must run exactly the kit's code. The published record is rebuilt from the values those checks read,
  ///      never copied from the candidate's text. It broadcasts nothing.
  /// @param _label The label that names the candidate and the published record.
  /// @return _deployment The deployment the record names.
  function confirmLabel(string memory _label) external returns (Deployment memory _deployment);

  /// @notice A test entry point: checks the inputs, deploys the methods the given pins ship in one broadcast, and
  ///         checks what was deployed. It broadcasts with the pins the caller passes and never looks up this
  ///         chain's table, so a test can drive a deployment with mock pins. Operators deploy with run, which reads
  ///         the table, and never call this.
  /// @dev Every check that needs nothing deployed runs before the broadcast starts, so a failing one reverts the
  ///      script before any creation. The live checks compare with the given pins, not with the table, and no
  ///      record is written. Both roles of each method go to that method's Safe. The last check requires each
  ///      method to run exactly the kit's code, and the local copy it builds is created after the broadcast stops.
  /// @param _pins The pins to deploy with, chosen by the caller.
  /// @param _inputs The operator's inputs.
  /// @return _deployment What this run deployed.
  function deploy(Pins memory _pins, Inputs memory _inputs) external returns (Deployment memory _deployment);

  /// @notice Builds the record of one deployment, the JSON the SDK and the screens read.
  /// @dev The keys are chainId, zkPassportMethod, aadhaarMethod, zkPassportMethodSafe, aadhaarMethodSafe,
  ///      zkPassportKeys (the eight words), aadhaarVerifier, aadhaarVerifierCodehash and aadhaarKey.
  /// @param _deployment What the run deployed.
  /// @param _pins The table entry it deployed with.
  /// @param _inputs The operator's inputs it deployed with.
  /// @param _chainId The chain the deployment lives on.
  /// @return _json The record.
  function recordJson(Deployment memory _deployment, Pins memory _pins, Inputs memory _inputs, uint256 _chainId)
    external
    returns (string memory _json);

  /// @notice Reads the inputs from the environment: ZKPASSPORT_METHOD_SAFE, AADHAAR_METHOD_SAFE where the chain
  ///         deploys the Aadhaar method, ZKPASSPORT_ROOT_ADMIN, ZKPASSPORT_ROOT_GUARDIAN and
  ///         ZKPASSPORT_SUBVERIFIER_ADMIN, then runs checkInputs over them.
  /// @dev Every variable it reads is required, the root guardian included, so a forgotten variable never turns
  ///      into a zero address. The root guardian may still be set to the zero address on purpose. On a chain that
  ///      deploys no Aadhaar method it never reads AADHAAR_METHOD_SAFE and leaves that Safe the zero address, as
  ///      the record holds it.
  /// @param _shipsAadhaar Whether the chain deploys the Aadhaar method.
  /// @return _inputs The inputs read.
  function inputsFromEnv(bool _shipsAadhaar) external view returns (Inputs memory _inputs);

  /// @notice Requires every zkPassport address in the table, and the Aadhaar verifier where the chain ships it, to
  ///         have code, and the Aadhaar verifier's code to have the pinned hash. A pin with no code is a typo or a
  ///         contract that does not exist on this chain, and a pin with other code is the wrong contract.
  /// @param _pins The table entry.
  function checkCode(Pins memory _pins) external view;

  /// @notice Compares a set of eight zkPassport trusted-key words with the live upstream contracts. The root
  ///         verifier must route the accepted version to the sub-verifier word, return the verifier helper word
  ///         for it and name the registry word. Its root admin and root guardian must equal the two root role
  ///         words, and the sub-verifier's admin must equal the last word.
  /// @dev It deploys nothing, so it is also the check to run before the zkPassport method's Safe sends a
  ///      setTrustedKeys transaction with a proposed set. Before any read it requires exactly eight words, then
  ///      checks the seven address words in order for bits above their twenty address bytes, so a mismatch error
  ///      never shows two equal addresses. A failed or malformed live read fails the comparison it feeds.
  /// @param _words The eight words, in the order zkPassportKeys gives them.
  function checkZkPassportKeys(bytes32[] memory _words) external view;

  /// @notice Requires the deployed methods to declare the roles and keys they were given, to answer ERC-165 for
  ///         their three interfaces, and the Aadhaar method to call the pinned verifier.
  /// @dev Each method must answer trustedParties with its own Safe as key admin and pause holder, no pending
  ///      holder and exactly the keys it was given. A method's constructor stores its verifier as given, so the
  ///      verifier is read back from the method itself.
  /// @param _deployment What the run deployed.
  /// @param _pins The table entry it deployed with.
  /// @param _inputs The operator's inputs it deployed with.
  function checkDeployment(Deployment memory _deployment, Pins memory _pins, Inputs memory _inputs) external view;

  /// @notice Reads DEPLOYMENT_LABEL from the environment and applies the label rule to it.
  /// @param _chainId The chain id used when no label is set.
  /// @return _label The label.
  function recordLabel(uint256 _chainId) external view returns (string memory _label);

  /// @notice The table. Any other chain id reverts.
  /// @param _chainId The chain id.
  /// @return _pins The table entry for that chain.
  function pinsFor(uint256 _chainId) external pure returns (Pins memory _pins);

  /// @notice Requires the Safe of each method the chain deploys to be nonzero, the zkPassport method's first. The
  ///         script never substitutes the operator's key or any other address for a missing Safe.
  /// @param _inputs The operator's inputs.
  /// @param _shipsAadhaar Whether the chain deploys the Aadhaar method. Without it, the Aadhaar method's Safe is
  ///        not checked.
  function checkInputs(Inputs memory _inputs, bool _shipsAadhaar) external pure;

  /// @notice The eight zkPassport trusted-key words, in the order the method documents: the accepted version, the
  ///         root verifier, the sub-verifier, the verifier helper, the root registry, the root admin, the root
  ///         guardian and the sub-verifier admin. Each address is left-padded to one word.
  /// @param _pins The table entry.
  /// @param _inputs The operator's inputs.
  /// @return _words The eight words.
  function zkPassportKeys(Pins memory _pins, Inputs memory _inputs) external pure returns (bytes32[] memory _words);

  /// @notice Requires the Aadhaar key not to be the Anon Aadhaar stack's published test key, nor one of UIDAI's
  ///         two expired production keys. None of the three ever enters a deployment.
  /// @param _key The key the Aadhaar method would trust.
  function checkAadhaarKey(bytes32 _key) external pure;

  /// @notice The label rule: the decimal chain id without a set value, else the value once it is 1 to 64
  ///         characters of lowercase letters, digits and the hyphen, with at least one that is not a digit.
  /// @param _isSet Whether a label value was given.
  /// @param _value The label value, read only when _isSet is true.
  /// @param _chainId The chain id used when no value is set.
  /// @return _label The label.
  function labelFor(bool _isSet, string memory _value, uint256 _chainId) external pure returns (string memory _label);
}
