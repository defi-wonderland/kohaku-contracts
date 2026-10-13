// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {CommonBase} from 'forge-std/Base.sol';
import {StdUtils} from 'forge-std/StdUtils.sol';
import {Vm, VmSafe} from 'forge-std/Vm.sol';
import {BindingDigest} from 'libraries/BindingDigest.sol';
import {SetupBody} from 'libraries/SetupBody.sol';
import {IPolicyAction} from 'interfaces/IPolicyAction.sol';
import {IPolicyManager} from 'interfaces/IPolicyManager.sol';
import {IPolicyMethod} from 'interfaces/IPolicyMethod.sol';
import {IPolicyMethodPause} from 'interfaces/IPolicyMethodPause.sol';
import {PolicyManagerMockDigestMethod} from 'test/mocks/PolicyManagerMockDigestMethod.sol';
import {PolicyManagerMockMethod} from 'test/mocks/PolicyManagerMockMethod.sol';
import {PolicyManagerMockWritingMethod} from 'test/mocks/PolicyManagerMockWritingMethod.sol';
import {PolicyManagerGhostStorage} from 'test/policy-manager/invariants/handlers/GhostStorage.t.sol';
import {PolicyManagerHarness} from 'test/utils/PolicyManagerHarness.sol';
import {SetupBodyHarness} from 'test/utils/SetupBodyHarness.sol';

/// @notice The state and checks that every handler in the policy manager's invariant suite shares.
///         It holds the manager, the callers and actions the handlers pick from, the methods rules
///         may name, the rule each entry committed and the hash of every entry as last seen. The
///         handlers keep no copy of the manager's logic. Each check compares what stateOf returned
///         just before a call with what it returns just after, or what a call did with what the
///         handler built it to be, and raises a ghost flag when the result breaks a property. The
///         invariants read those flags.
/// @dev An entry is the setup and attempt of one (account, action) pair, as stateOf returns it. The
///      handlers keep the hash of every entry as stateOf last returned it, so the state before a call
///      is known without reading every entry again. A rule is a setup body the handler built from
///      credentials it knows, so it can write a proof for any place. Honest methods are
///      PolicyManagerMockDigestMethod instances, which approve a proof only when it seals the exact
///      config and digest they are handed. Hostile methods never approve: one reports a stop and
///      refuses everything, the other writes its storage while answering.
abstract contract PolicyManagerBaseHandler is PolicyManagerGhostStorage, CommonBase, StdUtils {
  /// @notice One credential of a rule, written out.
  struct Credential {
    address method;
    bytes config;
    bytes32 salt;
  }

  /// @notice The rule an entry's setup commits, when the handler built that setup. `live` is false
  ///         once a write the handler did not build replaced it, and `nonce` is the setup nonce it
  ///         was committed under.
  // solhint-disable-next-line gas-struct-packing
  struct Rule {
    bool live;
    bool ignoresPause;
    uint48 wait;
    bytes body;
    uint64 nonce;
  }

  /// @notice A proof set the handler built over a rule, and what it knows about it by construction:
  ///         whether it meets every threshold with honest places, whether it names a hostile method,
  ///         and whether it names a method that reports a stop under a setup that does not ignore
  ///         stops.
  struct ProofSet {
    uint256[] places;
    bool complete;
    bool hostile;
    bool stopped;
  }

  /// @notice The most methods the pool of honest methods grows to.
  uint256 internal constant _MAX_HONEST_METHODS = 6;
  /// @notice The most requests a bank keeps. A new one overwrites the oldest.
  uint256 internal constant _MAX_BANKED = 16;

  /// @notice The manager under test.
  PolicyManagerHarness public manager;
  /// @notice A method that reports itself stopped and reverts on every other call.
  address public stoppedMethod;
  /// @notice A method that writes its storage while answering, so under a static call it never
  ///         answers at all.
  address public writingMethod;
  /// @notice An honest method no rule ever names. It approves any proof that seals the config and
  ///         digest it is handed, so only the manager's credential check keeps it from counting.
  address public strangerMethod;

  /// @notice The setup body library behind an external door, to read the pause choice out of a body
  ///         an opening event carries.
  SetupBodyHarness internal _bodyReader;

  /// @notice Every caller the handler uses. Each is the account of its own entries and a stranger
  ///         to everyone else's.
  address[] internal _callers;
  /// @notice Every action the handler uses.
  address[] internal _actions;
  /// @notice The hash of each entry as stateOf last returned it, in callers-then-actions order.
  bytes32[] internal _seen;
  /// @notice The honest methods rules may name. The deploy handler adds to it.
  address[] internal _honestMethods;

  /// @notice The rule of each entry's setup.
  mapping(uint256 _entry => Rule _rule) internal _rules;
  /// @notice The credentials of each entry's rule, in place order.
  mapping(uint256 _entry => Credential[] _credentials) internal _ruleCredentials;
  /// @notice The clause thresholds of each entry's rule, in clause order.
  mapping(uint256 _entry => uint8[] _thresholds) internal _ruleThresholds;
  /// @notice The clause sizes of each entry's rule, in clause order.
  mapping(uint256 _entry => uint256[] _sizes) internal _ruleSizes;

  /// @dev Stores the manager, the callers and the actions, deploys the methods and records every
  ///      entry's starting hash.
  constructor(PolicyManagerHarness _managerUnderTest, address[] memory _callerList, address[] memory _actionList) {
    manager = _managerUnderTest;
    _callers = _callerList;
    _actions = _actionList;
    stoppedMethod = address(new PolicyManagerMockMethod());
    writingMethod = address(new PolicyManagerMockWritingMethod());
    strangerMethod = address(new PolicyManagerMockDigestMethod());
    for (uint256 _i; _i < 3; ++_i) {
      _honestMethods.push(address(new PolicyManagerMockDigestMethod()));
    }
    _bodyReader = new SetupBodyHarness();
    IPolicyManager.ActionState memory _empty;
    _empty.nextAttemptId = 1;
    for (uint256 _i; _i < _callerList.length; ++_i) {
      for (uint256 _j; _j < _actionList.length; ++_j) {
        _seen.push(_hash(_managerUnderTest.stateOf(_callerList[_i], _actionList[_j])));
        ghost_rebuiltEntry[_seen.length - 1] = abi.encode(_empty);
      }
    }
  }

  /*///////////////////////////////////////////////////////////////
                            SHARED HANDLERS
  ///////////////////////////////////////////////////////////////*/

  /// @notice Moves 1 to 1000 blocks forward, so each write records a block of its own.
  function handler_roll(uint256 _blocks) external {
    vm.roll(block.number + bound(_blocks, 1, 1000));
  }

  /// @notice Moves time 1 second to 2 days forward, so windows pass and waits end. Time alone must
  ///         change no entry.
  function handler_warp(uint256 _seconds) external {
    vm.warp(block.timestamp + bound(_seconds, 1, 2 days));
    _checkNothingChanged();
  }

  /// @notice Makes an honest method picked by `_methodSeed` answer the pause read with exactly true
  ///         once in six, as `_stopSeed` picks, and otherwise lifts its stop with one of the answers
  ///         that are no stop: a false word, a revert, a revert carrying true, nothing, less than a word, another
  ///         word, or true followed by more. A stop alone must change no entry.
  function handler_setStopped(uint256 _methodSeed, uint256 _stopSeed) external {
    PolicyManagerMockDigestMethod _method =
      PolicyManagerMockDigestMethod(_honestMethods[bound(_methodSeed, 0, _honestMethods.length - 1)]);
    uint8 _answer = _method.ANSWER_TRUE();
    if (bound(_stopSeed, 0, 5) != 0) {
      // casting to 'uint8' is safe because the index is bound to six
      // forge-lint: disable-next-line(unsafe-typecast)
      uint8 _other = uint8(bound(_stopSeed >> 8, 0, 6));
      _answer = _other == 0 ? _method.ANSWER_FALSE() : _other + 1;
    }
    _method.setPauseAnswer(_answer);
    _checkNothingChanged();
  }

  /// @notice Deploys a new honest method that later rules may name, with nobody's permission, until
  ///         the pool holds six. A deployment alone must change no entry.
  function handler_deployMethod() external {
    if (_honestMethods.length == _MAX_HONEST_METHODS) return;
    _honestMethods.push(address(new PolicyManagerMockDigestMethod()));
    _checkNothingChanged();
  }

  /*///////////////////////////////////////////////////////////////
                        READS FOR THE INVARIANTS
  ///////////////////////////////////////////////////////////////*/

  /// @notice Every caller the handler uses.
  function callers() external view returns (address[] memory _list) {
    _list = _callers;
  }

  /// @notice Every action the handler uses.
  function actions() external view returns (address[] memory _list) {
    _list = _actions;
  }

  /// @notice Every honest method rules may name.
  function honestMethods() external view returns (address[] memory _list) {
    _list = _honestMethods;
  }

  /// @notice The rule stored for entry `_entry`, in callers-then-actions order.
  function ruleOf(uint256 _entry) external view returns (Rule memory _rule) {
    _rule = _rules[_entry];
  }

  /// @notice How many places of entry `_entry`'s rule name a hostile method.
  function hostilePlaces(uint256 _entry) external view returns (uint256 _count) {
    Credential[] storage _credentials = _ruleCredentials[_entry];
    for (uint256 _i; _i < _credentials.length; ++_i) {
      if (_isHostile(_credentials[_i].method)) ++_count;
    }
  }

  /*///////////////////////////////////////////////////////////////
                                 RULES
  ///////////////////////////////////////////////////////////////*/

  /// @notice Builds a rule from `_seed` for entry `_entry`, without storing it. It has one or two
  ///         clauses of one to three credentials each; the first clause needs at least one and the
  ///         second may need none. Each credential names an honest method from the pool, or now and
  ///         then a hostile one. The wait is up to 30 days and the rule ignores stops when bits 200
  ///         and 201 of the seed read 1, once in four.
  function _buildRule(uint256 _entry, uint256 _seed)
    internal
    view
    returns (Rule memory _rule, Credential[] memory _credentials, uint8[] memory _thresholds, uint256[] memory _sizes)
  {
    uint256 _clauseCount = bound(uint256(keccak256(abi.encode(_seed, 'clauses'))), 1, 2);
    _thresholds = new uint8[](_clauseCount);
    _sizes = new uint256[](_clauseCount);
    uint256 _total;
    for (uint256 _c; _c < _clauseCount; ++_c) {
      _sizes[_c] = bound(uint256(keccak256(abi.encode(_seed, 'size', _c))), 1, 3);
      uint256 _threshold = bound(uint256(keccak256(abi.encode(_seed, 'threshold', _c))), _c == 0 ? 1 : 0, _sizes[_c]);
      // casting to 'uint8' is safe because the threshold is bound to the clause size, at most three
      // forge-lint: disable-next-line(unsafe-typecast)
      _thresholds[_c] = uint8(_threshold);
      _total += _sizes[_c];
    }
    _credentials = new Credential[](_total);
    IPolicyManager.Clause[] memory _clauses = new IPolicyManager.Clause[](_clauseCount);
    uint256 _next;
    for (uint256 _c; _c < _clauseCount; ++_c) {
      bytes32[] memory _hashes = new bytes32[](_sizes[_c]);
      for (uint256 _k; _k < _hashes.length; ++_k) {
        _credentials[_next] = Credential({
          method: _methodFor(uint256(keccak256(abi.encode(_seed, 'method', _next)))),
          config: abi.encode('config', _entry, _next, _seed),
          salt: keccak256(abi.encode('salt', _entry, _next, _seed))
        });
        _hashes[_k] = BindingDigest.credentialCommitment(
          _credentials[_next].method, _credentials[_next].config, _credentials[_next].salt
        );
        ++_next;
      }
      _clauses[_c] = IPolicyManager.Clause({threshold: _thresholds[_c], credentials: _hashes});
    }
    _rule.ignoresPause = (_seed >> 200) & 3 == 1;
    // casting to 'uint48' is safe because the wait is bound to 30 days
    // forge-lint: disable-next-line(unsafe-typecast)
    _rule.wait = uint48(bound(uint256(keccak256(abi.encode(_seed, 'wait'))), 0, 30 days));
    _rule.body = SetupBody.encode(_rule.wait, _rule.ignoresPause, _clauses);
  }

  /// @notice An honest method from the pool nine times in ten, and a hostile one otherwise.
  function _methodFor(uint256 _seed) internal view returns (address _method) {
    uint256 _index = bound(_seed, 0, 19);
    if (_index == 18) return stoppedMethod;
    if (_index == 19) return writingMethod;
    _method = _honestMethods[_index % _honestMethods.length];
  }

  /// @notice Stores a rule as entry `_entry`'s current one, committed under `_nonce`.
  function _storeRule(
    uint256 _entry,
    Rule memory _rule,
    Credential[] memory _credentials,
    uint8[] memory _thresholds,
    uint256[] memory _sizes,
    uint64 _nonce
  ) internal {
    _rule.live = true;
    _rule.nonce = _nonce;
    _rules[_entry] = _rule;
    delete _ruleCredentials[_entry];
    for (uint256 _i; _i < _credentials.length; ++_i) {
      _ruleCredentials[_entry].push(_credentials[_i]);
    }
    _ruleThresholds[_entry] = _thresholds;
    _ruleSizes[_entry] = _sizes;
  }

  /// @notice The rule stored for entry `_entry`, read back into memory.
  function _loadRule(uint256 _entry)
    internal
    view
    returns (Rule memory _rule, Credential[] memory _credentials, uint8[] memory _thresholds, uint256[] memory _sizes)
  {
    _rule = _rules[_entry];
    _credentials = _ruleCredentials[_entry];
    _thresholds = _ruleThresholds[_entry];
    _sizes = _ruleSizes[_entry];
  }

  /// @notice Whether a method is hostile, so it never approves.
  function _isHostile(address _method) internal view returns (bool _hostile) {
    _hostile = _method == stoppedMethod || _method == writingMethod;
  }

  /// @notice Whether a method reports a stop right now: the stopped mock always, an honest method
  ///         while its stop is on, the writing method never, since its read cannot answer.
  function _reportsStop(address _method) internal view returns (bool _stops) {
    if (_method == stoppedMethod) return true;
    if (_method == writingMethod) return false;
    _stops = PolicyManagerMockDigestMethod(_method).stopped();
  }

  /*///////////////////////////////////////////////////////////////
                              PROOF SETS
  ///////////////////////////////////////////////////////////////*/

  /// @notice Builds a proof set over entry `_entry`'s rule from `_setSeed`. Per clause it takes the
  ///         honest places in order up to the threshold, or every honest place for a set with
  ///         surplus. One set in five then drops the last place of the first clause, and one in
  ///         six adds the first hostile place. The set is complete when every clause keeps at least
  ///         its threshold of honest places.
  function _chooseSet(uint256 _entry, uint256 _setSeed) internal view returns (ProofSet memory _set) {
    (Rule memory _rule, Credential[] memory _credentials, uint8[] memory _thresholds, uint256[] memory _sizes) =
      _loadRule(_entry);
    bool[] memory _chosen = new bool[](_credentials.length);
    bool _surplus = _setSeed & 1 == 1;
    _set.complete = true;
    uint256 _offset;
    uint256 _lastOfFirst = type(uint256).max;
    uint256 _takenOfFirst;
    for (uint256 _c; _c < _sizes.length; ++_c) {
      uint256 _taken;
      for (uint256 _k; _k < _sizes[_c]; ++_k) {
        uint256 _place = _offset + _k;
        if (_isHostile(_credentials[_place].method)) continue;
        if (_taken < _thresholds[_c] || _surplus) {
          _chosen[_place] = true;
          ++_taken;
          if (_c == 0) _lastOfFirst = _place;
        }
      }
      if (_taken < _thresholds[_c]) _set.complete = false;
      if (_c == 0) _takenOfFirst = _taken;
      _offset += _sizes[_c];
    }
    if (bound(_setSeed >> 8, 0, 4) == 0 && _lastOfFirst != type(uint256).max) {
      _chosen[_lastOfFirst] = false;
      if (_takenOfFirst - 1 < _thresholds[0]) _set.complete = false;
    }
    if (bound(_setSeed >> 16, 0, 5) == 0) {
      for (uint256 _p; _p < _credentials.length; ++_p) {
        if (_isHostile(_credentials[_p].method)) {
          _chosen[_p] = true;
          _set.hostile = true;
          break;
        }
      }
    }
    uint256 _count;
    for (uint256 _p; _p < _chosen.length; ++_p) {
      if (_chosen[_p]) ++_count;
    }
    _set.places = new uint256[](_count);
    _count = 0;
    for (uint256 _p; _p < _chosen.length; ++_p) {
      if (!_chosen[_p]) continue;
      _set.places[_count++] = _p;
      if (!_rule.ignoresPause && _reportsStop(_credentials[_p].method)) _set.stopped = true;
    }
  }

  /// @notice The proofs for `_places` of entry `_entry`'s rule, each sealing its own config and the
  ///         digest in `_digests` at the same index.
  function _proofsFor(uint256 _entry, uint256[] memory _places, bytes32[] memory _digests)
    internal
    view
    returns (IPolicyManager.ProofPlace[] memory _proofs)
  {
    _proofs = new IPolicyManager.ProofPlace[](_places.length);
    for (uint256 _i; _i < _places.length; ++_i) {
      Credential storage _credential = _ruleCredentials[_entry][_places[_i]];
      _proofs[_i] = IPolicyManager.ProofPlace({
        place: _places[_i],
        method: _credential.method,
        config: _credential.config,
        salt: _credential.salt,
        proof: _seal(_credential.config, _digests[_i])
      });
    }
  }

  /// @notice The proof an honest method approves for `_config` and `_digest`.
  function _seal(bytes memory _config, bytes32 _digest) internal view returns (bytes memory _proof) {
    _proof = PolicyManagerMockDigestMethod(strangerMethod).seal(_config, _digest);
  }

  /// @notice The distinct methods of `_proofs`, in the order the proofs first name them: the list an
  ///         accepted attempt records as used.
  function _distinctMethods(IPolicyManager.ProofPlace[] memory _proofs)
    internal
    pure
    returns (address[] memory _methodList)
  {
    address[] memory _found = new address[](_proofs.length);
    uint256 _count;
    for (uint256 _i; _i < _proofs.length; ++_i) {
      bool _known;
      for (uint256 _j; _j < _count; ++_j) {
        if (_found[_j] == _proofs[_i].method) _known = true;
      }
      if (!_known) _found[_count++] = _proofs[_i].method;
    }
    _methodList = new address[](_count);
    for (uint256 _i; _i < _count; ++_i) {
      _methodList[_i] = _found[_i];
    }
  }

  /// @notice The places `_proofs` fill, in order.
  function _placesOf(IPolicyManager.ProofPlace[] memory _proofs) internal pure returns (uint256[] memory _places) {
    _places = new uint256[](_proofs.length);
    for (uint256 _i; _i < _proofs.length; ++_i) {
      _places[_i] = _proofs[_i].place;
    }
  }

  /*///////////////////////////////////////////////////////////////
                                CHECKS
  ///////////////////////////////////////////////////////////////*/

  /// @notice The caller and action `_callerSeed` and `_actionSeed` pick, and the index of their entry
  ///         in callers-then-actions order.
  function _pick(uint256 _callerSeed, uint256 _actionSeed)
    internal
    view
    returns (address _caller, address _pairAction, uint256 _entry)
  {
    uint256 _i = bound(_callerSeed, 0, _callers.length - 1);
    uint256 _j = bound(_actionSeed, 0, _actions.length - 1);
    _caller = _callers[_i];
    _pairAction = _actions[_j];
    _entry = _i * _actions.length + _j;
  }

  /// @notice Three times in four, as `_steerSeed` picks, moves from entry `_entry` to the first entry
  ///         at or after it, wrapping, whose rule the handler built and still holds and, when
  ///         `_wantWaiting` is set, whose attempt waits. Otherwise, or when no entry qualifies, it
  ///         keeps `_entry`. This steers most openings and cancels to entries where they can land,
  ///         and leaves the rest to test the refusals.
  function _steer(uint256 _entry, uint256 _steerSeed, bool _wantWaiting)
    internal
    view
    returns (address _account, address _action, uint256 _steered)
  {
    uint256 _count = _callers.length * _actions.length;
    _steered = _entry;
    if (bound(_steerSeed, 0, 3) != 0) {
      for (uint256 _k; _k < _count; ++_k) {
        uint256 _candidate = (_entry + _k) % _count;
        if (!_rules[_candidate].live) continue;
        (address _candidateAccount, address _candidateAction) = _entryPair(_candidate);
        if (
          _wantWaiting
            && manager.stateOf(_candidateAccount, _candidateAction).attempt.state != IPolicyManager.AttemptState.Waiting
        ) continue;
        _steered = _candidate;
        break;
      }
    }
    (_account, _action) = _entryPair(_steered);
  }

  /// @notice Opens an attempt with a valid request over a rule the handler holds, built from `_seed`,
  ///         through the startAttempt handler's own build, send and checks.
  function _openAValidAttempt(uint256 _seed) internal virtual;

  /// @notice Seven times in eight, as bits 0 to 2 of `_seed` pick, and only while no attempt the handler saw
  ///         accepted still waits, first opens one with a valid request. Attempts rarely outlive the
  ///         cancels and writes around them, so without this the spend and the veto would seldom
  ///         find an attempt to act on.
  function _openOneIfNoneWaits(uint256 _seed) internal {
    if (_seed & 7 == 0) return;
    uint256 _count = _callers.length * _actions.length;
    for (uint256 _k; _k < _count; ++_k) {
      if (!ghost_acceptedOpening[_k].known) continue;
      (address _account, address _action) = _entryPair(_k);
      if (manager.stateOf(_account, _action).attempt.state == IPolicyManager.AttemptState.Waiting) return;
    }
    _openAValidAttempt(_seed >> 3);
  }

  /// @notice Moves from entry `_entry` to the first entry at or after it, wrapping, whose last opening
  ///         the handler saw accepted and whose attempt still waits; failing that, to the first entry
  ///         with any opening the handler saw accepted; failing that, it keeps `_entry`. This steers
  ///         every spend and veto to an attempt they can act on, and leaves their corruptions and the
  ///         other handlers' moves to reach the refusals.
  function _steerToOpening(uint256 _entry) internal view returns (address _account, address _action, uint256 _steered) {
    uint256 _count = _callers.length * _actions.length;
    _steered = type(uint256).max;
    uint256 _fallback = type(uint256).max;
    for (uint256 _k; _k < _count; ++_k) {
      uint256 _candidate = (_entry + _k) % _count;
      if (!ghost_acceptedOpening[_candidate].known) continue;
      if (_fallback == type(uint256).max) _fallback = _candidate;
      (address _candidateAccount, address _candidateAction) = _entryPair(_candidate);
      if (manager.stateOf(_candidateAccount, _candidateAction).attempt.state == IPolicyManager.AttemptState.Waiting) {
        _steered = _candidate;
        break;
      }
    }
    if (_steered == type(uint256).max) _steered = _fallback == type(uint256).max ? _entry : _fallback;
    (_account, _action) = _entryPair(_steered);
  }

  /// @notice The account and the action of entry `_entry`.
  function _entryPair(uint256 _entry) internal view returns (address _account, address _action) {
    _account = _callers[_entry / _actions.length];
    _action = _actions[_entry % _actions.length];
  }

  /// @notice Checks every entry after an accepted call on entry `_entry`. Every other entry must
  ///         still hash as it did before the call. Records every entry's new hash and returns the
  ///         call's own entry as it now reads, for the calling handler to check against its own
  ///         arguments.
  function _checkEntries(uint256 _entry) internal returns (IPolicyManager.ActionState memory _ownAfter) {
    for (uint256 _i; _i < _callers.length; ++_i) {
      for (uint256 _j; _j < _actions.length; ++_j) {
        uint256 _k = _i * _actions.length + _j;
        IPolicyManager.ActionState memory _entryState = manager.stateOf(_callers[_i], _actions[_j]);
        bytes32 _hashed = _hash(_entryState);
        if (_k == _entry) {
          _ownAfter = _entryState;
        } else if (_hashed != _seen[_k]) {
          ghost_foreignEntryChanged = true;
        }
        _seen[_k] = _hashed;
      }
    }
  }

  /// @notice Raises ghost_stateMovedWithoutACall when any entry no longer hashes as last seen.
  function _checkNothingChanged() internal {
    for (uint256 _i; _i < _callers.length; ++_i) {
      for (uint256 _j; _j < _actions.length; ++_j) {
        uint256 _k = _i * _actions.length + _j;
        if (_hash(manager.stateOf(_callers[_i], _actions[_j])) != _seen[_k]) ghost_stateMovedWithoutACall = true;
      }
    }
  }

  /// @notice Raises ghost_counterMovedWrongly when a call that is not an opening moved the counter.
  function _checkCounterKept(IPolicyManager.ActionState memory _before, IPolicyManager.ActionState memory _after)
    internal
  {
    if (_after.nextAttemptId != _before.nextAttemptId) ghost_counterMovedWrongly = true;
  }

  /// @notice Checks the events and the attempt record a setup write left behind. The write must
  ///         emit exactly one event of its own. When an attempt was waiting, the write must emit
  ///         AttemptCancelled for it first, and the attempt must now read Cancelled.
  function _checkWriteEvents(
    Vm.Log[] memory _logs,
    address _pairAccount,
    address _pairAction,
    IPolicyManager.Attempt memory _attemptBefore,
    IPolicyManager.Attempt memory _attemptAfter,
    bytes32 _writeTopic,
    bytes memory _writeData
  ) internal {
    bool _waited =
      _attemptBefore.state == IPolicyManager.AttemptState.Waiting;
    if (_logs.length != (_waited ? 2 : 1)) {
      ghost_wrongEvents = true;
      return;
    }
    if (_waited && !_isCancelLog(_logs[0], _pairAccount, _pairAction, _attemptBefore, address(0))) {
      ghost_wrongEvents = true;
    }
    if (!_isLog(_logs[_logs.length - 1], _writeTopic, _pairAccount, _pairAction, _writeData)) ghost_wrongEvents = true;

    IPolicyManager.Attempt memory _expectedRecord = _attemptBefore;
    if (_waited) _expectedRecord.state = IPolicyManager.AttemptState.Cancelled;
    if (keccak256(abi.encode(_attemptAfter)) != keccak256(abi.encode(_expectedRecord))) {
      ghost_acceptedCallWrong = true;
    }
  }

  /// @notice Whether `_log` is the AttemptCancelled event for `_record`, with `_canceller` as the
  ///         canceller, address(0) as the vetoing method and an empty list of used places.
  function _isCancelLog(
    Vm.Log memory _log,
    address _pairAccount,
    address _pairAction,
    IPolicyManager.Attempt memory _record,
    address _canceller
  ) internal view returns (bool _matches) {
    _matches = _isLog(
      _log,
      IPolicyManager.AttemptCancelled.selector,
      _pairAccount,
      _pairAction,
      abi.encode(_record.attemptId, _canceller, address(0), _record.setupNonce, new uint256[](0))
    );
  }

  /// @notice Whether `_log` is a manager event with this topic0, account, action and data.
  function _isLog(Vm.Log memory _log, bytes32 _topic, address _pairAccount, address _pairAction, bytes memory _data)
    internal
    view
    returns (bool _matches)
  {
    _matches = _log.emitter == address(manager) && _log.topics.length == 3 && _log.topics[0] == _topic
      && _log.topics[1] == bytes32(uint256(uint160(_pairAccount)))
      && _log.topics[2] == bytes32(uint256(uint160(_pairAction))) && _eq(_log.data, _data);
  }

  /// @notice Raises ghost_reachedOtherContract when the manager called or read any contract other
  ///         than itself during the call.
  function _checkNoOtherContract(Vm.AccountAccess[] memory _accesses) internal {
    for (uint256 _i; _i < _accesses.length; ++_i) {
      if (_accesses[_i].accessor != address(manager)) continue;
      if (_accesses[_i].kind == VmSafe.AccountAccessKind.Resume) continue;
      if (_accesses[_i].account != address(manager)) ghost_reachedOtherContract = true;
    }
  }

  /// @notice Raises ghost_reachedOtherContract when the manager, during a setup write by `_caller`
  ///         for `_pairAction`, reached any contract other than itself, except by a static call to
  ///         `_pairAction` asking supportsAccount(_caller). That question is the one call a write
  ///         makes, so no method and no pause read can block it.
  function _checkOnlyServingProbe(Vm.AccountAccess[] memory _accesses, address _caller, address _pairAction) internal {
    bytes memory _probe = abi.encodeCall(IPolicyAction.supportsAccount, (_caller));
    for (uint256 _i; _i < _accesses.length; ++_i) {
      Vm.AccountAccess memory _access = _accesses[_i];
      if (_access.accessor != address(manager)) continue;
      if (_access.kind == VmSafe.AccountAccessKind.Resume) continue;
      if (_access.account == address(manager)) continue;
      bool _isProbe = _access.account == _pairAction && _access.kind == VmSafe.AccountAccessKind.StaticCall
        && _eq(_access.data, _probe);
      if (!_isProbe) ghost_reachedOtherContract = true;
    }
  }

  /// @notice Checks every call the manager made to another contract during a call carrying
  ///         `_proofs`, whose place digests are `_digests`. Each must be a static call, never reach
  ///         the stranger method, and carry either the pause read or a verify of a method some proof
  ///         names, with that proof's own config, the digest of its own place and its own proof. No
  ///         contract but the manager may keep a storage write.
  function _checkMethodCalls(
    Vm.AccountAccess[] memory _accesses,
    IPolicyManager.ProofPlace[] memory _proofs,
    bytes32[] memory _digests
  ) internal {
    for (uint256 _i; _i < _accesses.length; ++_i) {
      Vm.AccountAccess memory _access = _accesses[_i];
      for (uint256 _k; _k < _access.storageAccesses.length; ++_k) {
        Vm.StorageAccess memory _slot = _access.storageAccesses[_k];
        if (_slot.isWrite && !_slot.reverted && _slot.account != address(manager)) ghost_methodWroteState = true;
      }
      if (_access.accessor != address(manager) || _access.account == address(manager)) continue;
      if (uint256(_access.kind) > uint256(VmSafe.AccountAccessKind.Create)) continue;
      if (_access.account == strangerMethod) ghost_uncommittedModuleReached = true;
      if (_access.kind != VmSafe.AccountAccessKind.StaticCall) ghost_nonStaticMethodCall = true;
      if (_eq(_access.data, abi.encodeCall(IPolicyMethodPause.paused, ()))) continue;
      if (!_isOwnVerify(_access, _proofs, _digests)) ghost_methodHandedForeignInput = true;
    }
  }

  /// @notice Whether `_access` is a verify call to a method of `_proofs` with that proof's own
  ///         config, digest and proof.
  function _isOwnVerify(
    Vm.AccountAccess memory _access,
    IPolicyManager.ProofPlace[] memory _proofs,
    bytes32[] memory _digests
  ) internal pure returns (bool _own) {
    for (uint256 _p; _p < _proofs.length; ++_p) {
      if (_proofs[_p].method != _access.account) continue;
      bytes memory _call = abi.encodeCall(IPolicyMethod.verify, (_proofs[_p].config, _digests[_p], _proofs[_p].proof));
      if (_eq(_access.data, _call)) return true;
    }
  }

  /// @notice Raises ghost_storageRevealsRule when the manager wrote a credential hash, a salt or the
  ///         body hash of entry `_entry`'s rule into its storage during the recorded call.
  function _checkStorageHidesRule(Vm.AccountAccess[] memory _accesses, uint256 _entry) internal {
    Credential[] memory _credentials = _ruleCredentials[_entry];
    bytes32 _bodyHash = keccak256(_rules[_entry].body);
    for (uint256 _i; _i < _accesses.length; ++_i) {
      Vm.StorageAccess[] memory _slots = _accesses[_i].storageAccesses;
      for (uint256 _k; _k < _slots.length; ++_k) {
        if (_slots[_k].account != address(manager) || !_slots[_k].isWrite) continue;
        bytes32 _written = _slots[_k].newValue;
        if (_written == _bodyHash) ghost_storageRevealsRule = true;
        for (uint256 _c; _c < _credentials.length; ++_c) {
          Credential memory _credential = _credentials[_c];
          if (_written == _credential.salt) ghost_storageRevealsRule = true;
          if (_written == BindingDigest.credentialCommitment(_credential.method, _credential.config, _credential.salt))
          {
            ghost_storageRevealsRule = true;
          }
        }
      }
    }
  }

  /// @notice Raises ghost_unnamedMethodCounted when `_usedMethods` holds a method entry `_entry`'s
  ///         rule does not name.
  function _checkUsedMethodsNamed(address[] memory _usedMethods, uint256 _entry) internal {
    Credential[] memory _credentials = _ruleCredentials[_entry];
    for (uint256 _i; _i < _usedMethods.length; ++_i) {
      bool _named;
      for (uint256 _c; _c < _credentials.length; ++_c) {
        if (_credentials[_c].method == _usedMethods[_i]) _named = true;
      }
      if (!_named) ghost_unnamedMethodCounted = true;
    }
  }

  /// @notice The hash of an entry, to tell whether it changed.
  function _hash(IPolicyManager.ActionState memory _entryState) internal pure returns (bytes32 _hashed) {
    _hashed = keccak256(abi.encode(_entryState));
  }

  /// @notice The hash of an attempt record, to tell whether it reads back as written.
  function _hash(IPolicyManager.Attempt memory _record) internal pure returns (bytes32 _hashed) {
    _hashed = keccak256(abi.encode(_record));
  }

  /// @notice Whether two byte strings are equal.
  function _eq(bytes memory _a, bytes memory _b) internal pure returns (bool _equal) {
    _equal = keccak256(_a) == keccak256(_b);
  }

  /*///////////////////////////////////////////////////////////////
                    THE EVENT STREAM AND THE LIFECYCLE
  ///////////////////////////////////////////////////////////////*/

  /// @notice Takes the logs recorded since the last take, after a manager call that succeeded. It
  ///         applies every manager event to the state rebuilt from events alone, then checks every
  ///         entry's attempt against what the handlers last saw of it. Returns the logs.
  function _observe() internal returns (Vm.Log[] memory _logs) {
    _logs = vm.getRecordedLogs();
    for (uint256 _i; _i < _logs.length; ++_i) {
      if (_logs[_i].emitter == address(manager)) _rebuildFrom(_logs[_i]);
    }
    _checkLifecycle();
  }

  /// @notice Applies one manager event to the rebuilt state of the entry it names, using the event's
  ///         own fields and the block it was emitted in, never a read of the manager. An event that
  ///         names no entry of the suite, has an unknown topic, or claims a transition the rebuilt
  ///         state does not allow raises ghost_phantomEvent.
  function _rebuildFrom(Vm.Log memory _log) internal {
    if (_log.topics.length != 3) {
      ghost_phantomEvent = true;
      return;
    }
    (bool _found, uint256 _entry) =
      _entryOf(address(uint160(uint256(_log.topics[1]))), address(uint160(uint256(_log.topics[2]))));
    if (!_found) {
      ghost_phantomEvent = true;
      return;
    }
    IPolicyManager.ActionState memory _rebuilt = abi.decode(ghost_rebuiltEntry[_entry], (IPolicyManager.ActionState));
    bytes32 _topic = _log.topics[0];
    if (_topic == IPolicyManager.SetupCommitted.selector) {
      (_rebuilt.setupNonce, _rebuilt.setupCommitment,,) = abi.decode(_log.data, (uint64, bytes32, bytes, bytes));
      _rebuilt.setupCommittedAtBlock = uint48(block.number);
    } else if (_topic == IPolicyManager.SetupCleared.selector) {
      _rebuilt.setupNonce = abi.decode(_log.data, (uint64));
      _rebuilt.setupCommitment = bytes32(0);
      _rebuilt.setupCommittedAtBlock = uint48(block.number);
    } else if (_topic == IPolicyManager.AttemptStarted.selector) {
      _rebuildStarted(_rebuilt, _log.data);
    } else if (_topic == IPolicyManager.AttemptCancelled.selector) {
      (uint64 _attemptId,,, uint64 _setupNonce,) = abi.decode(_log.data, (uint64, address, address, uint64, uint256[]));
      _endRebuilt(_rebuilt, _attemptId, _setupNonce, IPolicyManager.AttemptState.Cancelled);
    } else if (_topic == IPolicyManager.AttemptConsumed.selector) {
      uint64 _attemptId = abi.decode(_log.data, (uint64));
      _endRebuilt(_rebuilt, _attemptId, _rebuilt.attempt.setupNonce, IPolicyManager.AttemptState.Consumed);
    } else {
      ghost_phantomEvent = true;
    }
    ghost_rebuiltEntry[_entry] = abi.encode(_rebuilt);
  }

  /// @notice The fields of an AttemptStarted event, as one struct so they decode in one step.
  // solhint-disable-next-line gas-struct-packing
  struct StartedFields {
    uint64 attemptId;
    uint64 setupNonce;
    bytes setupBody;
    uint256[] usedPlaces;
    address[] usedMethods;
    bytes payload;
    IPolicyManager.PaymentOrder order;
    uint48 consumableAfter;
  }

  /// @notice Writes the attempt an AttemptStarted event describes into `_rebuilt`: the pause choice
  ///         read from the body it carries, the hash of the payload it carries, and the next id one
  ///         past its own. A start over a waiting attempt is a phantom.
  function _rebuildStarted(IPolicyManager.ActionState memory _rebuilt, bytes memory _data) internal {
    StartedFields memory _fields = abi.decode(bytes.concat(abi.encode(uint256(32)), _data), (StartedFields));
    if (_rebuilt.attempt.state == IPolicyManager.AttemptState.Waiting) ghost_phantomEvent = true;
    _rebuilt.attempt = IPolicyManager.Attempt({
      attemptId: _fields.attemptId,
      setupNonce: _fields.setupNonce,
      consumableAfter: _fields.consumableAfter,
      state: IPolicyManager.AttemptState.Waiting,
      ignoresPause: _bodyReader.ignoresPauseOf(_fields.setupBody),
      payloadHash: keccak256(_fields.payload),
      order: _fields.order,
      usedMethods: _fields.usedMethods
    });
    _rebuilt.nextAttemptId = _fields.attemptId + 1;
  }

  /// @notice Ends the rebuilt attempt as `_state`. An end naming another attempt, another setup nonce,
  ///         or an attempt that is not waiting is a phantom.
  function _endRebuilt(
    IPolicyManager.ActionState memory _rebuilt,
    uint64 _attemptId,
    uint64 _setupNonce,
    IPolicyManager.AttemptState _state
  ) internal {
    if (
      _rebuilt.attempt.state != IPolicyManager.AttemptState.Waiting || _rebuilt.attempt.attemptId != _attemptId
        || _rebuilt.attempt.setupNonce != _setupNonce
    ) ghost_phantomEvent = true;
    _rebuilt.attempt.state = _state;
  }

  /// @notice The entry of `_account` and `_action`, and whether the suite uses that pair.
  function _entryOf(address _account, address _action) internal view returns (bool _found, uint256 _entry) {
    for (uint256 _i; _i < _callers.length; ++_i) {
      for (uint256 _j; _j < _actions.length; ++_j) {
        if (_callers[_i] == _account && _actions[_j] == _action) return (true, _i * _actions.length + _j);
      }
    }
  }

  /// @notice Compares every entry's attempt with what the handlers last saw of it. The same attempt
  ///         must not leave Cancelled or Consumed. A new attempt must not replace one that still
  ///         waits, and ids never go back.
  function _checkLifecycle() internal {
    for (uint256 _i; _i < _callers.length; ++_i) {
      for (uint256 _j; _j < _actions.length; ++_j) {
        uint256 _k = _i * _actions.length + _j;
        IPolicyManager.Attempt memory _now = manager.stateOf(_callers[_i], _actions[_j]).attempt;
        SeenAttempt memory _last = ghost_seenAttempt[_k];
        bool _ended =
          _last.state == IPolicyManager.AttemptState.Cancelled || _last.state == IPolicyManager.AttemptState.Consumed;
        if (_now.attemptId == _last.attemptId) {
          if (_ended && _now.state != _last.state) ghost_finishedAttemptMoved = true;
        } else {
          if (_last.state == IPolicyManager.AttemptState.Waiting) ghost_waitingAttemptDisplaced = true;
          if (_now.attemptId < _last.attemptId) ghost_finishedAttemptMoved = true;
        }
        ghost_seenAttempt[_k] = SeenAttempt({attemptId: _now.attemptId, state: _now.state});
      }
    }
  }

  /*///////////////////////////////////////////////////////////////
                              PAUSE READS
  ///////////////////////////////////////////////////////////////*/

  /// @notice Checks every call the manager made to another contract during a spend or a cancel by
  ///         veto. Each must be a static pause read of a method in `_allowed`, and no contract but the
  ///         manager may keep a storage write.
  function _checkPauseReadsOnly(Vm.AccountAccess[] memory _accesses, address[] memory _allowed) internal {
    for (uint256 _i; _i < _accesses.length; ++_i) {
      Vm.AccountAccess memory _access = _accesses[_i];
      for (uint256 _k; _k < _access.storageAccesses.length; ++_k) {
        Vm.StorageAccess memory _slot = _access.storageAccesses[_k];
        if (_slot.isWrite && !_slot.reverted && _slot.account != address(manager)) ghost_methodWroteState = true;
      }
      if (!_isOutsideCall(_access)) continue;
      if (_access.kind != VmSafe.AccountAccessKind.StaticCall) ghost_nonStaticMethodCall = true;
      if (!_eq(_access.data, abi.encodeCall(IPolicyMethodPause.paused, ())) || !_contains(_allowed, _access.account)) {
        ghost_pauseReadWrong = true;
      }
    }
  }

  /// @notice How many calls the manager made to another contract during the recorded call.
  function _outsideCalls(Vm.AccountAccess[] memory _accesses) internal view returns (uint256 _count) {
    for (uint256 _i; _i < _accesses.length; ++_i) {
      if (_isOutsideCall(_accesses[_i])) ++_count;
    }
  }

  /// @notice Whether `_access` is a call the manager made to another contract.
  function _isOutsideCall(Vm.AccountAccess memory _access) internal view returns (bool _outside) {
    _outside = _access.accessor == address(manager) && _access.account != address(manager)
      && uint256(_access.kind) < uint256(VmSafe.AccountAccessKind.Create) + 1;
  }

  /// @notice Whether `_list` holds `_item`.
  function _contains(address[] memory _list, address _item) internal pure returns (bool _found) {
    for (uint256 _i; _i < _list.length; ++_i) {
      if (_list[_i] == _item) return true;
    }
  }

  /// @notice The first method of `_list` that answers the pause read with exactly true, or address(0)
  ///         when none does.
  function _firstStopped(address[] memory _list) internal view returns (address _method) {
    for (uint256 _i; _i < _list.length; ++_i) {
      if (_reportsStop(_list[_i])) return _list[_i];
    }
  }
}
