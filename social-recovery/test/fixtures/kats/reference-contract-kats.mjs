import {
  concatHex,
  encodeAbiParameters,
  encodeEventTopics,
  encodeFunctionData,
  hashTypedData,
  keccak256,
  parseAbi,
  sha256,
  stringToHex,
  toBytes,
  toHex,
} from 'viem'
import { Address, P256, Secp256k1, Signature } from 'ox'
import { readFileSync, readdirSync } from 'node:fs'

const out = new Map()
const address = {
  account: '0x1111111111111111111111111111111111111111',
  action: '0x2222222222222222222222222222222222222222',
  method: '0x3333333333333333333333333333333333333333',
  token: '0x4444444444444444444444444444444444444444',
  payee: '0x5555555555555555555555555555555555555555',
  manager: '0x6666666666666666666666666666666666666666',
  newAuthority: '0x7777777777777777777777777777777777777777',
  removedAuthority: '0x8888888888888888888888888888888888888888',
}
const salt = `0x${'aa'.repeat(32)}`
const b32 = (n) => `0x${BigInt(n).toString(16).padStart(64, '0')}`
const abi = (params, values) => encodeAbiParameters(params, values)
const file = (name, format, derivation, vectors, source = 'docs/contracts.md', metadata = {}) => out.set(name, { format, source, ...metadata, derivation, vectors })

const credentialNormalPreimage = abi([
  { type: 'address', name: 'method' }, { type: 'bytes', name: 'config' }, { type: 'bytes32', name: 'salt' },
], [address.method, '0x1234', salt])
const credentialZeroPreimage = abi([
  { type: 'address' }, { type: 'bytes' }, { type: 'bytes32' },
], ['0x0000000000000000000000000000000000000000', '0x', b32(0)])
file('credential-commitment.json', 'credential-commitment-v1', 'keccak256(abi.encode(address method, bytes config, bytes32 salt))', [
  { id: 'normal', input: { method: address.method, config: '0x1234', salt }, expected: { preimage: credentialNormalPreimage, commitment: keccak256(credentialNormalPreimage) } },
  { id: 'zero-and-empty', input: { method: '0x0000000000000000000000000000000000000000', config: '0x', salt: b32(0) }, expected: { preimage: credentialZeroPreimage, commitment: keccak256(credentialZeroPreimage) } },
])

const clauses = [
  { threshold: 1, credentials: [keccak256(credentialNormalPreimage)] },
  { threshold: 2, credentials: [b32(1), b32(2), b32(3)] },
]
const bodyParams = [{ type: 'uint48' }, { type: 'bool' }, { type: 'tuple[]', components: [{ name: 'threshold', type: 'uint8' }, { name: 'credentials', type: 'bytes32[]' }] }]
const body = abi(bodyParams, [172800, false, clauses])
const emptyBody = abi(bodyParams, [0, true, []])
const maxBody = abi(bodyParams, [281474976710655n, true, [{ threshold: 255, credentials: [] }]])
file('setup-body.json', 'setup-body-v1', 'abi.encode(uint48 wait, bool ignoresPause, Clause[] clauses)', [
  { id: 'two-clauses', input: { wait: '172800', ignoresPause: false, clauses }, expected: { encoded: body } },
  { id: 'empty-clauses', input: { wait: '0', ignoresPause: true, clauses: [] }, expected: { encoded: emptyBody } },
  { id: 'maximum-widths', input: { wait: '281474976710655', ignoresPause: true, clauses: [{ threshold: 255, credentials: [] }] }, expected: { encoded: maxBody } },
])

const setupParams = [{ type: 'address' }, { type: 'address' }, { type: 'uint64' }, { type: 'bytes' }]
const setupPreimage = abi(setupParams, [address.account, address.action, 7n, body])
const zeroBodyPreimage = abi(setupParams, [address.account, address.action, 1n, '0x'])
file('setup-commitment.json', 'setup-commitment-v1', 'keccak256(abi.encode(address account, address action, uint64 nonce, bytes setupBody))', [
  { id: 'normal', input: { account: address.account, action: address.action, nonce: '7', setupBody: body }, expected: { preimage: setupPreimage, commitment: keccak256(setupPreimage) } },
  { id: 'zero-length-body', input: { account: address.account, action: address.action, nonce: '1', setupBody: '0x' }, expected: { preimage: zeroBodyPreimage, commitment: keccak256(zeroBodyPreimage), managerAcceptance: 'reject PolicyManager_InvalidCommitment input body' } },
])

const paymentParams = [{ type: 'address', name: 'token' }, { type: 'uint256', name: 'amount' }, { type: 'address', name: 'payee' }]
const order = { token: address.token, amount: 1234567890123456789n, payee: address.payee }
file('payment-order.json', 'payment-order-v1', 'abi.encode(address token, uint256 amount, address payee)', [
  { id: 'erc20', input: { ...order, amount: order.amount.toString() }, expected: { encoded: abi(paymentParams, [order.token, order.amount, order.payee]) } },
  { id: 'native-zero-open', input: { token: `0x${'00'.repeat(20)}`, amount: '0', payee: `0x${'00'.repeat(20)}` }, expected: { encoded: abi(paymentParams, [`0x${'00'.repeat(20)}`, 0n, `0x${'00'.repeat(20)}`]) } },
], 'docs/contracts.md', { role: 'component fixture embedded in approval and attempt formats' })

const proofComponent = [{ name: 'place', type: 'uint256' }, { name: 'method', type: 'address' }, { name: 'config', type: 'bytes' }, { name: 'salt', type: 'bytes32' }, { name: 'proof', type: 'bytes' }]
const proof = { place: 2n, method: address.method, config: '0x1234', salt, proof: '0xdeadbeef' }
file('proof-place.json', 'proof-place-v1', 'abi.encode(ProofPlace(uint256 place,address method,bytes config,bytes32 salt,bytes proof))', [
  { id: 'normal', input: { ...proof, place: proof.place.toString() }, expected: { encoded: abi([{ type: 'tuple', components: proofComponent }], [proof]) } },
  { id: 'empty-dynamic-members', input: { place: '0', method: address.method, config: '0x', salt: b32(0), proof: '0x' }, expected: { encoded: abi([{ type: 'tuple', components: proofComponent }], [{ place: 0n, method: address.method, config: '0x', salt: b32(0), proof: '0x' }]) } },
], 'docs/contracts.md', { role: 'component fixture embedded in attempt and cancellation formats' })

const requestAbi = parseAbi([
  'function startAttempt((address account,address action,uint64 attemptId,uint64 setupNonce,bytes setupBody,bytes payload,(address token,uint256 amount,address payee) order,uint48 validUntil,(uint256 place,address method,bytes config,bytes32 salt,bytes proof)[] proofs) request)',
  'function cancelByProofs((address account,address action,uint64 attemptId,uint64 setupNonce,bytes setupBody,uint48 validUntil,(uint256 place,address method,bytes config,bytes32 salt,bytes proof)[] proofs) request)',
])
const attempt = { account: address.account, action: address.action, attemptId: 9n, setupNonce: 7n, setupBody: body, payload: '0xabcdef', order, validUntil: 1800000000, proofs: [{ ...proof, place: 0n }, { ...proof, place: 3n, config: '0x5678', proof: '0xcafe' }] }
const cancel = { account: address.account, action: address.action, attemptId: 9n, setupNonce: 7n, setupBody: body, validUntil: 1800000000, proofs: [{ ...proof, place: 0n }] }
file('attempt-request.json', 'attempt-request-v1', 'abi.encodeWithSelector(IPolicyManager.startAttempt.selector, AttemptRequest)', [
  { id: 'sorted-proofs', input: { ...attempt, attemptId: '9', setupNonce: '7', order: { ...order, amount: order.amount.toString() }, validUntil: '1800000000', proofs: attempt.proofs.map((p) => ({ ...p, place: p.place.toString() })) }, expected: { calldata: encodeFunctionData({ abi: requestAbi, functionName: 'startAttempt', args: [attempt] }) } },
])
file('cancel-request.json', 'cancel-request-v1', 'abi.encodeWithSelector(IPolicyManager.cancelByProofs.selector, CancelRequest)', [
  { id: 'one-proof', input: { ...cancel, attemptId: '9', setupNonce: '7', validUntil: '1800000000', proofs: cancel.proofs.map((p) => ({ ...p, place: p.place.toString() })) }, expected: { calldata: encodeFunctionData({ abi: requestAbi, functionName: 'cancelByProofs', args: [cancel] }) } },
])

const domain = { name: 'PolicyManager', version: '1', chainId: 1, verifyingContract: address.manager }
const approvalTypes = {
  PaymentOrder: paymentParams,
  Approval: [
    { name: 'account', type: 'address' }, { name: 'action', type: 'address' }, { name: 'attemptId', type: 'uint64' }, { name: 'setupNonce', type: 'uint64' }, { name: 'setupBodyHash', type: 'bytes32' }, { name: 'payload', type: 'bytes' }, { name: 'order', type: 'PaymentOrder' }, { name: 'validUntil', type: 'uint48' }, { name: 'place', type: 'uint256' },
  ],
}
const cancellationTypes = { Cancellation: [
  { name: 'account', type: 'address' }, { name: 'action', type: 'address' }, { name: 'attemptId', type: 'uint64' }, { name: 'setupNonce', type: 'uint64' }, { name: 'setupBodyHash', type: 'bytes32' }, { name: 'validUntil', type: 'uint48' }, { name: 'place', type: 'uint256' },
] }
const approvalMessage = { account: address.account, action: address.action, attemptId: 9n, setupNonce: 7n, setupBodyHash: keccak256(body), payload: '0xabcdef', order, validUntil: 1800000000, place: 0n }
const cancellationMessage = { account: address.account, action: address.action, attemptId: 9n, setupNonce: 7n, setupBodyHash: keccak256(body), validUntil: 1800000000, place: 0n }
// Boundary rows: each overrides the normal message and goes through the same hashTypedData path.
const onesAddress = `0x${'ff'.repeat(20)}`
const zeroAddress = `0x${'00'.repeat(20)}`
const maxUint64 = 2n ** 64n - 1n
const maxUint48 = 2n ** 48n - 1n
const maxUint256 = 2n ** 256n - 1n
const digestInput = (message) => Object.fromEntries(Object.entries(message).map(([k, v]) => [k, typeof v === 'bigint' || typeof v === 'number' ? v.toString() : k === 'order' ? { ...v, amount: v.amount.toString() } : v]))
const approvalRow = (id, overrides, rowDomain = domain) => {
  const message = { ...approvalMessage, ...overrides }
  return { id, input: { domain: rowDomain, message: digestInput(message) }, expected: { digest: hashTypedData({ domain: rowDomain, types: approvalTypes, primaryType: 'Approval', message }) } }
}
const cancellationRow = (id, overrides, rowDomain = domain) => {
  const message = { ...cancellationMessage, ...overrides }
  return { id, input: { domain: rowDomain, message: digestInput(message) }, expected: { digest: hashTypedData({ domain: rowDomain, types: cancellationTypes, primaryType: 'Cancellation', message }) } }
}
// The kit deploys on two chains, so one row per message type binds Sepolia's chain id: a domain
// separator with a hard-coded chain id passes every mainnet row and fails this one.
const sepoliaDomain = { ...domain, chainId: 11155111 }
const widthMaxima = { account: onesAddress, action: onesAddress, attemptId: maxUint64, setupNonce: maxUint64, validUntil: maxUint48, place: maxUint256 }
file('approval-digest.json', 'approval-digest-v1', 'EIP-712 Approval under PolicyManager domain version 1', [
  { id: 'normal', input: { domain, message: { ...approvalMessage, attemptId: '9', setupNonce: '7', order: { ...order, amount: order.amount.toString() }, validUntil: '1800000000', place: '0' } }, expected: { digest: hashTypedData({ domain, types: approvalTypes, primaryType: 'Approval', message: approvalMessage }) } },
  approvalRow('place-two', { place: 2n }),
  approvalRow('place-max', { place: maxUint256 }),
  approvalRow('empty-payload-and-body', { setupBodyHash: keccak256('0x'), payload: '0x' }),
  approvalRow('width-maxima', { ...widthMaxima, order: { token: onesAddress, amount: maxUint256, payee: onesAddress } }),
  approvalRow('zero-order-open', { order: { token: zeroAddress, amount: 0n, payee: zeroAddress } }),
  approvalRow('sepolia-chain', {}, sepoliaDomain),
])
file('cancellation-digest.json', 'cancellation-digest-v1', 'EIP-712 Cancellation under PolicyManager domain version 1', [
  { id: 'normal', input: { domain, message: { ...cancellationMessage, attemptId: '9', setupNonce: '7', validUntil: '1800000000', place: '0' } }, expected: { digest: hashTypedData({ domain, types: cancellationTypes, primaryType: 'Cancellation', message: cancellationMessage }) } },
  cancellationRow('place-two', { place: 2n }),
  cancellationRow('place-max', { place: maxUint256 }),
  cancellationRow('empty-body', { setupBodyHash: keccak256('0x') }),
  cancellationRow('width-maxima', widthMaxima),
  cancellationRow('sepolia-chain', {}, sepoliaDomain),
])

const kitSlotHash = keccak256(abi([{ type: 'string' }, { type: 'address' }], ['kit', address.action]))
const kitSlot = `0x${kitSlotHash.slice(-40)}`
const binding = keccak256(abi([{ type: 'address' }, { type: 'bytes' }], [address.action, '0x']))
file('ambire-kit-slot.json', 'ambire-kit-slot-v1', 'slot = low20(keccak256(abi.encode("kit", action))); binding = keccak256(abi.encode(action, bytes("")))', [
  { id: 'normal', input: { action: address.action }, expected: { slotPreimage: abi([{ type: 'string' }, { type: 'address' }], ['kit', address.action]), slotHash: kitSlotHash, slot: kitSlot, bindingPreimage: abi([{ type: 'address' }, { type: 'bytes' }], [address.action, '0x']), binding } },
])
const handover = abi([{ type: 'address' }, { type: 'address' }], [address.newAuthority, address.removedAuthority])
file('ambire-handover.json', 'ambire-handover-v1', 'abi.encode(address newAuthority, address removedAuthority)', [
  { id: 'normal', input: { newAuthority: address.newAuthority, removedAuthority: address.removedAuthority }, expected: { encoded: handover, payloadHash: keccak256(handover), managerAcceptance: 'opaque', actionAcceptance: true } },
  { id: 'trailing-byte', input: { encoded: `${handover}00` }, expected: { actionAcceptance: false, reason: 'canonical re-encoding hashes differently from the supplied payload' } },
])

const events = parseAbi([
  'event SetupCommitted(address indexed account,address indexed action,uint64 nonce,bytes32 setupCommitment,bytes publicMetadata,bytes privateMetadata)',
  'event SetupCleared(address indexed account,address indexed action,uint64 nonce)',
  'event AttemptStarted(address indexed account,address indexed action,uint64 attemptId,uint64 setupNonce,bytes setupBody,uint256[] usedPlaces,address[] usedMethods,bytes payload,(address token,uint256 amount,address payee) order,uint48 consumableAfter)',
  'event AttemptCancelled(address indexed account,address indexed action,uint64 attemptId,address canceller,address stoppedMethod,uint64 setupNonce,uint256[] usedPlaces)',
  'event AttemptConsumed(address indexed account,address indexed action,uint64 attemptId)',
])
const eventRows = [
  ['SetupCommitted', { account: address.account, action: address.action, nonce: 7n, setupCommitment: keccak256(setupPreimage), publicMetadata: '0x', privateMetadata: '0x1234' }, [{ type: 'uint64' }, { type: 'bytes32' }, { type: 'bytes' }, { type: 'bytes' }], [7n, keccak256(setupPreimage), '0x', '0x1234']],
  ['SetupCleared', { account: address.account, action: address.action, nonce: 8n }, [{ type: 'uint64' }], [8n]],
  ['AttemptStarted', { account: address.account, action: address.action, attemptId: 9n, setupNonce: 7n, setupBody: body, usedPlaces: [0n, 1n, 3n], usedMethods: [address.method], payload: '0xabcdef', order, consumableAfter: 1800172800 }, [{ type: 'uint64' }, { type: 'uint64' }, { type: 'bytes' }, { type: 'uint256[]' }, { type: 'address[]' }, { type: 'bytes' }, { type: 'tuple', components: paymentParams }, { type: 'uint48' }], [9n, 7n, body, [0n, 1n, 3n], [address.method], '0xabcdef', order, 1800172800]],
  ['AttemptCancelled', { account: address.account, action: address.action, attemptId: 9n, canceller: address.payee, stoppedMethod: address.method, setupNonce: 7n, usedPlaces: [] }, [{ type: 'uint64' }, { type: 'address' }, { type: 'address' }, { type: 'uint64' }, { type: 'uint256[]' }], [9n, address.payee, address.method, 7n, []]],
  ['AttemptConsumed', { account: address.account, action: address.action, attemptId: 9n }, [{ type: 'uint64' }], [9n]],
]
file('manager-events.json', 'manager-events-v1', 'keccak256(event signature) in topic0; indexed account and action in topics; remaining fields ABI encoded in data', eventRows.map(([name, args, params, values]) => ({ id: name, input: Object.fromEntries(Object.entries(args).map(([k,v]) => [k, typeof v === 'bigint' ? v.toString() : v])), expected: { topics: encodeEventTopics({ abi: events, eventName: name, args: { account: args.account, action: args.action } }), data: abi(params, values) } })))

const methodEvents = parseAbi([
  'event Paused(address account)',
  'event Unpaused(address account)',
  'event TrustedKeysUpdated(bytes32[] previous,bytes32[] current)',
  'event AdminTransferOffered(address indexed current,address indexed pending)',
  'event AdminTransferred(address indexed previous,address indexed current)',
  'event AdminRenounced(address indexed previous)',
])
const methodEventRows = [
  ['Paused', { account: address.payee }, [{ type: 'address' }], [address.payee], {}],
  ['Unpaused', { account: address.payee }, [{ type: 'address' }], [address.payee], {}],
  ['TrustedKeysUpdated', { previous: [b32(1)], current: [b32(2), b32(3)] }, [{ type: 'bytes32[]' }, { type: 'bytes32[]' }], [[b32(1)], [b32(2), b32(3)]], {}],
  ['AdminTransferOffered', { current: address.account, pending: address.payee }, [], [], { current: address.account, pending: address.payee }],
  ['AdminTransferred', { previous: address.account, current: address.payee }, [], [], { previous: address.account, current: address.payee }],
  ['AdminRenounced', { previous: address.account }, [], [], { previous: address.account }],
]
file('method-events.json', 'method-events-v1', 'keccak256(event signature) in topic0; indexed role addresses in topics; remaining fields ABI encoded in data', methodEventRows.map(([name, args, params, values, indexed]) => ({ id: name, input: args, expected: { topics: encodeEventTopics({ abi: methodEvents, eventName: name, args: indexed }), data: abi(params, values) } })))

const selector = keccak256(stringToHex('verify(bytes,bytes32,bytes)')).slice(0, 10)
file('method-verdict.json', 'method-verdict-v1', 'bytes4(keccak256("verify(bytes,bytes32,bytes)"))', [
  { id: 'magic', input: { signature: 'verify(bytes,bytes32,bytes)' }, expected: { selector, abiWord: `${selector}${'00'.repeat(28)}`, managerAcceptance: 'exactly 32 returned bytes with this word' } },
])

const testKey = `0x${'01'.padStart(64, '0')}`
const signerAddress = Address.fromPublicKey(Secp256k1.getPublicKey({ privateKey: testKey }), { checksum: true })
const ecdsaDigest = hashTypedData({ domain, types: cancellationTypes, primaryType: 'Cancellation', message: cancellationMessage })
const ecdsaSig = Signature.toHex(Secp256k1.sign({ payload: ecdsaDigest, privateKey: testKey }))
file('method-ecdsa-config.json', 'method-ecdsa-config-v1', 'abi.encode(address signer)', [
  { id: 'test-signer', input: { signer: signerAddress }, expected: { encoded: abi([{ type: 'address' }], [signerAddress]) } },
  { id: 'zero-address', input: { signer: `0x${'00'.repeat(20)}` }, expected: { encoded: abi([{ type: 'address' }], [`0x${'00'.repeat(20)}`]), verification: 'cannot recover zero signer' } },
])
file('method-ecdsa-proof.json', 'method-ecdsa-proof-v1', 'raw signature bytes over the place digest; not abi.encode(bytes)', [
  { id: 'deterministic-test-key', input: { privateKeyNotice: 'public test fixture key 0x01', signer: signerAddress, digest: ecdsaDigest }, expected: { proof: ecdsaSig, eoaVerification: true } },
  { id: 'empty', input: { signer: signerAddress, digest: ecdsaDigest }, expected: { proof: '0x', eoaVerification: false } },
])

const passPrivate = `0x${'02'.padStart(64, '0')}`
const passPublic = P256.getPublicKey({ privateKey: passPrivate })
const challenge = hashTypedData({ domain, types: approvalTypes, primaryType: 'Approval', message: approvalMessage })
const challengeB64 = Buffer.from(challenge.slice(2), 'hex').toString('base64url')
const rpId = 'recover.example'
const rpIdHash = sha256(stringToHex(rpId))
const authenticatorData = concatHex([rpIdHash, '0x05', '0x00000000'])
const clientDataJSON = JSON.stringify({ type: 'webauthn.get', challenge: challengeB64, origin: 'https://recover.example', crossOrigin: false, extra: 'kept' })
const signedHash = sha256(concatHex([authenticatorData, sha256(stringToHex(clientDataJSON))]))
const passSig = P256.sign({ payload: signedHash, privateKey: passPrivate })
if (!P256.verify({ payload: signedHash, publicKey: passPublic, signature: passSig })) throw new Error('invalid P-256 reference signature')
const passAssertion = (id, authenticatorData, clientDataJSON, reason) => {
  const signedHash = sha256(concatHex([authenticatorData, sha256(stringToHex(clientDataJSON))]))
  const signature = P256.sign({ payload: signedHash, privateKey: passPrivate })
  if (!P256.verify({ payload: signedHash, publicKey: passPublic, signature })) throw new Error(`invalid P-256 reference signature for ${id}`)
  return {
    id,
    input: { digest: challenge, authenticatorData, clientDataJSON, r: signature.r.toString(), s: signature.s.toString() },
    expected: {
      encoded: abi([{ type: 'bytes' }, { type: 'bytes' }, { type: 'uint256' }, { type: 'uint256' }], [authenticatorData, stringToHex(clientDataJSON), signature.r, signature.s]),
      signedHash,
      signatureVerification: true,
      verification: false,
      reason,
    },
  }
}
// The client data below is written by hand on purpose: JSON.stringify would always close the
// challenge's quote, and this row checks that the method refuses client data that does not.
const unquotedChallengeClientData = `{"type":"webauthn.get","challenge":"${challengeB64},"origin":"https://recover.example","crossOrigin":false}`
// A signature over another hash, presented with the valid assertion: the precompile rejects it.
const wrongSig = P256.sign({ payload: sha256(stringToHex('not the signed hash')), privateKey: passPrivate })
if (P256.verify({ payload: signedHash, publicKey: passPublic, signature: wrongSig })) throw new Error('the invalid-signature row verifies')
const passConfig = abi([{ type: 'uint256' }, { type: 'uint256' }, { type: 'bytes32' }], [passPublic.x, passPublic.y, rpIdHash])
const passProof = abi([{ type: 'bytes' }, { type: 'bytes' }, { type: 'uint256' }, { type: 'uint256' }], [authenticatorData, stringToHex(clientDataJSON), passSig.r, passSig.s])
file('method-passkey-config.json', 'method-passkey-config-v1', 'abi.encode(uint256 x, uint256 y, bytes32 rpIdHash)', [
  { id: 'recover-example', input: { x: BigInt(passPublic.x).toString(), y: BigInt(passPublic.y).toString(), rpId, rpIdHash }, expected: { encoded: passConfig } },
])
file('method-passkey-proof.json', 'method-passkey-proof-v1', 'abi.encode(bytes authenticatorData, bytes clientDataJSON, uint256 r, uint256 s)', [
  { id: 'valid-extra-client-field', input: { digest: challenge, authenticatorData, clientDataJSON, r: passSig.r.toString(), s: passSig.s.toString() }, expected: { encoded: passProof, challengeBase64url: challengeB64, signedHash, verification: true, requiredFlags: { userPresent: true, userVerified: true } } },
  passAssertion('missing-user-verification', concatHex([rpIdHash, '0x01', '0x00000000']), clientDataJSON, 'UV flag absent'),
  passAssertion('missing-user-presence', concatHex([rpIdHash, '0x04', '0x00000000']), clientDataJSON, 'UP flag absent'),
  passAssertion('wrong-challenge', authenticatorData, JSON.stringify({ type: 'webauthn.get', challenge: Buffer.from(b32(1).slice(2), 'hex').toString('base64url'), origin: 'https://recover.example', crossOrigin: false }), 'challenge differs from the place digest'),
  passAssertion('wrong-client-data-type', authenticatorData, JSON.stringify({ type: 'webauthn.create', challenge: challengeB64, origin: 'https://recover.example', crossOrigin: false }), 'client data type is not webauthn.get'),
  passAssertion('wrong-relying-party-hash', concatHex([sha256(stringToHex('other.example')), '0x05', '0x00000000']), clientDataJSON, 'relying-party hash differs from config'),
  passAssertion('missing-challenge-closing-quote', authenticatorData, unquotedChallengeClientData, 'the challenge is not followed by its closing quote'),
  { id: 'invalid-signature', input: { digest: challenge, authenticatorData, clientDataJSON, r: wrongSig.r.toString(), s: wrongSig.s.toString() }, expected: { encoded: abi([{ type: 'bytes' }, { type: 'bytes' }, { type: 'uint256' }, { type: 'uint256' }], [authenticatorData, stringToHex(clientDataJSON), wrongSig.r, wrongSig.s]), signedHash, signatureVerification: false, verification: false, reason: 'the signature does not verify under the committed key' } },
])

const zkConfigValues = [b32(123), 'recover.example', 'social-recovery', 86400n]
file('method-zkpassport-config.json', 'method-zkpassport-config-v2', 'abi.encode(bytes32 uniqueIdentifier, string domain, string scope, uint256 validityPeriodInSeconds)', [
  { id: 'normal', input: { uniqueIdentifier: b32(123), domain: 'recover.example', scope: 'social-recovery', validityPeriodInSeconds: '86400' }, expected: { encoded: abi([{type:'bytes32'},{type:'string'},{type:'string'},{type:'uint256'}], zkConfigValues) } },
])
const customData = challenge.toLowerCase()
const committedInputs = '0x1234'
const publicInputs = [b32(10), b32(11), b32(12), b32(13), b32(14), b32(0), b32(123), b32(0)]
const zkProofData = { vkeyHash: b32(99), proof: '0x123456', publicInputs }
const zkEncoded = abi([{ type:'tuple', components:[{name:'vkeyHash',type:'bytes32'},{name:'proof',type:'bytes'},{name:'publicInputs',type:'bytes32[]'}]},{type:'bytes'}],[zkProofData, committedInputs])
file('method-zkpassport-proof.json', 'method-zkpassport-proof-v1', 'abi.encode(ProofVerificationData(bytes32 vkeyHash,bytes proof,bytes32[] publicInputs), bytes committedInputs)', [
  { id: 'outer-encoding-and-required-binding', input: { proofVerificationData: zkProofData, committedInputs, digest: challenge }, expected: { encoded: zkEncoded, requiredCustomData: customData, nullifierTypeIndexFromEnd: 3, nullifierType: '0 NON_SALTED_NULLIFIER', upstreamFixtureValidity: false, productionValidityClaim: false } },
])

const aadhaarConfig = { nullifier: 22n, nullifierSeed: 77n, freshnessWindow: 4500n }
file('method-aadhaar-config.json', 'method-aadhaar-config-v2', 'abi.encode(uint256 nullifier, uint256 nullifierSeed, uint256 freshnessWindow)', [
  { id: 'normal', input: { nullifier: '22', nullifierSeed: '77', freshnessWindow: '4500' }, expected: { encoded: abi([{type:'uint256'},{type:'uint256'},{type:'uint256'}],[aadhaarConfig.nullifier,aadhaarConfig.nullifierSeed,aadhaarConfig.freshnessWindow]) } },
])
const signalHash = BigInt(keccak256(abi([{type:'uint256'}],[BigInt(challenge)]))) >> 3n
const aadhaarA = [1n,2n]
const packedBWords = [4n,3n,6n,5n]
const aadhaarB = [[packedBWords[0],packedBWords[1]],[packedBWords[2],packedBWords[3]]]
const aadhaarC = [7n,8n]
const aadhaarInputs = [99n,aadhaarConfig.nullifier,1700000000n,18n,1n,110001n,7n,aadhaarConfig.nullifierSeed,signalHash]
const aadhaarEncoded = abi([{type:'uint256[2]'},{type:'uint256[2][2]'},{type:'uint256[2]'},{type:'uint256[9]'}],[aadhaarA,aadhaarB,aadhaarC,aadhaarInputs])
if ((aadhaarEncoded.length - 2) / 2 !== 544) throw new Error('unexpected Aadhaar proof length')
file('method-aadhaar-proof.json', 'method-aadhaar-proof-v1', 'abi.encode(uint256[2] a, uint256[2][2] b, uint256[2] c, uint256[9] inputs)', [
  { id: 'pack-groth16-order-and-signal', input: { upstreamProof: { pi_a:['1','2'], pi_b:[['3','4'],['5','6']], pi_c:['7','8'] }, digest: challenge, inputs: aadhaarInputs.map(String) }, expected: { a: aadhaarA.map(String), b: aadhaarB.map((x)=>x.map(String)), c: aadhaarC.map(String), signalHash: signalHash.toString(), encoded: aadhaarEncoded, byteLength: 544, upstreamFixtureValidity: false, productionValidityClaim: false } },
])

if (process.argv.includes('--check')) {
  const expectedNames = [...out.keys()].sort()
  const committedNames = readdirSync(new URL('.', import.meta.url)).filter((name) => name.endsWith('.json')).sort()
  if (JSON.stringify(committedNames) !== JSON.stringify(expectedNames)) {
    throw new Error(`contract KAT file set differs: expected ${expectedNames.join(', ')}, found ${committedNames.join(', ')}`)
  }
}

for (const [name, value] of out) {
  const selected = process.argv.find((argument) => argument.startsWith('--file='))?.slice('--file='.length)
  if (selected && selected !== name) continue
  const body = JSON.stringify(value, (_, v) => typeof v === 'bigint' ? v.toString() : v, 2) + '\n'
  if (process.argv.includes('--check')) {
    const committed = readFileSync(new URL(name, import.meta.url), 'utf8')
    if (committed !== body) throw new Error(`${name} differs from the reference output`)
  } else {
    process.stdout.write(`// FILE ${name}\n${body}`)
  }
}

if (process.argv.includes('--check')) process.stdout.write(`checked ${out.size} contract KAT files\n`)
