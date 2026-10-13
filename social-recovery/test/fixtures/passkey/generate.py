#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Render the real passkey assertions in fixture.json as Solidity constants.

Reads fixture.json from this directory and writes PasskeyRealAssertionFixture.sol next to it. Tests may
read files only under test/fixtures/kats and out, so they take the assertions from the generated contract
instead of reading the file. Run it from anywhere:

    python3 test/fixtures/passkey/generate.py

fixture.json keeps every value in the encoding its source published: the public key as a COSE key or
as two decimal coordinates, the signature as DER or as two decimal scalars, and the authenticator data
and client data as unpadded base64url. This script derives the method's inputs from them:

- x and y from the COSE key's -2 and -3 members, after checking it is an EC2 key (kty 2) on P-256
  (crv 1) for ES256 (alg -7);
- r and s from the DER SEQUENCE of two INTEGERs;
- the digest, which is the challenge member of the client data decoded from base64url, and must be
  exactly 32 bytes;
- the relying-party hash, which is the first 32 bytes of the authenticator data, and must equal
  sha256 of the relying-party id the source names.

It refuses a fixture whose signature does not verify under its key over
sha256(authenticatorData || sha256(clientDataJSON)), so every assertion in the output is one its
authenticator really signed. It does not decide whether the passkey method accepts an assertion: that
is what the tests check. The output is deterministic, so running it again on an unchanged fixture.json
leaves the .sol file unchanged, which `git diff --exit-code` confirms. Only the Python 3 standard
library is needed.
"""

import base64
import hashlib
import json
import pathlib
import textwrap

HERE = pathlib.Path(__file__).resolve().parent

# The P-256 curve: field prime, coefficients, generator and group order.
P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
A = P - 3
B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
G = (
  0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
  0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
)
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

PREFIX = b'{"type":"webauthn.get","challenge":"'


def b64url(text):
  """Decode unpadded base64url."""
  return base64.urlsafe_b64decode(text + '=' * (-len(text) % 4))


def point_add(p1, p2):
  """Add two affine points, None being the point at infinity."""
  if p1 is None:
    return p2
  if p2 is None:
    return p1
  if p1[0] == p2[0] and (p1[1] + p2[1]) % P == 0:
    return None
  if p1 == p2:
    slope = (3 * p1[0] * p1[0] + A) * pow(2 * p1[1], -1, P) % P
  else:
    slope = (p2[1] - p1[1]) * pow(p2[0] - p1[0], -1, P) % P
  x = (slope * slope - p1[0] - p2[0]) % P
  return (x, (slope * (p1[0] - x) - p1[1]) % P)


def point_mul(k, point):
  """Multiply an affine point by a scalar, double and add."""
  result = None
  while k:
    if k & 1:
      result = point_add(result, point)
    point = point_add(point, point)
    k >>= 1
  return result


def ecdsa_verify(message_hash, r, s, x, y):
  """ECDSA over P-256 for a 32-byte hash, as FIPS 186-4 defines it. Accepts both halves of s."""
  assert (y * y - x * x * x - A * x - B) % P == 0, 'the public key is not on P-256'
  if not (0 < r < N and 0 < s < N):
    return False
  w = pow(s, -1, N)
  e = int.from_bytes(message_hash, 'big')
  point = point_add(point_mul(e * w % N, G), point_mul(r * w % N, (x, y)))
  return point is not None and point[0] % N == r


def cbor_item(data, i):
  """Decode one CBOR item of the kinds a COSE key holds: integers, byte and text strings, maps."""
  major, info = data[i] >> 5, data[i] & 31
  i += 1
  if info < 24:
    value = info
  else:
    size = {24: 1, 25: 2, 26: 4, 27: 8}[info]
    value = int.from_bytes(data[i:i + size], 'big')
    i += size
  if major == 0:
    return value, i
  if major == 1:
    return -1 - value, i
  if major in (2, 3):
    return data[i:i + value], i + value
  if major == 5:
    items = {}
    for _ in range(value):
      key, i = cbor_item(data, i)
      items[key], i = cbor_item(data, i)
    return items, i
  raise ValueError(f'unexpected CBOR major type {major}')


def cose_p256(text):
  """The x and y coordinates of an ES256 COSE key."""
  key, end = cbor_item(b64url(text), 0)
  assert end == len(b64url(text)), 'trailing bytes after the COSE key'
  assert key[1] == 2 and key[3] == -7 and key[-1] == 1, 'not an ES256 P-256 COSE key'
  assert len(key[-2]) == 32 and len(key[-3]) == 32, 'a coordinate is not 32 bytes'
  return int.from_bytes(key[-2], 'big'), int.from_bytes(key[-3], 'big')


def der_signature(text):
  """The r and s scalars of a DER ECDSA signature."""
  data = b64url(text)
  assert data[0] == 0x30 and data[1] == len(data) - 2, 'not a DER SEQUENCE'
  scalars, i = [], 2
  for _ in range(2):
    assert data[i] == 0x02, 'not a DER INTEGER'
    length = data[i + 1]
    scalars.append(int.from_bytes(data[i + 2:i + 2 + length], 'big'))
    i += 2 + length
  assert i == len(data), 'trailing bytes after the DER signature'
  return scalars


def derive(entry):
  """The method's inputs for one fixture entry, after checking the entry is a genuine assertion."""
  key = entry['publicKey']
  x, y = cose_p256(key['value']) if key['format'] == 'cose' else map(int, key['value'])
  signature = entry['signature']
  r, s = der_signature(signature['value']) if signature['format'] == 'der' else map(int, signature['value'])
  authenticator_data = b64url(entry['authenticatorData'])
  client_data = b64url(entry['clientDataJSON'])
  assert len(authenticator_data) >= 37, entry['name']
  digest = b64url(json.loads(client_data)['challenge'])
  assert len(digest) == 32, f"{entry['name']}: the challenge is {len(digest)} bytes, not 32"
  rp_id_hash = authenticator_data[:32]
  assert rp_id_hash == hashlib.sha256(entry['rpId'].encode()).digest(), f"{entry['name']}: rpIdHash"
  signed = hashlib.sha256(authenticator_data + hashlib.sha256(client_data).digest()).digest()
  assert ecdsa_verify(signed, r, s, x, y), f"{entry['name']}: the signature does not verify"
  assert entry['expected'] in ('accepted', 'refused'), entry['name']
  return {
    'x': x,
    'y': y,
    'r': r,
    's': s,
    'digest': digest,
    'rpIdHash': rp_id_hash,
    'authenticatorData': authenticator_data,
    'clientDataJSON': client_data,
  }


def word(value):
  """A 32-byte word as a 0x literal."""
  return '0x' + (value.hex() if isinstance(value, bytes) else f'{value:064x}')


def chunks(text, size):
  """Split a string into pieces of at most `size` characters."""
  return [text[i:i + size] for i in range(0, len(text), size)] or ['']


def function_lines(entry, values):
  """One internal pure function returning the entry as a RealAssertion."""
  name = entry['name']
  getter = '_real' + name[0].upper() + name[1:]
  client_data = values['clientDataJSON'].decode()
  assert "'" not in client_data and '\\' not in client_data, f'{name}: client data needs escaping'
  repository = entry['source']['repository'].removeprefix('https://github.com/')
  note = entry['note'][0].upper() + entry['note'][1:]
  doc = (
    f"{entry['authenticator']}. Source: {repository}, {entry['source']['entry']}. "
    f"Expected verdict: {entry['expected']}. {note}."
  )
  wrapped = textwrap.wrap(doc, 120 - len('  ///         '))
  lines = [f'  /// @notice {wrapped[0]}'] + [f'  ///         {line}' for line in wrapped[1:]]
  lines += [
    f'  function {getter}() internal pure returns (RealAssertion memory _assertion) {{',
    '    _assertion = RealAssertion({',
    f"      name: '{name}',",
    f'      x: {word(values["x"])},',
    f'      y: {word(values["y"])},',
    f'      rpIdHash: {word(values["rpIdHash"])},',
    f'      digest: {word(values["digest"])},',
  ]
  hex_pieces = chunks(values['authenticatorData'].hex(), 96)
  lines.append('      authenticatorData: ' + (f"hex'{hex_pieces[0]}'," if len(hex_pieces) == 1 else 'bytes('))
  if len(hex_pieces) > 1:
    for piece in hex_pieces:
      lines.append(f"        hex'{piece}'")
    lines.append('      ),')
  text_pieces = chunks(client_data, 90)
  lines.append('      clientDataJSON: ' + (f"bytes('{text_pieces[0]}')," if len(text_pieces) == 1 else 'bytes('))
  if len(text_pieces) > 1:
    for piece in text_pieces:
      lines.append(f"        '{piece}'")
    lines.append('      ),')
  lines += [
    f'      r: {word(values["r"])},',
    f'      s: {word(values["s"])}',
    '    });',
    '  }',
    '',
  ]
  return getter, lines


def main():
  data = json.loads((HERE / 'fixture.json').read_text())
  lines = [
    '// SPDX-License-Identifier: GPL-3.0-or-later',
    'pragma solidity 0.8.30;',
    '',
    '// Generated by test/fixtures/passkey/generate.py from fixture.json. Do not edit by hand.',
    '//',
    '// Real WebAuthn ES256 assertions published as test data by base-org/webauthn-sol (MIT),',
    '// Yubico/java-webauthn-server (BSD-2-Clause) and go-webauthn/webauthn (BSD-3-Clause). See README.md',
    '// and NOTICE in this directory for the commits, the authenticators and the licences.',
    '',
    '/// @notice Real passkey assertions, each signed by its authenticator over the challenge its client',
    '///         data carries. The generator checked every signature before writing this file.',
    'abstract contract PasskeyRealAssertionFixture {',
    '  /// @notice One assertion in the passkey method\'s terms: the config fields, the digest the',
    '  ///         challenge decodes to, and the proof fields.',
    '  /// @param name The fixture entry\'s name in fixture.json.',
    '  /// @param x The public key\'s x coordinate.',
    '  /// @param y The public key\'s y coordinate.',
    '  /// @param rpIdHash sha256 of the relying-party id, the first 32 bytes of the authenticator data.',
    '  /// @param digest The 32 bytes the client data\'s challenge decodes to.',
    '  /// @param authenticatorData The authenticator data exactly as the authenticator returned it.',
    '  /// @param clientDataJSON The client data exactly as the browser serialized it.',
    '  /// @param r The signature\'s r scalar.',
    '  /// @param s The signature\'s s scalar, in the half the authenticator produced.',
    '  struct RealAssertion {',
    '    string name;',
    '    uint256 x;',
    '    uint256 y;',
    '    bytes32 rpIdHash;',
    '    bytes32 digest;',
    '    bytes authenticatorData;',
    '    bytes clientDataJSON;',
    '    uint256 r;',
    '    uint256 s;',
    '  }',
    '',
  ]
  accepted = []
  for entry in data['assertions']:
    getter, function = function_lines(entry, derive(entry))
    lines += function
    if entry['expected'] == 'accepted':
      accepted.append(getter)
  lines += [
    '  /// @notice Every assertion whose client data is in the order the standard fixes and whose flags',
    '  ///         carry user present and user verified, which the passkey method must accept.',
    '  function _acceptedRealAssertions() internal pure returns (RealAssertion[] memory _assertions) {',
    f'    _assertions = new RealAssertion[]({len(accepted)});',
  ]
  for index, getter in enumerate(accepted):
    lines.append(f'    _assertions[{index}] = {getter}();')
  lines += ['  }', '}', '']
  (HERE / 'PasskeyRealAssertionFixture.sol').write_text('\n'.join(lines))


if __name__ == '__main__':
  main()
