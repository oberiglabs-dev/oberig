'use strict';
// keccak256 and secp256k1 recovery, against public vectors and node:crypto.

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const E = require('../src/ecdsa.js');

test('keccak256 known vectors', () => {
  assert.equal(E.keccak256('').toString('hex'), 'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470');
  assert.equal(E.keccak256('abc').toString('hex'), '4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45');
});

test('the same sponge with SHA3 padding equals node sha3-256 at block edges', () => {
  for (const n of [0, 1, 55, 135, 136, 137, 271, 272, 273, 1000]) {
    const m = crypto.randomBytes(n);
    assert.deepEqual(E.sponge256(m, 0x06), crypto.createHash('sha3-256').update(m).digest(), `length ${n}`);
  }
});

test('secp256k1 recovery finds the key node:crypto signed with', () => {
  const ecdh = crypto.createECDH('secp256k1');
  ecdh.generateKeys();
  const pub = ecdh.getPublicKey().subarray(1);
  const jwk = { kty: 'EC', crv: 'secp256k1', d: ecdh.getPrivateKey().toString('base64url'), x: pub.subarray(0, 32).toString('base64url'), y: pub.subarray(32).toString('base64url') };
  const key = crypto.createPrivateKey({ key: jwk, format: 'jwk' });
  for (let i = 0; i < 3; i++) {
    const msg = crypto.randomBytes(40);
    const sig = crypto.sign('sha256', msg, { key, dsaEncoding: 'ieee-p1363' });
    const h = crypto.createHash('sha256').update(msg).digest();
    const found = [0, 1].some((id) => { try { return E.recoverPublicKey(h, sig.subarray(0, 32), sig.subarray(32), id).equals(pub); } catch { return false; } });
    assert.ok(found);
  }
});

test('address derivation matches a public vector', () => {
  const ecdh = crypto.createECDH('secp256k1');
  ecdh.setPrivateKey(Buffer.from(['4c0883a69102937d6231471b5dbb6204', 'fe5129617082792ae468d01a3f362318'].join(''), 'hex'));
  assert.equal(E.addressOf(ecdh.getPublicKey().subarray(1)), '0x2c7536e3605d9c16a7a3d7b1898e529396a65c23');
  assert.equal(E.eip191Hash('Some data').toString('hex'), '1da44b586eb0729ff70a73c326926f6ed5a25f5b056e7f47fbc6e58d86871655');
});

test('malformed signatures are rejected', () => {
  assert.throws(() => E.recoverEip191('x', '00'));
  assert.throws(() => E.recoverPublicKey(Buffer.alloc(32), 0n, 1n, 0));
});
