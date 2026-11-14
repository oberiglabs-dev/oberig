'use strict';
// NEAR encoding: base58, borsh, transaction hashing and Ed25519 signing.
// The borsh code is checked against real mainnet transactions: re-serialized,
// their SHA-256 must equal the on-chain transaction hash, and their signatures must verify.

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const util = require('node:util');
const path = require('node:path');
const bs58 = require('../src/near/base58.js');
const B = require('../src/near/borsh.js');
const T = require('../src/near/tx.js');

const fixtures = require(path.join(__dirname, 'fixtures', 'near-mainnet-txs.json'));

/** A throwaway NEAR key, made at runtime: "ed25519:" + base58(seed + public key). */
function testKey() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
  const seed = Buffer.from(privateKey.export({ format: 'jwk' }).d, 'base64url');
  const pub = Buffer.from(publicKey.export({ format: 'jwk' }).x, 'base64url');
  return { seed, pub, text: ['ed25519', bs58.encode(Buffer.concat([seed, pub]))].join(':') };
}

test('base58 matches known vectors and round-trips', () => {
  const cases = [
    ['', ''],
    ['00', '1'],
    ['000001', '112'],
    [Buffer.from('Hello World!').toString('hex'), '2NEpo7TZRRrLZSi2U'],
    ['00'.repeat(32), '1'.repeat(32)],
    ['ff', '5Q'],
  ];
  for (const [hex, text] of cases) {
    assert.equal(bs58.encode(Buffer.from(hex, 'hex')), text, hex);
    assert.equal(bs58.decode(text).toString('hex'), hex, text);
  }
  const key = 'GP3ong2t4rAipUrRoe4XLwSzFRbpaFro3DBsDbnorkBG';
  assert.equal(bs58.decode(key).length, 32);
  assert.equal(bs58.encode(bs58.decode(key)), key);
  for (let i = 0; i < 50; i++) {
    const b = crypto.randomBytes(i % 3 === 0 ? 64 : 32);
    if (i % 5 === 0) b[0] = 0;
    assert.ok(bs58.decode(bs58.encode(b)).equals(b));
  }
});

test('base58 refuses characters outside the alphabet without echoing the input', () => {
  for (const bad of ['0abc', 'Oabc', 'Iabc', 'labc', 'ab c']) {
    assert.throws(() => bs58.decode(bad), (err) => { assert.ok(!err.message.includes(bad)); return true; });
  }
});

test('borsh primitives are little-endian with u32 length prefixes', () => {
  const w = new B.Writer();
  w.u8(7).u32(0x01020304).u64(1n).u128((1n << 64n) + 2n).string('ok').option(null, () => {}).option(5n, (x, v) => x.u64(v));
  assert.equal(w.toBuffer().toString('hex'),
    '07' + '04030201' + '0100000000000000' + '0200000000000000' + '0100000000000000' + '020000006f6b' + '00' + '01' + '0500000000000000');
  const r = new B.Reader(w.toBuffer());
  assert.equal(r.u8(), 7);
  assert.equal(r.u32(), 0x01020304);
  assert.equal(r.u64(), 1n);
  assert.equal(r.u128(), (1n << 64n) + 2n);
  assert.equal(r.string(), 'ok');
  assert.equal(r.option((x) => x.u64()), null);
  assert.equal(r.option((x) => x.u64()), 5n);
  r.end();
  assert.throws(() => new B.Writer().u64(-1n), RangeError);
  assert.throws(() => new B.Writer().u64(1n << 64n), RangeError);
  assert.throws(() => new B.Writer().u128(1n << 128n), RangeError);
  assert.throws(() => new B.Writer().u8(256), RangeError);
  assert.throws(() => new B.Reader(Buffer.from([1, 0])).u32(), RangeError);
});

for (const fx of fixtures.txs) {
  test(`real mainnet transaction re-serializes to its on-chain hash: ${fx.label}`, () => {
    const view = fx.transaction;
    const tx = T.transactionFromView(view, fx.signed_block_hash);
    const h = T.hashTransaction(tx);
    assert.equal(h.id, view.hash);
    assert.ok(T.verifySignature(tx.publicKey, h.hash, T.parseSignature(view.signature)), 'signature over the transaction hash');

    const signed = B.serializeSignedTransaction({ transaction: tx, signature: T.parseSignature(view.signature) });
    const back = B.deserializeSignedTransaction(signed);
    assert.ok(B.serializeSignedTransaction(back).equals(signed), 'decode then encode gives the same bytes');
    assert.equal(back.transaction.signerId, view.signer_id);
    assert.equal(back.transaction.receiverId, view.receiver_id);
    assert.equal(back.transaction.nonce, BigInt(view.nonce));
    assert.equal(T.signatureToString(back.signature), view.signature);
    assert.equal(T.publicKeyToString(back.transaction.publicKey), view.public_key);

    const changed = { ...tx, nonce: tx.nonce + 1n };
    const h2 = T.hashTransaction(changed);
    assert.notEqual(h2.id, view.hash);
    assert.equal(T.verifySignature(tx.publicKey, h2.hash, T.parseSignature(view.signature)), false);
  });
}

test('the real SocialDB write is a set call with the expected arguments', () => {
  const fx = fixtures.txs[0];
  const tx = T.transactionFromView(fx.transaction, fx.signed_block_hash);
  assert.equal(tx.receiverId, 'social.near');
  const fc = tx.actions[0];
  assert.equal(fc.type, 'FunctionCall');
  assert.equal(fc.methodName, 'set');
  assert.equal(fc.gas, 30000000000000n);
  const args = JSON.parse(fc.args.toString('utf8'));
  assert.ok(args.data[fx.transaction.signer_id]);
  // SocialDB 0.12 returns the block height of the write as a decimal string.
  const ret = JSON.parse(Buffer.from(fx.status.SuccessValue, 'base64').toString('utf8'));
  assert.match(ret.block_height, /^\d+$/);
  assert.ok(Number(ret.block_height) > fx.signed_block_height);
});

test('the inner signature of a real meta transaction (NEP-366) verifies', () => {
  const fx = fixtures.txs.find((t) => t.transaction.actions[0].Delegate);
  const tx = T.transactionFromView(fx.transaction, fx.signed_block_hash);
  const d = tx.actions[0];
  const w = new B.Writer();
  w.u32((1 << 30) + 366); // NEP-461 on-chain message prefix for delegate actions
  const full = new B.Writer();
  B.writeAction(full, d);
  const bytes = full.toBuffer();
  const delegate = bytes.subarray(1, bytes.length - 65); // drop the action tag and the signature
  const hash = T.sha256(Buffer.concat([w.toBuffer(), delegate]));
  assert.ok(T.verifySignature(d.delegateAction.publicKey, hash, d.signature));
});

test('keys: "ed25519:" secret keys load, sign and never show the secret', () => {
  const k = testKey();
  const signer = T.keyPairFromSecret(k.text);
  assert.equal(signer.publicKeyText, `ed25519:${bs58.encode(k.pub)}`);
  const msg = crypto.randomBytes(32);
  const sig = signer.sign(msg);
  assert.equal(sig.length, 64);
  assert.ok(T.verifySignature(signer.publicKey, msg, { keyType: 0, data: sig }));
  assert.equal(T.verifySignature(signer.publicKey, crypto.randomBytes(32), { keyType: 0, data: sig }), false);
  const secretPart = k.text.split(':')[1];
  for (const shown of [JSON.stringify(signer), util.inspect(signer), String(signer), Object.keys(signer).join(',')]) {
    assert.ok(!shown.includes(secretPart), 'secret must not be visible');
  }
  // A bare 32-byte seed gives the same key.
  assert.equal(T.keyPairFromSecret(`ed25519:${bs58.encode(k.seed)}`).publicKeyText, signer.publicKeyText);
});

test('keys: malformed or damaged secret keys are refused without echoing them', () => {
  const k = testKey();
  const other = testKey();
  const damaged = `ed25519:${bs58.encode(Buffer.concat([k.seed, other.pub]))}`;
  for (const bad of [damaged, k.text.replace('ed25519:', 'secp256k1:'), 'ed25519:' + bs58.encode(crypto.randomBytes(40)), k.text + '0', 'not a key']) {
    assert.throws(() => T.keyPairFromSecret(bad), (err) => {
      assert.ok(!err.message.includes(bad.split(':').pop()), err.message);
      assert.match(err.message, /NEAR_PRIVATE_KEY/);
      return true;
    });
  }
});

test('signTransaction signs the SHA-256 of the borsh bytes, and the result decodes and verifies', () => {
  const k = testKey();
  const signer = T.keyPairFromSecret(k.text);
  const blockHash = bs58.encode(crypto.randomBytes(32));
  const tx = T.createTransaction({
    signerId: 'anchor-test.near', publicKey: signer.publicKeyText, nonce: 224446692000001n, receiverId: 'social.near', blockHash,
    actions: [T.functionCall('set', { data: { 'anchor-test.near': { oberig: { anchors: { ['ab'.repeat(32)]: '{"v":1}' } } } } }, 30000000000000n, 10n ** 22n)],
  });
  const s = T.signTransaction(tx, signer);
  const back = B.deserializeSignedTransaction(Buffer.from(s.base64, 'base64'));
  assert.equal(back.transaction.version, 0);
  assert.equal(back.transaction.signerId, 'anchor-test.near');
  assert.equal(back.transaction.nonce, 224446692000001n);
  assert.equal(bs58.encode(back.transaction.blockHash), blockHash);
  assert.equal(back.transaction.actions[0].methodName, 'set');
  assert.equal(back.transaction.actions[0].deposit, 10n ** 22n);
  const hash = T.sha256(B.serializeTransaction(back.transaction));
  assert.equal(bs58.encode(hash), s.id);
  assert.ok(T.verifySignature(back.transaction.publicKey, hash, back.signature));
  // The signer refuses a transaction made out to a different key.
  const wrong = T.keyPairFromSecret(testKey().text);
  assert.throws(() => T.signTransaction(tx, wrong), /different public key/);
});

test('account ids follow NEAR rules', () => {
  for (const ok of ['oberiglabs.near', 'social.near', 'v1.social08.testnet', 'a-b_c.near', '04a8b892fb7a90b9a6cec06e176c1577dfbd45b39c699074f53a141fbf01fde3']) assert.ok(T.isAccountId(ok), ok);
  for (const bad of ['', 'a', 'Upper.near', 'a..b', '-a.near', 'a.near.', 'x'.repeat(65), 'has space.near']) assert.ok(!T.isAccountId(bad), bad);
});
