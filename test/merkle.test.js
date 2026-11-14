'use strict';
// Merkle tree: RFC 6962 reference roots and audit paths, and proofs that fail when anything changes.

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const M = require('../src/near/merkle.js');

// The 8 leaves used by the Certificate Transparency reference tests.
const LEAVES = ['', '00', '10', '2021', '3031', '40414243', '5051525354555657', '606162636465666768696a6b6c6d6e6f'].map((h) => Buffer.from(h, 'hex'));
const ROOTS = [
  '6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d',
  'fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125',
  'aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77',
  'd37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7',
  '4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4',
  '76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef',
  'ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c',
  '5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328',
];
const PATHS = [
  { index: 0, size: 1, path: [] },
  { index: 0, size: 8, path: ['96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7', '5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e', '6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4'] },
  { index: 5, size: 8, path: ['bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b', 'ca854ea128ed050b41b35ffc1b87b8eb2bde461e9e3b5596ece6b9d5975a0ae0', 'd37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7'] },
  { index: 2, size: 3, path: ['fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125'] },
  { index: 1, size: 5, path: ['6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d', '5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e', 'bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b'] },
];

test('roots match the RFC 6962 reference values', () => {
  for (let n = 1; n <= 8; n++) assert.equal(M.root(LEAVES.slice(0, n)).toString('hex'), ROOTS[n - 1], `size ${n}`);
  assert.equal(M.root([]).toString('hex'), crypto.createHash('sha256').digest('hex'));
});

test('audit paths match the RFC 6962 reference values and verify', () => {
  for (const want of PATHS) {
    const leaves = LEAVES.slice(0, want.size);
    const p = M.proof(leaves, want.index);
    assert.deepEqual(p.path.map((b) => b.toString('hex')), want.path, `leaf ${want.index} of ${want.size}`);
    assert.ok(M.verify(leaves[want.index], { ...want }, ROOTS[want.size - 1]));
  }
});

test('every leaf of trees with 1 to 40 leaves proves, and changed proofs fail', () => {
  for (let n = 1; n <= 40; n++) {
    const leaves = Array.from({ length: n }, () => crypto.randomBytes(32));
    const root = M.root(leaves);
    for (let i = 0; i < n; i++) {
      const p = M.proof(leaves, i);
      assert.ok(M.verify(leaves[i], p, root), `leaf ${i} of ${n}`);
      assert.ok(!M.verify(crypto.randomBytes(32), p, root), 'another leaf');
      if (n > 1) {
        assert.ok(!M.verify(leaves[i], { ...p, index: (i + 1) % n }, root), 'wrong index');
        const bent = p.path.map((b, j) => (j === 0 ? Buffer.from(b.map((x, k) => (k === 0 ? x ^ 1 : x))) : b));
        assert.ok(!M.verify(leaves[i], { ...p, path: bent }, root), 'changed path');
        assert.ok(!M.verify(leaves[i], { ...p, path: p.path.slice(1) }, root), 'short path');
      }
    }
  }
});

test('malformed proofs are refused, not crashed on', () => {
  const leaves = [Buffer.alloc(32, 1), Buffer.alloc(32, 2), Buffer.alloc(32, 3)];
  const root = M.root(leaves);
  const p = M.proof(leaves, 1);
  assert.equal(M.rootFromProof(leaves[1], { ...p, index: 3 }), null);
  assert.equal(M.rootFromProof(leaves[1], { ...p, size: 0 }), null);
  assert.equal(M.rootFromProof(leaves[1], { ...p, path: ['abcd'] }), null);
  assert.equal(M.rootFromProof(leaves[1], { ...p, path: [...p.path, p.path[0]] }), null);
  assert.ok(!M.verify(leaves[1], { ...p, size: 7 }, root));
  assert.throws(() => M.proof(leaves, 3), RangeError);
});
