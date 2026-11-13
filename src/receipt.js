'use strict';
// Seal receipts: metadata only, kept in memory. The receipt hash draws the stitched seal.

const crypto = require('node:crypto');
const Seal = require('./seal.js');

const sha256 = (data) => crypto.createHash('sha256').update(data).digest('hex');

/** JSON with sorted keys, so the same receipt always hashes the same way. */
function canonical(v) {
  if (Array.isArray(v)) return '[' + v.map(canonical).join(',') + ']';
  if (v && typeof v === 'object') {
    return '{' + Object.keys(v).sort().filter((k) => v[k] !== undefined).map((k) => JSON.stringify(k) + ':' + canonical(v[k])).join(',') + '}';
  }
  return JSON.stringify(v === undefined ? null : v);
}

/** Adds hash and seal id to a receipt object (everything except those two fields is hashed). */
function seal(receipt) {
  const { hash, id, ...rest } = receipt;
  const h = sha256(canonical(rest));
  receipt.hash = h;
  receipt.id = Seal.short(h);
  return receipt;
}

/** Keeps the last `max` receipts in memory, newest first. */
class ReceiptBook {
  constructor(max = 200) {
    this.max = max;
    this.items = [];
    this.totals = { requests: 0, verified: 0, attestedOnly: 0, refused: 0, failedSignatures: 0, masked: 0, stopped: 0, scrubbedFiles: 0, scrubbedItems: 0 };
  }

  add(r) {
    this.items.unshift(r);
    if (this.items.length > this.max) this.items.pop();
    const t = this.totals;
    t.requests++;
    if (r.verdict === 'verified') t.verified++;
    else if (r.verdict === 'attested') t.attestedOnly++;
    else if (r.verdict === 'refused') t.refused++;
    else if (r.verdict === 'bad-signature') t.failedSignatures++;
    t.masked += (r.masked && r.masked.total) || 0;
    t.stopped += (r.shield && r.shield.stopped) || 0;
    return r;
  }
}

module.exports = { canonical, seal, sha256, ReceiptBook };
