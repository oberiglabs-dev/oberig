'use strict';
// Base58 with the Bitcoin alphabet, the text form NEAR uses for keys, hashes,
// signatures and block hashes. Errors never echo the input: it may be a secret key.

const ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const INDEX = new Map([...ALPHABET].map((c, i) => [c, BigInt(i)]));

/** Bytes (Buffer, Uint8Array or array) to a base58 string. */
function encode(bytes) {
  const b = Buffer.from(bytes);
  let zeros = 0;
  while (zeros < b.length && b[zeros] === 0) zeros++;
  let n = b.length > zeros ? BigInt('0x' + b.subarray(zeros).toString('hex')) : 0n;
  let out = '';
  while (n > 0n) {
    out = ALPHABET[Number(n % 58n)] + out;
    n /= 58n;
  }
  return '1'.repeat(zeros) + out;
}

/** A base58 string to a Buffer. Throws on characters outside the alphabet. */
function decode(text) {
  if (typeof text !== 'string') throw new TypeError('base58: string expected');
  let zeros = 0;
  while (zeros < text.length && text[zeros] === '1') zeros++;
  let n = 0n;
  for (const c of text) {
    const v = INDEX.get(c);
    if (v === undefined) throw new Error('base58: invalid character');
    n = n * 58n + v;
  }
  let hex = n > 0n ? n.toString(16) : '';
  if (hex.length % 2) hex = '0' + hex;
  return Buffer.concat([Buffer.alloc(zeros), Buffer.from(hex, 'hex')]);
}

const isBase58 = (text) => typeof text === 'string' && text.length > 0 && [...text].every((c) => INDEX.has(c));

module.exports = { encode, decode, isBase58, ALPHABET };
