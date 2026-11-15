// Field-element helpers for the gatekeeper circuit (BN128 scalar field).
// Only Node's standard library is used: Node >= 22 exposes the canonical
// Ethereum keccak-256 via crypto.createHash('keccak-256')
// (verified: keccak256("") = c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470).
const crypto = require('crypto');

const FIELD_PRIME = BigInt(
  '21888242871839275222246405745257275088548364400416034343698204186575808495617'
);

// x: 0x-hex string, decimal string, number, or BigInt -> BigInt mod p.
function toField(x) {
  let b;
  if (typeof x === 'bigint') b = x;
  else if (typeof x === 'number') b = BigInt(x);
  else b = BigInt(String(x));
  const r = b % FIELD_PRIME;
  return r < 0n ? r + FIELD_PRIME : r;
}

function keccak256Hex(buffers) {
  const h = crypto.createHash('keccak-256');
  for (const b of buffers) h.update(b);
  return '0x' + h.digest('hex');
}

function keccak256ModP(buffers) {
  return toField(BigInt(keccak256Hex(buffers)));
}

module.exports = { FIELD_PRIME, toField, keccak256Hex, keccak256ModP };
