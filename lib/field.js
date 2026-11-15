// Field-element helpers for the gatekeeper circuit (BN128 scalar field).
//
// Keccak-256 is implemented in pure JavaScript below instead of via
// crypto.createHash('keccak-256'): that digest depends on the OpenSSL
// build and is NOT available in every Node runtime (e.g. Railway's Node
// throws "Digest method not supported", which failed the deployed
// server's startup self-test). This self-contained implementation has no
// such dependency and is verified against the canonical test vectors and
// against Node's native digest (see STATUS.md, "Keccak portability fix").

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

// --- Pure-JS Keccak-256 -------------------------------------------------
// Keccak-f[1600] sponge, rate 136 bytes (capacity 512), 24 rounds, with
// the ORIGINAL Keccak pad10*1 suffix 0x01 — not SHA3's 0x06. Lanes are
// 64-bit BigInts, absorbed little-endian. State index: lane (x + 5*y).

const MASK64 = (1n << 64n) - 1n;

// Round constants (iota), one per round.
const RC = [
  0x0000000000000001n, 0x0000000000008082n, 0x800000000000808an, 0x8000000080008000n,
  0x000000000000808bn, 0x0000000080000001n, 0x8000000080008081n, 0x8000000000008009n,
  0x000000000000008an, 0x0000000000000088n, 0x0000000080008009n, 0x000000008000000an,
  0x000000008000808bn, 0x800000000000008bn, 0x8000000000008089n, 0x8000000000008003n,
  0x8000000000008002n, 0x8000000000000080n, 0x000000000000800an, 0x800000008000000an,
  0x8000000080008081n, 0x8000000000008080n, 0x0000000080000001n, 0x8000000080008008n,
];

// Rotation offsets (rho), indexed [x][y].
const RHO = [
  [0, 36, 3, 41, 18],
  [1, 44, 10, 45, 2],
  [62, 6, 43, 15, 61],
  [28, 55, 25, 21, 56],
  [27, 20, 39, 8, 14],
];

function rotl64(x, n) {
  if (n === 0) return x;
  const b = BigInt(n);
  return ((x << b) | (x >> (64n - b))) & MASK64;
}

function keccakF1600(A) {
  const C = new Array(5);
  const D = new Array(5);
  const B = new Array(25);
  for (let round = 0; round < 24; round++) {
    // theta: column parity, mixed into every lane
    for (let x = 0; x < 5; x++) {
      C[x] = A[x] ^ A[x + 5] ^ A[x + 10] ^ A[x + 15] ^ A[x + 20];
    }
    for (let x = 0; x < 5; x++) {
      D[x] = C[(x + 4) % 5] ^ rotl64(C[(x + 1) % 5], 1);
    }
    for (let x = 0; x < 5; x++) {
      for (let y = 0; y < 5; y++) A[x + 5 * y] ^= D[x];
    }
    // rho + pi: rotate each lane and move it to its new position
    for (let x = 0; x < 5; x++) {
      for (let y = 0; y < 5; y++) {
        B[y + 5 * ((2 * x + 3 * y) % 5)] = rotl64(A[x + 5 * y], RHO[x][y]);
      }
    }
    // chi: the only non-linear step. (~b1) & b2 is exact here because b2
    // is a 64-bit value, so the AND keeps only the low 64 bits.
    for (let x = 0; x < 5; x++) {
      for (let y = 0; y < 5; y++) {
        A[x + 5 * y] =
          B[x + 5 * y] ^ (~B[((x + 1) % 5) + 5 * y] & B[((x + 2) % 5) + 5 * y]);
      }
    }
    // iota: round constant
    A[0] ^= RC[round];
  }
}

const KECCAK256_RATE = 136; // bytes; 17 lanes per block

function xorBlock(A, block, offset) {
  for (let i = 0; i < KECCAK256_RATE / 8; i++) {
    A[i] ^= block.readBigUInt64LE(offset + i * 8);
  }
}

// Keccak-256 digest of the concatenation of `buffers`, as a Buffer.
function keccak256(buffers) {
  const data = Buffer.concat(
    buffers.map((b) => (Buffer.isBuffer(b) ? b : Buffer.from(b)))
  );
  const A = new Array(25).fill(0n);
  let offset = 0;
  while (offset + KECCAK256_RATE <= data.length) {
    xorBlock(A, data, offset);
    keccakF1600(A);
    offset += KECCAK256_RATE;
  }
  // Final block: remaining bytes + pad10*1 (suffix 0x01, top bit 0x80 of
  // the last rate byte; both land on the same byte 0x81 when rem = 135).
  // An exact multiple of the rate correctly gets a whole padding block.
  const tail = Buffer.alloc(KECCAK256_RATE, 0);
  data.copy(tail, 0, offset);
  const rem = data.length - offset;
  tail[rem] |= 0x01;
  tail[KECCAK256_RATE - 1] |= 0x80;
  xorBlock(A, tail, 0);
  keccakF1600(A);
  // Squeeze: the 32 output bytes are the first 4 lanes, little-endian.
  const out = Buffer.alloc(32);
  for (let i = 0; i < 4; i++) out.writeBigUInt64LE(A[i], i * 8);
  return out;
}

function keccak256Hex(buffers) {
  return '0x' + keccak256(buffers).toString('hex');
}

function keccak256ModP(buffers) {
  return toField(BigInt(keccak256Hex(buffers)));
}

module.exports = { FIELD_PRIME, toField, keccak256Hex, keccak256ModP };
