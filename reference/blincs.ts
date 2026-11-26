// EDUCATIONAL / SPECIFICATION-CONFORMANCE REFERENCE ONLY — FOR READING, NOT PRODUCTION EXECUTION.
//
// Runs without dependencies under Node 24 native TypeScript type-stripping.

import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

// ---------------- BLAKE3 ----------------
const IV = new Uint32Array([0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]);
const PERM = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];
const CHUNK_START = 1, CHUNK_END = 2, PARENT = 4, ROOT = 8, KEYED_HASH = 16, DK_CTX = 32, DK_MAT = 64;

const rotr = (x: number, n: number): number => (x >>> n) | (x << (32 - n));
function g(v: Uint32Array, a: number, b: number, c: number, d: number, x: number, y: number): void {
  v[a] = v[a] + v[b] + x; v[d] = rotr(v[d] ^ v[a], 16);
  v[c] = v[c] + v[d];     v[b] = rotr(v[b] ^ v[c], 12);
  v[a] = v[a] + v[b] + y; v[d] = rotr(v[d] ^ v[a], 8);
  v[c] = v[c] + v[d];     v[b] = rotr(v[b] ^ v[c], 7);
}
function compress(cv: Uint32Array, block: Uint32Array, ctr: number, len: number, flags: number): Uint32Array {
  const v = new Uint32Array(16);
  v.set(cv.subarray(0, 8), 0); v.set(IV.subarray(0, 4), 8);
  v[12] = ctr >>> 0; v[13] = Math.floor(ctr / 0x100000000); v[14] = len; v[15] = flags;
  let m = Uint32Array.from(block);
  for (let r = 0; r < 7; r++) {
    g(v, 0, 4, 8, 12, m[0], m[1]);   g(v, 1, 5, 9, 13, m[2], m[3]);
    g(v, 2, 6, 10, 14, m[4], m[5]);  g(v, 3, 7, 11, 15, m[6], m[7]);
    g(v, 0, 5, 10, 15, m[8], m[9]);  g(v, 1, 6, 11, 12, m[10], m[11]);
    g(v, 2, 7, 8, 13, m[12], m[13]); g(v, 3, 4, 9, 14, m[14], m[15]);
    const p = new Uint32Array(16); for (let i = 0; i < 16; i++) p[i] = m[PERM[i]]; m = p;
  }
  for (let i = 0; i < 8; i++) { v[i] ^= v[i + 8]; v[i + 8] ^= cv[i]; }
  return v;
}
function toWords(b: Uint8Array, off: number, len: number, count: number): Uint32Array {
  const w = new Uint32Array(count);
  for (let i = 0; i < len; i++) w[i >> 2] |= b[off + i] << (8 * (i & 3));
  return w;
}
function cat32(a: Uint32Array, b: Uint32Array): Uint32Array { const r = new Uint32Array(16); r.set(a.subarray(0, 8)); r.set(b.subarray(0, 8), 8); return r; }

function b3(key: Uint32Array, flags: number, input: Uint8Array): Uint8Array {
  const n = Math.max(1, Math.ceil(input.length / 1024));
  const stack: Uint32Array[] = [];
  let out: [Uint32Array, Uint32Array, number, number, number] = [key, new Uint32Array(16), 0, 0, flags];
  for (let ci = 0; ci < n; ci++) {
    const start = ci * 1024, end = Math.min(start + 1024, input.length);
    const nb = Math.max(1, Math.ceil((end - start) / 64));
    let cv = key;
    for (let bi = 0; bi < nb; bi++) {
      const bs = start + bi * 64, bl = Math.min(64, end - bs);
      const m = toWords(input, bs, bl, 16);
      const f = flags | (bi === 0 ? CHUNK_START : 0) | (bi === nb - 1 ? CHUNK_END : 0);
      if (bi === nb - 1 && ci === n - 1) out = [cv, m, ci, bl, f];
      else cv = compress(cv, m, ci, bl, f).slice(0, 8);
    }
    if (ci < n - 1) {
      let t = ci + 1;
      while ((t & 1) === 0) { cv = compress(key, cat32(stack.pop()!, cv), 0, 64, flags | PARENT).slice(0, 8); t = Math.floor(t / 2); }
      stack.push(cv);
    }
  }
  while (stack.length) {
    const cv = compress(out[0], out[1], out[2], out[3], out[4]).slice(0, 8);
    out = [key, cat32(stack.pop()!, cv), 0, 64, flags | PARENT];
  }
  const r = compress(out[0], out[1], out[2], out[3], out[4] | ROOT);
  const o = new Uint8Array(32);
  for (let i = 0; i < 8; i++) for (let j = 0; j < 4; j++) o[4 * i + j] = (r[i] >>> (8 * j)) & 0xff;
  return o;
}
export const blake3 = (m: Uint8Array): Uint8Array => b3(IV, 0, m);
export function keyed(k: Uint8Array, m: Uint8Array): Uint8Array {
  if (k.length !== 32) throw new Error("key must be 32 bytes");
  return b3(toWords(k, 0, 32, 8), KEYED_HASH, m);
}
const enc = new TextEncoder();
export const derive = (ctx: string, m: Uint8Array): Uint8Array =>
  b3(toWords(b3(IV, DK_CTX, enc.encode(ctx)), 0, 32, 8), DK_MAT, m);

// ---------------- BLINCS-128-7x5 ----------------
const N = 16, LAYERS = 7, TREE_HEIGHT = 5, CHAINS = 35, SIG_LEN = 6432, MAX_CTX = 255;
const UFORS_TREES = 15, UFORS_CHAINS = 3, UFORS_STEPS = 9, UFORS_SUM = 16, UFORS_CODE_BITS = 6, UFORS_LAYER_BASE = 0x80;
const UFORS_TREE_LEN = (UFORS_CHAINS + TREE_HEIGHT) * N;
const BP = "BLINCS-128-7x5 2026-11-26 ";
const SP = "Signet 2026-11-26 randomness: ";
const CTX_PUBLIC_HASH = BP + "public hash", CTX_CONTENT = BP + "content",
  CTX_MIX = SP + "mix", CTX_NEXT_SEED = SP + "next seed",
  CTX_RUN_KEY = SP + "key of this run", CTX_KEYGEN_KEY = SP + "keygen key";
const CHAIN = 2, ONE_TIME_KEY = 3, NODE = 4, FEW_ROOT = 5, MESSAGE = 6;

const UFORS_CODE: readonly [number, number, number][] = (() => {
  const all: [number, number, number][] = [];
  for (let a = 0; a <= UFORS_STEPS; a++) {
    for (let b = 0; b <= UFORS_STEPS; b++) {
      const c = UFORS_SUM - a - b;
      if (c >= 0 && c <= UFORS_STEPS) all.push([a, b, c]);
    }
  }
  const byNorm = [...all].sort((x, y) => {
    const nx = x[0] * x[0] + x[1] * x[1] + x[2] * x[2];
    const ny = y[0] * y[0] + y[1] * y[1] + y[2] * y[2];
    return nx - ny || x[0] - y[0] || x[1] - y[1] || x[2] - y[2];
  });
  const dropped = new Set(byNorm.slice(0, all.length - (1 << UFORS_CODE_BITS)).map((t) => t.join(",")));
  return all.filter((t) => !dropped.has(t.join(",")));
})();

function cat(...xs: Uint8Array[]): Uint8Array {
  const r = new Uint8Array(xs.reduce((s, x) => s + x.length, 0));
  let o = 0; for (const x of xs) { r.set(x, o); o += x.length; } return r;
}
function tweak(kind: number, layer: number, tree: number, leaf: number, a: number, b: number): Uint8Array {
  const t = new Uint8Array(16);
  t[0] = kind; t[1] = layer;
  for (let i = 0; i < 6; i++) t[2 + i] = Math.floor(tree / 2 ** (8 * i)) % 256;
  t[8] = leaf & 0xff; t[9] = (leaf >>> 8) & 0xff;
  t[10] = a & 0xff; t[11] = (a >>> 8) & 0xff;
  for (let i = 0; i < 4; i++) t[12 + i] = (b >>> (8 * i)) & 0xff;
  return t;
}
const shortHash = (k: Uint8Array, t: Uint8Array, d: Uint8Array): Uint8Array => keyed(k, cat(t, d)).slice(0, N);
function u64le(x: bigint): Uint8Array {
  if (x < 0n || x >= (1n << 64n)) throw new Error("u64 out of range");
  const r = new Uint8Array(8); for (let i = 0; i < 8; i++) r[i] = Number((x >> BigInt(8 * i)) & 0xffn); return r;
}
function readBits(d: Uint8Array, bitOff: number, width: number): number {
  let acc = 0n;
  for (let i = 31; i >= 0; i--) acc = (acc << 8n) | BigInt(d[i]);
  return Number((acc >> BigInt(bitOff)) & ((1n << BigInt(width)) - 1n));
}
function digits(node: Uint8Array): number[] {
  const d: number[] = [];
  for (let i = 0; i < 16; i++) { d.push(node[i] & 0x0f, node[i] >> 4); }
  let cs = 0; for (let j = 0; j < 32; j++) cs += 15 - d[j];
  d.push(cs & 0x0f, (cs >> 4) & 0x0f, (cs >> 8) & 0x0f);
  return d;
}
function verifyTreeLeaf(
  kPub: Uint8Array, layer: number, tree: number, leaf: number,
  ds: readonly number[], maxSteps: number, sig: Uint8Array, off: number,
): Uint8Array {
  const ends: Uint8Array[] = [];
  for (let c = 0; c < ds.length; c++) {
    let v: Uint8Array = sig.slice(off + c * N, off + (c + 1) * N);
    for (let s = ds[c]; s < maxSteps; s++) v = shortHash(kPub, tweak(CHAIN, layer, tree, leaf, c, s), v);
    ends.push(v);
  }
  let v = shortHash(kPub, tweak(ONE_TIME_KEY, layer, tree, leaf, 0, 0), cat(...ends));
  for (let lv = 1; lv <= TREE_HEIGHT; lv++) {
    const a0 = off + (ds.length + lv - 1) * N;
    const auth = sig.subarray(a0, a0 + N);
    const tw = tweak(NODE, layer, tree, 0, lv, leaf >> lv);
    v = shortHash(kPub, tw, ((leaf >> (lv - 1)) & 1) === 0 ? cat(v, auth) : cat(auth, v));
  }
  return v;
}

export function verify(vk: Uint8Array, ctx: Uint8Array, message: Uint8Array, sig: Uint8Array): boolean {
  if (ctx.length > MAX_CTX) throw new Error("context exceeds 255 bytes");
  if (vk.length !== 32 || sig.length !== SIG_LEN) return false;
  const framedCtx = cat(new Uint8Array([ctx.length]), ctx);
  const kPub = derive(CTX_PUBLIC_HASH, vk.slice(0, 16));
  const root = vk.slice(16, 32);
  const kContent = derive(CTX_CONTENT, vk);
  const e = sig.slice(0, 16), R = sig.slice(16, 32);
  const kMsg = keyed(kContent, cat(e, framedCtx));
  const short = cat(e, keyed(kMsg, message));
  const D = keyed(kPub, cat(tweak(MESSAGE, 0, 0, 0, 0, 0), R, root, short, framedCtx));
  const leafAddr = readBits(D, UFORS_TREES * (TREE_HEIGHT + UFORS_CODE_BITS), LAYERS * TREE_HEIGHT);

  // U-FORS (15 uniform height-5 trees, 3 chains/leaf, w=10, S=16)
  const roots: Uint8Array[] = [];
  for (let t = 0; t < UFORS_TREES; t++) {
    const leaf = readBits(D, 11 * t, TREE_HEIGHT);
    const code = readBits(D, 11 * t + TREE_HEIGHT, UFORS_CODE_BITS);
    roots.push(verifyTreeLeaf(kPub, UFORS_LAYER_BASE + t, leafAddr, leaf, UFORS_CODE[code], UFORS_STEPS, sig, 32 + t * UFORS_TREE_LEN));
  }
  let node = shortHash(kPub, tweak(FEW_ROOT, 0, leafAddr, 0, 0, 0), cat(...roots));

  // Hypertree (7 uniform height-5 layers)
  let addr = leafAddr, off = 32 + UFORS_TREES * UFORS_TREE_LEN;
  for (let layer = 0; layer < LAYERS; layer++) {
    const leaf = addr % (1 << TREE_HEIGHT), tree = Math.floor(addr / (1 << TREE_HEIGHT));
    node = verifyTreeLeaf(kPub, layer, tree, leaf, digits(node), 15, sig, off);
    addr = tree; off += (CHAINS + TREE_HEIGHT) * N;
  }
  let diff = 0; for (let i = 0; i < 16; i++) diff |= node[i] ^ root[i];
  return diff === 0;
}

export function mixPool(priorSalt: Uint8Array | null, system: Uint8Array, pid: number, clock: Uint8Array): Uint8Array {
  if (system.length !== 32) throw new Error("system randomness must be 32 bytes");
  if (!Number.isInteger(pid) || pid < 0 || pid > 0xffffffff) throw new Error("pid must be a u32");
  const prefix = priorSalt === null ? new Uint8Array([0]) : (() => {
    if (priorSalt.length !== 32) throw new Error("prior salt must be 32 bytes");
    return cat(new Uint8Array([32]), priorSalt);
  })();
  const pidBytes = new Uint8Array([pid & 0xff, (pid >>> 8) & 0xff, (pid >>> 16) & 0xff, (pid >>> 24) & 0xff]);
  return derive(CTX_MIX, cat(prefix, system, pidBytes, clock));
}
export function expandPool(pool: Uint8Array): [Uint8Array, Uint8Array, Uint8Array] {
  if (pool.length !== 32) throw new Error("pool must be 32 bytes");
  return [derive(CTX_NEXT_SEED, pool), derive(CTX_RUN_KEY, pool), derive(CTX_KEYGEN_KEY, pool)];
}
export function draw(key: Uint8Array, n: bigint): Uint8Array { return keyed(key, u64le(n)); }

// ---------------- CLI ----------------
function hex(s: string, len?: number): Uint8Array {
  if (!/^([0-9a-fA-F]{2})*$/.test(s) || (len !== undefined && s.length !== 2 * len)) throw new Error("bad hex: " + s);
  const r = new Uint8Array(s.length / 2);
  for (let i = 0; i < r.length; i++) r[i] = parseInt(s.slice(2 * i, 2 * i + 2), 16);
  return r;
}
const toHex = (b: Uint8Array): string => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
function u64arg(s: string): bigint {
  if (!/^[0-9]+$/.test(s)) throw new Error("bad u64: " + s);
  const v = BigInt(s); if (v >= 1n << 64n) throw new Error("u64 overflow"); return v;
}

const proc = (globalThis as any).process;
const isMain = proc && Array.isArray(proc.argv) && proc.argv[1] && import.meta.url === pathToFileURL(proc.argv[1]).href;
if (isMain) {
  const a: string[] = proc.argv.slice(2);
  try {
    if (a[0] === "--verify" && a.length === 5) {
      const ok = verify(hex(a[1], 32), hex(a[2]), new Uint8Array(readFileSync(a[4])), new Uint8Array(readFileSync(a[3])));
      console.log(ok ? "true" : "false");
      proc.exit(ok ? 0 : 1);
    } else if (a[0] === "--mix" && a.length === 6) {
      const prior = a[1] === "-" ? null : hex(a[1], 32);
      const pid = Number(a[3]);
      const [ns, rk, kk] = expandPool(mixPool(prior, hex(a[2], 32), pid, enc.encode(a[4])));
      console.log([ns, rk, kk].map(toHex).join(" "));
      if (a[5] !== "-") console.log(toHex(draw(rk, u64arg(a[5]))));
    } else if (a[0] === "--draw" && a.length === 3) {
      console.log(toHex(draw(hex(a[1], 32), u64arg(a[2]))));
    } else {
      console.error("usage: --verify <vk_hex> <ctx_hex> <sig_path> <msg_path> | --mix <prior_hex|-> <sys_hex> <pid> <clock_utf8> <draw_n|-> | --draw <key_hex> <n>");
      proc.exit(2);
    }
  } catch (err) {
    console.error(String(err));
    proc.exit(2);
  }
}
