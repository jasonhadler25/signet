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

// ---------------- BLINCS-48-X ----------------
const N = 16, LAYERS = 6, LOW_HEIGHT = 7, TOP_HEIGHT = 13, HYPER_BITS = 48, SIG_LEN = 3990, MAX_CTX = 255;
const WOTS_N = 21, WOTS_W = 60, WOTS_STEPS = 59, WOTS_SUM = 679, WOTS_Z = 2, WOTS_CTR_LEN = 3;
const UPORS_HEIGHT = 11, UPORS_N = 3, UPORS_STEPS = 23, UPORS_SUM = 42, UPORS_C = 376;
const UPORS_K = 9, UPORS_M_MAX = 45, UPORS_CTR_LEN = 4, UPORS_LAYER = 0x80, UPORS_SELECT_MAX_DRAWS = 18;
const BP = "BLINCS-48-X 2026-11-26 ";
const SP = "Signet 2026-11-26 randomness: ";
const CTX_PUBLIC_HASH = BP + "public hash", CTX_CONTENT = BP + "content",
  CTX_MIX = SP + "mix", CTX_NEXT_SEED = SP + "next seed",
  CTX_RUN_KEY = SP + "key of this run", CTX_KEYGEN_KEY = SP + "keygen key";
const CHAIN = 2, ONE_TIME_KEY = 3, NODE = 4, ONE_TIME_MSG = 5, MESSAGE = 6, FEW_SELECT = 7, FEW_CODE = 8;

function decodeWotsC(hMsg: Uint8Array): number[] | null {
  let lo = 0n;
  for (let i = 15; i >= 0; i--) lo = (lo << 8n) | BigInt(hMsg[i]);
  if ((lo & 3n) !== 0n) return null;
  const out: number[] = [];
  let sum = 0;
  for (let i = 0; i < WOTS_N; i++) {
    const d = Number((lo >> BigInt(WOTS_Z + 6 * i)) & 63n);
    if (d >= WOTS_W) return null;
    out.push(d);
    sum += d;
  }
  return sum === WOTS_SUM ? out : null;
}

function cat(...xs: Uint8Array[]): Uint8Array {
  const r = new Uint8Array(xs.reduce((s, x) => s + x.length, 0));
  let o = 0; for (const x of xs) { r.set(x, o); o += x.length; } return r;
}
function u32le(x: number): Uint8Array {
  return new Uint8Array([x & 0xff, (x >>> 8) & 0xff, (x >>> 16) & 0xff, (x >>> 24) & 0xff]);
}
function readU32le(b: Uint8Array, off: number): number {
  return (b[off] | (b[off + 1] << 8) | (b[off + 2] << 16) | (b[off + 3] << 24)) >>> 0;
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
function hexUnrank(idx: number): [number, number, number] {
  let remIdx = idx;
  for (let a = 0; a <= UPORS_STEPS; a++) {
    const rem = UPORS_SUM - a;
    const bLo = Math.max(0, rem - UPORS_STEPS);
    const bHi = Math.min(rem, UPORS_STEPS);
    if (bHi < bLo) continue;
    const len = bHi - bLo + 1;
    if (remIdx < len) { const b = bLo + remIdx; return [a, b, rem - b]; }
    remIdx -= len;
  }
  throw new Error("hexUnrank out of range");
}
function countOctopusSibs(sortedLeaves: number[]): number {
  let cur = [...sortedLeaves], sibs = 0;
  for (let lv = 0; lv < UPORS_HEIGHT; lv++) {
    const nxt: number[] = [];
    for (let i = 0; i < cur.length;) {
      const x = cur[i];
      if (i + 1 < cur.length && (x ^ 1) === cur[i + 1]) { nxt.push(x >> 1); i += 2; }
      else { sibs++; nxt.push(x >> 1); i++; }
    }
    cur = nxt;
  }
  return sibs;
}
function parseSelectDigest(d: Uint8Array): { leafAddr: number; leaves: number[]; sibs: number } | null {
  const seen = new Set<number>();
  const leaves: number[] = [];
  for (let i = 0; i < UPORS_SELECT_MAX_DRAWS; i++) {
    const x = readBits(d, i * UPORS_HEIGHT, UPORS_HEIGHT);
    if (!seen.has(x)) { seen.add(x); leaves.push(x); if (leaves.length === UPORS_K) break; }
  }
  if (leaves.length < UPORS_K) return null;
  leaves.sort((a, b) => a - b);
  const sibs = countOctopusSibs(leaves);
  if (sibs > UPORS_M_MAX) return null;
  const leafAddr = readBits(d, UPORS_SELECT_MAX_DRAWS * UPORS_HEIGHT, HYPER_BITS);
  return { leafAddr, leaves, sibs };
}
function extractUporsCodewords(kPub: Uint8Array, hSel: Uint8Array): [number, number, number][] {
  const out: [number, number, number][] = [];
  for (let blockIdx = 0; out.length < UPORS_K; blockIdx++) {
    if (blockIdx > 0xffff) throw new Error("FEW_CODE block_idx overflow");
    const blk = keyed(kPub, cat(tweak(FEW_CODE, UPORS_LAYER, 0, 0, blockIdx, 0), hSel));
    for (let j = 0; j < 28 && out.length < UPORS_K; j++) {
      const v = readBits(blk, j * 9, 9);
      if (v < UPORS_C) out.push(hexUnrank(v));
    }
  }
  return out;
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
  const dSeed = keyed(kPub, cat(tweak(MESSAGE, 0, 0, 0, 0, 0), R, root, short, framedCtx));

  // U-PORS verification (height-11 tree + Octopus multi-proof)
  let off = 32;
  const ctrFt = readU32le(sig, off); off += UPORS_CTR_LEN;
  const dSel = keyed(kPub, cat(tweak(FEW_SELECT, UPORS_LAYER, 0, 0, 0, 0), dSeed, u32le(ctrFt)));
  const sel = parseSelectDigest(dSel);
  if (!sel) return false;
  const codewords = extractUporsCodewords(kPub, dSel);

  let curVal: Uint8Array[] = [];
  for (let t = 0; t < UPORS_K; t++) {
    const leaf = sel.leaves[t], cw = codewords[t];
    const ends: Uint8Array[] = [];
    for (let c = 0; c < UPORS_N; c++) {
      let v: Uint8Array = sig.slice(off, off + N); off += N;
      for (let s = cw[c]; s < UPORS_STEPS; s++) v = shortHash(kPub, tweak(CHAIN, UPORS_LAYER, sel.leafAddr, leaf, c, s), v);
      ends.push(v);
    }
    curVal.push(shortHash(kPub, tweak(ONE_TIME_KEY, UPORS_LAYER, sel.leafAddr, leaf, 0, 0), cat(...ends)));
  }

  const octoOff = off; off += UPORS_M_MAX * N;
  let curIdx = [...sel.leaves], sibCursor = 0;
  for (let lv = 1; lv <= UPORS_HEIGHT; lv++) {
    const nxtIdx: number[] = [], nxtVal: Uint8Array[] = [];
    for (let i = 0; i < curIdx.length;) {
      const x = curIdx[i], p = x >> 1;
      const tw = tweak(NODE, UPORS_LAYER, sel.leafAddr, 0, lv, p);
      let pair: Uint8Array;
      if (i + 1 < curIdx.length && (x ^ 1) === curIdx[i + 1]) {
        pair = cat(curVal[i], curVal[i + 1]); i += 2;
      } else {
        const s0 = octoOff + sibCursor * N;
        const sib = sig.subarray(s0, s0 + N);
        sibCursor++;
        pair = (x & 1) === 0 ? cat(curVal[i], sib) : cat(sib, curVal[i]);
        i++;
      }
      nxtIdx.push(p); nxtVal.push(shortHash(kPub, tw, pair));
    }
    curIdx = nxtIdx; curVal = nxtVal;
  }
  if (sibCursor !== sel.sibs) return false;
  let padOr = 0;
  for (let i = octoOff + sibCursor * N; i < octoOff + UPORS_M_MAX * N; i++) padOr |= sig[i];
  if (padOr !== 0) return false;
  let node = curVal[0];

  // Hypertree verification (13+7+7+7+7+7 WOTS+C)
  let addr = sel.leafAddr;
  for (let layer = 0; layer < LAYERS; layer++) {
    const hL = layer === LAYERS - 1 ? TOP_HEIGHT : LOW_HEIGHT;
    const leaf = addr % (1 << hL), tree = Math.floor(addr / (1 << hL));
    const ctrL = sig[off] | (sig[off + 1] << 8) | (sig[off + 2] << 16); off += WOTS_CTR_LEN;
    const hMsg = keyed(kPub, cat(tweak(ONE_TIME_MSG, layer, tree, leaf, 0, 0), node, u32le(ctrL)));
    const ds = decodeWotsC(hMsg);
    if (!ds) return false;
    const ends: Uint8Array[] = [];
    for (let c = 0; c < WOTS_N; c++) {
      let v: Uint8Array = sig.slice(off, off + N); off += N;
      for (let s = ds[c]; s < WOTS_STEPS; s++) v = shortHash(kPub, tweak(CHAIN, layer, tree, leaf, c, s), v);
      ends.push(v);
    }
    let v = shortHash(kPub, tweak(ONE_TIME_KEY, layer, tree, leaf, 0, 0), cat(...ends));
    for (let lv = 1; lv <= hL; lv++) {
      const auth = sig.subarray(off, off + N); off += N;
      const tw = tweak(NODE, layer, tree, 0, lv, leaf >> lv);
      v = shortHash(kPub, tw, ((leaf >> (lv - 1)) & 1) === 0 ? cat(v, auth) : cat(auth, v));
    }
    node = v; addr = tree;
  }
  if (off !== SIG_LEN) return false;
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
  return derive(CTX_MIX, cat(prefix, system, u32le(pid), clock));
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
