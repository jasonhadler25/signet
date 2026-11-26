// Execute the freestanding #![no_std] wasm32-unknown-unknown build of `signet-verify`
// under Node 24's native WebAssembly engine, verifying:
//   1. Zero WASM imports (strictly freestanding: no WASI, no JS host imports, no allocator).
//   2. All 5 official vectors (reference-imprint-1.bin + 4 edge-vectors.json) pass BOTH
//      one-shot and chunked streaming verification inside WASM.
//   3. Negative cases (tampered signature byte, wrong SignetId, wrong Context, 256-byte
//      ContextTooLong) fail closed inside WASM.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.dirname(HERE);
const WASM_PATH = path.join(HERE, "target", "wasm32-unknown-unknown", "release", "signet_verify_wasm_test.wasm");

const wasmBytes = fs.readFileSync(WASM_PATH);
const mod = new WebAssembly.Module(wasmBytes);
const imports = WebAssembly.Module.imports(mod);
if (imports.length !== 0) {
  throw new Error(`freestanding WASM module unexpectedly imports ${imports.length} symbols: ${JSON.stringify(imports)}`);
}
const inst = new WebAssembly.Instance(mod, {});
const { set_id_byte, set_sig_byte, set_ctx_byte, set_msg_byte, verify_both } = inst.exports;

function hexBytes(h) {
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.slice(2 * i, 2 * i + 2), 16);
  return out;
}

function loadAndRun(id, sig, ctx, msg, chunkSize) {
  for (let i = 0; i < id.length; i++) set_id_byte(i, id[i]);
  for (let i = 0; i < sig.length; i++) set_sig_byte(i, sig[i]);
  for (let i = 0; i < ctx.length; i++) set_ctx_byte(i, ctx[i]);
  for (let i = 0; i < msg.length; i++) set_msg_byte(i, msg[i]);
  return verify_both(ctx.length, msg.length, chunkSize);
}

const id = hexBytes("b58abfb655db7c92808f12c3a8ffd2d04841cf61994321648cf193638876c492");
const refSig = new Uint8Array(fs.readFileSync(path.join(ROOT, "test_vectors", "reference-imprint-1.bin")));
const refCtx = new TextEncoder().encode("BLINCS-128-7x5 reference vector v1");
const refMsg = new TextEncoder().encode("hello, BLINCS");

if (loadAndRun(id, refSig, refCtx, refMsg, 7) !== 0) {
  throw new Error("WASM reference vector failed");
}

// Negative checks in WASM: tampered imprint, wrong ID, wrong context, 256-byte ContextTooLong.
const badSig = refSig.slice();
badSig[4096] ^= 1;
if (loadAndRun(id, badSig, refCtx, refMsg, 7) !== 1) throw new Error("WASM accepted tampered sig");

const badId = id.slice();
badId[31] ^= 1;
if (loadAndRun(badId, refSig, refCtx, refMsg, 7) !== 1) throw new Error("WASM accepted wrong SignetId");

if (loadAndRun(id, refSig, new Uint8Array(0), refMsg, 7) !== 1) throw new Error("WASM accepted wrong context");

if (loadAndRun(id, refSig, new Uint8Array(256), refMsg, 7) !== 2) throw new Error("WASM failed to return ContextTooLong");

// All 4 edge vectors (including 16,385 B streaming across 1024-B BLAKE3 chunk boundaries + 255-B context).
const edge = JSON.parse(fs.readFileSync(path.join(ROOT, "test_vectors", "edge-vectors.json"), "utf8"));
const edgeMsgs = {
  empty: new Uint8Array(0),
  "one-byte-zero": new Uint8Array([0]),
  "chunk-1024": Uint8Array.from({ length: 1024 }, (_, i) => (i * 31) & 0xff),
  "stream-16385-high-leaf": Uint8Array.from({ length: 16385 }, (_, i) => (i * 37 + 5) & 0xff),
};
for (const v of edge) {
  const ctx = hexBytes(v.ctx_hex);
  const sig = hexBytes(v.imprint_hex);
  const msg = edgeMsgs[v.name];
  if (!msg || msg.length !== v.msg_len) throw new Error(`unexpected edge vector ${v.name}`);
  const rc = loadAndRun(id, sig, ctx, msg, 1023);
  if (rc !== 0) throw new Error(`WASM edge vector ${v.name} failed with code ${rc}`);
}

console.log(
  `WASM freestanding signet-verify PASSED: ${(wasmBytes.length / 1024).toFixed(1)} KiB .wasm, 0 imports, 5/5 vectors + 4 negative checks verified.`
);
