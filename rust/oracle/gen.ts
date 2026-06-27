// Differential-fuzz oracle generator.
//
// Runs the REAL RAILGUN TypeScript functions over seeded random + boundary
// inputs and writes (input, output) corpora to rust/vectors/. The Rust
// integration tests (crates/*/tests/fuzz_*.rs) replay these and assert
// byte-equality. Coverage:
//   bytes.json          — ByteUtils (hex/bigint/byte/utf8)
//   crypto.json         — hashes, Poseidon (+ wide 13-input), spending/viewing
//                         keys, ECDH, AES-256-GCM/CTR, XChaCha20-Poly1305
//   keyderivation.json  — BIP39, BabyJubJub BIP32, wallet keys, 0zk addresses
//   higher.json         — token/note hashing, railgun-txid, txid leaf + tx
//                         verification hash, blinded commitments, tree position
//
//   NODE_ENV=test bun run rust/oracle/gen.ts [seed] [count]
//
// Deterministic: same seed+count => identical corpus (reproducible in CI). Bump
// the seed/count to hunt for new divergences.

import { mkdirSync } from 'node:fs';
import { ByteUtils, ByteLength } from '../../src/utils/bytes';
import { sha256, sha512, keccak256, sha512HMAC } from '../../src/utils/hash';
import { poseidon, poseidonHex, initPoseidonPromise } from '../../src/utils/poseidon';
import {
  getPublicSpendingKey,
  getPublicViewingKey,
  getPrivateScalarFromPrivateKey,
  getSharedSymmetricKey,
  signEDDSA,
  verifyEDDSA,
  getNoteBlindingKeys,
  unblindNoteKey,
} from '../../src/utils/keys-utils';
import { encryptJSONDataWithSharedKey } from '../../src/utils/ecies';
import { TransactNote } from '../../src/note/transact-note';
import { initCurve25519Promise } from '../../src/utils/scalar-multiply';
import { Mnemonic } from '../../src/key-derivation/bip39';
import { WalletNode } from '../../src/key-derivation/wallet-node';
import { getMasterKeyFromSeed, childKeyDerivationHardened } from '../../src/key-derivation/bip32';
import { encodeAddress, decodeAddress } from '../../src/key-derivation/bech32';
import { AES } from '../../src/utils/encryption/aes';
import { XChaCha20 } from '../../src/utils/encryption/x-cha-cha-20';
import {
  getTokenDataHash,
  getNoteHash,
  getTokenDataERC20,
  getTokenDataNFT,
} from '../../src/note/note-util';
import {
  getRailgunTransactionIDHex,
  getRailgunTxidLeafHash,
  calculateRailgunTransactionVerificationHash,
} from '../../src/transaction/railgun-txid';
import { BlindedCommitment } from '../../src/poi/blinded-commitment';
import { getGlobalTreePosition } from '../../src/poi/global-tree-position';
import { TokenType } from '../../src/models/formatted-types';

await initPoseidonPromise;
await initCurve25519Promise;

const SEED = process.argv[2] ? Number(process.argv[2]) : 0xc0ffee;
const N = process.argv[3] ? Number(process.argv[3]) : 400;
// Output dir: VECTORS_DIR lets the parallel fuzz runner give each random-seed
// worker its own corpus directory; defaults to the committed rust/vectors.
const OUT = process.env.VECTORS_DIR ?? `${import.meta.dir}/../vectors`;
mkdirSync(OUT, { recursive: true });

const SNARK_PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

// ---- deterministic PRNG (mulberry32) ------------------------------------
function mulberry32(seed: number) {
  let s = seed >>> 0;
  return () => {
    s = (s + 0x6d2b79f5) | 0;
    let t = Math.imul(s ^ (s >>> 15), 1 | s);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
const rng = mulberry32(SEED);
const randByte = () => Math.floor(rng() * 256);
const randInt = (n: number) => Math.floor(rng() * n);
const randBytes = (len: number) => Uint8Array.from({ length: len }, randByte);
const randHex = (len: number) => ByteUtils.fastBytesToHex(randBytes(len));
const randBigint = (numBytes: number) => ByteUtils.hexToBigInt(randHex(numBytes) || '00');
// Field elements: deliberately mix < p and (often) >= p to exercise reduction.
const randField = () => randBigint(32);
const choice = <T>(arr: T[]): T => arr[randInt(arr.length)];

const hex = (u8: Uint8Array) => ByteUtils.fastBytesToHex(u8);
const dec = (n: bigint) => n.toString();

// ---- bytes / bigint ------------------------------------------------------
function genBytes() {
  const hexlifyBytes: any[] = [];
  const hexlifyBigint: any[] = [];
  const arrayify: any[] = [];
  const nToHex: any[] = [];
  const formatToByteLength: any[] = [];
  const padToLength: any[] = [];
  const trim: any[] = [];
  const chunkCombine: any[] = [];
  const hexToBigint: any[] = [];
  const bytesToN: any[] = [];
  const utf8: any[] = [];

  const byteLengths = [1, 7, 15, 16, 20, 24, 31, 32];
  const sides: ('left' | 'right')[] = ['left', 'right'];

  // boundary inputs mixed with random
  const boundaryBig = [0n, 1n, 255n, 256n, SNARK_PRIME - 1n, (1n << 256n) - 1n];

  for (let i = 0; i < N; i++) {
    const blen = randInt(48);
    const inBytes = randBytes(blen);
    const prefix = rng() < 0.5;
    hexlifyBytes.push({ in: hex(inBytes), prefix, out: ByteUtils.hexlify(inBytes, prefix) });

    const big = i < boundaryBig.length ? boundaryBig[i] : randBigint(1 + randInt(40));
    hexlifyBigint.push({ in: dec(big), prefix, out: ByteUtils.hexlify(big, prefix) });

    const evenHex = randHex(randInt(40));
    arrayify.push({ in: evenHex, out: hex(Uint8Array.from(ByteUtils.arrayify(evenHex))) });

    const n = i < boundaryBig.length ? boundaryBig[i] : randBigint(32);
    const bl = choice(byteLengths) as ByteLength;
    nToHex.push({ in: dec(n), byteLength: bl, prefix, out: ByteUtils.nToHex(n, bl, prefix) });

    const fHex = randHex(randInt(40));
    formatToByteLength.push({
      in: fHex,
      byteLength: bl,
      prefix,
      out: ByteUtils.formatToByteLength(fHex, bl, prefix),
    });

    const pHex = randHex(randInt(40));
    const plen = 1 + randInt(40);
    const side = choice(sides);
    padToLength.push({
      in: pHex,
      length: plen,
      side,
      out: ByteUtils.padToLength(pHex, plen, side) as string,
    });

    const tHex = randHex(2 + randInt(40));
    const tlen = randInt(tHex.length / 2);
    trim.push({ in: tHex, length: tlen, side, out: ByteUtils.trim(tHex, tlen, side) as string });

    const cHex = randHex(randInt(80));
    const size = 1 + randInt(40);
    const chunks = ByteUtils.chunk(cHex, size);
    chunkCombine.push({ in: cHex, size, chunks, combined: ByteUtils.combine(chunks) });

    const hHex = randHex(1 + randInt(40));
    hexToBigint.push({ in: hHex, out: dec(ByteUtils.hexToBigInt(hHex)) });

    const bnBytes = randBytes(1 + randInt(40));
    bytesToN.push({ in: hex(bnBytes), out: dec(ByteUtils.bytesToN(bnBytes)) });

    // utf8 roundtrip: build a random string from the safe codepoint range (< 0x800)
    let s = '';
    const slen = randInt(30);
    for (let j = 0; j < slen; j++) s += String.fromCodePoint(randInt(0x800));
    const sHex = Buffer.from(s, 'utf8').toString('hex');
    utf8.push({ str: s, hex: sHex });
  }

  return {
    hexlifyBytes, hexlifyBigint, arrayify, nToHex, formatToByteLength,
    padToLength, trim, chunkCombine, hexToBigint, bytesToN, utf8,
  };
}

// ---- crypto --------------------------------------------------------------
async function genCrypto() {
  const sha256s: any[] = [];
  const sha512s: any[] = [];
  const keccak256s: any[] = [];
  const sha512Hmac: any[] = [];
  const poseidons: any[] = [];
  const poseidonWide: any[] = [];
  const poseidonHexs: any[] = [];
  const spendingKey: any[] = [];
  const viewingKey: any[] = [];
  const privateScalar: any[] = [];
  const sharedKey: any[] = [];
  const aesGcm: any[] = [];
  const aesCtr: any[] = [];
  const xchacha: any[] = [];
  const eddsa: any[] = [];
  const blindingKeys: any[] = [];
  const ecies: any[] = [];

  for (let i = 0; i < N; i++) {
    const msg = randHex(randInt(200));
    sha256s.push({ in: msg, out: sha256(msg) });
    sha512s.push({ in: msg, out: sha512(msg) });
    keccak256s.push({ in: msg, out: keccak256(msg) });
    const key = randHex(1 + randInt(64));
    sha512Hmac.push({ key, data: msg, out: sha512HMAC(key, msg) });

    const arity = 1 + randInt(6);
    const inputs = Array.from({ length: arity }, randField);
    poseidons.push({ in: inputs.map(dec), out: dec(poseidon(inputs)) });
    const hexInputs = inputs.map((x) => ByteUtils.nToHex(x % SNARK_PRIME, ByteLength.UINT_256));
    poseidonHexs.push({ in: hexInputs, out: poseidonHex(hexInputs) });

    // Wide Poseidon (7..13 inputs) — exercises the > 12-input path used by
    // getRailgunTransactionID, which light-poseidon cannot do (poseidon-ark in Rust).
    const wideArity = 7 + randInt(7);
    const wideInputs = Array.from({ length: wideArity }, randField);
    poseidonWide.push({ in: wideInputs.map(dec), out: dec(poseidon(wideInputs)) });

    // AES-256-GCM / -CTR: TS encrypts (random IV) -> Rust decrypts and must recover
    // the plaintext. 32-byte key, 1..40-byte value chunked at 32 bytes.
    const aesKey = randHex(32);
    const value = randHex(1 + randInt(40));
    const chunks = ByteUtils.chunk(value, 32);
    aesGcm.push({ key: aesKey, plaintext: value, ct: AES.encryptGCM(chunks, aesKey) });
    aesCtr.push({ key: aesKey, plaintext: value, ct: AES.encryptCTR(chunks, aesKey) });

    // XChaCha20-Poly1305: TS encrypts -> Rust decrypts.
    const xKey = randBytes(32);
    const xValue = randHex(1 + randInt(60));
    xchacha.push({
      key: hex(xKey),
      plaintext: xValue,
      ct: XChaCha20.encryptChaCha20Poly1305(xValue, xKey),
    });

    const priv = randBytes(32);
    const [sx, sy] = getPublicSpendingKey(priv);
    spendingKey.push({ in: hex(priv), x: dec(sx), y: dec(sy) });
    viewingKey.push({ in: hex(priv), out: hex(await getPublicViewingKey(priv)) });
    privateScalar.push({ in: hex(priv), out: dec(await getPrivateScalarFromPrivateKey(priv)) });

    const privA = randBytes(32);
    const pubB = randBytes(32);
    const sk = await getSharedSymmetricKey(privA, pubB);
    sharedKey.push({ privA: hex(privA), pubB: hex(pubB), out: sk ? hex(sk) : null });

    // BabyJubJub Poseidon-EdDSA: spending-auth signature. Deterministic, so the
    // signature itself must match byte-for-byte; verify must accept it.
    const edPriv = randBytes(32);
    const edMsg = randField() % SNARK_PRIME;
    const sig = signEDDSA(edPriv, edMsg);
    const edPub = getPublicSpendingKey(edPriv);
    eddsa.push({
      priv: hex(edPriv),
      msg: dec(edMsg),
      r8x: dec(sig.R8[0]),
      r8y: dec(sig.R8[1]),
      s: dec(sig.S),
      pubX: dec(edPub[0]),
      pubY: dec(edPub[1]),
      verified: verifyEDDSA(edMsg, sig, edPub),
    });

    // Note blinding keys (X25519): blind sender/receiver viewing pubkeys, then
    // unblind must recover the originals. Pubkeys are real Ed25519 points.
    const sViewPub = await getPublicViewingKey(randBytes(32));
    const rViewPub = await getPublicViewingKey(randBytes(32));
    const sharedRandom = randHex(16);
    const senderRandom = randHex(16);
    const { blindedSenderViewingKey, blindedReceiverViewingKey } = getNoteBlindingKeys(
      sViewPub,
      rViewPub,
      sharedRandom,
      senderRandom,
    );
    blindingKeys.push({
      senderPub: hex(sViewPub),
      receiverPub: hex(rViewPub),
      sharedRandom,
      senderRandom,
      blindedSender: hex(blindedSenderViewingKey),
      blindedReceiver: hex(blindedReceiverViewingKey),
      // Sanity: TS itself can round-trip the receiver key.
      unblindedReceiver: hex(unblindNoteKey(blindedReceiverViewingKey, sharedRandom, senderRandom)!),
    });

    // ECIES: TS encrypts a small JSON object with a shared key; Rust must decrypt
    // it back to the identical object (and reject a wrong key).
    const eciesKey = randBytes(32);
    const obj: Record<string, unknown> = {};
    const nFields = 1 + randInt(3);
    for (let f = 0; f < nFields; f++) obj[`k${f}`] = randHex(1 + randInt(40));
    if (rng() < 0.5) obj.num = randInt(1_000_000);
    if (rng() < 0.5) obj.nested = { a: randHex(8), b: randInt(256) };
    ecies.push({ key: hex(eciesKey), json: obj, encrypted: encryptJSONDataWithSharedKey(obj, eciesKey) });
  }

  return {
    sha256: sha256s, sha512: sha512s, keccak256: keccak256s, sha512Hmac,
    poseidon: poseidons, poseidonWide, poseidonHex: poseidonHexs,
    spendingKey, viewingKey, privateScalar, sharedKey,
    aesGcm, aesCtr, xchacha, eddsa, blindingKeys, ecies,
  };
}

// ---- higher layers: note / transaction / poi ----------------------------
function genHigher() {
  const tokenHashErc20: any[] = [];
  const tokenHashNft: any[] = [];
  const noteHash: any[] = [];
  const railgunTxid: any[] = [];
  const txidLeafHash: any[] = [];
  const verificationHash: any[] = [];
  const blindedShieldTransact: any[] = [];
  const blindedUnshield: any[] = [];
  const globalTreePosition: any[] = [];
  const nullifier: any[] = [];

  const nftTypes = [TokenType.ERC721, TokenType.ERC1155] as const;

  for (let i = 0; i < N; i++) {
    const erc20 = getTokenDataERC20(randHex(20));
    tokenHashErc20.push({ tokenData: erc20, out: getTokenDataHash(erc20) });

    const nft = getTokenDataNFT(randHex(20), choice([...nftTypes]), randHex(32));
    tokenHashNft.push({ tokenData: nft, out: getTokenDataHash(nft) });

    // getNoteHash(address, tokenData, value): random 0zk masterPublicKey + value.
    const addr = ByteUtils.nToHex(randField() % SNARK_PRIME, ByteLength.UINT_256, true);
    const td = rng() < 0.5 ? erc20 : nft;
    const noteValue = randBigint(16);
    noteHash.push({ address: addr, tokenData: td, value: dec(noteValue), out: dec(getNoteHash(addr, td, noteValue)) });

    // getRailgunTransactionID: random 1..5 nullifiers + commitments (exercises wide Poseidon).
    const nNull = 1 + randInt(5);
    const nComm = 1 + randInt(5);
    const nullifiers = Array.from({ length: nNull }, () => ByteUtils.nToHex(randField() % SNARK_PRIME, ByteLength.UINT_256, true));
    const commitments = Array.from({ length: nComm }, () => ByteUtils.nToHex(randField() % SNARK_PRIME, ByteLength.UINT_256, true));
    const boundParamsHash = ByteUtils.nToHex(randField() % SNARK_PRIME, ByteLength.UINT_256, true);
    railgunTxid.push({ nullifiers, commitments, boundParamsHash, out: getRailgunTransactionIDHex({ nullifiers, commitments, boundParamsHash }) });

    const txidBig = randField() % SNARK_PRIME;
    const utxoTreeIn = BigInt(randInt(20));
    const gpos = getGlobalTreePosition(randInt(50), randInt(0xffff));
    txidLeafHash.push({ txid: dec(txidBig), utxoTreeIn: dec(utxoTreeIn), globalPos: dec(gpos), out: getRailgunTxidLeafHash(txidBig, utxoTreeIn, gpos) });

    const prev = rng() < 0.3 ? undefined : ByteUtils.nToHex(randField(), ByteLength.UINT_256, true);
    const firstNullifier = ByteUtils.nToHex(randField(), ByteLength.UINT_256, true);
    verificationHash.push({ prev: prev ?? null, firstNullifier, out: calculateRailgunTransactionVerificationHash(prev, firstNullifier) });

    const commitmentHash = ByteUtils.nToHex(randField() % SNARK_PRIME, ByteLength.UINT_256, true);
    const npk = randField() % SNARK_PRIME;
    const gtp = getGlobalTreePosition(randInt(50), randInt(0xffff));
    blindedShieldTransact.push({ commitmentHash, npk: dec(npk), globalTreePosition: dec(gtp), out: BlindedCommitment.getForShieldOrTransact(commitmentHash, npk, gtp) });

    const rt = ByteUtils.nToHex(randField() % SNARK_PRIME, ByteLength.UINT_256, true);
    blindedUnshield.push({ railgunTxid: rt, out: BlindedCommitment.getForUnshield(rt) });

    const tree = randInt(100);
    const index = randInt(0xffff);
    globalTreePosition.push({ tree, index, out: dec(getGlobalTreePosition(tree, index)) });

    // Nullifier = poseidon([nullifyingKey, leafIndex]).
    const nk = randField() % SNARK_PRIME;
    const leafIndex = randInt(0xffffff);
    nullifier.push({ nullifyingKey: dec(nk), leafIndex, out: dec(TransactNote.getNullifier(nk, leafIndex)) });
  }

  return {
    tokenHashErc20, tokenHashNft, noteHash, railgunTxid, txidLeafHash,
    verificationHash, blindedShieldTransact, blindedUnshield, globalTreePosition, nullifier,
  };
}

// ---- key derivation / mnemonic ------------------------------------------
async function genKeyDerivation() {
  const toSeed: any[] = [];
  const entropy: any[] = [];
  const to0xPrivateKey: any[] = [];
  const masterKey: any[] = [];
  const childKey: any[] = [];
  const spendingKeyPair: any[] = [];
  const viewingKeyPair: any[] = [];
  const nullifyingKey: any[] = [];
  const address: any[] = [];

  const printable = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 ._-';
  const randPassword = () => {
    let p = '';
    const len = randInt(12);
    for (let j = 0; j < len; j++) p += printable[randInt(printable.length)];
    return p;
  };
  const entropyBytes = [16, 24, 32];

  for (let i = 0; i < N; i++) {
    const eHex = randHex(choice(entropyBytes));
    const mnemonic = Mnemonic.fromEntropy(eHex);
    entropy.push({ entropy: eHex, mnemonic });

    const pw = randPassword();
    toSeed.push({ mnemonic, password: pw, out: Mnemonic.toSeed(mnemonic, pw) });

    const idx = randInt(0x7fffffff);
    to0xPrivateKey.push({ mnemonic, index: idx, out: Mnemonic.to0xPrivateKey(mnemonic, idx) });

    const seedHex = randHex(16 + randInt(48));
    masterKey.push({ seed: seedHex, ...getMasterKeyFromSeed(seedHex) });

    const parent = getMasterKeyFromSeed(randHex(64));
    const cidx = randInt(0x7fffffff);
    childKey.push({ parent, index: cidx, ...childKeyDerivationHardened(parent, cidx) });

    // wallet node derive along a random hardened path
    const depth = 1 + randInt(4);
    const segs = Array.from({ length: depth }, () => randInt(0x7fffffff));
    const path = `m/${segs.map((s) => `${s}'`).join('/')}`;
    const node = WalletNode.fromMnemonic(mnemonic).derive(path);
    const skp = node.getSpendingKeyPair();
    spendingKeyPair.push({
      mnemonic, path,
      privateKey: hex(skp.privateKey),
      x: dec(skp.pubkey[0]), y: dec(skp.pubkey[1]),
    });
    const vkp = await node.getViewingKeyPair();
    viewingKeyPair.push({ mnemonic, path, privateKey: hex(vkp.privateKey), pubkey: hex(vkp.pubkey) });
    nullifyingKey.push({ mnemonic, path, out: dec(await node.getNullifyingKey()) });

    // bech32 address roundtrip
    const mpk = randBigint(32);
    const vpk = randBytes(32);
    const chain = rng() < 0.3 ? undefined : { type: randByte(), id: randBigint(7) };
    const addr = encodeAddress({ masterPublicKey: mpk, viewingPublicKey: vpk, chain });
    address.push({
      masterPublicKey: dec(mpk),
      viewingPublicKey: hex(vpk),
      chain: chain ? { type: chain.type, id: dec(chain.id) } : null,
      encoded: addr,
    });
  }

  return {
    toSeed, entropy, to0xPrivateKey, masterKey, childKey,
    spendingKeyPair, viewingKeyPair, nullifyingKey, address,
  };
}

const meta = { seed: SEED, count: N };
await Bun.write(`${OUT}/bytes.json`, JSON.stringify({ meta, ...genBytes() }));
await Bun.write(`${OUT}/crypto.json`, JSON.stringify({ meta, ...(await genCrypto()) }));
await Bun.write(`${OUT}/keyderivation.json`, JSON.stringify({ meta, ...(await genKeyDerivation()) }));
await Bun.write(`${OUT}/higher.json`, JSON.stringify({ meta, ...genHigher() }));
console.log(`Wrote corpora to ${OUT} (seed=${SEED.toString(16)}, count=${N})`);
