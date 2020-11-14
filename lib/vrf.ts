import BN from "bn.js";
import * as elliptic from "elliptic";
import { SHA256, concatArrays } from "pmcrypto";

type Point = elliptic.curve.base.BasePoint;
/* eslint-disable new-cap */
const EDDSA = new elliptic.eddsa("ed25519");
/* eslint-enable new-cap */
const N2 = 32;
const N = N2 / 2;
const G = EDDSA.curve.g as Point;
const LIMIT = 100;
const CO_FACTOR = 8;

function proofToHash(proof: Buffer) {
  return proof.slice(1, N2 + 1);
}

function checkHash(proof: Buffer, value: Buffer) {
  if (value.length === N2 && proof.length > N2 + 1) {
    if (value.equals(proofToHash(proof))) {
      return true;
    }
  }
  return false;
}

function OS2ECP(os: Buffer) {
  const b = elliptic.utils.toArray(os, 16);
  try {
    return EDDSA.decodePoint(b) as Point;
  } catch (e) {
    return null;
  }
}

function S2OS(os: number[]) {
  const sign = os[31] >>> 7;
  os.unshift(sign + 2);
  return Buffer.from(os);
}

function ECP2OS(P: Point) {
  return S2OS([...EDDSA.encodePoint(P)]);
}

function OS2IP(os: Buffer) {
  return new BN(os);
}

function I2OSP(i: BN, len?: number) {
  return Buffer.from(i.toArray("be", len));
}

function decodeProof(proof: Buffer) {
  let pos = 0;
  const sign = proof[pos++];
  if (sign !== 2 && sign !== 3) {
    return;
  }
  const r = OS2ECP(proof.slice(pos, pos + N2));
  if (!r) {
    return;
  }
  pos += N2;
  const c = proof.slice(pos, pos + N);
  pos += N;
  const s = proof.slice(pos, pos + N2);
  return { r, c: OS2IP(c), s: OS2IP(s) };
}

async function hashToCurve(message: Buffer, publicKey: Buffer): Promise<any> {
  for (let i = 0; i < LIMIT; i++) {
    const ctr = I2OSP(new BN(i), 4);
    const digest = Buffer.from(
      await SHA256(
        concatArrays([
          new Uint8Array(message),
          new Uint8Array(publicKey),
          new Uint8Array(ctr),
        ])
      )
    );

    let point = OS2ECP(digest);
    if (point) {
      for (let j = 1; j < CO_FACTOR; j *= 2) {
        point = point.add(point);
      }
      return point;
    }
  }
  return null;
}

async function hashPoints(...args: Point[]) {
  let hash = new Uint8Array();
  for (let i = 0; i < args.length; i++) {
    hash = concatArrays([hash, new Uint8Array(ECP2OS(args[i]))]);
  }
  const digest = Buffer.from(await SHA256(hash));
  return OS2IP(digest.slice(0, N));
}

export async function vrfVerify(
  publicKey: Buffer,
  message: Buffer,
  proof: Buffer,
  value: Buffer
) {
  if (!checkHash(proof, value)) {
    throw new Error("Fetched name is different than name in proof");
  }
  const o = decodeProof(proof);
  if (!o) {
    throw new Error("Proof decoding failed");
  }
  const P1 = OS2ECP(publicKey);
  if (!P1) {
    throw new Error("VRF public key parsing failed");
  }
  const u = P1.mul(o.c).add(G.mul(o.s));
  const h = await hashToCurve(message, publicKey);
  const v = o.r.mul(o.c).add(h.mul(o.s));
  const c = await hashPoints(G, h, P1, o.r, u, v);
  if (!c.eq(o.c)) {
    throw new Error("Verification went through but failed");
  }
}
