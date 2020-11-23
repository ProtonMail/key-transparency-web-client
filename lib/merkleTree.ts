import { SHA256, arrayToHexString, concatArrays, binaryStringToArray } from 'pmcrypto';
import { vrfVerify } from './vrf';
import { vrfHexKey } from './constants';

const LEFT_N = 1; // left neighbor

function hexStringToArray(hex: string): Uint8Array {
    const result = new Uint8Array(hex.length >> 1);
    for (let k = 0; k < hex.length >> 1; k++) {
        result[k] = parseInt(hex.substr(k << 1, 2), 16);
    }
    return result;
}

export async function verifyChainHash(TreeHash: string, PreviousChainHash: string, ChainHash: string) {
    if (ChainHash !== arrayToHexString(await SHA256(hexStringToArray(`${PreviousChainHash}${TreeHash}`)))) {
        throw new Error('Chain hash of fetched epoch is not consistent');
    }
}

export async function verifyProof(
    Name: string,
    Revision: number,
    Proof: string,
    Neighbors: string[],
    TreeHash: string,
    sklData: string,
    email: string
) {
    // Verify proof
    const pkBuffer = Buffer.from(hexStringToArray(vrfHexKey));
    const emailBuffer = Buffer.from(binaryStringToArray(email));
    const proofBuffer = Buffer.from(hexStringToArray(Proof));
    const valueBuffer = Buffer.from(hexStringToArray(Name));

    try {
        await vrfVerify(pkBuffer, emailBuffer, proofBuffer, valueBuffer);
    } catch (err) {
        throw new Error(`VRF verification failed with error "${err.message}"`);
    }

    // Parse proof and verify epoch against proof
    let val = await SHA256(
        concatArrays([
            await SHA256(binaryStringToArray(sklData)),
            new Uint8Array([Revision >>> 24, Revision >>> 16, Revision >>> 8, Revision]),
        ])
    );
    const emptyNode = new Uint8Array(32);
    const key = hexStringToArray(Name);

    for (let i = Neighbors.length - 1; i >= 0; i--) {
        const bit = (key[Math.floor(i / 8) % 32] >>> (8 - (i % 8) - 1)) & 1;
        const neighbor = Neighbors[i] === null ? emptyNode : hexStringToArray(Neighbors[i]);
        const toHash = bit === LEFT_N ? concatArrays([neighbor, val]) : concatArrays([val, neighbor]);
        val = await SHA256(toHash);
    }

    if (arrayToHexString(val) !== TreeHash) {
        throw new Error('Hash chain does not result in TreeHash');
    }
}
