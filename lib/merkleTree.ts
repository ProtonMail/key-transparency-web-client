import { SHA256, arrayToHexString, concatArrays, binaryStringToArray } from 'pmcrypto';
import { ecvrf } from 'vrf.js';
import { stringToUint8Array } from './helpers/helpers/encoding';
import { vrfHexKey } from './certificates';

const LEFT_N = 1; // left neighbor

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
    const publicKey = Buffer.from(stringToUint8Array(vrfHexKey));
    const message = Buffer.from(binaryStringToArray(email));
    const proofBuffer = Buffer.from(stringToUint8Array(Proof));
    const valueBuffer = Buffer.from(stringToUint8Array(Name));

    const verifiedProof = ecvrf.verify(publicKey, message, proofBuffer, valueBuffer);
    if (!verifiedProof) {
        throw new Error('Proof verification failed');
    }

    // Parse proof and verify epoch against proof
    let val = await SHA256(
        concatArrays([
            await SHA256(binaryStringToArray(sklData)),
            binaryStringToArray('.'),
            binaryStringToArray(`${Revision}`),
        ])
    );
    const emptyNode = new Uint8Array(32);
    const key = stringToUint8Array(Name);

    for (let i = Neighbors.length - 1; i >= 0; i--) {
        const bit = (key[Math.floor(i / 8) % 32] >> (8 - (i % 8) - 1)) & 1;
        const neighbor = Neighbors[i] === null ? emptyNode : stringToUint8Array(Neighbors[i]);
        const toHash = bit === LEFT_N ? concatArrays([neighbor, val]) : concatArrays([val, neighbor]);
        val = await SHA256(toHash);
    }

    if (arrayToHexString(val) !== TreeHash) {
        throw new Error('Hash chain does not result in TreeHash');
    }
}
