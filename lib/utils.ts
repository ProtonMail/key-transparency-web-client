import {
    verifyMessage,
    OpenPGPKey,
    getSHA256Fingerprints,
    getKeys,
    VERIFICATION_STATUS,
    getSignature,
    createMessage,
    OpenPGPSignature,
} from 'pmcrypto';
import Certificate from 'pkijs/src/Certificate';
import { Api } from './helpers/interfaces/Api';
import { Epoch, EpochExtended, KeyInfo } from './interfaces';
import { SignedKeyListInfo } from './helpers/interfaces/SignedKeyList';
import { fetchProof, fetchEpoch } from './fetchHelper';
import { parseCertificate, checkAltName, verifyLEcert, verifySCT } from './certTransparency';
import { verifyProof, verifyChainHash } from './merkleTree';
import { MAX_EPOCH_INTERVAL } from './constants';

export function compareKeyInfo(keyInfo: KeyInfo, sklKeyInfo: KeyInfo) {
    // Check fingerprints
    if (keyInfo.Fingerprint !== sklKeyInfo.Fingerprint) {
        throw new Error('Fingerprints');
    }

    // Check SHA256Fingerprints
    if (keyInfo.SHA256Fingerprints.length !== sklKeyInfo.SHA256Fingerprints.length) {
        throw new Error('SHA256Fingerprints length');
    }
    keyInfo.SHA256Fingerprints.forEach((sha256Fingerprint, i) => {
        if (sha256Fingerprint !== sklKeyInfo.SHA256Fingerprints[i]) {
            throw new Error('SHA256Fingerprints');
        }
    });

    // Check Flags
    if (keyInfo.Flags !== sklKeyInfo.Flags) {
        throw new Error('Flags');
    }

    // Check primariness
    if (keyInfo.Primary !== sklKeyInfo.Primary) {
        throw new Error('Primariness');
    }
}

export async function verifyKeyLists(
    keyList: {
        Flags: number;
        PublicKey: OpenPGPKey;
    }[],
    signedKeyListData: KeyInfo[]
) {
    // Check arrays validity
    if (keyList.length === 0) {
        throw new Error('No keys detected');
    }
    if (keyList.length !== signedKeyListData.length) {
        throw new Error('Key list and signed key list have different lengths');
    }

    // Prepare key lists
    const keyListInfo = await Promise.all(
        keyList.map(async (key, i) => {
            return {
                Fingerprint: key.PublicKey.getFingerprint().toLowerCase(),
                SHA256Fingerprints: (await getSHA256Fingerprints(key.PublicKey)).map((sha256fingerprint: string) =>
                    sha256fingerprint.toLowerCase()
                ),
                Primary: i === 0 ? 1 : 0,
                Flags: key.Flags,
            };
        })
    );
    keyListInfo.sort((key1, key2) => {
        return key1.Fingerprint.localeCompare(key2.Fingerprint);
    });

    const signedKeyListInfo = signedKeyListData.map((keyInfo) => {
        return {
            ...keyInfo,
            Fingerprint: keyInfo.Fingerprint.toLowerCase(),
            SHA256Fingerprints: keyInfo.SHA256Fingerprints.map((sha256fingerprint: string) =>
                sha256fingerprint.toLowerCase()
            ),
        };
    });
    signedKeyListInfo.sort((key1, key2) => {
        return key1.Fingerprint.localeCompare(key2.Fingerprint);
    });

    // Check keys
    keyListInfo.forEach((key, i) => {
        compareKeyInfo(key, signedKeyListInfo[i]);
    });
}

export async function verifyEpoch(
    epoch: Epoch,
    email: string,
    signedKeyListArmored: string,
    api: Api
): Promise<number> {
    // Fetch and verify proof
    const proof = await fetchProof(epoch.EpochID, email, api);
    await verifyProof(proof, epoch.TreeHash, signedKeyListArmored, email);

    // Verify ChainHash
    await verifyChainHash(epoch.TreeHash, epoch.PrevChainHash, epoch.ChainHash);

    // Parse and verify certificate
    let certificate: Certificate;
    try {
        certificate = parseCertificate(epoch.Certificate);
    } catch (err) {
        throw new Error(`Certificate parsing failed with error: ${err.message}`);
    }
    if (!certificate) {
        throw new Error('Certificate is undefined');
    }
    checkAltName(certificate, epoch.ChainHash, epoch.EpochID);
    await verifyLEcert(certificate);
    await verifySCT(certificate);

    let returnedDate: number;
    switch (certificate.notBefore.toJSON().type) {
        case 0:
        case 1:
            returnedDate = certificate.notBefore.toJSON().value.getTime();
            break;
        default:
            throw new Error(`Certificate's notBefore date is invalid (type = ${certificate.notBefore.toJSON().type})`);
    }

    return returnedDate;
}

export async function parseKeyLists(
    keyList: {
        Flags: number | undefined;
        PublicKey: string;
    }[],
    signedKeyListData: string
): Promise<{
    signedKeyListData: KeyInfo[];
    parsedKeyList: { Flags: number; PublicKey: OpenPGPKey }[];
}> {
    return {
        signedKeyListData: JSON.parse(signedKeyListData),
        parsedKeyList: await Promise.all(
            keyList.map(async (key) => {
                return {
                    Flags: key.Flags ? key.Flags : 0,
                    PublicKey: (await getKeys(key.PublicKey))[0],
                };
            })
        ),
    };
}

export async function checkSignature(
    message: string,
    publicKeys: OpenPGPKey[],
    signature: string,
    failMessage: string
) {
    const { verified } = await verifyMessage({
        message: createMessage(message),
        publicKeys,
        signature: await getSignature(signature),
    });
    if (verified !== VERIFICATION_STATUS.SIGNED_AND_VALID) {
        throw new Error(`Signature verification failed (${failMessage})`);
    }
}

export function getSignatureTime(signature: OpenPGPSignature): number {
    const packet = signature.packets.findPacket(2);
    if (!packet) {
        throw new Error('Signature contains no signature packet');
    }
    return (packet as any).created.getTime();
}

export function compareTimes(time: number, refereceTime?: number) {
    if (!refereceTime) {
        refereceTime = Date.now();
    }
    return refereceTime - time > MAX_EPOCH_INTERVAL;
}

export async function verifyCurrentEpoch(signedKeyList: SignedKeyListInfo, email: string, api: Api) {
    const currentEpoch = await fetchEpoch(signedKeyList.MaxEpochID as number, api);

    const returnedDate: number = await verifyEpoch(currentEpoch, email, signedKeyList.Data, api);

    if (compareTimes(returnedDate)) {
        throw new Error('Returned date is older than MAX_EPOCH_INTERVAL');
    }

    const { Revision }: { Revision: number } = await fetchProof(currentEpoch.EpochID, email, api);

    return {
        ...currentEpoch,
        Revision,
        CertificateDate: returnedDate,
    } as EpochExtended;
}
