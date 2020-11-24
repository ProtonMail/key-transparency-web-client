import { getSignedKeyLists } from './helpers/api/keys';
import { getCertificate, getLatestVerifiedEpoch, getProof } from './helpers/api/keyTransparency';
import { Api } from './helpers/interfaces/Api';
import { SignedKeyListInfo } from './helpers/interfaces/SignedKeyList';
import { EpochExtended, Proof } from './interfaces';

const cachedEpochs: Map<number, EpochExtended> = new Map();
const cachedProofs: Map<[string, number], Proof> = new Map();

export async function fetchEpoch(epochID: number, api: Api) {
    const cachedEpoch = cachedEpochs.get(epochID);
    if (cachedEpoch) {
        return cachedEpoch;
    }

    const epoch = await api(getCertificate({ EpochID: epochID }));
    cachedEpochs.set(epochID, epoch as EpochExtended);

    return epoch as EpochExtended;
}

export async function fetchProof(epochID: number, email: string, api: Api) {
    const cachedProof = cachedProofs.get([email, epochID]);
    if (cachedProof) {
        return cachedProof;
    }

    const { Code: code, ...proof } = await api(getProof({ EpochID: epochID, Email: email }));
    cachedProofs.set([email, epochID], proof as Proof);

    return proof as Proof;
}

export async function getParsedSignedKeyLists(
    api: Api,
    epochID: number,
    email: string,
    includeLastExpired: boolean
): Promise<SignedKeyListInfo[]> {
    const fetchedSKLs: {
        SignedKeyLists: SignedKeyListInfo[];
    } = await api(getSignedKeyLists({ SinceEpochID: epochID, Email: email }));
    /*
    fetchedSKLs.SignedKeyLists contains:
        - the last expired SKL, i.e. the newest SKL such that MinEpochID <= SinceEpochID
        - all SKLs such that MinEpochID > SinceEpochID
        - the latest SKL, i.e. such that MinEpochID is null
    in chronological order.
    */
    return fetchedSKLs.SignedKeyLists.slice(includeLastExpired ? 0 : 1);
}

export async function getVerifiedEpoch(
    api: Api,
    addressID: string
): Promise<{ Data: string; Signature: string } | undefined> {
    let verifiedEpoch: { Data: string; Signature: string };
    try {
        verifiedEpoch = await api(getLatestVerifiedEpoch({ AddressID: addressID }));
    } catch (err) {
        return;
    }

    return verifiedEpoch;
}
