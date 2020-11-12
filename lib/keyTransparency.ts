import {
    verifyMessage,
    OpenPGPKey,
    getSHA256Fingerprints,
    getKeys,
    VERIFICATION_STATUS,
    getSignature,
    createMessage,
    signMessage,
    OpenPGPSignature,
    encryptMessage,
    decryptMessage,
    getMessage,
} from 'pmcrypto';
import { Api } from './helpers/interfaces/Api';
import { Key } from './helpers/interfaces/Key';
import { getProof, getCertificate, getLatestVerifiedEpoch, uploadVerifiedEpoch } from './helpers/api/keyTransparency';
import { queryAddresses } from './helpers/api/addresses';
import { getSignedKeyLists, updateSignedKeyList } from './helpers/api/keys';
import { getItem, setItem, removeItem, hasStorage } from './helpers/helpers/storage';
import { getCanonicalEmailMap } from './helpers/api/helpers/canonicalEmailMap';
import { parseCertificate, checkAltName, verifyLEcert, verifySCT } from './certTransparency';
import { verifyProof } from './merkleTree';

// const expectedEpochInterval = 4 * 60 * 60 * 1000;
const maximumEpochInterval = 24 * 60 * 60 * 1000;

function compareKeyInfo(
    keyInfo: {
        Fingerprint: string;
        SHA256Fingerprints: string[];
        Primary: number;
        Flags: number;
    },
    sklKeyInfo: {
        Fingerprint: string;
        SHA256Fingerprints: string[];
        Primary: number;
        Flags: number;
    }
) {
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

async function verifyKeyLists(
    keyList: {
        Flags: number;
        PublicKey: OpenPGPKey;
    }[],
    signedKeyListData: {
        Fingerprint: string;
        SHA256Fingerprints: string[];
        Primary: number;
        Flags: number;
    }[]
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
        try {
            compareKeyInfo(key, signedKeyListInfo[i]);
        } catch (error) {
            throw new Error(`Key info mismatch: ${error.message}`);
        }
    });
}

async function verifyEpoch(
    epoch: {
        EpochID: number;
        TreeHash: string;
        ChainHash: string;
        Certificate: string;
        IssuerKeyHash: string;
    },
    email: string,
    signedKeyListArmored: string,
    api: Api
): Promise<number> {
    // Fetch and verify proof
    const { Name, Proof, Revision, Neighbors } = await api(getProof({ EpochID: epoch.EpochID, Email: email }));
    await verifyProof(Name, Revision, Proof, Neighbors, epoch.TreeHash, signedKeyListArmored, email);

    // Parse and verify certificate
    let certificate;
    try {
        certificate = parseCertificate(epoch.Certificate);
    } catch (err) {
        throw new Error(`Certificate parsing failed with error: ${err.message}`);
    }
    if (!certificate) {
        throw new Error('Certificate is undefined');
    }
    checkAltName(certificate, epoch);
    await verifyLEcert(certificate);
    verifySCT(certificate);

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

async function parseKeyLists(
    keyList: {
        Flags: number;
        PublicKey: string;
    }[],
    signedKeyListData: string
): Promise<{
    signedKeyListData: { Fingerprint: string; SHA256Fingerprints: string[]; Primary: number; Flags: number }[];
    parsedKeyList: { Flags: number; PublicKey: OpenPGPKey }[];
}> {
    return {
        signedKeyListData: JSON.parse(signedKeyListData),
        parsedKeyList: await Promise.all(
            keyList.map(async (key) => {
                return {
                    Flags: key.Flags,
                    PublicKey: (await getKeys(key.PublicKey))[0],
                };
            })
        ),
    };
}

async function checkSignature(message: string, publicKeys: OpenPGPKey[], signature: string) {
    const { verified } = await verifyMessage({
        message: createMessage(message),
        publicKeys,
        signature: await getSignature(signature),
    });
    if (verified !== VERIFICATION_STATUS.SIGNED_AND_VALID) {
        throw new Error('Signature verification failed');
    }
}

export async function verifyPublicKeys(
    keyList: {
        Flags: number;
        PublicKey: string;
    }[],
    email: string,
    signedKeyList: {
        MinEpochID: number;
        MaxEpochID: number;
        Data: string;
        Signature: string;
    },
    api: Api
): Promise<void> {
    const canonicalEmail = (await getCanonicalEmailMap([email], api))[email];
    if (!canonicalEmail) {
        throw new Error(`Failed to canonize email ${email}`);
    }
    // Parse key lists
    const { signedKeyListData, parsedKeyList } = await parseKeyLists(keyList, signedKeyList.Data);

    // Check signature
    await checkSignature(
        signedKeyList.Data,
        parsedKeyList.map((key) => key.PublicKey),
        signedKeyList.Signature
    );

    // Check key list and signed key list
    try {
        await verifyKeyLists(parsedKeyList, signedKeyListData);
    } catch (error) {
        throw new Error(`Mismatch found between key list and signed key list. ${error.message}`);
    }

    // If signedKeyList is (allegedly) too young, users is warned and verification cannot continue
    if (signedKeyList.MaxEpochID === null) {
        /* eslint-disable no-console */
        console.warn('Signed key list has not been included in an epoch yet');
        /* eslint-enable no-console */
        return;
    }

    // Verify latest epoch
    const maxEpoch: {
        EpochID: number;
        TreeHash: string;
        ChainHash: string;
        Certificate: string;
        IssuerKeyHash: string;
    } = await api(getCertificate({ EpochID: signedKeyList.MaxEpochID }));

    const returnedDate = await verifyEpoch(maxEpoch, canonicalEmail, signedKeyList.Data, api);

    if (Date.now() - returnedDate > maximumEpochInterval) {
        throw new Error('Returned date is older than the maximum epoch interval');
    }
}

// TODO: fix signature and/or packet types
function getSignatureTime(signature: OpenPGPSignature): number {
    const packet = signature.packets.findPacket(2);
    if (!packet) {
        throw new Error('Signature contains no signature packet');
    }
    return (packet as any).created.getTime();
}

async function getParsedSignedKeyLists(
    api: Api,
    epochID: number,
    email: string,
    includeLastExpired: boolean
): Promise<{ MaxEpochID: number; MinEpochID: number; Data: string; Signature: string }[]> {
    const fetchedSKLs: {
        SignedKeyLists: {
            MaxEpochID: number;
            MinEpochID: number;
            Data: string;
            Signature: string;
        }[];
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

export async function ktSelfAudit(
    api: Api,
    userKey: Key
): Promise<
    Map<
        string,
        {
            EpochID: number;
            TreeHash: string;
            ChainHash: string;
            Certificate: string;
            IssuerKeyHash: string;
            CertificateDate: number;
        }
    >
> {
    const addresses: {
        ID: string;
        Email: string;
        SignedKeyList: {
            MaxEpochID: number;
            MinEpochID: number;
            Data: string;
            Signature: string;
        };
        Keys: {
            ID: string;
            Primary: number;
            Flags: number;
            PublicKey: string;
            PrivateKey: string;
        }[];
    }[] = await api(queryAddresses());

    if (addresses.length === 0) {
        throw new Error('No addresses to audit');
    }

    const addressesToVerifiedEpochs = new Map();
    const canonicalEmailMap = await getCanonicalEmailMap(
        addresses.map((address) => address.Email),
        api
    );

    for (let i = 0; i < addresses.length; i++) {
        const address = addresses[i];
        const email = canonicalEmailMap[address.Email];
        if (!email) {
            throw new Error(`Failed to canonize email ${address.Email}`);
        }

        // Parse key lists
        const { signedKeyListData, parsedKeyList } = await parseKeyLists(address.Keys, address.SignedKeyList.Data);

        const ktBlob = getItem(`kt:${address.ID}`);
        if (ktBlob !== undefined && ktBlob !== null) {
            let decryptedBlob;
            try {
                decryptedBlob = JSON.parse(
                    (
                        await decryptMessage({
                            message: await getMessage(ktBlob),
                            privateKeys: await getKeys(userKey.PrivateKey),
                        })
                    ).data
                );
            } catch (error) {
                throw new Error('Decrytption of ktBlob in localStorage failed');
            }

            const localSKL = decryptedBlob.SignedKeyList;
            const localEpoch = decryptedBlob.Epoch;

            const fetchedSKLs = await getParsedSignedKeyLists(api, localEpoch.EpochID, email, false);

            const localSignature = await getSignature(localSKL.Signature);

            const includedSKLarray: {
                MaxEpochID: number;
                MinEpochID: number;
                Data: string;
                Signature: string;
            }[] = await Promise.all(
                fetchedSKLs.filter(async (skl) => {
                    const sklSignature = await getSignature(skl.Signature);
                    return (
                        (skl.MinEpochID === null || skl.MinEpochID > localEpoch.EpochID) &&
                        getSignatureTime(sklSignature) >= getSignatureTime(localSignature)
                    );
                })
            );
            // NOTE: "first" in 1b is interpreted as "in position 0", since getParsedSignedKeyLists returns ordered SKLs
            const includedSKL = includedSKLarray.shift();

            if (!includedSKL) {
                throw new Error('Included signed key list not found');
            }

            const includedSignature = await getSignature(includedSKL.Signature);

            if (getSignatureTime(includedSignature) - getSignatureTime(localSignature) > maximumEpochInterval) {
                throw new Error(
                    'Signed key list in localStorage is older than included signed key list by more than maximumEpochInterval'
                );
            }

            // Check signature
            await checkSignature(
                includedSKL.Data,
                parsedKeyList.map((key) => key.PublicKey),
                includedSKL.Signature
            );

            if (includedSKL.MinEpochID !== null) {
                const minEpoch: {
                    EpochID: number;
                    TreeHash: string;
                    ChainHash: string;
                    Certificate: string;
                    IssuerKeyHash: string;
                } = await api(getCertificate({ EpochID: includedSKL.MinEpochID }));

                const returnedDate = await verifyEpoch(minEpoch, email, includedSKL.Data, api);

                if (returnedDate - getSignatureTime(localSignature) > maximumEpochInterval) {
                    throw new Error(
                        'Returned date is older than the signed key list in localStorage by more than maximumEpochInterval'
                    );
                }

                const err = removeItem(`kt:${address.ID}`);
                if (!err) {
                    throw new Error('Removing from localStorage failed');
                }
            } else if (Date.now() - getSignatureTime(localSignature) > maximumEpochInterval) {
                throw new Error('Signed key list in localStorage is older than maximumEpochInterval');
            }
        }

        // Check key list and signed key list
        try {
            await verifyKeyLists(parsedKeyList, signedKeyListData);
        } catch (error) {
            throw new Error(`Mismatch found between key list and signed key list. ${error.message}`);
        }

        // Check signature
        await checkSignature(
            address.SignedKeyList.Data,
            parsedKeyList.map((key) => key.PublicKey),
            address.SignedKeyList.Signature
        );

        const signatureSKL = await getSignature(address.SignedKeyList.Signature);
        if (address.SignedKeyList.MinEpochID === null) {
            if (Date.now() - getSignatureTime(signatureSKL) > maximumEpochInterval) {
                throw new Error('Signed key list is older than maximumEpochInterval');
            }
        }

        const verifiedEpoch: {
            Data: string;
            Signature: string;
        } = await api(getLatestVerifiedEpoch({ AddressID: address.ID }));

        // Check signature
        await checkSignature(
            verifiedEpoch.Data,
            parsedKeyList.map((key) => key.PublicKey),
            verifiedEpoch.Signature
        );

        const verifiedEpochData = JSON.parse(verifiedEpoch.Data);

        // Fetch all new SKLs and corresponding epochs
        const newerSKLs = await getParsedSignedKeyLists(api, verifiedEpochData.EpochID, email, true);

        if (newerSKLs.length > 3) {
            throw new Error('More than 3 SKLs found');
        }

        // The epochs are fetched according to when SKLs changed. There could be at most one such that MinEpochID is null.
        // That's excluded because it does not belong to any epoch.
        const newerEpochs = await Promise.all(
            newerSKLs
                .filter((skl) => skl.MinEpochID !== null)
                .map(async (skl) => {
                    const epoch: {
                        EpochID: number;
                        TreeHash: string;
                        ChainHash: string;
                        Certificate: string;
                        IssuerKeyHash: string;
                    } = await api(getCertificate({ EpochID: skl.MinEpochID }));

                    const { Revision }: { Revision: number } = await api(
                        getProof({ EpochID: epoch.EpochID, Email: email })
                    );

                    return {
                        ...epoch,
                        Revision,
                        CertificateDate: 0,
                    };
                })
        );

        // Check revision consistency
        newerEpochs.reduce((previousEpoch, currentEpoch) => {
            if (currentEpoch.Revision !== previousEpoch.Revision + 1) {
                throw new Error('Revisions for new signed key lists have not been incremented correctly');
            }
            return currentEpoch;
        });

        // If there aren't any new epochs in which a SKL changed, than newerEpochs will only have one element.
        // That corresponds to the old SKL (NOTE: because any SKL with MinEpochID equal to null was ignored when constructing newerEpochs).
        if (newerEpochs.length === 1) {
            addressesToVerifiedEpochs.set(
                address.ID,
                newerSKLs.find((skl) => skl.MaxEpochID === newerEpochs[0].EpochID)!.MaxEpochID
            );
            continue;
        }

        let previousSKL;
        if (address.SignedKeyList.MinEpochID === null || address.SignedKeyList.MinEpochID > newerEpochs[0].EpochID) {
            // NOTE: "first" in 10c is interpreted as "in position 0", since getParsedSignedKeyLists returns ordered SKLs
            previousSKL = newerSKLs.shift();
        }

        for (let j = 0; j < newerEpochs.length; j++) {
            const epoch = newerEpochs[j];

            const previousEpoch = j === 0 ? verifiedEpochData : newerEpochs[j - 1];
            if (epoch.EpochID <= previousEpoch.EpochID) {
                throw new Error('Current epoch is older than or equal to previous epoch');
            }

            const includedSKL =
                (address.SignedKeyList.MinEpochID > epoch.EpochID && previousSKL) ||
                address.SignedKeyList.MinEpochID === null
                    ? previousSKL
                    : address.SignedKeyList;

            epoch.CertificateDate = await verifyEpoch(epoch, email, includedSKL!.Data, api);

            if (
                epoch.CertificateDate < previousEpoch.CertificateDate &&
                epoch.CertificateDate > previousEpoch.CertificateDate + maximumEpochInterval
            ) {
                throw new Error('Certificate date control error');
            }

            if (
                address.SignedKeyList.MinEpochID > epoch.EpochID &&
                epoch.CertificateDate > getSignatureTime(signatureSKL) + maximumEpochInterval
            ) {
                throw new Error(
                    "The certificate date is older than signed key list's signature by more than maximumEpochInterval"
                );
            }
        }

        if (newerEpochs[newerEpochs.length - 1].CertificateDate >= maximumEpochInterval) {
            throw new Error('Last certificate date is older than maximumEpochInterval');
        }

        const bodyData = {
            EpochID: newerEpochs[newerEpochs.length - 1].EpochID,
            ChainHash: newerEpochs[newerEpochs.length - 1].ChainHash,
            CertificateDate: newerEpochs[newerEpochs.length - 1].CertificateDate,
        };

        await api(
            uploadVerifiedEpoch({
                AddressID: address.ID,
                Data: bodyData,
                Signature: (
                    await signMessage({
                        data: JSON.stringify(bodyData),
                        privateKeys: await getKeys(address.Keys[0].PrivateKey),
                        detached: true,
                    })
                ).signature,
            })
        );

        addressesToVerifiedEpochs.set(address.ID, newerEpochs[newerEpochs.length - 1]);
    }

    return addressesToVerifiedEpochs;
}

export async function updateKT(
    address: {
        ID: string;
        Email: string;
        SignedKeyList: {
            MaxEpochID: number;
            MinEpochID: number;
            Data: string;
            Signature: string;
        };
        Keys: {
            ID: string;
            Primary: number;
            Flags: number;
            PublicKey: string;
            PrivateKey: string;
        }[];
    },
    api: Api,
    userKey: Key
): Promise<void> {
    // TODO: 1, this should be checked against some sort of flag that selfaudit saves, say, the component state

    let addressesToVerifiedEpochs;
    try {
        // TODO: this result should be taken from, say, the component's state rather than from calling selfaudit
        addressesToVerifiedEpochs = await ktSelfAudit(api, userKey);
    } catch (error) {
        throw new Error(`Self audit failed with error "${error.message}"`);
    }

    const verifiedEpoch = addressesToVerifiedEpochs.get(address.ID);
    if (!verifiedEpoch) {
        throw new Error(`The address ${address.ID} was not self audited`);
    }

    if (Date.now() - verifiedEpoch.CertificateDate > maximumEpochInterval) {
        throw new Error('The last verified epoch is too old');
    }

    // TODO: move this logic to the app. Alternatively, this is the only bit that might make sense to leave here
    await api(
        updateSignedKeyList(
            { AddressID: address.ID },
            {
                SignedKeyList: {
                    Data: address.SignedKeyList.Data,
                    Signature: address.SignedKeyList.Signature,
                },
            }
        )
    );

    const message = JSON.stringify({
        Epoch: {
            EpochID: verifiedEpoch.EpochID,
            TreeHash: verifiedEpoch.TreeHash,
            ChainHash: verifiedEpoch.ChainHash,
        },
        SignedKeyList: {
            Data: address.SignedKeyList.Data,
            Signature: address.SignedKeyList.Signature,
        },
    });

    if (hasStorage()) {
        const err = setItem(
            `kt:${address.ID}`,
            (await encryptMessage({ data: message, publicKeys: await getKeys(userKey.PublicKey) })).data
        );
        if (!err) {
            throw new Error('Saving to localStorage failed');
        }
    }
}
