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
import Certificate from 'pkijs/src/Certificate';
import { Api } from './helpers/interfaces/Api';
import { Address } from './helpers/interfaces/Address';
import { CachedKey } from './helpers/interfaces/CachedKey';
import { Epoch, EpochExtended, KeyInfo } from './interfaces';
import { SignedKeyListInfo } from './helpers/interfaces/SignedKeyList';
import { getProof, getCertificate, getLatestVerifiedEpoch, uploadVerifiedEpoch } from './helpers/api/keyTransparency';
import { getSignedKeyLists } from './helpers/api/keys';
import { getItem, setItem, removeItem, hasStorage } from './helpers/storage';
import { getCanonicalEmailMap } from './helpers/api/canonicalEmailMap';
import { parseCertificate, checkAltName, verifyLEcert, verifySCT } from './certTransparency';
import { verifyProof, verifyChainHash } from './merkleTree';
import { KT_STATUS } from './constants';

const maximumEpochInterval = 24 * 60 * 60 * 1000;
const expectedEpochInterval = 4 * 60 * 60 * 1000;

function compareKeyInfo(keyInfo: KeyInfo, sklKeyInfo: KeyInfo) {
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

async function verifyEpoch(epoch: Epoch, email: string, signedKeyListArmored: string, api: Api): Promise<number> {
    // Fetch and verify proof
    const { Name, Proof, Revision, Neighbors } = await api(getProof({ EpochID: epoch.EpochID, Email: email }));
    await verifyProof(Name, Revision, Proof, Neighbors, epoch.TreeHash, signedKeyListArmored, email);

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

async function parseKeyLists(
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
    signedKeyList: SignedKeyListInfo | undefined,
    api: Api
): Promise<{ code: number; error: string }> {
    if (!signedKeyList) {
        return {
            code: KT_STATUS.KT_WARNING,
            error: 'Signed key list undefined',
        };
    }

    let canonicalEmail: string | undefined;
    try {
        canonicalEmail = (await getCanonicalEmailMap([email], api))[email];
    } catch (err) {
        return { code: KT_STATUS.KT_FAILED, error: err.message };
    }
    if (!canonicalEmail) {
        return {
            code: KT_STATUS.KT_FAILED,
            error: `Failed to canonize email "${email}"`,
        };
    }
    // Parse key lists
    const { signedKeyListData, parsedKeyList } = await parseKeyLists(keyList, signedKeyList.Data);

    // Check signature
    try {
        await checkSignature(
            signedKeyList.Data,
            parsedKeyList.map((key) => key.PublicKey),
            signedKeyList.Signature
        );
    } catch (err) {
        return { code: KT_STATUS.KT_FAILED, error: err.message };
    }

    // Check key list and signed key list
    try {
        await verifyKeyLists(parsedKeyList, signedKeyListData);
    } catch (error) {
        return {
            code: KT_STATUS.KT_FAILED,
            error: `Mismatch found between key list and signed key list. ${error.message}`,
        };
    }

    // If signedKeyList is (allegedly) too young, users is warned and verification cannot continue
    if (signedKeyList.MaxEpochID === null) {
        return {
            code: KT_STATUS.KT_WARNING,
            error: 'The keys were generated too recently to be included in key transparency',
        };
    }

    // Verify latest epoch
    let maxEpoch: Epoch;
    try {
        maxEpoch = await api(getCertificate({ EpochID: signedKeyList.MaxEpochID }));
    } catch (err) {
        return { code: KT_STATUS.KT_FAILED, error: err.message };
    }

    let returnedDate: number;
    try {
        returnedDate = await verifyEpoch(maxEpoch, canonicalEmail, signedKeyList.Data, api);
    } catch (err) {
        return { code: KT_STATUS.KT_FAILED, error: err.message };
    }

    if (Date.now() - returnedDate > maximumEpochInterval) {
        return {
            code: KT_STATUS.KT_FAILED,
            error: 'Returned date is older than the maximum epoch interval',
        };
    }

    return { code: KT_STATUS.KT_PASSED, error: '' };
}

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

async function verifyCurrentEpoch(signedKeyList: SignedKeyListInfo, email: string, api: Api) {
    const currentEpoch: Epoch = await api(
        getCertificate({
            EpochID: signedKeyList.MaxEpochID as number,
        })
    );

    const returnedDate: number = await verifyEpoch(currentEpoch, email, signedKeyList.Data, api);

    if (Date.now() - returnedDate > maximumEpochInterval) {
        throw new Error('Returned date is older than the maximum epoch interval');
    }

    const { Revision }: { Revision: number } = await api(getProof({ EpochID: currentEpoch.EpochID, Email: email }));

    return {
        ...currentEpoch,
        Revision,
        CertificateDate: returnedDate,
    } as EpochExtended;
}

export async function ktSelfAudit(
    apis: Api[],
    addresses: Address[],
    userKeys: CachedKey[]
): Promise<
    Map<
        string,
        {
            code: number;
            verifiedEpoch?: EpochExtended;
            error: string;
        }
    >
> {
    const [api, silentApi] = apis;

    const addressesToVerifiedEpochs: Map<
        string,
        {
            code: number;
            verifiedEpoch?: EpochExtended;
            error: string;
        }
    > = new Map();
    const canonicalEmailMap = await getCanonicalEmailMap(
        addresses.map((address) => address.Email),
        api
    );

    const userPrivateKeys = (
        await Promise.all(
            userKeys.map(async (cachedKey) => {
                if (cachedKey.error) {
                    return;
                }
                if (!cachedKey.privateKey) {
                    try {
                        [cachedKey.privateKey] = await getKeys(cachedKey.Key.PrivateKey);
                    } catch (err) {
                        return;
                    }
                }
                return cachedKey.privateKey;
            })
        )
    ).filter((privateKey: OpenPGPKey | undefined): privateKey is OpenPGPKey => {
        return privateKey !== undefined;
    });

    for (let i = 0; i < addresses.length; i++) {
        const address = addresses[i];
        const email = canonicalEmailMap[address.Email];
        if (!email) {
            addressesToVerifiedEpochs.set(address.ID, {
                code: KT_STATUS.KT_FAILED,
                error: `Failed to canonize email ${address.Email}`,
            });
            continue;
        }

        if (!address.SignedKeyList) {
            addressesToVerifiedEpochs.set(address.ID, {
                code: KT_STATUS.KT_FAILED,
                error: `Signed key list not found for ${address.Email}`,
            });
            continue;
        }

        // Parse key lists
        const { signedKeyListData, parsedKeyList } = await parseKeyLists(
            address.Keys.map((key) => ({
                Flags: key.Flags,
                PublicKey: key.PublicKey,
            })),
            address.SignedKeyList.Data
        );

        const ktBlob = hasStorage() ? getItem(`kt:${address.ID}`) : undefined;
        if (ktBlob !== undefined && ktBlob !== null) {
            let decryptedBlob;
            try {
                decryptedBlob = JSON.parse(
                    (
                        await decryptMessage({
                            message: await getMessage(ktBlob),
                            privateKeys: userPrivateKeys,
                        })
                    ).data
                );
            } catch (error) {
                addressesToVerifiedEpochs.set(address.ID, {
                    code: KT_STATUS.KT_FAILED,
                    error: `Decrytption of ktBlob in localStorage failed with error "${error.message}"`,
                });
                continue;
            }

            const localSKL = decryptedBlob.SignedKeyList;
            const localEpoch = decryptedBlob.Epoch;

            const fetchedSKLs = await getParsedSignedKeyLists(api, localEpoch.EpochID, email, false);

            const localSignature = await getSignature(localSKL.Signature);

            const includedSKLarray: SignedKeyListInfo[] = await Promise.all(
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
                addressesToVerifiedEpochs.set(address.ID, {
                    code: KT_STATUS.KT_FAILED,
                    error: 'Included signed key list not found',
                });
                continue;
            }

            const includedSignature = await getSignature(includedSKL.Signature);

            if (getSignatureTime(includedSignature) - getSignatureTime(localSignature) > maximumEpochInterval) {
                addressesToVerifiedEpochs.set(address.ID, {
                    code: KT_STATUS.KT_FAILED,
                    error:
                        'Signed key list in localStorage is older than included signed key list by more than maximumEpochInterval',
                });
                continue;
            }

            // Check signature
            try {
                await checkSignature(
                    includedSKL.Data,
                    parsedKeyList.map((key) => key.PublicKey),
                    includedSKL.Signature
                );
            } catch (err) {
                addressesToVerifiedEpochs.set(address.ID, {
                    code: KT_STATUS.KT_FAILED,
                    error: err.message,
                });
                continue;
            }

            if (includedSKL.MinEpochID !== null) {
                const minEpoch: Epoch = await api(getCertificate({ EpochID: includedSKL.MinEpochID }));

                const returnedDate = await verifyEpoch(minEpoch, email, includedSKL.Data, api);

                if (returnedDate - getSignatureTime(localSignature) > maximumEpochInterval) {
                    addressesToVerifiedEpochs.set(address.ID, {
                        code: KT_STATUS.KT_FAILED,
                        error:
                            'Returned date is older than the signed key list in localStorage by more than maximumEpochInterval',
                    });
                    continue;
                }

                removeItem(`kt:${address.ID}`);
            } else if (Date.now() - getSignatureTime(localSignature) > maximumEpochInterval) {
                addressesToVerifiedEpochs.set(address.ID, {
                    code: KT_STATUS.KT_FAILED,
                    error: 'Signed key list in localStorage is older than maximumEpochInterval',
                });
                continue;
            }
        }

        // Check key list and signed key list
        try {
            await verifyKeyLists(parsedKeyList, signedKeyListData);
        } catch (error) {
            addressesToVerifiedEpochs.set(address.ID, {
                code: KT_STATUS.KT_FAILED,
                error: `Mismatch found between key list and signed key list. ${error.message}`,
            });
            continue;
        }

        // Check signature
        try {
            await checkSignature(
                address.SignedKeyList.Data,
                parsedKeyList.map((key) => key.PublicKey),
                address.SignedKeyList.Signature
            );
        } catch (err) {
            addressesToVerifiedEpochs.set(address.ID, {
                code: KT_STATUS.KT_FAILED,
                error: err.message,
            });
            continue;
        }

        const signatureSKL = await getSignature(address.SignedKeyList.Signature);
        if (address.SignedKeyList.MinEpochID === null) {
            if (Date.now() - getSignatureTime(signatureSKL) > maximumEpochInterval) {
                addressesToVerifiedEpochs.set(address.ID, {
                    code: KT_STATUS.KT_FAILED,
                    error: 'Signed key list is older than maximumEpochInterval',
                });
                continue;
            }
        }

        let verifiedEpoch;
        let errorResponse;
        try {
            verifiedEpoch = await silentApi(getLatestVerifiedEpoch({ AddressID: address.ID }));
        } catch (err) {
            errorResponse = err.message;
        }
        if (!verifiedEpoch && errorResponse === 'Unprocessable Entity') {
            if (address.SignedKeyList.MinEpochID === null) {
                addressesToVerifiedEpochs.set(address.ID, {
                    code: KT_STATUS.KT_WARNING,
                    error: 'Signed key list has not been included in any epoch yet, self-audit is postponed',
                });
                continue;
            }

            // Verify current epoch
            let verifiedCurrent;
            try {
                verifiedCurrent = await verifyCurrentEpoch(address.SignedKeyList, email, api);
            } catch (err) {
                addressesToVerifiedEpochs.set(address.ID, {
                    code: KT_STATUS.KT_FAILED,
                    error: err.message,
                });
                continue;
            }
            addressesToVerifiedEpochs.set(address.ID, {
                code: KT_STATUS.KT_PASSED,
                verifiedEpoch: verifiedCurrent,
                error: '',
            });
            continue;
        }
        verifiedEpoch = verifiedEpoch as { Data: string; Signature: string };

        // Check signature
        try {
            await checkSignature(
                verifiedEpoch.Data,
                parsedKeyList.map((key) => key.PublicKey),
                verifiedEpoch.Signature
            );
        } catch (err) {
            addressesToVerifiedEpochs.set(address.ID, {
                code: KT_STATUS.KT_FAILED,
                error: err.message,
            });
            continue;
        }

        const verifiedEpochData = JSON.parse(verifiedEpoch.Data);

        // Fetch all new SKLs and corresponding epochs
        const newerSKLs = await getParsedSignedKeyLists(api, verifiedEpochData.EpochID, email, true);

        if (newerSKLs.length > 3) {
            addressesToVerifiedEpochs.set(address.ID, {
                code: KT_STATUS.KT_FAILED,
                error: 'More than 3 SKLs found',
            });
            continue;
        }

        // The epochs are fetched according to when SKLs changed. There could be at most one such that MinEpochID is null.
        // That's excluded because it does not belong to any epoch.
        const newerEpochs: EpochExtended[] = await Promise.all(
            newerSKLs
                .filter((skl) => skl.MinEpochID !== null)
                .map(async (skl) => {
                    const epoch: Epoch = await api(getCertificate({ EpochID: skl.MinEpochID as number }));

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
        try {
            newerEpochs.reduce((previousEpoch, currentEpoch) => {
                if (currentEpoch.Revision !== previousEpoch.Revision + 1) {
                    throw new Error('Revisions for new signed key lists have not been incremented correctly');
                }
                return currentEpoch;
            });
        } catch (err) {
            addressesToVerifiedEpochs.set(address.ID, {
                code: KT_STATUS.KT_FAILED,
                error: err.message,
            });
            continue;
        }

        // If there aren't any new epochs in which a SKL changed, than newerEpochs will only have one element.
        // That corresponds to the old SKL (NOTE: because any SKL with MinEpochID equal to null was ignored when constructing newerEpochs).
        if (newerEpochs.length === 1) {
            const [newestEpoch] = newerEpochs;
            const newestSKL = newerSKLs.find((skl) => skl.MinEpochID === newestEpoch.EpochID);
            if (!newestEpoch || !newestSKL) {
                addressesToVerifiedEpochs.set(address.ID, {
                    code: KT_STATUS.KT_FAILED,
                    error: 'Newest epoch is undefined',
                });
                continue;
            }
            // Verify current epoch
            let verifiedCurrent;
            try {
                verifiedCurrent = await verifyCurrentEpoch(newestSKL, email, api);
            } catch (err) {
                addressesToVerifiedEpochs.set(address.ID, {
                    code: KT_STATUS.KT_FAILED,
                    error: err.message,
                });
                continue;
            }
            addressesToVerifiedEpochs.set(address.ID, {
                code: KT_STATUS.KT_PASSED,
                verifiedEpoch: verifiedCurrent,
                error: '',
            });
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
                addressesToVerifiedEpochs.set(address.ID, {
                    code: KT_STATUS.KT_FAILED,
                    error: 'Current epoch is older than or equal to previous epoch',
                });
                continue;
            }

            const includedSKL =
                address.SignedKeyList.MinEpochID === null ||
                (address.SignedKeyList.MinEpochID > epoch.EpochID && previousSKL)
                    ? previousSKL
                    : address.SignedKeyList;

            if (!includedSKL) {
                addressesToVerifiedEpochs.set(address.ID, {
                    code: KT_STATUS.KT_FAILED,
                    error: 'Included SKL could not be defined',
                });
                continue;
            }

            epoch.CertificateDate = await verifyEpoch(epoch, email, includedSKL.Data, api);

            if (
                epoch.CertificateDate < previousEpoch.CertificateDate &&
                epoch.CertificateDate > previousEpoch.CertificateDate + maximumEpochInterval
            ) {
                addressesToVerifiedEpochs.set(address.ID, {
                    code: KT_STATUS.KT_FAILED,
                    error: 'Certificate date control error',
                });
                continue;
            }

            if (
                address.SignedKeyList.MinEpochID === null ||
                (address.SignedKeyList.MinEpochID > epoch.EpochID &&
                    epoch.CertificateDate > getSignatureTime(signatureSKL) + maximumEpochInterval)
            ) {
                addressesToVerifiedEpochs.set(address.ID, {
                    code: KT_STATUS.KT_FAILED,
                    error:
                        "The certificate date is older than signed key list's signature by more than maximumEpochInterval",
                });
                continue;
            }
        }

        if (newerEpochs[newerEpochs.length - 1].CertificateDate >= maximumEpochInterval) {
            addressesToVerifiedEpochs.set(address.ID, {
                code: KT_STATUS.KT_FAILED,
                error: 'Last certificate date is older than maximumEpochInterval',
            });
            continue;
        }

        addressesToVerifiedEpochs.set(address.ID, {
            code: KT_STATUS.KT_PASSED,
            verifiedEpoch: newerEpochs[newerEpochs.length - 1],
            error: '',
        });
    }

    for (const element of addressesToVerifiedEpochs) {
        const [addressID, result] = element;
        if (result.code === KT_STATUS.KT_PASSED) {
            const epochToUpload = result.verifiedEpoch as EpochExtended;
            const bodyData = JSON.stringify({
                EpochID: epochToUpload.EpochID,
                ChainHash: epochToUpload.ChainHash,
                CertificateDate: epochToUpload.CertificateDate,
            });

            const [privateKey] = (addresses.find((address) => address.ID === addressID) as Address).Keys.map(
                (key) => key.PrivateKey
            );
            await api(
                uploadVerifiedEpoch({
                    AddressID: addressID,
                    Data: bodyData,
                    Signature: (
                        await signMessage({
                            data: bodyData,
                            privateKeys: await getKeys(privateKey),
                            detached: true,
                        })
                    ).signature,
                })
            );
        }
    }

    return addressesToVerifiedEpochs;
}

export async function updateKT(
    address: Address,
    ktSelfAuditResult: Map<
        string,
        {
            code: number;
            verifiedEpoch: EpochExtended;
            error: string;
        }
    >,
    lastSelfAudit: number,
    isRunning: boolean,
    userKeys: CachedKey[]
): Promise<{ code: number; error: string }> {
    if (isRunning) {
        return { code: KT_STATUS.KT_WARNING, error: 'Self-audit is still running' };
    }

    if (Date.now() - lastSelfAudit > expectedEpochInterval) {
        return { code: KT_STATUS.KT_WARNING, error: 'Self-audit should run before proceeding' };
    }

    const ktResult = ktSelfAuditResult.get(address.ID);

    if (!ktResult) {
        return { code: KT_STATUS.KT_FAILED, error: `${address.Email} was never audited` };
    }

    if (ktResult.code !== KT_STATUS.KT_PASSED) {
        return {
            code: KT_STATUS.KT_FAILED,
            error: `Self-audit failed for ${address.Email} with error "${ktResult.error}"`,
        };
    }

    const { verifiedEpoch } = ktResult;

    if (Date.now() - verifiedEpoch.CertificateDate > maximumEpochInterval) {
        return {
            code: KT_STATUS.KT_FAILED,
            error: `Verified epoch for ${address.Email} is older than maximumEpochInterval`,
        };
    }

    const message = JSON.stringify({
        Epoch: verifiedEpoch,
        SignedKeyList: address.SignedKeyList,
    });

    if (hasStorage()) {
        const userPrimaryPublicKey = (
            await Promise.all(
                userKeys.map(async (cachedKey) => {
                    if (cachedKey.error || cachedKey.Key.Primary !== 1) {
                        return;
                    }
                    if (!cachedKey.publicKey) {
                        try {
                            [cachedKey.publicKey] = await getKeys(cachedKey.Key.PublicKey);
                        } catch (err) {
                            return;
                        }
                    }
                    return cachedKey.publicKey;
                })
            )
        ).filter((publicKey: OpenPGPKey | undefined): publicKey is OpenPGPKey => {
            return publicKey !== undefined;
        });

        if (userPrimaryPublicKey.length === 0) {
            return { code: KT_STATUS.KT_FAILED, error: 'No keys found to encrypt KT blob to localStorage' };
        }

        setItem(
            `kt:${address.ID}`,
            (
                await encryptMessage({
                    data: message,
                    publicKeys: userPrimaryPublicKey,
                })
            ).data
        );
    }

    return { code: KT_STATUS.KT_PASSED, error: '' };
}
