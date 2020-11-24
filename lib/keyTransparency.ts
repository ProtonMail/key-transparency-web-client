import { OpenPGPKey, getKeys, getSignature, signMessage, encryptMessage, decryptMessage, getMessage } from 'pmcrypto';
import { Api } from './helpers/interfaces/Api';
import { Address } from './helpers/interfaces/Address';
import { CachedKey } from './helpers/interfaces/CachedKey';
import { Epoch, EpochExtended } from './interfaces';
import { SignedKeyListInfo } from './helpers/interfaces/SignedKeyList';
import { uploadVerifiedEpoch } from './helpers/api/keyTransparency';
import { getParsedSignedKeyLists, fetchProof, fetchEpoch, getVerifiedEpoch } from './fetchHelper';
import { getItem, setItem, removeItem, hasStorage } from './helpers/storage';
import { getCanonicalEmailMap } from './helpers/api/canonicalEmailMap';
import { KT_STATUS, MAX_EPOCH_INTERVAL, EXP_EPOCH_INTERVAL } from './constants';
import { SimpleMap } from './helpers/interfaces/utils';
import {
    checkSignature,
    getSignatureTime,
    compareTimes,
    parseKeyLists,
    verifyCurrentEpoch,
    verifyEpoch,
    verifyKeyLists,
} from './utils';

export async function verifyPublicKeys(
    keyList: {
        Flags: number;
        PublicKey: string;
    }[],
    email: string,
    signedKeyList: SignedKeyListInfo | undefined,
    api: Api
): Promise<{ code: KT_STATUS; error: string }> {
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
            signedKeyList.Signature,
            'SKL during PK verification'
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
        maxEpoch = await fetchEpoch(signedKeyList.MaxEpochID, api);
    } catch (err) {
        return { code: KT_STATUS.KT_FAILED, error: err.message };
    }

    let returnedDate: number;
    try {
        returnedDate = await verifyEpoch(maxEpoch, canonicalEmail, signedKeyList.Data, api);
    } catch (err) {
        return { code: KT_STATUS.KT_FAILED, error: err.message };
    }

    if (compareTimes(returnedDate)) {
        return {
            code: KT_STATUS.KT_FAILED,
            error: 'Returned date is older than the maximum epoch interval',
        };
    }

    return { code: KT_STATUS.KT_PASSED, error: '' };
}

export async function ktSelfAudit(
    apis: Api[],
    addresses: Address[],
    userKeys: CachedKey[]
): Promise<
    Map<
        string,
        {
            code: KT_STATUS;
            verifiedEpoch?: EpochExtended;
            error: string;
        }
    >
> {
    // silentApi is used to prevent red banner when a verified epoch is not found
    const [api, silentApi] = apis;

    // Initialise output
    const addressesToVerifiedEpochs: Map<
        string,
        {
            code: number;
            verifiedEpoch?: EpochExtended;
            error: string;
        }
    > = new Map();

    // Canonize emails
    let canonicalEmailMap: SimpleMap<string> | undefined;
    try {
        canonicalEmailMap = await getCanonicalEmailMap(
            addresses.map((address) => address.Email),
            api
        );
    } catch (err) {
        canonicalEmailMap = undefined;
    }

    // Prepare user private key for localStorage decrypt
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

    // Main loop through addresses
    for (let i = 0; i < addresses.length; i++) {
        // Parse info from address
        const address = addresses[i];
        if (!canonicalEmailMap) {
            addressesToVerifiedEpochs.set(address.ID, {
                code: KT_STATUS.KT_FAILED,
                error: 'Failed to get canonized emails',
            });
            continue;
        }
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

        // Check content of localStorage
        if (hasStorage()) {
            const ktBlobs = [getItem(`kt:0:${address.ID}`), getItem(`kt:1:${address.ID}`)];
            let errorFlag = false;
            for (let i = 0; i < ktBlobs.length; i++) {
                const ktBlob = ktBlobs[i];
                if (ktBlob) {
                    // Decrypt and parektBlob
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
                        errorFlag = true;
                        break;
                    }
                    const { SignedKeyList: localSKL, Epoch: localEpoch } = decryptedBlob;
                    const localSignature = await getSignature(localSKL.Signature);

                    // Retrieve oldest SKL since localEpoch.EpochID
                    const fetchedSKLs = await getParsedSignedKeyLists(api, localEpoch.EpochID, email, false);
                    const includedSKLarray: SignedKeyListInfo[] = await Promise.all(
                        fetchedSKLs.filter(async (skl) => {
                            const sklSignature = await getSignature(skl.Signature);
                            return (
                                (skl.MinEpochID === null || skl.MinEpochID > localEpoch.EpochID) &&
                                getSignatureTime(sklSignature) >= getSignatureTime(localSignature)
                            );
                        })
                    );
                    const [includedSKL] = includedSKLarray;
                    if (!includedSKL) {
                        addressesToVerifiedEpochs.set(address.ID, {
                            code: KT_STATUS.KT_FAILED,
                            error: 'Included signed key list not found',
                        });
                        errorFlag = true;
                        break;
                    }
                    const includedSignature = await getSignature(includedSKL.Signature);

                    if (compareTimes(getSignatureTime(localSignature), getSignatureTime(includedSignature))) {
                        addressesToVerifiedEpochs.set(address.ID, {
                            code: KT_STATUS.KT_FAILED,
                            error:
                                'Signed key list in localStorage is older than included signed key list by more than MAX_EPOCH_INTERVAL',
                        });
                        errorFlag = true;
                        break;
                    }

                    // Check signature
                    try {
                        await checkSignature(
                            includedSKL.Data,
                            parsedKeyList.map((key) => key.PublicKey),
                            includedSKL.Signature,
                            'Included SKL localStorage self-audit'
                        );
                    } catch (err) {
                        addressesToVerifiedEpochs.set(address.ID, {
                            code: KT_STATUS.KT_FAILED,
                            error: err.message,
                        });
                        errorFlag = true;
                        break;
                    }

                    // If the includedSKL hasn't had time of entering an epoch, self-audit proceeds.
                    // Otherwise, we check it's there.
                    if (includedSKL.MinEpochID !== null) {
                        const minEpoch = await fetchEpoch(includedSKL.MinEpochID, api);

                        const returnedDate = await verifyEpoch(minEpoch, email, includedSKL.Data, api);

                        if (compareTimes(getSignatureTime(localSignature), returnedDate)) {
                            addressesToVerifiedEpochs.set(address.ID, {
                                code: KT_STATUS.KT_FAILED,
                                error:
                                    'Returned date is older than the signed key list in localStorage by more than MAX_EPOCH_INTERVAL',
                            });
                            errorFlag = true;
                            break;
                        }

                        removeItem(`kt:${i}:${address.ID}`);
                    } else if (compareTimes(getSignatureTime(localSignature))) {
                        addressesToVerifiedEpochs.set(address.ID, {
                            code: KT_STATUS.KT_FAILED,
                            error: 'Signed key list in localStorage is older than MAX_EPOCH_INTERVAL',
                        });
                        errorFlag = true;
                        break;
                    }
                }
            }
            if (errorFlag) {
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
                address.SignedKeyList.Signature,
                'Fetched SKL elf-audit'
            );
        } catch (err) {
            addressesToVerifiedEpochs.set(address.ID, {
                code: KT_STATUS.KT_FAILED,
                error: err.message,
            });
            continue;
        }

        const signatureSKL = await getSignature(address.SignedKeyList.Signature);
        if (address.SignedKeyList.MinEpochID === null && compareTimes(getSignatureTime(signatureSKL))) {
            addressesToVerifiedEpochs.set(address.ID, {
                code: KT_STATUS.KT_FAILED,
                error: 'Signed key list is older than MAX_EPOCH_INTERVAL',
            });
            continue;
        }

        const verifiedEpoch = await getVerifiedEpoch(silentApi, address.ID);
        if (!verifiedEpoch) {
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

        // Check signature
        try {
            await checkSignature(
                verifiedEpoch.Data,
                parsedKeyList.map((key) => key.PublicKey),
                verifiedEpoch.Signature,
                'Verified epoch self-audit'
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
                    const epoch = await fetchEpoch(skl.MinEpochID as number, api);

                    const { Revision }: { Revision: number } = await fetchProof(epoch.EpochID, email, api);

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
                compareTimes(previousEpoch.CertificateDate, epoch.CertificateDate)
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
                    compareTimes(getSignatureTime(signatureSKL), epoch.CertificateDate))
            ) {
                addressesToVerifiedEpochs.set(address.ID, {
                    code: KT_STATUS.KT_FAILED,
                    error:
                        "The certificate date is older than signed key list's signature by more than MAX_EPOCH_INTERVAL",
                });
                continue;
            }
        }

        // Chech latest certificate is within acceptable range
        if (newerEpochs[newerEpochs.length - 1].CertificateDate >= MAX_EPOCH_INTERVAL) {
            addressesToVerifiedEpochs.set(address.ID, {
                code: KT_STATUS.KT_FAILED,
                error: 'Last certificate date is older than MAX_EPOCH_INTERVAL',
            });
            continue;
        }

        // Set output for current address
        addressesToVerifiedEpochs.set(address.ID, {
            code: KT_STATUS.KT_PASSED,
            verifiedEpoch: newerEpochs[newerEpochs.length - 1],
            error: '',
        });

        // Upload verified epoch for current address
        const bodyData = JSON.stringify({
            EpochID: newerEpochs[newerEpochs.length - 1].EpochID,
            ChainHash: newerEpochs[newerEpochs.length - 1].ChainHash,
            CertificateDate: newerEpochs[newerEpochs.length - 1].CertificateDate,
        });

        const [privateKey] = address.Keys.map((key) => key.PrivateKey);
        await api(
            uploadVerifiedEpoch({
                AddressID: address.ID,
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

    return addressesToVerifiedEpochs;
}

export async function updateKT(
    address: Address,
    ktSelfAuditResult: Map<
        string,
        {
            code: KT_STATUS;
            verifiedEpoch: EpochExtended;
            error: string;
        }
    >,
    lastSelfAudit: number,
    isRunning: boolean,
    userKeys: CachedKey[]
): Promise<{ code: KT_STATUS; error: string }> {
    if (isRunning) {
        return { code: KT_STATUS.KT_WARNING, error: 'Self-audit is still running' };
    }

    if (Date.now() - lastSelfAudit > EXP_EPOCH_INTERVAL) {
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

    if (compareTimes(verifiedEpoch.CertificateDate)) {
        return {
            code: KT_STATUS.KT_FAILED,
            error: `Verified epoch for ${address.Email} is older than MAX_EPOCH_INTERVAL`,
        };
    }

    const message = JSON.stringify({
        Epoch: verifiedEpoch,
        SignedKeyList: address.SignedKeyList,
    });

    if (hasStorage()) {
        // Check if there is something in localStorage with counter either 0 or 1
        let counter = 0;
        const firstLS = getItem(`kt:0:${address.ID}`);
        const secondLS = getItem(`kt:1:${address.ID}`);

        if (firstLS && !secondLS) {
            counter = 1;
        } else if (!firstLS && secondLS) {
            counter = 1;
            setItem(`kt:0:${address.ID}`, secondLS);
        } else if (firstLS && secondLS) {
            return { code: KT_STATUS.KT_FAILED, error: 'There are already two blobs in localStorage' };
        }

        // Save the new blob
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
            `kt:${counter}:${address.ID}`,
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
