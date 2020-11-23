import { testEmail, keyList, skl, epoch, proof } from './keyTransparency.data';
import { verifyPublicKeys } from '../lib/keyTransparency';
import { KT_STATUS } from '../lib/constants';

describe('key transparency', () => {
    const mockAddress = {
        Responses: [
            {
                Email: testEmail,
                Response: { Code: 1000, CanonicalEmail: testEmail },
            },
        ],
        Code: 1001,
    };

    const mockApi = (returnedEpoch, returnedProof, returnedAddress) => (call) => {
        const splitCall = call.url.split('/');
        if (splitCall[0] === 'addresses') {
            return returnedAddress;
        }
        if (splitCall[0] === 'kt') {
            if (splitCall.length > 3) {
                return returnedProof;
            }
            return returnedEpoch;
        }
    };

    it('should verify public keys', async () => {
        let newestEpoch;
        let newestProof;
        const path = 'https://protonmail.blue/api/kt/epochs/';
        try {
            const response1 = await fetch(`${path}`);
            if (response1.ok) {
                const epochInfo = await response1.json();
                const response2 = await fetch(`${path}${epochInfo.Epochs[0].EpochID}`);
                if (response2.ok) {
                    newestEpoch = await response2.json();
                } else {
                    throw new Error('response2 failed');
                }
                const response3 = await fetch(`${path}${epochInfo.Epochs[0].EpochID}/proof/${testEmail}`);
                if (response3.ok) {
                    newestProof = await response3.json();
                } else {
                    throw new Error('response3 failed');
                }
            } else {
                throw new Error('response1 failed');
            }
        } catch (err) {
            console.warn('Cannot perform verification test');
        }

        if (newestEpoch && newestProof) {
            const result = await verifyPublicKeys(
                keyList,
                testEmail,
                { ...skl, MaxEpochID: newestEpoch.EpochID },
                mockApi(newestEpoch, newestProof, mockAddress)
            );
            expect(result.code).toEqual(KT_STATUS.KT_PASSED);
            expect(result.error).toEqual('');
        }
    });

    it('should verify public keys and fail when it checks the certificate returnedDate', async () => {
        const result = await verifyPublicKeys(keyList, testEmail, skl, mockApi(epoch, proof, mockAddress));
        expect(result.code).toEqual(KT_STATUS.KT_FAILED);
        expect(result.error).toEqual('Returned date is older than the maximum epoch interval');
    });

    it('should warn that public keys are too young to be verified', async () => {
        const result = await verifyPublicKeys(
            keyList,
            testEmail,
            { ...skl, MinEpochID: null, MaxEpochID: null },
            mockApi(epoch, proof, mockAddress)
        );
        expect(result.code).toEqual(KT_STATUS.KT_WARNING);
        expect(result.error).toEqual('The keys were generated too recently to be included in key transparency');
    });

    it('should fail with undefined canonizeEmail', async () => {
        const corruptAddress = JSON.parse(JSON.stringify(mockAddress));
        corruptAddress.Responses[0].Response.CanonicalEmail = undefined;

        const result = await verifyPublicKeys(keyList, testEmail, skl, mockApi(epoch, proof, corruptAddress));
        expect(result.code).toEqual(KT_STATUS.KT_FAILED);
        expect(result.error).toEqual(`Failed to canonize email "${testEmail}"`);
    });

    it('should fail with no signed key list given', async () => {
        const result = await verifyPublicKeys(keyList, testEmail, null, mockApi(epoch, proof, mockAddress));
        expect(result.code).toEqual(KT_STATUS.KT_WARNING);
        expect(result.error).toEqual('Signed key list undefined');
    });

    it('should fail signature verification', async () => {
        const result = await verifyPublicKeys(
            keyList,
            testEmail,
            { ...skl, Data: `${skl.Data.slice(0, 12)}3${skl.Data.slice(13)}` },
            mockApi(epoch, proof, mockAddress)
        );
        expect(result.code).toEqual(KT_STATUS.KT_FAILED);
        expect(result.error).toEqual('Signature verification failed');
    });

    it('should fail signed key list check', async () => {
        const result = await verifyPublicKeys([keyList[0]], testEmail, skl, mockApi(epoch, proof, mockAddress));
        expect(result.code).toEqual(KT_STATUS.KT_FAILED);
        expect(result.error).toEqual(
            'Mismatch found between key list and signed key list. Key list and signed key list have different lengths'
        );
    });
});
