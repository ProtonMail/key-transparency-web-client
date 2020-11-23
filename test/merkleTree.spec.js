import { testEmail, skl, epoch, proof } from './keyTransparency.data';
import { verifyProof, verifyChainHash } from '../lib/merkleTree';

describe('merkle tree', () => {
    it('should verify a proof', async () => {
        const { Name, Revision, Proof, Neighbors } = proof;
        const { TreeHash } = epoch;
        const { Data } = skl;

        await verifyProof(Name, Revision, Proof, Neighbors, TreeHash, Data, testEmail);
    });

    it('should fail with corrupt length', async () => {
        const { Name, Revision, Proof, Neighbors } = proof;
        const { TreeHash } = epoch;
        const { Data } = skl;

        let errorThrown = true;
        try {
            await verifyProof(Name, Revision, Proof.slice(0, 70), Neighbors, TreeHash, Data, testEmail);
            errorThrown = false;
        } catch (err) {
            expect(err.message).toEqual('VRF verification failed with error "Length mismatch found"');
        }
        expect(errorThrown).toEqual(true);
    });

    it('should fail with corrupt initial byte', async () => {
        const { Name, Revision, Proof, Neighbors } = proof;
        const { TreeHash } = epoch;
        const { Data } = skl;

        let errorThrown = true;
        try {
            await verifyProof(
                Name,
                Revision,
                `00${Proof.slice(2, Proof.length)}`,
                Neighbors,
                TreeHash,
                Data,
                testEmail
            );
            errorThrown = false;
        } catch (err) {
            expect(err.message).toEqual('VRF verification failed with error "Proof decoding failed"');
        }
        expect(errorThrown).toEqual(true);
    });

    it('should fail with corrupt name', async () => {
        const { Name, Revision, Proof, Neighbors } = proof;
        const { TreeHash } = epoch;
        const { Data } = skl;

        let errorThrown = true;
        try {
            await verifyProof(`00${Name.slice(2, Name.length)}`, Revision, Proof, Neighbors, TreeHash, Data, testEmail);
            errorThrown = false;
        } catch (err) {
            expect(err.message).toEqual(
                'VRF verification failed with error "Fetched name is different than name in proof"'
            );
        }
        expect(errorThrown).toEqual(true);
    });

    it('should fail with corrupt proof', async () => {
        const { Name, Revision, Proof, Neighbors } = proof;
        const { TreeHash } = epoch;
        const { Data } = skl;

        let errorThrown = true;
        try {
            await verifyProof(
                Name,
                Revision,
                `${Proof.slice(0, Proof.length - 2)}00`,
                Neighbors,
                TreeHash,
                Data,
                testEmail
            );
            errorThrown = false;
        } catch (err) {
            expect(err.message).toEqual('VRF verification failed with error "Verification went through but failed"');
        }
        expect(errorThrown).toEqual(true);
    });

    it('should fail with corrupt root hash', async () => {
        const { Name, Revision, Proof, Neighbors } = proof;
        const { TreeHash } = epoch;
        const { Data } = skl;

        let errorThrown = true;
        try {
            await verifyProof(
                Name,
                Revision,
                Proof,
                Neighbors,
                `00${TreeHash.slice(2, TreeHash.length)}`,
                Data,
                testEmail
            );
            errorThrown = false;
        } catch (err) {
            expect(err.message).toEqual('Hash chain does not result in TreeHash');
        }
        expect(errorThrown).toEqual(true);
    });

    it('should fail with corrupt revision', async () => {
        const { Name, Revision, Proof, Neighbors } = proof;
        const { TreeHash } = epoch;
        const { Data } = skl;

        let errorThrown = true;
        try {
            await verifyProof(Name, Revision + 1, Proof, Neighbors, TreeHash, Data, testEmail);
            errorThrown = false;
        } catch (err) {
            expect(err.message).toEqual('Hash chain does not result in TreeHash');
        }
        expect(errorThrown).toEqual(true);
    });

    it('should fail with corrupt skl', async () => {
        const { Name, Revision, Proof, Neighbors } = proof;
        const { TreeHash } = epoch;
        const { Data } = skl;

        let errorThrown = true;
        try {
            await verifyProof(Name, Revision, Proof, Neighbors, TreeHash, `00${Data.slice(2, Data.length)}`, testEmail);
            errorThrown = false;
        } catch (err) {
            expect(err.message).toEqual('Hash chain does not result in TreeHash');
        }
        expect(errorThrown).toEqual(true);
    });

    it('should fail with corrupt but matching names', async () => {
        const { Name, Revision, Proof, Neighbors } = proof;
        const { TreeHash } = epoch;
        const { Data } = skl;

        let errorThrown = true;
        try {
            await verifyProof(
                `00${Name.slice(2, Name.length)}`,
                Revision,
                `${Proof.slice(0, 2)}00${Proof.slice(4, Proof.length)}`,
                Neighbors,
                TreeHash,
                Data,
                testEmail
            );
            errorThrown = false;
        } catch (err) {
            // NOTE: the error message in this case varies depending on the corruption, i.e. depending on the
            // corrupt Name being parsable to an EC point by OS2ECP. If it is, then the error message will be
            // "Verification went through but failed", if it isn't the errow will be "Proof decoding failed".
            expect(err.message.substring(0, 36)).toEqual('VRF verification failed with error "');
        }
        expect(errorThrown).toEqual(true);
    });

    it('should fail with corrupt email', async () => {
        const { Name, Revision, Proof, Neighbors } = proof;
        const { TreeHash } = epoch;
        const { Data } = skl;

        let errorThrown = true;
        try {
            await verifyProof(Name, Revision, Proof, Neighbors, TreeHash, Data, 'corrupt@protonmail.blue');
            errorThrown = false;
        } catch (err) {
            // NOTE: the error message in this case varies depending on the corruption, i.e. depending on
            // SHA256(email||pk|ctr) being parsable to an EC point by OS2ECP within the LIMIT constant.
            // If it is, then the error message will be "Verification went through but failed", if it
            // isn't the errow will be "Point generation failed".
            expect(err.message.substring(0, 36)).toEqual('VRF verification failed with error "');
        }
        expect(errorThrown).toEqual(true);
    });

    it('should fail with corrupt neighbors', async () => {
        const { Name, Revision, Proof, Neighbors } = proof;
        const { TreeHash } = epoch;
        const { Data } = skl;

        let errorThrown = true;
        try {
            await verifyProof(
                Name,
                Revision,
                Proof,
                [
                    ...Neighbors.slice(0, Neighbors.length - 1),
                    '250e8651e520ac6ff1b163c892f1a262006bc546c14d428641ef663f3fc366f3',
                ],
                TreeHash,
                Data,
                testEmail
            );
            errorThrown = false;
        } catch (err) {
            expect(err.message).toEqual('Hash chain does not result in TreeHash');
        }
        expect(errorThrown).toEqual(true);
    });

    it('should verify chain hash consistency', async () => {
        const { TreeHash, ChainHash, PrevChainHash } = epoch;

        await verifyChainHash(TreeHash, PrevChainHash, ChainHash);
    });

    it('should fail chain hash consistency', async () => {
        const { TreeHash, ChainHash, PrevChainHash } = epoch;

        let errorThrown = true;
        try {
            await verifyChainHash(TreeHash, PrevChainHash, `0${ChainHash.slice(1)}`);
            errorThrown = false;
        } catch (err) {
            expect(err.message).toEqual('Chain hash of fetched epoch is not consistent');
        }
        expect(errorThrown).toEqual(true);
    });
});
