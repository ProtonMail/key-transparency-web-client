import { testEmail, skl, epoch, proof } from "./keyTransparency.data";
import { verifyProof } from "../lib/merkleTree";

describe("merkle tree", () => {
  it("should verify a proof", async () => {
    const { Name, Revision, Proof, Neighbors } = proof;
    const { TreeHash } = epoch;
    const { Data } = skl;

    await verifyProof(
      Name,
      Revision,
      Proof,
      Neighbors,
      TreeHash,
      Data,
      testEmail
    );
  });

  it("should fail with corrupt length", async () => {
    const { Name, Revision, Proof, Neighbors } = proof;
    const { TreeHash } = epoch;
    const { Data } = skl;

    try {
      await verifyProof(
        Name,
        Revision,
        Proof.slice(0, 70),
        Neighbors,
        TreeHash,
        Data,
        testEmail
      );
    } catch (err) {
      expect(err.message).toEqual(
        'VRF verification failed with error "Length mismatch found"'
      );
    }
  });

  it("should fail with corrupt initial byte", async () => {
    const { Name, Revision, Proof, Neighbors } = proof;
    const { TreeHash } = epoch;
    const { Data } = skl;

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
    } catch (err) {
      expect(err.message).toEqual(
        'VRF verification failed with error "Proof decoding failed"'
      );
    }
  });

  it("should fail with corrupt name", async () => {
    const { Name, Revision, Proof, Neighbors } = proof;
    const { TreeHash } = epoch;
    const { Data } = skl;

    try {
      await verifyProof(
        `00${Name.slice(2, Name.length)}`,
        Revision,
        Proof,
        Neighbors,
        TreeHash,
        Data,
        testEmail
      );
    } catch (err) {
      expect(err.message).toEqual(
        'VRF verification failed with error "Fetched name is different than name in proof"'
      );
    }
  });

  it("should fail with corrupt proof", async () => {
    const { Name, Revision, Proof, Neighbors } = proof;
    const { TreeHash } = epoch;
    const { Data } = skl;

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
    } catch (err) {
      expect(err.message).toEqual(
        'VRF verification failed with error "Verification went through but failed"'
      );
    }
  });

  it("should fail with corrupt root hash", async () => {
    const { Name, Revision, Proof, Neighbors } = proof;
    const { TreeHash } = epoch;
    const { Data } = skl;

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
    } catch (err) {
      expect(err.message).toEqual("Hash chain does not result in TreeHash");
    }
  });

  it("should fail with corrupt revision", async () => {
    const { Name, Revision, Proof, Neighbors } = proof;
    const { TreeHash } = epoch;
    const { Data } = skl;

    try {
      await verifyProof(
        Name,
        Revision + 1,
        Proof,
        Neighbors,
        TreeHash,
        Data,
        testEmail
      );
    } catch (err) {
      expect(err.message).toEqual("Hash chain does not result in TreeHash");
    }
  });

  it("should fail with corrupt skl", async () => {
    const { Name, Revision, Proof, Neighbors } = proof;
    const { TreeHash } = epoch;
    const { Data } = skl;

    try {
      await verifyProof(
        Name,
        Revision,
        Proof,
        Neighbors,
        TreeHash,
        `00${Data.slice(2, Data.length)}`,
        testEmail
      );
    } catch (err) {
      expect(err.message).toEqual("Hash chain does not result in TreeHash");
    }
  });

  it("should fail with corrupt but matching names", async () => {
    const { Name, Revision, Proof, Neighbors } = proof;
    const { TreeHash } = epoch;
    const { Data } = skl;

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
    } catch (err) {
      expect(err.message).toEqual(
        'VRF verification failed with error "Proof decoding failed"'
      );
    }
  });

  it("should fail with corrupt email", async () => {
    const { Name, Revision, Proof, Neighbors } = proof;
    const { TreeHash } = epoch;
    const { Data } = skl;

    try {
      await verifyProof(
        Name,
        Revision,
        Proof,
        Neighbors,
        TreeHash,
        Data,
        "corrupt@protonmail.blue"
      );
    } catch (err) {
      expect(err.message).toEqual(
        'VRF verification failed with error "Verification went through but failed"'
      );
    }
  });

  it("should fail with corrupt neighbors", async () => {
    const { Name, Revision, Proof, Neighbors } = proof;
    const { TreeHash } = epoch;
    const { Data } = skl;

    try {
      await verifyProof(
        Name,
        Revision,
        Proof,
        [
          ...Neighbors.slice(0, Neighbors.length - 1),
          "250e8651e520ac6ff1b163c892f1a262006bc546c14d428641ef663f3fc366f3",
        ],
        TreeHash,
        Data,
        testEmail
      );
    } catch (err) {
      expect(err.message).toEqual("Hash chain does not result in TreeHash");
    }
  });
});
