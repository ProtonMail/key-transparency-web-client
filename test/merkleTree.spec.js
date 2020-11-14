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
});
