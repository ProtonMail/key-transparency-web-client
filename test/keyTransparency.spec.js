import { getSignature } from "pmcrypto";
import { testEmail, keyList, skl, epoch, proof } from "./keyTransparency.data";
import { verifyProof } from "../lib/merkleTree";
import { verifyPublicKeys, getSignatureTime } from "../lib/keyTransparency";
import {
  parseCertificate,
  checkAltName,
  verifyLEcert,
  verifySCT,
} from "../lib/certTransparency";
import { VERIFY_PK_STATUS } from "../lib/constants";

describe("key transparency", () => {
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

  it("should verify a certificate", async () => {
    const { Certificate, ChainHash, EpochID } = epoch;

    const cert = parseCertificate(Certificate);
    checkAltName(cert, ChainHash, EpochID);
    await verifyLEcert(cert);
    await verifySCT(cert);
  });

  it("should verify public keys (and fail when it checks the certificate returnedDate", async () => {
    const mockApi = (call) => {
      const splitCall = call.url.split("/");
      if (splitCall[0] === "addresses") {
        return {
          Responses: [
            {
              Email: testEmail,
              Response: { Code: 1000, CanonicalEmail: testEmail },
            },
          ],
          Code: 1001,
        };
      }
      if (splitCall[0] === "kt") {
        if (splitCall.length > 3) {
          return proof;
        }
        return epoch;
      }
    };

    const result = await verifyPublicKeys(keyList, testEmail, skl, mockApi);
    expect(result.code).toEqual(VERIFY_PK_STATUS.VERIFY_PK_FAILED);
    expect(result.error).toEqual(
      "Returned date is older than the maximum epoch interval"
    );
  });

  it("should warn that public keys are too young to be verified", async () => {
    const mockApi = (call) => {
      const splitCall = call.url.split("/");
      if (splitCall[0] === "addresses") {
        return {
          Responses: [
            {
              Email: testEmail,
              Response: { Code: 1000, CanonicalEmail: testEmail },
            },
          ],
          Code: 1001,
        };
      }
      if (splitCall[0] === "kt") {
        if (splitCall.length > 3) {
          return proof;
        }
        return epoch;
      }
    };

    const result = await verifyPublicKeys(
      keyList,
      testEmail,
      { ...skl, MinEpochID: null, MaxEpochID: null },
      mockApi
    );
    expect(result.code).toEqual(VERIFY_PK_STATUS.VERIFY_PK_WARNING);
    expect(result.error).toEqual("");
  });

  it("should get signature time", async () => {
    const { Signature } = skl;
    const time = getSignatureTime(await getSignature(Signature));

    expect(typeof time).toEqual("number");
  });
});
