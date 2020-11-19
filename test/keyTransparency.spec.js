import {
  testEmail,
  keyList,
  skl,
  epoch,
  epochOld,
  proof,
} from "./keyTransparency.data";
import { verifyPublicKeys } from "../lib/keyTransparency";
import { KT_STATUS } from "../lib/constants";

describe("key transparency", () => {
  const mockAddress = {
    Responses: [
      {
        Email: testEmail,
        Response: { Code: 1000, CanonicalEmail: testEmail },
      },
    ],
    Code: 1001,
  };

  const mockApi = (returnEpoch, returnedAddress) => (call) => {
    const splitCall = call.url.split("/");
    if (splitCall[0] === "addresses") {
      return returnedAddress;
    }
    if (splitCall[0] === "kt") {
      if (splitCall.length > 3) {
        return proof;
      }
      const list = [].concat(returnEpoch);
      if (list.length === 1) {
        return list.shift();
      }
      const epochID = parseInt(splitCall.pop(), 10);
      for (let i = 0; i < list.length; i++) {
        if (list[i].EpochID === epochID) {
          return list[i];
        }
      }
    }
  };

  const path = "https://protonmail.blue/api";

  async function fetchEpoch(epochID) {
    const response = await fetch(`${path}/kt/epochs/${epochID}`);
    if (response.ok) {
      return response.json();
    }
  }

  async function currentEpoch() {
    try {
      const response = await fetch(`${path}/kt/epochs`);
      if (response.ok) {
        const epochInfo = await response.json();
        return fetchEpoch(epochInfo.Epochs[0].EpochID);
      }
      return;
    } catch (err) {
      console.warn("Cannot perform verification test");
    }
  }

  it("should verify public keys", async () => {
    const newestEpoch = await currentEpoch();
    if (newestEpoch) {
      const previous = await fetchEpoch(newestEpoch.EpochID - 1);
      if (previous) {
        const result = await verifyPublicKeys(
          keyList,
          testEmail,
          { ...skl, MaxEpochID: newestEpoch.EpochID },
          mockApi([newestEpoch, previous], mockAddress)
        );
        expect(result.code).toEqual(KT_STATUS.KT_PASSED);
        expect(result.error).toEqual("");
      }
    }
  });

  it("should verify public keys and fail when it checks the certificate returnedDate", async () => {
    const result = await verifyPublicKeys(
      keyList,
      testEmail,
      skl,
      mockApi(epoch, mockAddress)
    );
    expect(result.code).toEqual(KT_STATUS.KT_FAILED);
    expect(result.error).toEqual(
      "Returned date is older than the maximum epoch interval"
    );
  });

  it("should warn that public keys are too young to be verified", async () => {
    const result = await verifyPublicKeys(
      keyList,
      testEmail,
      { ...skl, MinEpochID: null, MaxEpochID: null },
      mockApi(epoch, mockAddress)
    );
    expect(result.code).toEqual(KT_STATUS.KT_WARNING);
    expect(result.error).toEqual(
      "The keys were generated too recently to be included in key transparency"
    );
  });

  it("should fail with undefined canonizeEmail", async () => {
    const corruptAddress = JSON.parse(JSON.stringify(mockAddress));
    corruptAddress.Responses[0].Response.CanonicalEmail = undefined;

    const result = await verifyPublicKeys(
      keyList,
      testEmail,
      skl,
      mockApi(epoch, corruptAddress)
    );
    expect(result.code).toEqual(KT_STATUS.KT_FAILED);
    expect(result.error).toEqual(`Failed to canonize email "${testEmail}"`);
  });

  it("should fail with no signed key list given", async () => {
    const result = await verifyPublicKeys(
      keyList,
      testEmail,
      null,
      mockApi(epoch, mockAddress)
    );
    expect(result.code).toEqual(KT_STATUS.KT_WARNING);
    expect(result.error).toEqual("Signed key list undefined");
  });

  it("should fail signature verification", async () => {
    const result = await verifyPublicKeys(
      keyList,
      testEmail,
      { ...skl, Data: `${skl.Data.slice(0, 12)}3${skl.Data.slice(13)}` },
      mockApi(epoch, mockAddress)
    );
    expect(result.code).toEqual(KT_STATUS.KT_FAILED);
    expect(result.error).toEqual("Signature verification failed");
  });

  it("should fail signed key list check", async () => {
    const result = await verifyPublicKeys(
      [keyList[0]],
      testEmail,
      skl,
      mockApi(epoch, mockAddress)
    );
    expect(result.code).toEqual(KT_STATUS.KT_FAILED);
    expect(result.error).toEqual(
      "Mismatch found between key list and signed key list. Key list and signed key list have different lengths"
    );
  });

  it("should fail epoch verification", async () => {
    const result = await verifyPublicKeys(
      keyList,
      testEmail,
      skl,
      mockApi(epochOld, mockAddress)
    );
    expect(result.code).toEqual(KT_STATUS.KT_FAILED);
    expect(result.error).toEqual("Hash chain does not result in TreeHash");
  });
});
