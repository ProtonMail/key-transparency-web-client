import { epoch } from "./keyTransparency.data";
import {
  parseCertificate,
  checkAltName,
  verifyLEcert,
  verifySCT,
} from "../lib/certTransparency";

describe("certificate transparency", () => {
  it("should verify a certificate", async () => {
    const { Certificate, ChainHash, EpochID } = epoch;

    const cert = parseCertificate(Certificate);
    checkAltName(cert, ChainHash, EpochID);
    await verifyLEcert(cert);
    await verifySCT(cert);
  });
});
