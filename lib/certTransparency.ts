import * as asn1js from "asn1js";
import Certificate from "pkijs/src/Certificate";
import { verifySCTsForCertificate } from "pkijs/src/SignedCertificateTimestampList";
import { base64StringToUint8Array } from "./helpers/encoding";
import { ctLogs, LECert } from "./constants";

function pemToBinary(pem: string) {
  const lines = pem.split("\n");
  let encoded = "";
  for (let i = 0; i < lines.length; i++) {
    if (
      lines[i].trim().length > 0 &&
      lines[i].indexOf("-BEGIN CERTIFICATE-") < 0 &&
      lines[i].indexOf("-END CERTIFICATE-") < 0
    ) {
      encoded += lines[i].trim();
    }
  }
  return base64StringToUint8Array(encoded).buffer;
}

export function parseCertificate(cert: string) {
  const asn1Certificate = asn1js.fromBER(pemToBinary(cert));
  return new Certificate({ schema: asn1Certificate.result });
}

export function checkAltName(
  certificate: Certificate,
  ChainHash: string,
  EpochID: number
) {
  if (!certificate.extensions) {
    throw new Error("Epoch certificate does not have extensions");
  }
  const altNamesExt = certificate.extensions.find(
    (ext) => ext.extnID === "2.5.29.17"
  );
  if (!altNamesExt) {
    throw new Error("Epoch certificate does not have AltName extension");
  }
  const altName = altNamesExt.parsedValue.altNames[0].value;
  const domain = altNamesExt.parsedValue.altNames[1].value;
  if (
    `${ChainHash.slice(0, 32)}.${ChainHash.slice(
      32
    )}.${EpochID}.0.${domain}` !== altName
  ) {
    throw new Error("Epoch certificate alternative name does not match");
  }
}

export async function verifyLEcert(certificate: Certificate) {
  const asn1LE = asn1js.fromBER(pemToBinary(LECert));
  const certLE = new Certificate({ schema: asn1LE.result });
  const verified = await certificate.verify(certLE);
  if (!verified) {
    throw new Error(
      "Epoch certificate did not pass verification against issuer's public key"
    );
  }
}

export async function verifySCT(certificate: Certificate) {
  const issuerCert = parseCertificate(LECert);
  let verificationResult: boolean[];
  try {
    verificationResult = await verifySCTsForCertificate(
      certificate,
      issuerCert,
      ctLogs
    );
  } catch (err) {
    throw new Error(`SCT verification halted with error "${err.message}"`);
  }
  const verified = verificationResult.reduce((previous, current) => {
    return previous && current;
  });
  if (!verified) {
    throw new Error("SCT verification failed");
  }
}