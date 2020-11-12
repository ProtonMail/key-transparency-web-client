import * as asn1js from 'asn1js';
import Certificate from 'pkijs/src/Certificate';
import { base64StringToUint8Array } from './helpers/helpers/encoding';
import { ctLogs, LECert } from './certificates';

function pemToBinary(pem: string) {
    const lines = pem.split('\n');
    let encoded = '';
    for (let i = 0; i < lines.length; i++) {
        if (
            lines[i].trim().length > 0 &&
            lines[i].indexOf('-BEGIN CERTIFICATE-') < 0 &&
            lines[i].indexOf('-END CERTIFICATE-') < 0
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

export function checkAltName(certificate: Certificate, epoch: { ChainHash: string; EpochID: number }) {
    if (!certificate.extensions) {
        throw new Error('Epoch certificate does not have extensions');
    }
    const altName = certificate.extensions.find((ext) => ext.extnID === '2.5.29.17')!.parsedValue.altNames[0].value;
    const domain = certificate.extensions.find((ext) => ext.extnID === '2.5.29.17')!.parsedValue.altNames[1].value;
    if (`${epoch.ChainHash.slice(0, 32)}.${epoch.ChainHash.slice(32)}.${epoch.EpochID}.0.${domain}` !== altName) {
        throw new Error('Epoch certificate alternative name does not match');
    }
}

export async function verifyLEcert(certificate: Certificate) {
    const asn1LE = asn1js.fromBER(pemToBinary(LECert));
    const certLE = new Certificate({ schema: asn1LE.result });
    const verified = await certificate.verify(certLE);
    if (!verified) {
        throw new Error("Epoch certificate did not pass verification against issuer's public key");
    }
}

export function verifySCT(certificate: Certificate) {
    const SCTs = certificate.extensions!.find((e) => e.extnID === '1.3.6.1.4.1.11129.2.4.2')!.parsedValue.timestamps;
    SCTs.array.forEach((SCT: any) => {
        SCT.verify(ctLogs, certificate.tbs).then((verified: boolean) => {
            if (!verified) {
                throw new Error('SCT failed verification');
            }
        });
    });
}
