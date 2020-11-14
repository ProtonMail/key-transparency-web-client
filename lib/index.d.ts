import { Api } from "./helpers/interfaces/Api";
import { Key } from "./helpers/interfaces/Key";

export const VERIFY_PK_STATUS: { [key: string]: number };

export function ktSelfAudit(
  api: Api,
  userKey: Key
): Promise<
  Map<
    string,
    {
      EpochID: number;
      TreeHash: string;
      ChainHash: string;
      Certificate: string;
      IssuerKeyHash: string;
      CertificateDate: number;
    }
  >
>;

export function updateKT(
  address: {
    ID: string;
    Email: string;
    SignedKeyList: {
      MaxEpochID: number;
      MinEpochID: number;
      Data: string;
      Signature: string;
    };
    Keys: {
      ID: string;
      Primary: number;
      Flags: number;
      PublicKey: string;
      PrivateKey: string;
    }[];
  },
  api: Api,
  userKey: Key
): Promise<void>;

export function verifyPublicKeys(
  keyList: {
    Flags: number;
    PublicKey: string;
  }[],
  email: string,
  signedKeyList: {
    MinEpochID: number;
    MaxEpochID: number;
    Data: string;
    Signature: string;
  },
  api: Api
): Promise<{ code: number; error: string }>;
