export interface SignedKeyList {
  Data: string;
  Signature: string;
}

export interface SignedKeyListInfo extends SignedKeyList {
  MinEpochID: number | null;
  MaxEpochID: number | null;
}

export interface KeyInfo {
  Fingerprint: string;
  SHA256Fingerprints: string[];
  Primary: number;
  Flags: number;
}
