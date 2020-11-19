export interface SignedKeyList {
    Data: string;
    Signature: string;
}

export interface SignedKeyListInfo extends SignedKeyList {
    MinEpochID: number | null;
    MaxEpochID: number | null;
}
