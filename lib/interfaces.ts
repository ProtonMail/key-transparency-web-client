export interface Epoch {
    EpochID: number;
    TreeHash: string;
    ChainHash: string;
    PreviousChainHash?: string;
    Certificate: string;
    IssuerKeyHash: string;
}

export interface EpochExtended extends Epoch {
    Revision: number;
    CertificateDate: number;
}

export interface KeyInfo {
    Fingerprint: string;
    SHA256Fingerprints: string[];
    Primary: number;
    Flags: number;
}
