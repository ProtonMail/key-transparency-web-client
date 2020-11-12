import { SignedKeyList } from '../interfaces/SignedKeyList';

export const getSignedKeyLists = (params: { SinceEpochID: number; Email: string }) => ({
    url: 'keys/signedkeylists',
    method: 'get',
    params,
});

export const updateSignedKeyList = (params: { AddressID: string }, data: { SignedKeyList: SignedKeyList }) => ({
    url: 'keys/signedkeylists',
    method: 'post',
    params,
    data,
});
