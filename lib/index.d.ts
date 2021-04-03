interface IBaseResponse {
    certData: {
        commonName: string;
        countryName: string;
        emailAddress: string;
        givenName: string;
        serialNumber: string;
        surname: string;
        type: string;
    };
    certExpireDate: string;
    certificate: string;
    signedData: string;
}
export interface IEDSRequest {
    path: string;
    password: string;
    data: string;
}
export interface IEDSResponsePlain extends IBaseResponse {
    signature: string;
}
export interface IEDSResponseXML extends IBaseResponse {
    signedXML: string;
}
export declare function authPlainData({ path, password, data, }: IEDSRequest): Promise<IEDSResponsePlain>;
export declare function signPlainData({ path, password, data, }: IEDSRequest): Promise<IEDSResponsePlain>;
export declare function authXMLData({ path, password, data, }: IEDSRequest): Promise<IEDSResponseXML>;
export declare function signXMLData({ path, password, data, }: IEDSRequest): Promise<IEDSResponseXML>;
declare const RNEDS: {
    signPlainData: typeof signPlainData;
    authPlainData: typeof authPlainData;
    signXMLData: typeof signXMLData;
    authXMLData: typeof authXMLData;
};
export default RNEDS;
