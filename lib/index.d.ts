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
    signature: string;
    signedData: string;
}
export interface IEDSResponsePlain extends IBaseResponse {
}
export interface IEDSResponseXML extends IBaseResponse {
    signedXML: string;
}
export declare function authPlainData({ path, password, data, }: {
    path: any;
    password: any;
    data: any;
}): Promise<IEDSResponsePlain>;
export declare function signPlainData({ path, password, data, }: {
    path: any;
    password: any;
    data: any;
}): Promise<IEDSResponsePlain>;
export declare function authXMLData({ path, password, data, }: {
    path: any;
    password: any;
    data: any;
}): Promise<IEDSResponseXML>;
export declare function signXMLData({ path, password, data, }: {
    path: any;
    password: any;
    data: any;
}): Promise<IEDSResponseXML>;
declare const RNEDS: {
    signPlainData: typeof signPlainData;
    authPlainData: typeof authPlainData;
};
export default RNEDS;
