export interface IEDSResponse {
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
    signedXML: string;
}
export declare const authPlainData: ({ path, password, data, }: {
    path: any;
    password: any;
    data: any;
}) => Promise<IEDSResponse>;
export declare const signPlainData: ({ path, password, data, }: {
    path: any;
    password: any;
    data: any;
}) => Promise<IEDSResponse>;
