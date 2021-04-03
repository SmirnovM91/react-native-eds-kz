import { NativeModules } from "react-native";

const { Rnedskz } = NativeModules;

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

export interface IEDSRequest {
  path: string;
  password: string;
  data: string;
}

export interface IEDSResponsePlain extends IBaseResponse {}

export interface IEDSResponseXML extends IBaseResponse {
  signedXML: string;
}

const callback = (err, result: IEDSResponsePlain, resolve, reject) => {
  if (err) {
    return reject(err);
  }
  resolve(result);
};

export function authPlainData({
  path,
  password,
  data,
}: IEDSRequest): Promise<IEDSResponsePlain> {
  return new Promise((resolve, reject) => {
    Rnedskz.authPlainData(path, password, data, (err, result) =>
      callback(err, result, resolve, reject)
    );
  });
}
export function signPlainData({
  path,
  password,
  data,
}: IEDSRequest): Promise<IEDSResponsePlain> {
  return new Promise((resolve, reject) => {
    Rnedskz.signPlainData(path, password, data, (err, result) =>
      callback(err, result, resolve, reject)
    );
  });
}

export function authXMLData({
  path,
  password,
  data,
}: IEDSRequest): Promise<IEDSResponseXML> {
  return new Promise((resolve, reject) => {
    Rnedskz.authXMLData(path, password, data, (err, result) =>
      callback(err, result, resolve, reject)
    );
  });
}
export function signXMLData({
  path,
  password,
  data,
}: IEDSRequest): Promise<IEDSResponseXML> {
  return new Promise((resolve, reject) => {
    Rnedskz.signXMLData(path, password, data, (err, result) =>
      callback(err, result, resolve, reject)
    );
  });
}

const RNEDS = { signPlainData, authPlainData, signXMLData, authXMLData };

export default RNEDS;
