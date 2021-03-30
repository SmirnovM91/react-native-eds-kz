import { NativeModules } from "react-native";

const { Rnedskz } = NativeModules;

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

const callback = (err, result: IEDSResponse, resolve, reject) => {
  if (err) {
    return reject(err);
  }
  resolve(result);
};

export const authPlainData = ({
  path,
  password,
  data,
}): Promise<IEDSResponse> => {
  return new Promise((resolve, reject) => {
    Rnedskz.authPlainData(path, password, data, (err, result) =>
      callback(err, result, resolve, reject)
    );
  });
};
export const signPlainData = ({
  path,
  password,
  data,
}): Promise<IEDSResponse> => {
  return new Promise((resolve, reject) => {
    Rnedskz.signPlainData(path, password, data, (err, result) =>
      callback(err, result, resolve, reject)
    );
  });
};
export default Rnedskz;
