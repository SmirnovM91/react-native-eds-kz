# react-native-eds-kz

## Getting started

`npm install https://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@github.com/SmirnovM91/react-native-eds-kz.git`

### iOS

`cd ios && pod install && cd ..`

## Usage

### XML

```typescript
import RNEDS, { IEDSRequest, IEDSResponseXML } from "react-native-eds-kz";

const password = "Qwerty12";
const path = "path/to/.p12";

const XMLData: string = "<root>Test123</root>";
const xml_request_data: IEDSRequest = { data, password, path };

RNEDS.authXMLData(xml_request_data)
  .then((result: IEDSResponseXML) => {
    console.log(result);
  })
  .catch(console.log);
RNEDS.signXMLData(xml_request_data)
  .then((result: IEDSResponseXML) => {
    console.log(result);
  })
  .catch(console.log);
```

### Plain

```typescript
import RNEDS, { IEDSResponsePlain, IEDSRequest } from "react-native-eds-kz";

const password = "Qwerty12";
const path = "path/to/.p12";

const PlainData = "Test123";
const plain_request_data: IEDSRequest = { data, password, path };

RNEDS.authXMLData(plain_request_data)
  .then((result: IEDSResponsePlain) => {
    console.log(result);
  })
  .catch(console.log);
RNEDS.signXMLData(plain_request_data)
  .then((result: IEDSResponsePlain) => {
    console.log(result);
  })
  .catch(console.log);
```

## Types

```typescript
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

interface IEDSRequest {
  path: string;
  password: string;
  data: string;
}

interface IEDSResponsePlain extends IBaseResponse {
  signature: string;
}

interface IEDSResponseXML extends IBaseResponse {
  signedXML: string;
}
```
