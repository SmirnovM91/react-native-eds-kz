package dev.amsmirnov.rnedskz;

import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.bridge.Callback;
import com.facebook.react.bridge.WritableMap;
import com.facebook.react.bridge.WritableNativeMap;

import java.io.ByteArrayInputStream;
import java.io.InputStream;

import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.Signature;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.Enumeration;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import kz.gov.pki.kalkan.asn1.pkcs.PKCSObjectIdentifiers;
import kz.gov.pki.kalkan.jce.provider.KalkanProvider;
import kz.gov.pki.kalkan.xmldsig.KncaXS;

import org.apache.xml.security.encryption.XMLCipherParameters;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.utils.Constants;
import org.w3c.dom.Document;

import android.util.Base64;


import android.net.Uri;


import org.bouncycastle.jce.provider.BouncyCastleProvider;


public class RnedskzModule extends ReactContextBaseJavaModule {
    private static final String PHYSICAL_PERSON_OID = "1.2.398.3.3.4.1.1"; // Физическое лицо
    private static final String JURIDICAL_PERSON_OID = "1.2.398.3.3.4.1.2"; // Юридическое лицо

    private static final String AUTH_KEY = "1.3.6.1.5.5.7.3.2"; // AUTH ключ
    private static final String RSA_KEY = "1.3.6.1.5.5.7.3.4"; // RSA ключ

    private final ReactApplicationContext reactContext;

    public RnedskzModule(ReactApplicationContext reactContext) {
        super(reactContext);
        this.reactContext = reactContext;
    }

    @Override
    public String getName() {
        return "Rnedskz";
    }

    @ReactMethod
    public void signXMLData(String certPath, String certPassword, String signData, Callback callback) {
        try {
            callback.invoke(null, signXML(signData, certPath, certPassword, RSA_KEY));
        } catch (Exception e) {
            callback.invoke(e.getMessage());
        }
    }

    @ReactMethod
    public void authXMLData(String certPath, String certPassword, String signData, Callback callback) {
        try {
            callback.invoke(null, signXML(signData, certPath, certPassword, AUTH_KEY));
        } catch (Exception e) {
            callback.invoke(e.getMessage());
        }
    }


    @ReactMethod
    public void signPlainData(String certPath, String certPassword, String signData, Callback callback) {
        try {
            callback.invoke(null, sign(signData, certPath, certPassword, RSA_KEY));
        } catch (Exception e) {
            callback.invoke(e.getMessage());
        }
    }

    @ReactMethod
    public void authPlainData(String certPath, String certPassword, String signData, Callback callback) {
        try {
            callback.invoke(null, sign(signData, certPath, certPassword, AUTH_KEY));
        } catch (Exception e) {
            callback.invoke(e.getMessage());
        }
    }

    private WritableMap sign(String data, String path, String password, String keyType) throws Exception {
        CredentialInfo credentialInfo = loadCredentialFromFile(path, password);

        checkTypeAndExpiration(credentialInfo, keyType);

        WritableMap dictionary = new WritableNativeMap();
        String signature = sign(data, credentialInfo.key, credentialInfo.x509Certificate);
        dictionary.putString("signature", signature);
        dictionary.putString("signedData", data);
        writeBaseData(dictionary, credentialInfo);

        return dictionary;
    }

    private String sign(String data, PrivateKey privateKey, X509Certificate x509Certificate) throws Exception {
        return Base64.encodeToString(sign(data.getBytes(StandardCharsets.UTF_8), privateKey, x509Certificate), android.util.Base64.DEFAULT);
    }

    private byte[] sign(byte[] data, PrivateKey privateKey, X509Certificate x509Certificate) throws Exception {
        KalkanProvider provider = new KalkanProvider();
        Security.addProvider(provider);
        Provider p = new BouncyCastleProvider();
        Security.addProvider(p);
        try {
            Signature signature = Signature.getInstance(x509Certificate.getSigAlgName(), provider);
            signature.initSign(privateKey);
            signature.update(data);
            return signature.sign();
        } catch (InvalidKeyException | NoSuchAlgorithmException var3) {
            throw new RuntimeException(var3);
        }
    }

    public WritableMap signXML(String signData, String path, String password, String keyType) throws Exception {

        CredentialInfo credentialInfo = loadCredentialFromFile(path, password);
        checkTypeAndExpiration(credentialInfo, keyType);

        WritableMap dictionary = new WritableNativeMap();
        writeBaseData(dictionary, credentialInfo);
        try {
            dictionary.putString("signedData", signData);
            writeBaseData(dictionary, credentialInfo);

            //подписываем XML
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();


            dbf.setNamespaceAware(true);
            DocumentBuilder documentBuilder = dbf.newDocumentBuilder();
            Document doc = documentBuilder.parse(new ByteArrayInputStream(signData.getBytes("UTF-8")));
            String signMethod;
            String digestMethod;

            String sigAlgOid = credentialInfo.x509Certificate.getSigAlgOID();

            if (sigAlgOid.equals(PKCSObjectIdentifiers.sha1WithRSAEncryption.getId())) {

                digestMethod = Constants.MoreAlgorithmsSpecNS + "sha1";
                signMethod = Constants.MoreAlgorithmsSpecNS + "rsa-sha1";
            } else if (sigAlgOid.equals(PKCSObjectIdentifiers.sha256WithRSAEncryption.getId())) {

                digestMethod = XMLCipherParameters.SHA256;
                signMethod = Constants.MoreAlgorithmsSpecNS + "rsa-sha256";
            } else {

                digestMethod = Constants.MoreAlgorithmsSpecNS + "gost34311";
                signMethod = Constants.MoreAlgorithmsSpecNS + "gost34310-gost34311";
            }


            XMLSignature xsig = new XMLSignature(doc, "", signMethod);

            String sxml = null;
            if (doc.getFirstChild() != null) {
                doc.getFirstChild().appendChild(xsig.getElement());
                Transforms transforms = new Transforms(doc);
                transforms.addTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE);
                transforms.addTransform(XMLCipherParameters.N14C_XML_CMMNTS);
                xsig.addDocument("", transforms, digestMethod);

                xsig.addKeyInfo(credentialInfo.x509Certificate);
                xsig.sign(credentialInfo.key);

                StringWriter os = new StringWriter();
                TransformerFactory tf = TransformerFactory.newInstance();
                Transformer trans = tf.newTransformer();
                trans.transform(new DOMSource(doc), new StreamResult(os));
                os.close();


                sxml = os.toString();
                dictionary.putString("signedXML", sxml);
            }

        } catch (Exception e) {
            System.err.println(e.getMessage());
            throw new Exception(e.getMessage());

        }
        return dictionary;
    }

    public void checkTypeAndExpiration(CredentialInfo credentialInfo, String keyType) throws Exception {
        try {
            boolean[] keyUsages = credentialInfo.x509Certificate.getKeyUsage();
            boolean digitalSignature = keyUsages[0];
            boolean nonRepudiation = keyUsages[1];
            boolean keyEncipherment = keyUsages[2];

            boolean isAuth = digitalSignature && keyEncipherment;
            boolean isRsa = digitalSignature && nonRepudiation;

            if (keyType == AUTH_KEY && isRsa) {
                throw new Exception("CERTIFICATE_NOT_FOR_AUTH");
            } else if (keyType == RSA_KEY && isAuth) {
                throw new Exception("CERTIFICATE_NOT_FOR_SIGN");
            } else if (!isRsa && !isAuth) {
                throw new Exception("UNKNOWN_CERTIFICATE_TYPE");
            }
        } catch (CertificateParsingException e) {
            throw new Exception("CERTIFICATE_PARSING_ERROR");
        }

        try {
            credentialInfo.x509Certificate.checkValidity();

        } catch (Exception e) {
            throw new Exception("CERTEXPIRED");
        }
    }

    public void writeBaseData(WritableMap dictionary, CredentialInfo credentialInfo) throws Exception {
        try {
            String certificate = Base64.encodeToString(credentialInfo.x509Certificate.getEncoded(), android.util.Base64.DEFAULT);
            dictionary.putString("certificate", certificate);
            Principal principal = credentialInfo.x509Certificate.getSubjectDN();
            WritableMap certData = new WritableNativeMap();
            String type = "";
            for (String oid : credentialInfo.x509Certificate.getExtendedKeyUsage()) {
                // Определим субъект и позицию владельца ключа
                switch (oid) {
                    case PHYSICAL_PERSON_OID:
                        type = "FL";
                        break;
                    case JURIDICAL_PERSON_OID:
                        type = "UL";
                        break;
                }
            }
            certData.putString("type", type);
            String[] tmp = principal.toString().split(",");
            for (String value : tmp) {
                String[] nameValue = value.trim().split("=");
                switch (nameValue[0]) {
                    case "CN":
                        certData.putString("commonName", nameValue[1]);
                        break;
                    case "SERIALNUMBER":
                        certData.putString("serialNumber", nameValue[1]);
                        break;
                    case "GIVENNAME":
                        certData.putString("givenName", nameValue[1]);
                        break;
                    default:
                        certData.putString(nameValue[0], nameValue[1]);
                        break;
                }
            }
            dictionary.putMap("certData", certData);
            SimpleDateFormat dateFormat = new SimpleDateFormat("yyyyMMddHHmmss");
            dictionary.putString("certExpireDate", dateFormat.format(credentialInfo.x509Certificate.getNotAfter()) + "Z");
        } catch (Exception e) {
            throw new Exception("CANNOT_SET_DATA");
        }
    }

    public CredentialInfo loadCredentialFromFile(String path, String password) throws Exception {

        Provider kal = new KalkanProvider();
        Security.addProvider(kal);
        Provider p = new BouncyCastleProvider();
        Security.addProvider(p);
        KncaXS.loadXMLSecurity();
        InputStream ksis;
        try {
            Uri uri = Uri.parse(path);
            ksis = getReactApplicationContext().getContentResolver().openInputStream(uri);
        } catch (Exception e) {
            throw new Exception("NOFILE");
        }

        char[] pwd = password.toCharArray();

        KeyStore ks = KeyStore.getInstance("PKCS12", p.getName());
        try {
            ks.load(ksis, pwd);
        } catch (Exception e) {
            throw new Exception("WRONGPASSWORDKEY");
        }


        PrivateKey key;
        X509Certificate x509Certificate;
        try {
            Enumeration<String> als = ks.aliases();
            String al = null;
            while (als.hasMoreElements()) {
                al = als.nextElement();
            }
            key = (PrivateKey) ks.getKey(al, pwd);
            x509Certificate = (X509Certificate) ks.getCertificate(al);
        } catch (Exception e) {
            throw new Exception("WRONGPASSWORDKEY");
        }

        return new CredentialInfo(key, x509Certificate);
    }


    public static class CredentialInfo {

        private PrivateKey key;
        private X509Certificate x509Certificate;

        public CredentialInfo(PrivateKey key, X509Certificate x509Certificate) {
            this.key = key;
            this.x509Certificate = x509Certificate;
        }

        public PrivateKey getKey() {
            return key;
        }

        public X509Certificate getX509Certificate() {
            return x509Certificate;
        }
    }
}
