//
//  Rnedskz.m
//  
//  Created by Михаил Смирнов on 04/09/2019.
//  Copyright © 2019 Facebook. All rights reserved.
//

#import "Rnedskz.h"

const xmlChar* NS_XMLDSIG = BAD_CAST "http://www.w3.org/2000/09/xmldsig#";
const xmlChar* C14N_OMIT_COMMENTS = BAD_CAST "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
const xmlChar* C14N_WITH_COMMENTS = BAD_CAST "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments";
const xmlChar* ALG_GOST34310 = BAD_CAST "http://www.w3.org/2001/04/xmldsig-more#gost34310-gost34311";
const xmlChar* ALG_TRANSFORM = BAD_CAST "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
const xmlChar* ALG_GOST34311 = BAD_CAST "http://www.w3.org/2001/04/xmldsig-more#gost34311";
const xmlChar* ALG_RSA256 = BAD_CAST "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
const xmlChar* ALG_SHA256 = BAD_CAST "http://www.w3.org/2001/04/xmlenc#sha256";
const xmlChar* ALG_RSA = BAD_CAST "http://www.w3.org/2001/04/xmldsig-more#rsa-sha1";
const xmlChar* ALG_SHA1 = BAD_CAST "http://www.w3.org/2001/04/xmldsig-more#sha1";

#define PHYSICAL_PERSON_OID "1.2.398.3.3.4.1.1" // Физическое лицо
#define JURIDICAL_PERSON_OID "1.2.398.3.3.4.1.2" // Юридическое лицо
#define JP_FIRST_DIRECTOR_OID "1.2.398.3.3.4.1.2.1" //  Первый руководитель юридического лица, имеющий право подписи
#define JP_WITH_SIGN_RIGHT_OID "1.2.398.3.3.4.1.2.2" // Лицо, наделенное правом подписи
#define JP_WITH_SIGN_RIGHT_OF_FINANCE_OID "1.2.398.3.3.4.1.2.3" // Лицо, наделенное правом подписи финансовых документов
#define JP_HR_EMPLOYEE_OID "1.2.398.3.3.4.1.2.4" //  Сотрудник отдела кадров, наделенный правом подтверждать заявки на выпуск регистрационных свидетельств поданные от сотрудников юридического лица
#define JP_EMPLOYEE_OID "1.2.398.3.3.4.1.2.5" // Сотрудник организации

#define AUTH_KEY "1.3.6.1.5.5.7.3.2" // ключ AUTH
#define RSA_KEY "1.3.6.1.5.5.7.3.4" // ключ RSA

@implementation Rnedskz

RCT_EXPORT_MODULE();

- (void)initialize{
  OpenSSL_add_all_algorithms();
  ENGINE_load_gost();
  ERR_load_crypto_strings();
}

- (NSString *)stringFromHexString:(NSString *)hexString {
  
  // The hex codes should all be two characters.
  if (([hexString length] % 2) != 0)
    return nil;
  
  NSMutableString *string = [NSMutableString string];
  
  for (NSInteger i = 0; i < [hexString length]; i += 2) {
    
    NSString *hex = [hexString substringWithRange:NSMakeRange(i, 2)];
    NSInteger decimalValue = 0;
    sscanf([hex UTF8String], "%x", &decimalValue);
    [string appendFormat:@"%c", decimalValue];
  }
  
  return string;
}

RCT_EXPORT_METHOD(
                  signPlainData:(NSString*)certPath
                  certPassword:(NSString*)certPassword
                  signData:(NSString*)signData
                  callback:(RCTResponseSenderBlock)callback
                  )
{
  @try{
    [self initialize];
    callback(@[[NSNull null], [self signXml:certPath :certPassword :signData :@RSA_KEY]]);
  }
  @catch(NSException *exception){
    callback(@[exception.reason, [NSNull null]]);
  }
}

RCT_EXPORT_METHOD(
                  authPlainData:(NSString*)certPath
                  certPassword:(NSString*)certPassword
                  signData:(NSString*)signData
                  callback:(RCTResponseSenderBlock)callback
                  )
{
  @try{
    [self initialize];
    callback(@[[NSNull null], [self signXml:certPath :certPassword :signData :@AUTH_KEY]]);
  }
  @catch(NSException *exception){
    callback(@[exception.reason, [NSNull null]]);
  }
}

- (NSDictionary *)signXml
:(NSString*)pkcs12_path
:(NSString*)certPassword
:(NSString*)signData
:(NSString*)keyType
{
  @try {
    
    
    unsigned char *cXml = ( unsigned char *) [signData UTF8String];
    
    xmlDocPtr doc = NULL;
    xmlNodePtr root = NULL, signEl = NULL, sInfoEl = NULL, canMethEl = NULL, signMethEl = NULL, refEl = NULL, transEl = NULL, tranEl = NULL, tran2El = NULL, digMethEl = NULL, digValEl = NULL, sigValEl = NULL, kInfoEl = NULL, x509DataEl = NULL, x509CertEl = NULL;
    
    FILE *fp;
    PKCS12 *p12;
    EVP_PKEY *pkey;
    X509 *cert;
    int err;
    
    STACK_OF(X509) *ca = NULL;
    //  NSLog(@"PKCS#12: %@", pkcs12_path);
    if(![[NSFileManager defaultManager] fileExistsAtPath:pkcs12_path]) {
      @throw([NSException exceptionWithName:@"NOFILE" reason:@"NOFILE" userInfo:nil]);
    }
    
    fp = fopen([pkcs12_path UTF8String], "rb");
    p12 = d2i_PKCS12_fp(fp, NULL);
    fclose (fp);
    if (!p12) {
      @throw([NSException exceptionWithName:@"WRONGFILE" reason:@"WRONGFILE" userInfo:nil]);
    }
    
    const char *password = ( char *) [certPassword UTF8String];
    
    if (!PKCS12_parse(p12, password, &pkey, &cert, &ca)) { //Error at parsing or password error
      @throw([NSException exceptionWithName:@"WRONGPASSWORDKEY" reason:@"WRONGPASSWORDKEY" userInfo:nil]);
    }
    
    
    
    int len;
    unsigned char *buf;
    unsigned char *pem;
    buf = NULL;
    len = i2d_X509(cert, &buf);
    pem = base64encode(buf, len);
    
    //    NSLog(@"pem = %s\n\n", pem);
    
    
    PKCS12_free(p12);
    
    
    
    doc = xmlParseDoc(cXml);
    xmlChar* c14nXML = NULL;
    xmlC14NDocDumpMemory(doc, NULL, 0, NULL, 0, &c14nXML);
    int c14nXMLLen = strlen((char*)c14nXML);
    //    printf(c14nXML);
    
    EVP_MD_CTX *mdCtx;
    EVP_MD *md;
    xmlChar *xmlHashAlg = ALG_GOST34311;
    xmlChar *xmlSignAlg = ALG_GOST34310;
    
    X509_NAME *x509Name = X509_get_subject_name(cert);
    unsigned int x509count = X509_NAME_entry_count(x509Name);
    
    
    char *value = NULL;
    char name[1024];
    NSMutableDictionary *x509dictionary = [[NSMutableDictionary alloc] init];
    
    for (unsigned int i = 0; i < x509count; i++)
    {
      X509_NAME_ENTRY *entry = X509_NAME_get_entry(x509Name, i);
      OBJ_obj2txt(name, sizeof(name), entry->object, 0);
      ASN1_STRING_to_UTF8((unsigned char **)&value, entry->value);
      [x509dictionary setObject:
       [NSString stringWithUTF8String:(char *)value]
                         forKey:[NSString stringWithUTF8String:(char *)name]];
      
    }
    
    
    // getting type of user(FL/UL and etc)
    struct stack_st_ASN1_OBJECT *obj = X509_get_ext_d2i(cert, NID_ext_key_usage, NULL, NULL);
    for (int i=0; i<sk_ASN1_OBJECT_num(obj); i++) {
      char buffer[100];
      OBJ_obj2txt(buffer, sizeof(buffer), sk_ASN1_OBJECT_value(obj, i), 1);
      if (strcmp(buffer, PHYSICAL_PERSON_OID) == 0){
        [x509dictionary setObject:@"FL" forKey:@"type"];
      } else
        if (strcmp(buffer, JURIDICAL_PERSON_OID) == 0){
          [x509dictionary setObject:@"UL" forKey:@"type"];
        }
    }
    
    
    
    const char *keytype = [keyType UTF8String];
    ASN1_BIT_STRING *key_usage = X509_get_ext_d2i(cert, NID_key_usage, NULL, NULL);
    
    int digitalSignature = ASN1_BIT_STRING_get_bit(key_usage, 0);
    int nonRepudiation = ASN1_BIT_STRING_get_bit(key_usage, 1);
    int keyEncipherment = ASN1_BIT_STRING_get_bit(key_usage, 2);
    
    BOOL isAuth = digitalSignature == 1 && keyEncipherment == 1;
    BOOL isRsa = digitalSignature == 1 && nonRepudiation == 1;
    
    if (strcmp(keytype, AUTH_KEY) == 0 && isRsa ){
      @throw([NSException exceptionWithName:@"CERTIFICATE_NOT_FOR_AUTH" reason:@"CERTIFICATE_NOT_FOR_AUTH" userInfo:nil]);
    } else  if (strcmp(keytype, RSA_KEY) == 0 && isAuth ){
      @throw([NSException exceptionWithName:@"CERTIFICATE_NOT_FOR_SIGN" reason:@"CERTIFICATE_NOT_FOR_SIGN" userInfo:nil]);
    } else if (!isRsa && !isAuth) {
      @throw([NSException exceptionWithName:@"UNKNOWN_CERTIFICATE_TYPE" reason:@"UNKNOWN_CERTIFICATE_TYPE" userInfo:nil]);
    }
  
  
  
  
  
  ASN1_TIME *certificateExpiryDate = X509_get_notAfter(cert);
  ASN1_GENERALIZEDTIME *timeASN1Generalized = ASN1_TIME_to_generalizedtime(certificateExpiryDate, NULL);
  unsigned char *stringASN1Data = ASN1_STRING_data(timeASN1Generalized);
  NSString *certExpireDate = [NSString stringWithUTF8String:(char *)stringASN1Data];
  //  NSLog(@"Expire Date: %s",stringASN1Data);
  
  NSDateFormatter *dateFormatter = [[NSDateFormatter alloc] init];
  [dateFormatter setDateFormat:@"yyyyMMddHHmmssZ"];
  NSDate *date = [dateFormatter dateFromString:certExpireDate];
  if ([date timeIntervalSinceNow] < 0.0) {
    @throw([NSException exceptionWithName:@"CERTEXPIRED" reason:@"CERTEXPIRED" userInfo:nil]);
  }
  
  
  int algnid = OBJ_obj2nid(cert->cert_info->signature->algorithm);
  if(algnid == NID_id_GostOld34311_95_with_GostOld34310_2004 || algnid == NID_id_Gost34311_95_with_Gost34310_2004) {
    md = EVP_get_digestbynid(NID_id_Gost34311_95);
    xmlHashAlg = ALG_GOST34311;
    xmlSignAlg = ALG_GOST34310;
  } else if(algnid == NID_sha256WithRSAEncryption) {
    md = EVP_sha256();
    xmlHashAlg = ALG_SHA256;
    xmlSignAlg = ALG_RSA256;
  } else if(algnid == NID_sha1WithRSAEncryption) {
    md = EVP_sha1();
    xmlHashAlg = ALG_SHA1;
    xmlSignAlg = ALG_RSA;
  }
  unsigned char *cHash = (unsigned char*)malloc(EVP_MD_size(md));
  unsigned int cHashLen;
  mdCtx = EVP_MD_CTX_create();
  EVP_DigestInit_ex(mdCtx, md, NULL);
  EVP_DigestUpdate(mdCtx, c14nXML, c14nXMLLen);
  EVP_DigestFinal_ex(mdCtx, cHash, &cHashLen);
  EVP_MD_CTX_cleanup(mdCtx);
  
  char *base64Digest = base64encode(cHash, cHashLen);
  //    NSLog(@"Encoded hash: %s", base64Digest);
  
  xmlXPathContextPtr xpathCtx;
  xmlXPathObjectPtr xpathObj;
  xmlNodeSetPtr sInfoNS;
  
  // создаем Signature и заполняем
  root = xmlDocGetRootElement(doc);
  signEl = xmlNewNode(NULL, BAD_CAST "ds:Signature");
  xmlNsPtr signNS = xmlNewNs(signEl, NS_XMLDSIG, BAD_CAST "ds");
  xmlAddChild(root, signEl);
  sInfoEl = xmlNewChild(signEl, signNS, BAD_CAST "SignedInfo", NULL);
  canMethEl = xmlNewChild(sInfoEl, signNS, BAD_CAST "CanonicalizationMethod", NULL);
  xmlNewProp(canMethEl, BAD_CAST "Algorithm", C14N_OMIT_COMMENTS);
  signMethEl = xmlNewChild(sInfoEl, signNS, BAD_CAST "SignatureMethod", NULL);
  xmlNewProp(signMethEl, BAD_CAST "Algorithm", xmlSignAlg);
  refEl = xmlNewChild(sInfoEl, signNS, BAD_CAST "Reference", NULL);
  xmlNewProp(refEl, BAD_CAST "URI", NULL);
  transEl = xmlNewChild(refEl, signNS, BAD_CAST "Transforms", NULL);
  tranEl = xmlNewChild(transEl, signNS, BAD_CAST "Transform", NULL);
  xmlNewProp(tranEl, BAD_CAST "Algorithm", ALG_TRANSFORM);
  tran2El = xmlNewChild(transEl, signNS, BAD_CAST "Transform", NULL);
  xmlNewProp(tran2El, BAD_CAST "Algorithm", C14N_WITH_COMMENTS);
  digMethEl = xmlNewChild(refEl, signNS, BAD_CAST "DigestMethod", NULL);
  xmlNewProp(digMethEl, BAD_CAST "Algorithm", xmlHashAlg);
  digValEl = xmlNewChild(refEl, signNS, BAD_CAST "DigestValue", BAD_CAST base64Digest);
  
  xpathCtx = xmlXPathNewContext(doc);
  xmlXPathRegisterNs(xpathCtx, BAD_CAST "ds", NS_XMLDSIG);
  xpathObj = xmlXPathEvalExpression(BAD_CAST "(//. | //@* | //namespace::*)[ancestor-or-self::ds:SignedInfo]", xpathCtx);
  sInfoNS = xpathObj->nodesetval;
  
  xmlChar *c14nSInfo = NULL;
  xmlC14NDocDumpMemory(doc, sInfoNS, 0, NULL, 1, &c14nSInfo);
  xmlXPathFreeObject(xpathObj);
  xmlXPathFreeContext(xpathCtx);
  
  int c14nSInfoLen = strlen((char*)c14nSInfo);
  //    NSLog(@"Canonicalized SignedInfo = %s", c14nSInfo);
  //    NSLog(@"key size = %d", EVP_PKEY_size(pkey));
  
  // подписываем
  unsigned char *cSignature = (unsigned char*)malloc(EVP_PKEY_size(pkey));
  unsigned int sigLen;
  EVP_SignInit_ex(mdCtx, md, NULL);
  EVP_SignUpdate (mdCtx, c14nSInfo, c14nSInfoLen);
  EVP_SignFinal (mdCtx, cSignature, &sigLen, pkey);
  
  // вообще, так надо проверять каждую функцию библиотеки провайдера
  // и что-то предпринимать
  if (err != 1) {
    ERR_print_errors_fp(stderr);
  }
  
  char *base64Signature = base64encode(cSignature, sigLen);
  //    NSLog(@"Encoded signature: %s", base64Signature);
  
  // дописываем xml
  sigValEl = xmlNewChild(signEl, signNS, BAD_CAST "SignatureValue", BAD_CAST base64Signature);
  kInfoEl = xmlNewChild(signEl, signNS, BAD_CAST "KeyInfo", NULL);
  x509DataEl = xmlNewChild(kInfoEl, signNS, BAD_CAST "X509Data", NULL);
  x509CertEl = xmlNewChild(x509DataEl, signNS, BAD_CAST "X509Certificate", BAD_CAST pem);
  
  // выдаем подписанный xml
  xmlChar *outXML;
  int outXMLSize;
  xmlDocDumpMemoryEnc(doc, &outXML, &outXMLSize, "UTF-8");
  
  
  NSString *signedXML = [NSString stringWithUTF8String:(char *)outXML];
  //  NSLog(@"Signed XML: %s",[signedXML cStringUsingEncoding:NSUTF8StringEncoding]);
  
  xmlFreeDoc(doc);
  xmlCleanupParser();
  xmlMemoryDump();
  EVP_PKEY_free(pkey);
  X509_free(cert);
  EVP_MD_CTX_destroy(mdCtx);
  ERR_free_strings();
  EVP_cleanup();// вызываем только, когда абсолютно все завершили
    NSString *certificate = [NSString stringWithUTF8String:(char *)pem];
    
    
    
    NSData *nsdata = [signedXML dataUsingEncoding:NSUTF8StringEncoding];
    NSString *signature = [nsdata base64EncodedStringWithOptions:0];
    
    id objects[] = { x509dictionary, certExpireDate, signedXML,signData, signature, certificate };
  id keys[] = { @"certData", @"certExpireDate", @"signedXML", @"signedData", @"signature", @"certificate"};
  NSUInteger count = sizeof(objects) / sizeof(id);
  NSDictionary *dictionary = [NSDictionary dictionaryWithObjects:objects
                                                         forKeys:keys
                                                           count:count];
  
  return dictionary;
} @catch (NSException *exception) {
  @throw exception;
}

}

@end
