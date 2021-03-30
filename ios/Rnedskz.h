//
//  Rnedskz.h
//  kgd
//
//  Created by Михаил Смирнов on 04/09/2019.
//  Copyright © 2019 Facebook. All rights reserved.
//



#import <React/RCTBridgeModule.h>

#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pkcs12.h>
#include <openssl/x509.h>

#include <libxml/parser.h>
#include <libxml/tree.h>
#include "libxml/c14n.h"
#include "libxml/xpath.h"
#include "libxml/xpathInternals.h"


#include "Base64.h"
#include "obj_mac.h"

@interface Rnedskz : NSObject <RCTBridgeModule>
-(void) initialize;
- (NSString *)stringFromHexString:(NSString *)hexString;
@end
