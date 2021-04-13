//
//  ViewController.m
//  CtkConsumer
//
//  Created on 10/16/20.
//

#import "ViewController.h"
#include <CommonCrypto/CommonDigest.h>

#include <vector>

NSMutableArray* algs = nil;
SecPadding paddings[6] = {
    //kSecPaddingPKCS1,
    kSecPaddingPKCS1SHA1,
    kSecPaddingPKCS1SHA224,
    kSecPaddingPKCS1SHA256,
    kSecPaddingPKCS1SHA384,
    kSecPaddingPKCS1SHA512,
    kSecPaddingNone
    //kSecPaddingOAEP
};

SecPadding encpaddings[3] = {
    kSecPaddingPKCS1,
    //kSecPaddingPKCS1SHA1,
    //kSecPaddingPKCS1SHA224,
    //kSecPaddingPKCS1SHA256,
    //kSecPaddingPKCS1SHA384,
    //kSecPaddingPKCS1SHA512,
    kSecPaddingNone,
    kSecPaddingOAEP
};

SecKeyAlgorithm rsaSigAlgsDigest[11] = {
    kSecKeyAlgorithmRSASignatureDigestPKCS1v15Raw,
    kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA1,
    kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA224,
    kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA256,
    kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA384,
    kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA512,
    
    kSecKeyAlgorithmRSASignatureDigestPSSSHA1,
    kSecKeyAlgorithmRSASignatureDigestPSSSHA224,
    kSecKeyAlgorithmRSASignatureDigestPSSSHA256,
    kSecKeyAlgorithmRSASignatureDigestPSSSHA384,
    kSecKeyAlgorithmRSASignatureDigestPSSSHA512
};
SecKeyAlgorithm rsaSigAlgsMessage[11] = {
    kSecKeyAlgorithmRSASignatureRaw,
    kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA1,
    kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA224,
    kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA256,
    kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA384,
    kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA512,
    kSecKeyAlgorithmRSASignatureMessagePSSSHA1,
    kSecKeyAlgorithmRSASignatureMessagePSSSHA224,
    kSecKeyAlgorithmRSASignatureMessagePSSSHA256,
    kSecKeyAlgorithmRSASignatureMessagePSSSHA384,
    kSecKeyAlgorithmRSASignatureMessagePSSSHA512
};

SecKeyAlgorithm rsaEncAlgs[12] {
    kSecKeyAlgorithmRSAEncryptionRaw,
    kSecKeyAlgorithmRSAEncryptionPKCS1,
    kSecKeyAlgorithmRSAEncryptionOAEPSHA1,
    kSecKeyAlgorithmRSAEncryptionOAEPSHA224,
    kSecKeyAlgorithmRSAEncryptionOAEPSHA256,
    kSecKeyAlgorithmRSAEncryptionOAEPSHA384,
    kSecKeyAlgorithmRSAEncryptionOAEPSHA512,
    kSecKeyAlgorithmRSAEncryptionOAEPSHA1AESGCM,
    kSecKeyAlgorithmRSAEncryptionOAEPSHA224AESGCM,
    kSecKeyAlgorithmRSAEncryptionOAEPSHA256AESGCM,
    kSecKeyAlgorithmRSAEncryptionOAEPSHA384AESGCM,
    kSecKeyAlgorithmRSAEncryptionOAEPSHA512AESGCM
};

void InitAlgArray()
{
    if(algs)return;
    
    algs = [[NSMutableArray alloc]init];
    [algs addObject:(id)kSecKeyAlgorithmRSAEncryptionRaw];
    [algs addObject:(id)kSecKeyAlgorithmRSASignatureDigestPKCS1v15Raw];
    [algs addObject:(id)kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA1];
    [algs addObject:(id)kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA224];
    [algs addObject:(id)kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA256];
    [algs addObject:(id)kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA384];
    [algs addObject:(id)kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA512];
    [algs addObject:(id)kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA1];
    [algs addObject:(id)kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA224];
    [algs addObject:(id)kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA256];
    [algs addObject:(id)kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA384];
    [algs addObject:(id)kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA512];
    [algs addObject:(id)kSecKeyAlgorithmRSASignatureDigestPSSSHA1];
    [algs addObject:(id)kSecKeyAlgorithmRSASignatureDigestPSSSHA224];
    [algs addObject:(id)kSecKeyAlgorithmRSASignatureDigestPSSSHA256];
    [algs addObject:(id)kSecKeyAlgorithmRSASignatureDigestPSSSHA384];
    [algs addObject:(id)kSecKeyAlgorithmRSASignatureDigestPSSSHA512];
    [algs addObject:(id)kSecKeyAlgorithmRSASignatureMessagePSSSHA1];
    [algs addObject:(id)kSecKeyAlgorithmRSASignatureMessagePSSSHA224];
    [algs addObject:(id)kSecKeyAlgorithmRSASignatureMessagePSSSHA256];
    [algs addObject:(id)kSecKeyAlgorithmRSASignatureMessagePSSSHA384];
    [algs addObject:(id)kSecKeyAlgorithmRSASignatureMessagePSSSHA512];
    [algs addObject:(id)kSecKeyAlgorithmECDSASignatureRFC4754];
    [algs addObject:(id)kSecKeyAlgorithmECDSASignatureDigestX962];
    [algs addObject:(id)kSecKeyAlgorithmECDSASignatureDigestX962SHA1];
    [algs addObject:(id)kSecKeyAlgorithmECDSASignatureDigestX962SHA224];
    [algs addObject:(id)kSecKeyAlgorithmECDSASignatureDigestX962SHA256];
    [algs addObject:(id)kSecKeyAlgorithmECDSASignatureDigestX962SHA384];
    [algs addObject:(id)kSecKeyAlgorithmECDSASignatureDigestX962SHA512];
    [algs addObject:(id)kSecKeyAlgorithmECDSASignatureMessageX962SHA1];
    [algs addObject:(id)kSecKeyAlgorithmECDSASignatureMessageX962SHA224];
    [algs addObject:(id)kSecKeyAlgorithmECDSASignatureMessageX962SHA256];
    [algs addObject:(id)kSecKeyAlgorithmECDSASignatureMessageX962SHA384];
    [algs addObject:(id)kSecKeyAlgorithmECDSASignatureMessageX962SHA512];
    [algs addObject:(id)kSecKeyAlgorithmRSAEncryptionRaw];
    [algs addObject:(id)kSecKeyAlgorithmRSAEncryptionPKCS1];
    [algs addObject:(id)kSecKeyAlgorithmRSAEncryptionOAEPSHA1];
    [algs addObject:(id)kSecKeyAlgorithmRSAEncryptionOAEPSHA224];
    [algs addObject:(id)kSecKeyAlgorithmRSAEncryptionOAEPSHA256];
    [algs addObject:(id)kSecKeyAlgorithmRSAEncryptionOAEPSHA384];
    [algs addObject:(id)kSecKeyAlgorithmRSAEncryptionOAEPSHA512];
    [algs addObject:(id)kSecKeyAlgorithmRSAEncryptionOAEPSHA1AESGCM];
    [algs addObject:(id)kSecKeyAlgorithmRSAEncryptionOAEPSHA224AESGCM];
    [algs addObject:(id)kSecKeyAlgorithmRSAEncryptionOAEPSHA256AESGCM];
    [algs addObject:(id)kSecKeyAlgorithmRSAEncryptionOAEPSHA384AESGCM];
    [algs addObject:(id)kSecKeyAlgorithmRSAEncryptionOAEPSHA512AESGCM];
    [algs addObject:(id)kSecKeyAlgorithmECIESEncryptionStandardX963SHA1AESGCM];
    [algs addObject:(id)kSecKeyAlgorithmECIESEncryptionStandardX963SHA224AESGCM];
    [algs addObject:(id)kSecKeyAlgorithmECIESEncryptionStandardX963SHA256AESGCM];
    [algs addObject:(id)kSecKeyAlgorithmECIESEncryptionStandardX963SHA384AESGCM];
    [algs addObject:(id)kSecKeyAlgorithmECIESEncryptionStandardX963SHA512AESGCM];
    [algs addObject:(id)kSecKeyAlgorithmECIESEncryptionCofactorX963SHA1AESGCM];
    [algs addObject:(id)kSecKeyAlgorithmECIESEncryptionCofactorX963SHA224AESGCM];
    [algs addObject:(id)kSecKeyAlgorithmECIESEncryptionCofactorX963SHA256AESGCM];
    [algs addObject:(id)kSecKeyAlgorithmECIESEncryptionCofactorX963SHA384AESGCM];
    [algs addObject:(id)kSecKeyAlgorithmECIESEncryptionCofactorX963SHA512AESGCM];
    [algs addObject:(id)kSecKeyAlgorithmECIESEncryptionStandardVariableIVX963SHA224AESGCM];
    [algs addObject:(id)kSecKeyAlgorithmECIESEncryptionStandardVariableIVX963SHA256AESGCM];
    [algs addObject:(id)kSecKeyAlgorithmECIESEncryptionStandardVariableIVX963SHA384AESGCM];
    [algs addObject:(id)kSecKeyAlgorithmECIESEncryptionStandardVariableIVX963SHA512AESGCM];
    [algs addObject:(id)kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA224AESGCM];
    [algs addObject:(id)kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA256AESGCM];
    [algs addObject:(id)kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA384AESGCM];
    [algs addObject:(id)kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA512AESGCM];
    [algs addObject:(id)kSecKeyAlgorithmECDHKeyExchangeStandard];
    [algs addObject:(id)kSecKeyAlgorithmECDHKeyExchangeStandardX963SHA1];
    [algs addObject:(id)kSecKeyAlgorithmECDHKeyExchangeStandardX963SHA224];
    [algs addObject:(id)kSecKeyAlgorithmECDHKeyExchangeStandardX963SHA256];
    [algs addObject:(id)kSecKeyAlgorithmECDHKeyExchangeStandardX963SHA384];
    [algs addObject:(id)kSecKeyAlgorithmECDHKeyExchangeStandardX963SHA512];
    [algs addObject:(id)kSecKeyAlgorithmECDHKeyExchangeCofactor];
    [algs addObject:(id)kSecKeyAlgorithmECDHKeyExchangeCofactorX963SHA1];
    [algs addObject:(id)kSecKeyAlgorithmECDHKeyExchangeCofactorX963SHA224];
    [algs addObject:(id)kSecKeyAlgorithmECDHKeyExchangeCofactorX963SHA256];
    [algs addObject:(id)kSecKeyAlgorithmECDHKeyExchangeCofactorX963SHA384];
    [algs addObject:(id)kSecKeyAlgorithmECDHKeyExchangeCofactorX963SHA512];
}

void GetAllIdentities(std::vector<SecIdentityRef>& identities, bool getSign, bool getDec)
{
    CFArrayRef items = nil;

    NSMutableDictionary * query = [[NSMutableDictionary alloc] init];

    [query setObject:(id)kSecClassKey forKey:(id)kSecClass];
    [query setObject:(id)kCFBooleanTrue forKey:(id)kSecReturnRef];
    [query setObject:(id)kSecClassIdentity forKey:(id)kSecClass];
    [query setObject:(id)kSecMatchLimitAll forKey:(id)kSecMatchLimit];
    [query setObject:(id)kSecAttrAccessGroupToken forKey:(id)kSecAttrAccessGroup];
    if(getSign)
        [query setObject:(id)kCFBooleanTrue forKey:(id)kSecAttrCanSign];
    if(getDec)
        [query setObject:(id)kCFBooleanTrue forKey:(id)kSecAttrCanDecrypt];

    //Execute the query saving the results in items.
    int resultCode = SecItemCopyMatching((CFDictionaryRef)query, (CFTypeRef *)&items);
    if(0 == resultCode)
    {
        CFIndex count = CFArrayGetCount(items);
        for(int ii = 0; ii < count; ++ii)
        {
            const void* item = CFArrayGetValueAtIndex(items, ii);

            SecIdentityRef identity = (SecIdentityRef)item;
            identities.push_back(identity);
        }
    }
    else
    {
//        if(items)
//            CFRelease(items);
    }

    return;
}

void GetAllCertificates(std::vector<SecCertificateRef>& certs, bool canVerify, bool canEncrypt)
{
    CFArrayRef items = nil;

    NSMutableDictionary * query = [[NSMutableDictionary alloc] init];

    [query setObject:(id)kSecClassKey forKey:(id)kSecClass];
    [query setObject:(id)kCFBooleanTrue forKey:(id)kSecReturnRef];
    [query setObject:(id)kSecClassCertificate forKey:(id)kSecClass];
    [query setObject:(id)kSecMatchLimitAll forKey:(id)kSecMatchLimit];
    [query setObject:(id)kSecAttrAccessGroupToken forKey:(id)kSecAttrAccessGroup];
    if(canVerify)
        [query setObject:(id)kCFBooleanTrue forKey:(id)kSecAttrCanVerify];
    if(canEncrypt)
        [query setObject:(id)kCFBooleanTrue forKey:(id)kSecAttrCanEncrypt];

    //Execute the query saving the results in items.
    int resultCode = SecItemCopyMatching((CFDictionaryRef)query, (CFTypeRef *)&items);
    if(0 == resultCode)
    {
        CFIndex count = CFArrayGetCount(items);
        for(int ii = 0; ii < count; ++ii)
        {
            const void* item = CFArrayGetValueAtIndex(items, ii);

            SecCertificateRef identity = (SecCertificateRef)item;
            certs.push_back(identity);
        }
    }
    else
    {
//        if(items)
//            CFRelease(items);
    }

    return;
}


void GetAllKeys(std::vector<SecKeyRef>& identities)
{
    CFArrayRef items = nil;

    CFMutableDictionaryRef query = CFDictionaryCreateMutable(NULL, 3, NULL, NULL);

    CFDictionaryAddValue (query, kSecMatchLimit, kSecMatchLimitAll);
    CFDictionaryAddValue (query, kSecReturnRef, kCFBooleanTrue);
    CFDictionaryAddValue (query, kSecClass, kSecClassKey);

    //Execute the query saving the results in items.
    int resultCode = SecItemCopyMatching(query, (CFTypeRef *)&items);
    CFRelease(query);

    if(0 == resultCode)
    {
        CFIndex count = CFArrayGetCount(items);
        for(int ii = 0; ii < count; ++ii)
        {
            const void* item = CFArrayGetValueAtIndex(items, ii);

            SecKeyRef identity = (SecKeyRef)item;
            identities.push_back(identity);
        }
    }
    else
    {
//        if(items)
//            CFRelease(items);
    }

    return;
}


@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view.
}

- (IBAction)onManyEnc:(id)sender {
    NSLog(@"CtkConsumer log: begin onManyEnc\n");
    
    if(identitiesEnc.empty()) return;
    
    int count = 0;
    std::vector<SecIdentityRef>::iterator pos = identitiesEnc.begin();
    SecIdentityRef cur = (*pos);

    SecCertificateRef certificateRef = nil;
    OSStatus status = SecIdentityCopyCertificate(cur, &certificateRef);
    if(errSecSuccess != status) {
        NSLog(@"CtkConsumer log: SecIdentityCopyCertificate failed %i\n", status);
        CFRelease(certificateRef);
        return;
    }

    CFStringRef commonName;
    status = SecCertificateCopyCommonName(certificateRef, &commonName);
    NSLog(@"CtkConsumer log: common name = %@\n", (__bridge NSString*)commonName);

    SecKeyRef privateKeyRef = nil;
    status = SecIdentityCopyPrivateKey(cur, &privateKeyRef);
    if(errSecSuccess != status) {
        NSLog(@"CtkConsumer log: SecIdentityCopyPrivateKey failed %i\n", status);
        CFRelease(privateKeyRef);
        return;
    }
    
    SecKeyRef publicKeyRef = SecCertificateCopyKey(certificateRef);

    //SecPadding padding = kSecPaddingPKCS1;

    for(int ii = 0; ii < 3; ++ii){
        SecPadding padding = encpaddings[ii];
        ++count;
        NSLog(@"CtkConsumer log: %i\n", count);
        cur = (*pos);

        NSData* dataToSign = [[NSData alloc]initWithBytes:"abc" length:3];
        unsigned char result[CC_SHA256_DIGEST_LENGTH];
        CC_SHA256([dataToSign bytes], (unsigned int)[dataToSign length], result);

        uint8_t cipher[256];
        size_t cipherLen = 256;

        status = SecKeyEncrypt(publicKeyRef, padding, result, CC_SHA256_DIGEST_LENGTH, cipher, &cipherLen);
        NSLog(@"CtkConsumer log: SecKeyEncrypt result %i\n", status);
        if(errSecSuccess != status) {
            continue;
        }

        uint8_t plain[256];
        size_t plainLen = 256;

        status = SecKeyDecrypt(privateKeyRef, padding, cipher, cipherLen, plain, &plainLen);
        NSLog(@"CtkConsumer log: SecKeyDecrypt result %i\n", status);
        if(errSecSuccess != status) {
            continue;
        }

        if(0 != memcmp(result, plain, plainLen)) {
            NSLog(@"CtkConsumer log: SecKeyDecrypt returned unexpected plaintext\n");
        }
        else {
            NSLog(@"CtkConsumer log: SecKeyDecrypt returned expected plaintext\n");
        }
    }
    
    for(int ii = 0; ii < 12; ++ii)
    {
        SecKeyAlgorithm curska = rsaEncAlgs[ii];
        ++count;
        NSLog(@"CtkConsumer log: %i - %@\n", count, curska);
        cur = (*pos);
        
        NSData* dataToSign = [[NSData alloc]initWithBytes:"abc" length:3];
        unsigned char result[CC_SHA256_DIGEST_LENGTH];
        CC_SHA256([dataToSign bytes], (unsigned int)[dataToSign length], result);

        BOOL canEnc = SecKeyIsAlgorithmSupported(publicKeyRef, kSecKeyOperationTypeEncrypt, curska);
        if(!canEnc) {
            NSLog(@"CtkConsumer log: SecKeyIsAlgorithmSupported returned false for kSecKeyOperationTypeEncrypt and %@\n", curska);
            continue;
        }
        
        CFDataRef cfplaintext = CFDataCreate(NULL, result, CC_SHA256_DIGEST_LENGTH);
        if(!cfplaintext)
        {
            NSLog(@"CtkConsumer log: CFDataCreate failed for plaintext value\n");
            continue;
        }

        CFErrorRef cferror = nil;
        CFDataRef cfciphertext = SecKeyCreateEncryptedData(publicKeyRef, curska, cfplaintext, &cferror);

        CFRelease(cfplaintext);
        if(cferror)CFRelease(cferror);

        if(!cfciphertext) {
            NSLog(@"CtkConsumer log: SecKeyCreateEncryptedData failed\n");
            if(cferror)CFRelease(cferror);
            continue;
        }
        else {
            NSLog(@"CtkConsumer log: SecKeyCreateEncryptedData succeeded\n");
        }

        cfplaintext = SecKeyCreateDecryptedData(privateKeyRef, curska, cfciphertext, &cferror);
        if(!cfplaintext) {
            NSLog(@"CtkConsumer log: SecKeyCreateDecryptedData failed\n");
            if(cferror)CFRelease(cferror);
        }
        else {
            unsigned char* pPlain = (unsigned char*)(CFDataGetBytePtr(cfplaintext));
            CFIndex plainLen = CFDataGetLength(cfplaintext);
            
            if(plainLen != CC_SHA256_DIGEST_LENGTH || 0 != memcmp(pPlain, result, CC_SHA256_DIGEST_LENGTH)){
                
                // Because we are not passing in data the size of the modulus, the plaintext gets padded with leading zeroes before encrypting
                // by SecKeyCreateEncryptedData. Those leading zeroes are returned here. Skip them when doing kSecKeyAlgorithmRSAEncryptionRaw.
                if(curska == kSecKeyAlgorithmRSAEncryptionRaw && 0 != memcmp(&pPlain[plainLen-CC_SHA256_DIGEST_LENGTH], result, CC_SHA256_DIGEST_LENGTH)) {
                    NSLog(@"CtkConsumer log: Recovered plaintext is not correct");
                }
                else if(curska != kSecKeyAlgorithmRSAEncryptionRaw) {
                    NSLog(@"CtkConsumer log: Recovered plaintext is not correct");
                }
            }
            else
                NSLog(@"CtkConsumer log: SecKeyCreateDecryptedData succeeded\n");

            CFRelease(cfplaintext);
            CFRelease(cfciphertext);
        }
    }
    CFRelease(privateKeyRef);
    CFRelease(publicKeyRef);
    CFRelease(certificateRef);
}

- (IBAction)onManySign:(id)sender {
    NSLog(@"CtkConsumer log: begin onManySign\n");

    if(identitiesSign.empty())return;
    
    int count = 0;
    std::vector<SecIdentityRef>::iterator pos = identitiesSign.begin();
    SecIdentityRef cur = (*pos);

    SecCertificateRef certificateRef = nil;
    OSStatus status = SecIdentityCopyCertificate(cur, &certificateRef);
    if(errSecSuccess != status) {
        NSLog(@"CtkConsumer log: SecIdentityCopyCertificate failed %i\n", status);
        if(certificateRef) CFRelease(certificateRef);
        return;
    }

    CFStringRef commonName;
    status = SecCertificateCopyCommonName(certificateRef, &commonName);
    NSLog(@"CtkConsumer log: common name = %@\n", (__bridge NSString*)commonName);

    //SecPadding padding = kSecPaddingPKCS1SHA256;

    SecKeyRef privateKeyRef = nil;
    status = SecIdentityCopyPrivateKey(cur, &privateKeyRef);
    if(errSecSuccess != status) {
        NSLog(@"CtkConsumer log: SecIdentityCopyPrivateKey result %i\n", status);
        CFRelease(privateKeyRef);
        return;
    }

    SecKeyRef publicKeyRef = SecCertificateCopyKey(certificateRef);

    for(int ii = 0; ii < 6; ++ii){
        SecPadding padding = paddings[ii];
        ++count;
        NSLog(@"CtkConsumer log: padding alg %i\n", padding);
        
        NSData* dataToSign = [[NSData alloc]initWithBytes:"abc" length:3];
        unsigned char result[CC_SHA512_DIGEST_LENGTH];
        int hashLen = CC_SHA512_DIGEST_LENGTH;

        if(kSecPaddingPKCS1SHA1 == padding){
            hashLen = CC_SHA1_DIGEST_LENGTH;
            CC_SHA1([dataToSign bytes], (unsigned int)[dataToSign length], result);
        }
        else if(kSecPaddingPKCS1SHA224 == padding){
            hashLen = CC_SHA224_DIGEST_LENGTH;
            CC_SHA224([dataToSign bytes], (unsigned int)[dataToSign length], result);
        }
        else if(kSecPaddingPKCS1SHA256 == padding){
            hashLen = CC_SHA256_DIGEST_LENGTH;
            CC_SHA256([dataToSign bytes], (unsigned int)[dataToSign length], result);
        }
        else if(kSecPaddingPKCS1SHA384 == padding){
            hashLen = CC_SHA384_DIGEST_LENGTH;
            CC_SHA384([dataToSign bytes], (unsigned int)[dataToSign length], result);
        }
        else if(kSecPaddingPKCS1SHA512 == padding){
            hashLen = CC_SHA512_DIGEST_LENGTH;
            CC_SHA512([dataToSign bytes], (unsigned int)[dataToSign length], result);
        }
        
        uint8_t sig[256];
        size_t sigLen = 256;
        status = SecKeyRawSign(privateKeyRef, padding, result, hashLen, sig, &sigLen);
        NSLog(@"CtkConsumer log: SecKeyRawSign result %i\n", status);
        if(errSecSuccess != status) {
            continue;
        }

        status = SecKeyRawVerify(publicKeyRef, padding, result, hashLen, sig, sigLen);
        NSLog(@"CtkConsumer log: SecKeyRawVerify result %i\n", status);
        if(errSecSuccess != status) {
            continue;
        }
    }

    count = 0;
    for(int ii = 0; ii < 11; ++ii){
        SecKeyAlgorithm alg = rsaSigAlgsMessage[ii];

        ++count;
        NSLog(@"CtkConsumer log: message alg %@\n", alg);
        
        NSData* dataToSign = [[NSData alloc]initWithBytes:"abc" length:3];

        BOOL canSign = SecKeyIsAlgorithmSupported(privateKeyRef,
                                                    kSecKeyOperationTypeSign,
                                                    alg);
        if(!canSign)
        {
            NSLog(@"CtkConsumer log: SecKeyIsAlgorithmSupported returned false for kSecKeyOperationTypeSign");
            continue;
        }

        CFErrorRef cferror;
        CFDataRef cfsignature = SecKeyCreateSignature(privateKeyRef, alg, (CFDataRef)dataToSign, &cferror);
        if(!cfsignature) {
            NSLog(@"CtkConsumer log: SecKeyCreateSignature result %i\n", status);
            continue;
        }
        NSLog(@"CtkConsumer log: SecKeyCreateSignature succeeded\n");

        BOOL canVerify = SecKeyIsAlgorithmSupported(publicKeyRef,
                                                    kSecKeyOperationTypeVerify,
                                                    alg);
        if(!canVerify)
        {
            NSLog(@"CtkConsumer log: SecKeyIsAlgorithmSupported returned false for kSecKeyOperationTypeVerify");
            continue;
        }
        bool b = SecKeyVerifySignature(publicKeyRef, alg, (CFDataRef)dataToSign, cfsignature, &cferror);
        if(!b) {
            NSError* e = (__bridge_transfer NSError*)cferror;
            NSLog(@"CtkConsumer log: SecKeyVerifySignature failed: %@", [e localizedDescription]);
            continue;
        }
        NSLog(@"CtkConsumer log: SecKeyVerifySignature succeeded\n");
    }

    count = 0;
    for(int ii = 0; ii < 11; ++ii){
        SecKeyAlgorithm alg = rsaSigAlgsDigest[ii];

        ++count;
        NSLog(@"CtkConsumer log: digest alg %@\n", alg);
        
        NSData* dataToSign = [[NSData alloc]initWithBytes:"abc" length:3];

        unsigned char result[CC_SHA512_DIGEST_LENGTH];
        int hashLen = CC_SHA512_DIGEST_LENGTH;
        
        if(alg == kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA1 || alg == kSecKeyAlgorithmRSASignatureDigestPSSSHA1)
        {
            hashLen = CC_SHA1_DIGEST_LENGTH;
            CC_SHA1([dataToSign bytes], (unsigned int)[dataToSign length], result);
        }
        else if(alg == kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA224 || alg == kSecKeyAlgorithmRSASignatureDigestPSSSHA224)
        {
            hashLen = CC_SHA224_DIGEST_LENGTH;
            CC_SHA224([dataToSign bytes], (unsigned int)[dataToSign length], result);
        }
        else if(alg == kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA256 || alg == kSecKeyAlgorithmRSASignatureDigestPSSSHA256)
        {
            hashLen = CC_SHA256_DIGEST_LENGTH;
            CC_SHA256([dataToSign bytes], (unsigned int)[dataToSign length], result);
        }
        else if(alg == kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA384 || alg == kSecKeyAlgorithmRSASignatureDigestPSSSHA384)
        {
            hashLen = CC_SHA384_DIGEST_LENGTH;
            CC_SHA384([dataToSign bytes], (unsigned int)[dataToSign length], result);
        }
        else if(alg == kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA512 || alg == kSecKeyAlgorithmRSASignatureDigestPSSSHA512)
        {
            hashLen = CC_SHA512_DIGEST_LENGTH;
            CC_SHA512([dataToSign bytes], (unsigned int)[dataToSign length], result);
        }
        
        NSData* hashedData = [NSData dataWithBytes:result length:hashLen];
        
        BOOL canSign = SecKeyIsAlgorithmSupported(privateKeyRef,
                                                    kSecKeyOperationTypeSign,
                                                    alg);
        if(!canSign)
        {
            NSLog(@"CtkConsumer log: SecKeyIsAlgorithmSupported returned false for kSecKeyOperationTypeSign");
            continue;
        }

        CFErrorRef cferror;
        CFDataRef cfsignature = SecKeyCreateSignature(privateKeyRef, alg, (CFDataRef)hashedData, &cferror);
        if(!cfsignature) {
            NSLog(@"CtkConsumer log: SecKeyCreateSignature result %i\n", status);
            continue;
        }
        NSLog(@"CtkConsumer log: SecKeyCreateSignature succeeded\n");

        BOOL canVerify = SecKeyIsAlgorithmSupported(publicKeyRef,
                                                    kSecKeyOperationTypeVerify,
                                                    alg);
        if(!canVerify)
        {
            NSLog(@"CtkConsumer log: SecKeyIsAlgorithmSupported returned false for kSecKeyOperationTypeVerify");
            continue;
        }
        bool b = SecKeyVerifySignature(publicKeyRef, alg, (CFDataRef)hashedData, cfsignature, &cferror);
        if(!b) {
            NSError* e = (__bridge_transfer NSError*)cferror;
            NSLog(@"CtkConsumer log: SecKeyVerifySignature failed: %@", [e localizedDescription]);
            continue;
        }
        NSLog(@"CtkConsumer log: SecKeyVerifySignature succeeded\n");
    }
    CFRelease(privateKeyRef);
    CFRelease(publicKeyRef);
    CFRelease(certificateRef);
}

- (IBAction)onDecrypt:(id)sender {
    NSLog(@"CtkConsumer log: begin onDecrypt\n");
    
    int count = 0;
    SecIdentityRef cur = nil;

    SecPadding padding = kSecPaddingPKCS1;

    std::vector<SecIdentityRef>::iterator pos;
    std::vector<SecIdentityRef>::iterator end = identitiesEnc.end();
    for(pos = identitiesEnc.begin(); pos != end; ++pos){
        ++count;
        NSLog(@"CtkConsumer log: %i\n", count);
        cur = (*pos);
        
        SecKeyRef privateKeyRef = nil;
        OSStatus status = SecIdentityCopyPrivateKey(cur, &privateKeyRef);
        NSLog(@"CtkConsumer log: SecIdentityCopyPrivateKey result %i\n", status);
        if(errSecSuccess != status) {
            CFRelease(privateKeyRef);
            continue;
        }
        
        SecCertificateRef certificateRef = nil;
        status = SecIdentityCopyCertificate(cur, &certificateRef);
        NSLog(@"CtkConsumer log: SecIdentityCopyCertificate result %i\n", status);
        if(errSecSuccess != status) {
            CFRelease(privateKeyRef);
            CFRelease(certificateRef);
            continue;
        }
        
        CFStringRef commonName;
        status = SecCertificateCopyCommonName(certificateRef, &commonName);
        NSLog(@"CtkConsumer log: common name = %@\n", (__bridge NSString*)commonName);

        SecKeyRef publicKeyRef = SecCertificateCopyKey(certificateRef);

        NSData* dataToSign = [[NSData alloc]initWithBytes:"abc" length:3];
        unsigned char result[CC_SHA256_DIGEST_LENGTH];
        CC_SHA256([dataToSign bytes], (unsigned int)[dataToSign length], result);
        
        uint8_t cipher[256];
        size_t cipherLen = 256;
        
        status = SecKeyEncrypt(publicKeyRef, padding, result, CC_SHA256_DIGEST_LENGTH, cipher, &cipherLen);
        NSLog(@"CtkConsumer log: SecKeyEncrypt result %i\n", status);
        if(errSecSuccess != status) {
            CFRelease(privateKeyRef);
            CFRelease(certificateRef);
            CFRelease(publicKeyRef);
            continue;
        }
        
        uint8_t plain[256];
        size_t plainLen = 256;

        status = SecKeyDecrypt(privateKeyRef, padding, cipher, cipherLen, plain, &plainLen);
        NSLog(@"CtkConsumer log: SecKeyDecrypt result %i\n", status);
        if(errSecSuccess != status) {
            CFRelease(privateKeyRef);
            CFRelease(publicKeyRef);
            CFRelease(certificateRef);
            continue;
        }
        
        if(0 != memcmp(result, plain, plainLen)) {
            NSLog(@"CtkConsumer log: SecKeyDecrypt returned unexpected plaintext\n");
        }
        else {
            NSLog(@"CtkConsumer log: SecKeyDecrypt returned expected plaintext\n");
        }
        
        CFRelease(privateKeyRef);
        CFRelease(publicKeyRef);
        CFRelease(certificateRef);
    }
}

/**
 Enumerates over the SecIdentityRef objects collected by onCollectIds, generates a signature then verifies it.
 */
- (IBAction)onSign:(id)sender {
    NSLog(@"CtkConsumer log: begin onSign\n");

    int count = 0;
    SecIdentityRef cur = nil;

    SecPadding padding = kSecPaddingPKCS1SHA256;

    std::vector<SecIdentityRef>::iterator pos;
    std::vector<SecIdentityRef>::iterator end = identitiesSign.end();
    for(pos = identitiesSign.begin(); pos != end; ++pos){
        ++count;
        NSLog(@"CtkConsumer log: %i\n", count);
        cur = (*pos);
        
        SecKeyRef privateKeyRef = nil;
        OSStatus status = SecIdentityCopyPrivateKey(cur, &privateKeyRef);
        if(errSecSuccess != status) {
            CFRelease(privateKeyRef);
            continue;
        }
        
        SecCertificateRef certificateRef = nil;
        status = SecIdentityCopyCertificate(cur, &certificateRef);
        if(errSecSuccess != status) {
            CFRelease(privateKeyRef);
            CFRelease(certificateRef);
            continue;
        }

        CFStringRef commonName;
        status = SecCertificateCopyCommonName(certificateRef, &commonName);
        NSLog(@"CtkConsumer log: common name = %@\n", (__bridge NSString*)commonName);

        NSData* dataToSign = [[NSData alloc]initWithBytes:"abc" length:3];
        unsigned char result[CC_SHA256_DIGEST_LENGTH];
        CC_SHA256([dataToSign bytes], (unsigned int)[dataToSign length], result);
        
        uint8_t sig[256];
        size_t sigLen = 256;
        status = SecKeyRawSign(privateKeyRef, padding, result, CC_SHA256_DIGEST_LENGTH, sig, &sigLen);
        NSLog(@"CtkConsumer log: SecKeyRawSign result %i\n", status);
        if(errSecSuccess != status) {
            CFRelease(privateKeyRef);
            CFRelease(certificateRef);
            continue;
        }

        SecKeyRef publicKeyRef = SecCertificateCopyKey(certificateRef);
        status = SecKeyRawVerify(publicKeyRef, padding, result, CC_SHA256_DIGEST_LENGTH, sig, sigLen);
        NSLog(@"CtkConsumer log: SecKeyRawVerify result %i\n", status);
        if(errSecSuccess != status) {
            CFRelease(privateKeyRef);
            CFRelease(publicKeyRef);
            CFRelease(certificateRef);
            continue;
        }
        CFRelease(privateKeyRef);
        CFRelease(publicKeyRef);
        CFRelease(certificateRef);
    }
}

- (IBAction)onCollectIds:(id)sender {
    NSLog(@"CtkConsumer log: begin onCollectIds\n");
    
    identitiesSign.clear();
    identitiesEnc.clear();

    // Collect up all the IDs once
    GetAllIdentities(identitiesSign, true, false);
    GetAllIdentities(identitiesEnc, false, true);

    // Enumerating certificates does not spare on the hassle of prompting the user on token access
    //GetAllCertificates(certsSign, true, false);
    //GetAllCertificates(certsEnc, false, true);
}

@end
