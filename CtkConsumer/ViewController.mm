//
//  ViewController.m
//  CtkConsumer
//
//  Created on 10/16/20.
//

#import "ViewController.h"
#include <CommonCrypto/CommonDigest.h>

#include <vector>
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
    
    // Collect up all the IDs once
    GetAllIdentities(identitiesSign, true, false);
    GetAllIdentities(identitiesEnc, false, true);

    // Enumerating certificates does not spare on the hassle of prompting the user on token access
    //GetAllCertificates(certsSign, true, false);
    //GetAllCertificates(certsEnc, false, true);
}

@end
