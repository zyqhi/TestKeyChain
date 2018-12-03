//
// NEKeychain.m
// Created by yebw on 15-7-9.
//

#import "YXKeychain.h"
#import <Security/Security.h>

@implementation YXKeychain

+ (void)setString:(NSString *)string forKey:(NSString	*)key
{
    NSLog(@"zyqtrack: start update keychain.");
    if (key.length == 0) {
        return;
    }
    
    if (string == nil) {
        [YXKeychain deleteStringForKey:key];
        return;
    }
    
    NSMutableDictionary *query = [NSMutableDictionary dictionaryWithDictionary:@{((__bridge id)kSecClass):((__bridge id)kSecClassGenericPassword),
                                                                                 ((__bridge id)kSecAttrAccount):key,
                                                                                 }];
    
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, NULL);
    if (status == errSecSuccess) {
        NSDictionary *attributes = @{((__bridge id)kSecValueData):[string dataUsingEncoding:NSUTF8StringEncoding]};
       
        NSLog(@"zyqtrack: %@:%@: SecItemUpdate start, status is: %d", self.class, NSStringFromSelector(_cmd), status);
        status = SecItemUpdate((__bridge CFDictionaryRef)query, (__bridge CFDictionaryRef)attributes);
        NSLog(@"zyqtrack: %@:%@: SecItemUpdate end, status is: %d", self.class, NSStringFromSelector(_cmd), status);
        if (status != errSecSuccess) {
            NSLog(@"zyqtrack: %@:%@: SecItemUpdate error, status is: %d", self.class, NSStringFromSelector(_cmd), status);
//            YXLogInfo(@"KeyChain - key:%@, value:%@; 1. SecItemUpdate failed: %@", key, string, @(status));
        }
    } else if (status == errSecItemNotFound) {
        query[((__bridge id)kSecValueData)] = [string dataUsingEncoding:NSUTF8StringEncoding];
        
        status = SecItemAdd((__bridge CFDictionaryRef)query, NULL);
        if (status != errSecSuccess) {
//            YXLogInfo(@"KeyChain - key:%@, value:%@; 2. SecItemAdd failed: %@", key, string, @(status));
        }
    } else {
//        YXLogInfo(@"KeyChain - key:%@, value:%@; 3. SecItemCopyMatching failed: %@", key, string, @(status));
    }
}

+ (NSString *)stringForKey:(NSString *)key
{
    if (key.length == 0) {
        return nil;
    }
    
    NSString *result = nil;
    NSDictionary *query = @{((__bridge id)kSecClass):((__bridge id)kSecClassGenericPassword),
                            ((__bridge id)kSecAttrAccount):key,
                            ((__bridge id)kSecReturnData):(__bridge id)kCFBooleanTrue};
    
    CFDataRef dataRef = nil;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, (CFTypeRef *)&dataRef);
    if (status == errSecSuccess) {
        result = [[NSString alloc] initWithData:(__bridge_transfer NSData *)dataRef
                                       encoding:NSUTF8StringEncoding];
        dataRef = NULL;
    }
    else {
//        YXLogInfo(@"KeyChain - key:%@; 4. SecItemCopyMatching failed: %@", key, @(status));
    }
    
    return result;
}

+ (void)deleteStringForKey:(NSString *)key
{
    if (key.length == 0) {
        return;
    }
    
    NSDictionary *query = @{((__bridge id)kSecClass):((__bridge id)kSecClassGenericPassword),
                            ((__bridge id)kSecAttrAccount):key};
    
    OSStatus status = SecItemDelete((__bridge CFDictionaryRef)query);
    if (status != errSecSuccess) {
//        YXLogInfo(@"KeyChain - key:%@; 5. SecItemDelete failed: %@", key, @(status));
    }
}

@end
