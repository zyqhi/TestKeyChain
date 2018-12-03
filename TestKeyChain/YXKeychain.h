//
// YXKeychain.h
// Created by yebw on 15-7-9.
//

#import <Foundation/Foundation.h>

@interface YXKeychain : NSObject {
}

+ (void)setString:(NSString *)string forKey:(NSString *)key;

+ (NSString *)stringForKey:(NSString *)key;

@end
