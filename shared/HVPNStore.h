// Список нод: разбор подписок, хранение, выбор активной.
#import <Foundation/Foundation.h>
#import "HVPNLinkParser.h"

NS_ASSUME_NONNULL_BEGIN

@interface HVPNNode : NSObject
@property (nonatomic, copy) NSString *link;
@property (nonatomic, copy) NSString *name;
@property (nonatomic, copy) NSString *type;
@property (nonatomic, copy) NSString *server;
@property (nonatomic, assign) NSInteger port;
@property (nonatomic, assign) BOOL supported;
@property (nonatomic, assign) NSInteger pingMs;   // -1 = не меряли
@property (nonatomic, copy, nullable) NSString *pingError;

+ (instancetype)nodeFromLink:(NSString *)link;
- (NSDictionary *)dictionary;
+ (instancetype)nodeFromDictionary:(NSDictionary *)dict;
@end

@interface HVPNStore : NSObject

@property (nonatomic, readonly) NSArray<HVPNNode *> *nodes;
@property (nonatomic, assign) NSInteger selectedIndex;      // -1 = ничего
@property (nonatomic, copy, nullable) NSString *subscriptionURL;
@property (nonatomic, copy, nullable) NSString *subscriptionInfo;  // трафик/срок
@property (nonatomic, readonly) NSArray<NSString *> *diagnostics;

+ (instancetype)shared;

- (void)load;
- (void)save;

/// Разбирает текст (ссылки и/или https-подписки), добавляет ноды без дублей.
/// completion вызывается на главном потоке; diagnostics содержит построчный отчёт.
- (void)addFromText:(NSString *)text completion:(void (^)(NSUInteger added, NSError *_Nullable error))completion;

- (void)removeNodeAtIndex:(NSInteger)index;
- (void)clearDiagnostics;
- (HVPNNode *_Nullable)nodeAtIndex:(NSInteger)index;

@end

NS_ASSUME_NONNULL_END
