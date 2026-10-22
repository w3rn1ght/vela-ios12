// Управление процессом ядра sing-box и системными маршрутами.
#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface HVPNTunnel : NSObject

+ (instancetype)shared;

/// Убирает «осиротевшие» маршруты, оставшиеся после падения демона.
+ (void)cleanupStaleRoutes;

/// {ok: BOOL, error: string?, status: {...}}
- (NSDictionary *)startWithLinks:(NSArray<NSString *> *)links options:(NSDictionary *_Nullable)options;
- (NSDictionary *)stop;
- (NSDictionary *)status;

/// Последние строки лога ядра (для показа в приложении).
- (NSString *)coreLog;

@end

NS_ASSUME_NONNULL_END
