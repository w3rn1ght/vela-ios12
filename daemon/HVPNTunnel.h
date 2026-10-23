// Управление процессом ядра sing-box и системными маршрутами.
#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface HVPNTunnel : NSObject

+ (instancetype)shared;

/// Убирает «осиротевшие» маршруты, оставшиеся после падения демона.
+ (void)cleanupStaleRoutes;

/// Физический интерфейс (en0 / pdp_ip0) — нужен, чтобы пинговать серверы
/// мимо собственного tun и привязывать direct-исходящие ядра.
+ (NSString *_Nullable)primaryInterfaceName;

/// TCP-пинг: 3 попытки, медиана. Возвращает {ok, ms, attempts, error}.
- (NSDictionary *)pingServer:(NSString *)server port:(NSInteger)port;

/// {ok: BOOL, error: string?, status: {...}}
- (NSDictionary *)startWithLinks:(NSArray<NSString *> *)links options:(NSDictionary *_Nullable)options;
- (NSDictionary *)stop;
- (NSDictionary *)status;

/// Последние строки лога ядра (для показа в приложении).
- (NSString *)coreLog;

@end

NS_ASSUME_NONNULL_END
