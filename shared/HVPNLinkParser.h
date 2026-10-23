// Разбор share-ссылок в outbound-описание sing-box.
//
// Поддерживаются:
//   vless:// vless://…?security=reality&pbk=…
//   vmess:// (base64 JSON, формат v2rayN)
//   trojan://
//   ss://     (оба варианта: ss://base64(method:pass)@host:port и ss://base64(method:pass@host:port))
//   hysteria2://  hy2://
//   tuic://   (TUIC v5)
//
// happ://…  ссылки не поддерживаются: приложение Happ шифрует подписки
// собственным ключом, формат не документирован. Если у вас ссылка вида
// happ://cryptN/… — возьмите в Happ обычную https-подписку или отдельную
// ссылку на ноду (vless:// / vmess:// / …), они у Happ стандартные.
#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

extern NSString *const HVPNErrorDomain;

@interface HVPNProxy : NSObject
/// Имя ноды (fragment ссылки либо host:port).
@property (nonatomic, copy) NSString *name;
/// vless / vmess / trojan / shadowsocks / hysteria2 / tuic
@property (nonatomic, copy) NSString *type;
/// Адрес сервера (домен или IP, без скобок для IPv6).
@property (nonatomic, copy) NSString *server;
@property (nonatomic, assign) NSInteger port;
/// Готовый outbound для sing-box (без tag, tag ставит HVPNConfig).
@property (nonatomic, copy) NSDictionary *outbound;
@end

@interface HVPNLinkParser : NSObject

/// nil + error, если ссылка битая или протокол не поддержан.
+ (nullable HVPNProxy *)proxyFromLink:(NSString *)link error:(NSError **)error;

/// Разбирает тело подписки: либо base64 от списка ссылок, либо plain-текст.
+ (NSArray<NSString *> *)linksFromSubscriptionData:(NSData *)data;

/// Похоже ли на поддерживаемую ссылку (для фильтрации мусора в подписке).
+ (BOOL)looksLikeLink:(NSString *)line;

/// «Заглушка» панели: 0.0.0.0:1 / 127.0.0.1:1 и т.п. Такие ноды панель отдаёт,
/// когда клиент не передал HWID или подписка не активирована.
+ (BOOL)isPlaceholderLink:(NSString *)link;

/// Панели (Remnawave/Xray) могут отдать вместо списка ссылок готовый JSON-конфиг.
/// Достаём из него vless/vmess/trojan/shadowsocks и превращаем в обычные ссылки.
+ (NSArray<NSString *> *)linksFromXrayConfigData:(NSData *)data;

@end

NS_ASSUME_NONNULL_END
