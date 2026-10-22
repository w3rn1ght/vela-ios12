// Общие хелперы для разбора share-ссылок (vless://, vmess://, trojan://, ss://, hy2://, tuic://).
// Используются и демоном, и приложением, поэтому никаких зависимостей кроме Foundation.
#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/// Разворачивает percent-encoding, не падая на битых строках.
NSString *HVPNPercent(NSString *_Nullable s);

/// base64 (в том числе url-safe, без padding). nil при ошибке.
NSData *_Nullable HVPNB64Data(NSString *_Nullable s);
NSString *_Nullable HVPNB64String(NSString *_Nullable s);

/// "k=v&k2=v2" -> словарь (значения percent-decoded).
NSDictionary<NSString *, NSString *> *HVPNQuery(NSString *_Nullable query);

/// "1" / "true" / "yes" -> YES
BOOL HVPNBool(NSString *_Nullable v);

/// Достаёт из строки вида scheme://userinfo@host:port/path?query#fragment части.
BOOL HVPNSplitURI(NSString *link,
                  NSString *_Nullable *_Nullable scheme,
                  NSString *_Nullable *_Nullable userinfo,
                  NSString *_Nullable *_Nullable host,
                  NSInteger *port,
                  NSString *_Nullable *_Nullable path,
                  NSDictionary<NSString *, NSString *> *_Nullable *_Nullable query,
                  NSString *_Nullable *_Nullable fragment);

/// Блок tls для sing-box из параметров ссылки (security=tls|reality, sni=, alpn=, fp=, pbk=, sid=).
/// Возвращает nil, если TLS не запрошен.
NSMutableDictionary *_Nullable HVPNTLSDict(NSDictionary<NSString *, NSString *> *q,
                                           NSString *_Nullable fallbackSNI);

/// Блок transport для sing-box (ws / grpc / http / h2). nil — обычный TCP.
/// В errMsg кладётся текст ошибки, если транспорт не поддерживается.
NSDictionary *_Nullable HVPNTransportDict(NSDictionary<NSString *, NSString *> *q,
                                          NSString *_Nullable *_Nullable errMsg);

NS_ASSUME_NONNULL_END
