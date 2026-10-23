// Сборка конфига sing-box из разобранной ноды.
#import <Foundation/Foundation.h>
#import "HVPNLinkParser.h"

NS_ASSUME_NONNULL_BEGIN

/// Версия пакета (показывается в приложении).
extern NSString *const HVPNVersionString;

/// Ключи options (все необязательные):
///   bypassLAN     NSNumber(BOOL) — пускать локальные сети мимо прокси (default YES)
///   localDomains  NSArray<NSString *> — домены/суффиксы, которые резолвить локальным DNS
///   bypassDomains NSArray<NSString *> — домены, которые идут напрямую
///   dnsRemote     NSString — DoH/DoT для прокси (default https://1.1.1.1/dns-query)
///   dnsLocal      NSString — DNS для direct (default 223.5.5.5)
///   mtu           NSNumber (default 1500)
///   interfaceName NSString — имя tun, ОБЯЗАТЕЛЬНО "utun<N>" (sing-tun парсит номер)
///   logLevel      NSString (default info)
///   logPath       NSString — файл лога ядра
NSDictionary *HVPNBuildConfig(HVPNProxy *proxy, NSDictionary *_Nullable options);

NS_ASSUME_NONNULL_END
