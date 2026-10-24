#import "HVPNConfig.h"

NSString *const HVPNVersionString = @"0.2.12";

NSDictionary *HVPNBuildConfig(HVPNProxy *proxy, NSDictionary *options) {
    NSDictionary *opts = options ?: @{};
    NSString *dnsRemote = opts[@"dnsRemote"] ?: @"https://1.1.1.1/dns-query";
    NSString *dnsLocal = opts[@"dnsLocal"] ?: @"223.5.5.5";
    NSNumber *bypassLAN = opts[@"bypassLAN"] ?: @YES;
    NSNumber *mtu = opts[@"mtu"] ?: @1400;
    NSString *logLevel = opts[@"logLevel"] ?: @"info";
    NSString *logPath = opts[@"logPath"];

    NSMutableDictionary *outbound = [proxy.outbound mutableCopy];
    outbound[@"tag"] = @"proxy";
    // Узел с самоподписанным сертификатом (частый случай у «белых списков»):
    // демон сначала пробует строгую проверку, а после ошибки сертификата
    // перезапускает ядро с этой опцией.
    if ([opts[@"forceInsecure"] boolValue]) {
        NSMutableDictionary *tls = [outbound[@"tls"] isKindOfClass:[NSDictionary class]]
            ? [outbound[@"tls"] mutableCopy] : nil;
        if (tls != nil) {
            tls[@"insecure"] = @YES;
            outbound[@"tls"] = tls;
        }
    }

    // Прокси-соединение жёстко привязываем к физическому интерфейсу: иначе
    // его собственный трафик попадает в наш же tun (петля) и «ничего не грузится».
    NSString *bindInterface = opts[@"bindInterface"];
    if ([bindInterface isKindOfClass:[NSString class]] && bindInterface.length > 0) {
        outbound[@"bind_interface"] = bindInterface;
    }

    // На iOS route.auto_detect_interface не работает, поэтому direct-исходящие
    // (локальный DNS, bypass-домены, приватные сети) жёстко привязываем к
    // физическому интерфейсу — иначе они уйдут в наш же tun (петля).
    NSMutableDictionary *direct = [@{@"type": @"direct", @"tag": @"direct"} mutableCopy];
    if ([bindInterface isKindOfClass:[NSString class]] && bindInterface.length > 0) {
        direct[@"bind_interface"] = bindInterface;
    }

    NSMutableArray *rules = [NSMutableArray array];
    // Всё, что похоже на DNS (в том числе запросы mDNSResponder на LAN-DNS),
    // уходит в модуль DNS внутри ядра — так работает перехват без правки resolv.conf.
    [rules addObject:@{@"protocol": @"dns", @"outbound": @"dns-out"}];
    // Страховка на случай, если sniff не сработал: обычный DNS-порт.
    [rules addObject:@{@"port": @53, @"outbound": @"dns-out"}];
    if (bypassLAN.boolValue) {
        [rules addObject:@{@"ip_is_private": @YES, @"outbound": @"direct"}];
    }
    for (NSString *domain in (NSArray *)opts[@"bypassDomains"] ?: @[]) {
        [rules addObject:@{@"domain": @[domain], @"outbound": @"direct"}];
    }

    NSMutableDictionary *dns = [@{
        @"servers": @[
            @{@"tag": @"remote", @"address": dnsRemote, @"detour": @"proxy"},
            @{@"tag": @"local", @"address": dnsLocal, @"detour": @"direct"}
        ],
        @"final": @"remote",
        @"strategy": @"prefer_ipv4",
        @"disable_cache": @NO
    } mutableCopy];
    NSArray *localDomains = (NSArray *)opts[@"localDomains"];
    if ([localDomains isKindOfClass:[NSArray class]] && localDomains.count) {
        // legacy-DNS формат 1.8.x: действие правила — "server".
        dns[@"rules"] = @[ @{@"server": @"local", @"domain_suffix": localDomains} ];
    }

    NSDictionary *inbound = @{
        @"type": @"tun",
        @"tag": @"tun-in",
        // sing-tun на Darwin требует имя вида utun<N> и парсит из него номер юнита.
        // Без явного имени sing-box при GOOS=ios подставляет "tun0" и падает
        // с "bad tun name: tun0".
        @"interface_name": opts[@"interfaceName"] ?: @"utun4",
        // Поля именно для sing-box 1.8.x (в 1.10+ они заменены на "address").
        @"inet4_address": @"172.19.0.1/30",
        @"inet6_address": @"fdfe:dcba:9876::1/126",
        @"mtu": mtu,
        // Маршруты ставим сами (см. HVPNRoute.m): так проще откатывать и отлаживать.
        @"auto_route": @NO,
        @"strict_route": @NO,
        @"stack": @"gvisor",
        @"sniff": @YES,
        @"sniff_override_destination": @YES,
        @"udp_timeout": @"5m"
    };

    NSMutableDictionary *config = [@{
        @"log": logPath.length ? @{@"level": logLevel, @"timestamp": @YES, @"output": logPath}
                               : @{@"level": logLevel, @"timestamp": @YES},
        @"dns": dns,
        @"inbounds": @[inbound],
        @"outbounds": @[
            outbound,
            direct,
            @{@"type": @"dns", @"tag": @"dns-out"}
        ],
        @"route": @{
            @"rules": rules,
            @"final": @"proxy",
            // Когда интерфейс известен, привязываем исходящие сами (см. выше),
            // а автоопределение выключаем: на iOS оно иногда выбирает наш же utun.
            @"auto_detect_interface": (bindInterface.length > 0) ? @NO : @YES
        },
        @"experimental": @{@"cache_file": @{@"enabled": @NO}}
    } mutableCopy];

    return config;
}
