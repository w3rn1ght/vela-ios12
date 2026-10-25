#import "HVPNConfig.h"

NSString *const HVPNVersionString = @"1.0.0";

NSDictionary *HVPNBuildConfig(HVPNProxy *proxy, NSDictionary *options) {
    NSDictionary *opts = options ?: @{};
    NSString *dnsRemote = opts[@"dnsRemote"] ?: @"1.1.1.1";
    // В новом формате DNS это просто адрес сервера: если пришёл URL вида
    // https://1.1.1.1/dns-query, оставляем только хост.
    if ([dnsRemote rangeOfString:@"://"].location != NSNotFound) {
        NSURLComponents *parts = [NSURLComponents componentsWithString:dnsRemote];
        if (parts.host.length) dnsRemote = parts.host;
    }
    NSString *dnsLocal = opts[@"dnsLocal"] ?: @"223.5.5.5";    NSNumber *bypassLAN = opts[@"bypassLAN"] ?: @YES;
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
    // Локальный DNS-листенер ядра (127.0.0.1:53). iOS резолвит имена не через tun,
    // а через свой резолвер на физическом интерфейсе; в РФ такой запрос получает
    // поддельный NXDOMAIN на youtube.com. Демон подменяет адрес резолвера на
    // 127.0.0.1, а запросы забирает это правило и отдаёт DNS-модулю.
    if ([opts[@"localDNS"] boolValue]) {
        [rules addObject:@{@"inbound": @[@"dns-in"], @"action": @"hijack-dns"}];
    }
    // sing-box 1.13 убрал outbound "dns" и поле inbound.sniff: теперь и то, и
    // другое — действия маршрута. sniff определяет протокол по первым байтам,
    // hijack-dns забирает запросы в DNS-модуль ядра (без правки resolv.conf).
    [rules addObject:@{@"action": @"sniff"}];
    [rules addObject:@{@"protocol": @"dns", @"action": @"hijack-dns"}];
    // Страховка на случай, если sniff не сработал: обычный DNS-порт.
    [rules addObject:@{@"port": @53, @"action": @"hijack-dns"}];
    if (bypassLAN.boolValue) {
        [rules addObject:@{@"ip_is_private": @YES, @"outbound": @"direct"}];
    }
    for (NSString *domain in (NSArray *)opts[@"bypassDomains"] ?: @[]) {
        [rules addObject:@{@"domain": @[domain], @"outbound": @"direct"}];
    }

    // DNS: с 1.12 сервер описывается типом и тегом, строка address:// больше
    // не разбирается, а "disable_cache" переехал в experimental.cache_file.
    // remote — TCP-DNS через прокси: работает всегда, в отличие от UDP, который
    // часть серверов VLESS не пропускает.
    // local — DNS физической сети; если её адрес неизвестен (или это наш же
    // локальный листенер 127.0.0.1 — иначе получится петля), сервер не добавляем
    // и всё резолвим через прокси.
    BOOL haveLocalDNS = dnsLocal.length > 0 &&
        ![dnsLocal isEqualToString:@"127.0.0.1"] && ![dnsLocal isEqualToString:@"::1"];
    NSMutableArray *dnsServers = [NSMutableArray arrayWithObject:
        @{@"type": @"tcp", @"tag": @"remote", @"server": dnsRemote, @"detour": @"proxy"}];
    if (haveLocalDNS) {
        [dnsServers addObject:@{@"type": @"udp", @"tag": @"local",
                                @"server": dnsLocal, @"detour": @"direct"}];
    }
    NSMutableDictionary *dns = [@{
        @"servers": dnsServers,
        @"final": @"remote",
        // ipv4_only: приложениям не отдаём AAAA-записи. Иначе iOS уводит их в IPv6,
        // а IPv6 через наш tun не ходит (маршруты ::/1 не ставим) — получаются
        // «висящие» соединения: YouTube/Opaline именно так и отваливались.
        // Заодно закрывает утечку мимо туннеля.
        @"strategy": opts[@"dnsStrategy"] ?: @"ipv4_only"
    } mutableCopy];
    NSArray *localDomains = (NSArray *)opts[@"localDomains"];
    if (haveLocalDNS && [localDomains isKindOfClass:[NSArray class]] && localDomains.count) {
        dns[@"rules"] = @[ @{@"server": @"local", @"domain_suffix": localDomains} ];
    }

    NSDictionary *inbound = @{
        @"type": @"tun",
        @"tag": @"tun-in",
        // sing-tun на Darwin требует имя вида utun<N> и парсит из него номер юнита.
        // Без явного имени sing-box при GOOS=ios подставляет "tun0" и падает
        // с "bad tun name: tun0".
        @"interface_name": opts[@"interfaceName"] ?: @"utun4",
        // С 1.11 адреса задаются массивом address вместо inet4_address/inet6_address.
        @"address": @[@"172.19.0.1/30", @"fdfe:dcba:9876::1/126"],
        @"mtu": mtu,
        // Маршруты ставим сами (см. HVPNRoute.m): так проще откатывать и отлаживать.
        @"auto_route": @NO,
        @"strict_route": @NO,
        @"stack": @"gvisor"
    };

    NSMutableArray *inbounds = [NSMutableArray arrayWithObject:inbound];
    if ([opts[@"localDNS"] boolValue]) {
        [inbounds addObject:@{@"type": @"direct", @"tag": @"dns-in",
                              @"listen": @"127.0.0.1", @"listen_port": @53}];
    }

    NSMutableDictionary *config = [@{
        @"log": logPath.length ? @{@"level": logLevel, @"timestamp": @YES, @"output": logPath}
                               : @{@"level": logLevel, @"timestamp": @YES},
        @"dns": dns,
        @"inbounds": inbounds,
        @"outbounds": @[
            outbound,
            direct
        ],
        @"route": @{
            @"rules": rules,
            @"final": @"proxy",
            // Когда интерфейс известен, привязываем исходящие сами (см. выше),
            // а автоопределение выключаем: на iOS оно иногда выбирает наш же utun.
            @"auto_detect_interface": (bindInterface.length > 0) ? @NO : @YES,
            // С 1.12 без этого нельзя: домены для direct/прокси-нод резолвятся
            // локальным DNS, а не сисколлом.
            @"default_domain_resolver": haveLocalDNS ? @"local" : @"remote"
        },
        @"experimental": @{@"cache_file": @{@"enabled": @NO}}
    } mutableCopy];

    return config;
}
