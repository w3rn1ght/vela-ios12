#import "HVPNTunnel.h"
#import "HVPNConfig.h"
#import "HVPNLinkParser.h"
#import "HVPNRoute.h"
#import "HVPNPaths.h"

#include <spawn.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <math.h>
#include <poll.h>
#include <string.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <crt_externs.h>

static NSString *const kBaseDir = HVPNStateDir;
static NSString *const kConfigPath = HVPNCoreConfigPath;
static NSString *const kCoreLogPath = HVPNCoreLogPath;
static NSString *const kCorePath = HVPNCorePath;

static NSArray<NSString *> *HVPNUtunNames(void) {
    NSMutableArray *utuns = [NSMutableArray array];
    struct if_nameindex *list = if_nameindex();
    if (list == NULL) return utuns;
    for (struct if_nameindex *p = list; p->if_index != 0; p++) {
        NSString *name = [NSString stringWithUTF8String:p->if_name];
        if (name.length && [name hasPrefix:@"utun"]) [utuns addObject:name];
    }
    if_freenameindex(list);
    return utuns;
}

static NSArray<NSString *> *HVPNResolveIPv4(NSString *host) {
    if (host.length == 0) return @[];
    if ([host rangeOfString:@":"].location != NSNotFound) return @[]; // IPv6-литерал
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo *res = NULL;
    if (getaddrinfo(host.UTF8String, NULL, &hints, &res) != 0 || res == NULL) return @[];
    NSMutableArray *out = [NSMutableArray array];
    for (struct addrinfo *p = res; p != NULL; p = p->ai_next) {
        if (p->ai_addr == NULL) continue;
        char text[INET_ADDRSTRLEN];
        struct sockaddr_in *sin = (struct sockaddr_in *)p->ai_addr;
        if (inet_ntop(AF_INET, &sin->sin_addr, text, sizeof(text)) != NULL) {
            NSString *s = [NSString stringWithUTF8String:text];
            if (s.length && ![out containsObject:s]) [out addObject:s];
        }
    }
    freeaddrinfo(res);
    return out;
}

static BOOL HVPNIsIPv4Literal(NSString *text) {
    if (text.length == 0) return NO;
    struct in_addr addr;
    return inet_pton(AF_INET, text.UTF8String, &addr) == 1;
}

// Следующее свободное имя utun: sing-tun на Darwin берёт номер из имени
// ("utun4" -> юнит 5) и падает, если номер уже занят.
// Интерфейс готов, когда он поднят и sing-box уже назначил ему IPv4-адрес.
// Иначе добавление маршрута падает с ENETUNREACH ("Network is unreachable").
static BOOL HVPNInterfaceReady(NSString *name) {
    if (name.length == 0) return NO;
    struct ifaddrs *list = NULL;
    if (getifaddrs(&list) != 0) return NO;
    BOOL hasIPv4 = NO, isUp = NO;
    for (struct ifaddrs *p = list; p != NULL; p = p->ifa_next) {
        if (p->ifa_name == NULL || strcmp(p->ifa_name, name.UTF8String) != 0) continue;
        if ((p->ifa_flags & IFF_UP) != 0) isUp = YES;
        if (p->ifa_addr != NULL && p->ifa_addr->sa_family == AF_INET) hasIPv4 = YES;
    }
    freeifaddrs(list);
    return isUp && hasIPv4;
}

static BOOL HVPNInterfaceHasIPv6(NSString *name) {
    if (name.length == 0) return NO;
    struct ifaddrs *list = NULL;
    if (getifaddrs(&list) != 0) return NO;
    BOOL found = NO;
    for (struct ifaddrs *p = list; p != NULL; p = p->ifa_next) {
        if (p->ifa_name == NULL || strcmp(p->ifa_name, name.UTF8String) != 0) continue;
        if (p->ifa_addr != NULL && p->ifa_addr->sa_family == AF_INET6) {
            struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)p->ifa_addr;
            if (!IN6_IS_ADDR_LINKLOCAL(&s6->sin6_addr)) { found = YES; break; }
        }
    }
    freeifaddrs(list);
    return found;
}

static NSString *HVPNNextTunName(void) {
    NSInteger maxIndex = -1;
    for (NSString *name in HVPNUtunNames()) {
        NSInteger index = [[name substringFromIndex:@"utun".length] integerValue];
        if (index > maxIndex) maxIndex = index;
    }
    return [NSString stringWithFormat:@"utun%ld", (long)(maxIndex + 1)];
}

// en0 (Wi-Fi) или pdp_ip0 (LTE) — интерфейс, через который идёт default-маршрут.
// SystemConfiguration на iOS недоступен, поэтому берём индекс из таблицы маршрутов.

// DNS физической сети: без него «local»-сервер может быть недоступен.
static NSString *HVPNSystemDNS(void) {
    NSString *text = [NSString stringWithContentsOfFile:@"/etc/resolv.conf"
                                               encoding:NSUTF8StringEncoding
                                                  error:NULL];
    if (text.length == 0) return nil;
    NSCharacterSet *spaces = [NSCharacterSet whitespaceCharacterSet];
    for (NSString *line in [text componentsSeparatedByCharactersInSet:
                            [NSCharacterSet newlineCharacterSet]]) {
        NSString *trimmed = [line stringByTrimmingCharactersInSet:spaces];
        if (![trimmed hasPrefix:@"nameserver"]) continue;
        NSArray<NSString *> *parts = [trimmed componentsSeparatedByCharactersInSet:spaces];
        if (parts.count >= 2 && [parts[1] rangeOfString:@"."].location != NSNotFound) {
            return parts[1];
        }
    }
    return nil;
}

// Сквозная проверка туннеля. connect() сам по себе ничего не доказывает: gvisor
// принимает TCP-хендшейк сразу, даже если прокси мёртв. Поэтому отправляем
// HTTP-запрос и ждём ответ: живой туннель отдаст "HTTP/...", мёртвый — EOF.
static NSDictionary *HVPNProbeHostPort(const char *host, uint16_t port, NSTimeInterval timeout) {
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, host, &addr.sin_addr);

    NSDate *started = [NSDate date];
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return @{@"ok": @NO, @"error": HVPNErrnoString()};

    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    int rc = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    if (rc != 0 && errno != EINPROGRESS) {
        NSString *error = HVPNErrnoString();
        close(fd);
        return @{@"ok": @NO, @"error": error};
    }

    fd_set wfds;
    FD_ZERO(&wfds);
    FD_SET(fd, &wfds);
    struct timeval tv;
    tv.tv_sec = (time_t)timeout;
    tv.tv_usec = 0;
    if (rc != 0) {
        int ready = select(fd + 1, NULL, &wfds, NULL, &tv);
        if (ready <= 0) {
            close(fd);
            return @{@"ok": @NO, @"error": ready == 0 ? @"таймаут подключения" : HVPNErrnoString()};
        }
        int soError = 0;
        socklen_t len = sizeof(soError);
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &soError, &len) != 0 || soError != 0) {
            close(fd);
            return @{@"ok": @NO,
                     @"error": [NSString stringWithUTF8String:strerror(soError)] ?: @"connect"};
        }
    }

    char request[128];
    int requestLen = snprintf(request, sizeof(request),
                              "GET / HTTP/1.0\r\nHost: %s\r\n\r\n", host);
    if (write(fd, request, (size_t)requestLen) <= 0) {
        NSString *error = HVPNErrnoString();
        close(fd);
        return @{@"ok": @NO, @"error": error};
    }

    char buf[64];
    FD_ZERO(&wfds);
    FD_SET(fd, &wfds);
    struct timeval rt = tv;
    int ready = select(fd + 1, &wfds, NULL, NULL, &rt);
    ssize_t got = (ready > 0) ? read(fd, buf, sizeof(buf)) : ready;
    close(fd);

    NSInteger ms = (NSInteger)([[NSDate date] timeIntervalSinceDate:started] * 1000);
    if (got > 0) return @{@"ok": @YES, @"ms": @(ms)};
    if (got == 0) {
        return @{@"ok": @NO, @"ms": @(ms),
                 @"error": [NSString stringWithFormat:
                            @"ядро закрыло соединение (%s) — прокси не пропускает", host]};
    }
    return @{@"ok": @NO, @"ms": @(ms),
             @"error": [NSString stringWithFormat:@"нет ответа от %s через туннель", host]};
}

// Проверяем два независимых адреса: провайдер может резать один из них.
static NSDictionary *HVPNRunProbe(NSTimeInterval timeout) {
    NSDictionary *first = HVPNProbeHostPort("1.1.1.1", 80, timeout);
    if ([first[@"ok"] boolValue]) return first;
    NSDictionary *second = HVPNProbeHostPort("8.8.8.8", 80, timeout);
    if ([second[@"ok"] boolValue]) return second;
    return first;
}

static NSString *HVPNPrimaryInterface(void) {
    NSString *gateway = nil;
    unsigned index = 0;
    if (!HVPNGetDefaultGateway(AF_INET, &gateway, &index) || index == 0) return nil;
    char name[IFNAMSIZ];
    memset(name, 0, sizeof(name));
    if (if_indextoname(index, name) == NULL) return nil;
    return [NSString stringWithUTF8String:name];
}

@implementation HVPNTunnel {
    pid_t _pid;
    NSString *_utun;
    NSString *_nodeName;
    NSString *_nodeServer;
    NSString *_nodeType;
    NSDate *_startedAt;
    NSDictionary *_lastProbe;
    NSInteger _nodePort;
    NSString *_outboundSummary;
    NSMutableArray<NSDictionary *> *_ifaceRoutes;   // {family, dst, prefix, ifindex}
    NSMutableArray<NSArray *> *_hostRoutes;         // [family, ip, gateway]
}

+ (instancetype)shared {
    static HVPNTunnel *instance;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ instance = [HVPNTunnel new]; });
    return instance;
}

- (instancetype)init {
    self = [super init];
    if (self) {
        _ifaceRoutes = [NSMutableArray array];
        _hostRoutes = [NSMutableArray array];
    }
    return self;
}

// MARK: - Очистка

+ (NSString *)primaryInterfaceName {
    return HVPNPrimaryInterface();
}

+ (void)cleanupStaleRoutes {
    // Если демон упал в подключённом состоянии, split-маршруты остаются в ядре
    // и интернет пропадает. Удаляем их с РЕАЛЬНЫМ индексом интерфейса:
    // с ifindex 0 ядро такой маршрут не находит и он остаётся навсегда.
    NSArray *routes = @[
        @[@(AF_INET), @"0.0.0.0", @1],
        @[@(AF_INET), @"128.0.0.0", @1],
        @[@(AF_INET6), @"::", @1],
        @[@(AF_INET6), @"8000::", @1]
    ];
    for (NSArray *route in routes) {
        int family = [route[0] intValue];
        NSString *dst = route[1];
        int prefix = [route[2] intValue];
        unsigned index = HVPNRouteInterfaceIndex(family, dst, prefix);
        if (index == 0) continue;   // маршрута нет — и хорошо
        if (HVPNRouteDeleteInterface(family, dst, prefix, index) == 0) {
            NSLog(@"[velad] снят оставшийся маршрут %@/%d (ifindex %u)", dst, prefix, index);
        } else {
            NSLog(@"[velad] не удалось снять %@/%d: %@", dst, prefix, HVPNErrnoString());
        }
    }
}

// MARK: - Публичный API

- (NSDictionary *)startWithLinks:(NSArray<NSString *> *)links options:(NSDictionary *)options {
    @synchronized (self) {
        [self stopLocked];

        if (links.count == 0) return [self failure:@"Нет ни одной ссылки"];

        NSError *parseError = nil;
        HVPNProxy *proxy = nil;
        NSUInteger skippedPlaceholders = 0;
        NSUInteger skippedUnsupported = 0;
        for (NSString *link in links) {
            NSError *err = nil;
            HVPNProxy *p = [HVPNLinkParser proxyFromLink:link error:&err];
            if (p == nil) {
                if ([HVPNLinkParser isPlaceholderLink:link]) skippedPlaceholders++;
                else skippedUnsupported++;
                if (parseError == nil && err != nil) parseError = err;
                continue;
            }
            if ([HVPNLinkParser isPlaceholderLink:link]) {
                skippedPlaceholders++;
                continue;
            }
            proxy = p;
            break;
        }
        if (proxy == nil) {
            if (skippedPlaceholders > 0) {
                return [self failure:[NSString stringWithFormat:
                    @"В подписке только заглушки (0.0.0.0:1) — %lu шт. Панель не выдала ноды: "
                    @"подписка не активирована, истекла или исчерпан лимит устройств.",
                    (unsigned long)skippedPlaceholders]];
            }
            if (skippedUnsupported > 0) {
                return [self failure:[NSString stringWithFormat:
                    @"Ни одна из %lu нод не поддерживается ядром. %@",
                    (unsigned long)skippedUnsupported,
                    parseError.localizedDescription ?: @""]];
            }
            return [self failure:parseError.localizedDescription ?: @"Не удалось разобрать ссылку"];
        }

        // Ядру не нужен DNS, чтобы дойти до сервера: подставляем IP в outbound.
        // Иначе получается петля «DNS идёт через прокси, адрес которого надо отрезолвить».
        // SNI (tls.server_name) остаётся доменом — он уже прописан парсером.
        NSArray<NSString *> *serverAddresses = HVPNResolveIPv4(proxy.server);
        if (!HVPNIsIPv4Literal(proxy.server)) {
            if (serverAddresses.count > 0) {
                NSMutableDictionary *outbound = [proxy.outbound mutableCopy];
                outbound[@"server"] = serverAddresses.firstObject;
                proxy.outbound = outbound;
                NSLog(@"[happvpnd] сервер %@ -> %@", proxy.server, serverAddresses.firstObject);
            } else {
                NSLog(@"[happvpnd] не удалось отрезолвить %@, оставляю домен", proxy.server);
            }
        }

        // Диагностика: что именно уходит в ядро (без uuid и паролей).
        NSDictionary *ob = proxy.outbound;
        NSDictionary *tlsOpt = [ob[@"tls"] isKindOfClass:[NSDictionary class]]
            ? ob[@"tls"] : nil;
        NSDictionary *realityOpt = [tlsOpt[@"reality"] isKindOfClass:[NSDictionary class]]
            ? tlsOpt[@"reality"] : nil;
        NSDictionary *utlsOpt = [tlsOpt[@"utls"] isKindOfClass:[NSDictionary class]]
            ? tlsOpt[@"utls"] : nil;
        NSDictionary *transportOpt = [ob[@"transport"] isKindOfClass:[NSDictionary class]]
            ? ob[@"transport"] : nil;
        _outboundSummary = [NSString stringWithFormat:
            @"%@ %@:%ld flow=%@ tls=%@ sni=%@ fp=%@ reality=%@ pbk=%lu sid=%lu transport=%@",
            ob[@"type"] ?: @"?", proxy.server, (long)proxy.port, ob[@"flow"] ?: @"-",
            [tlsOpt[@"enabled"] boolValue] ? @"on" : @"off",
            tlsOpt[@"server_name"] ?: @"-", utlsOpt[@"fingerprint"] ?: @"-",
            [realityOpt[@"enabled"] boolValue] ? @"on" : @"off",
            (unsigned long)[realityOpt[@"public_key"] length],
            (unsigned long)[realityOpt[@"short_id"] length],
            transportOpt[@"type"] ?: @"tcp"];
        NSLog(@"[velad] outbound: %@", _outboundSummary);

        NSFileManager *fm = [NSFileManager defaultManager];
        [fm createDirectoryAtPath:kBaseDir withIntermediateDirectories:YES
                       attributes:@{NSFilePosixPermissions: @0755} error:NULL];

        if (![fm isExecutableFileAtPath:kCorePath]) {
            return [self failure:[NSString stringWithFormat:@"Ядро не найдено: %@", kCorePath]];
        }

        NSMutableDictionary *opts = [options mutableCopy] ?: [NSMutableDictionary dictionary];
        NSString *systemDNS = HVPNSystemDNS();
        if (systemDNS.length) opts[@"dnsLocal"] = systemDNS;
        opts[@"logPath"] = kCoreLogPath;
        NSString *tunName = HVPNNextTunName();
        opts[@"interfaceName"] = tunName;
        NSLog(@"[velad] tun: %@", tunName);
        NSString *primaryInterface = HVPNPrimaryInterface();
        if (primaryInterface.length) {
            opts[@"bindInterface"] = primaryInterface;
            NSLog(@"[happvpnd] физический интерфейс: %@", primaryInterface);
        } else {
            NSLog(@"[happvpnd] не удалось определить физический интерфейс (direct пойдёт по общей таблице)");
        }
        NSDictionary *config = HVPNBuildConfig(proxy, opts);

        NSError *jsonError = nil;
        NSData *json = [NSJSONSerialization dataWithJSONObject:config
                                                       options:NSJSONWritingPrettyPrinted
                                                         error:&jsonError];
        if (json == nil) {
            return [self failure:[NSString stringWithFormat:@"Конфиг не собрался: %@",
                                  jsonError.localizedDescription]];
        }
        if (![json writeToFile:kConfigPath atomically:YES]) {
            return [self failure:@"Не удалось записать core.json"];
        }
        [@"" writeToFile:kCoreLogPath atomically:YES encoding:NSUTF8StringEncoding error:NULL];

        NSArray<NSString *> *beforeUtuns = HVPNUtunNames();

        pid_t pid = [self spawnCore];
        if (pid <= 0) {
            return [self failure:[NSString stringWithFormat:@"Не удалось запустить ядро (errno %d)", errno]];
        }

        NSString *utun = [self waitForTunNamed:tunName pid:pid timeout:15.0];
        if (utun == nil) {
            kill(pid, SIGKILL);
            waitpid(pid, NULL, WNOHANG);
            NSString *log = [self coreLog];
            return [self failure:[NSString stringWithFormat:
                                  @"Ядро не создало tun-интерфейс %@ (занятых utun: %lu). Лог:\n%@",
                                  tunName, (unsigned long)beforeUtuns.count,
                                  log.length ? [self tail:log] : @"(пусто)"]];
        }

        unsigned ifindex = if_nametoindex(utun.UTF8String);
        if (ifindex == 0) {
            kill(pid, SIGKILL);
            waitpid(pid, NULL, WNOHANG);
            return [self failure:@"Не удалось получить индекс tun-интерфейса"];
        }

        _pid = pid;
        _utun = utun;
        _nodeName = proxy.name;
        _nodeServer = proxy.server;
        _nodeType = proxy.type;
        _nodePort = proxy.port;
        _startedAt = [NSDate date];

        // 0. Снять всё, что осталось от прошлых сессий (иначе add даёт EEXIST).
        NSLog(@"[velad] tun %@, ifindex %u, route(8): %@", utun, ifindex,
              HVPNRouteBinaryPath() ?: @"не найден");
        HVPNRouteLogConflicts();
        [HVPNTunnel cleanupStaleRoutes];
        // 1. Сервер прокси должен ходить мимо tun, иначе петля.
        [self addHostRoutesForServerAddresses:serverAddresses];
        // 2. Заворачиваем весь IPv4/IPv6 в tun (split default).
        [self addInterfaceRoute:AF_INET dst:@"0.0.0.0" prefix:1 ifindex:ifindex];
        [self addInterfaceRoute:AF_INET dst:@"128.0.0.0" prefix:1 ifindex:ifindex];
        // IPv6 по умолчанию оставляем напрямую: если завернуть v6 в туннель без
        // рабочего v6-транспорта, iOS решает, что сеть «мертва», и уходит на LTE.
        BOOL tunnelIPv6 = [options[@"tunnelIPv6"] boolValue] && HVPNInterfaceHasIPv6(utun);
        if (tunnelIPv6) {
            [self addInterfaceRoute:AF_INET6 dst:@"::" prefix:1 ifindex:ifindex];
            [self addInterfaceRoute:AF_INET6 dst:@"8000::" prefix:1 ifindex:ifindex];
        } else {
            // Либо сервер только по IPv6, либо на utun нет IPv6-адреса — тогда
            // ::/1 ставить бессмысленно (ENETUNREACH), IPv4 работает как обычно.
            NSLog(@"[velad] IPv6 не заворачиваю (сервер v4: %@, tun v6: %@)",
                  serverAddresses.count > 0 ? @"да" : @"нет",
                  HVPNInterfaceHasIPv6(utun) ? @"да" : @"нет");
        }

        NSUInteger installedRoutes = _ifaceRoutes.count;
        NSUInteger expectedRoutes = tunnelIPv6 ? 4 : 2;
        NSLog(@"[velad] маршрутов поставлено %lu из %lu, проверка 0/1 -> ifindex %u (tun %u)",
              (unsigned long)installedRoutes, (unsigned long)expectedRoutes,
              HVPNRouteInterfaceIndex(AF_INET, @"0.0.0.0", 1), ifindex);
        if (installedRoutes < 2) {
            [self stopLocked];
            return [self failure:[NSString stringWithFormat:
                @"Не удалось поставить маршруты (получилось %lu из %lu). Подробности: "
                @"/var/mobile/Library/Logs/Vela/daemon.log",
                (unsigned long)installedRoutes, (unsigned long)expectedRoutes]];
        }

        // Пока туннель поднимался, mDNSResponder мог запомнить отрицательный ответ
        // (в том числе для youtube.com) и потом отдавать его приложениям. Просим
        // перечитать конфигурацию — кеш сбрасывается.
        if (system("killall -HUP mDNSResponder >/dev/null 2>&1") == 0) {
            NSLog(@"[velad] кеш DNS сброшен (mDNSResponder HUP)");
        }

        // Проверяем, что к серверу нет петли через наш же tun.
        for (NSString *ip in serverAddresses) {
            if (HVPNRouteInterfaceIndex(AF_INET, ip, 32) == ifindex) {
                NSLog(@"[velad] ОШИБКА: маршрут к серверу %@ ведёт в наш tun (петля)", ip);
            }
        }

        _lastProbe = HVPNRunProbe(4.0);
        if ([_lastProbe[@"ok"] boolValue]) {
            NSLog(@"[velad] проба через туннель: трафик идёт, %@ мс", _lastProbe[@"ms"]);
        } else {
            NSLog(@"[velad] проба через туннель: ТРАФИКА НЕТ (%@)", _lastProbe[@"error"]);

            // Частая причина у «белых списков»: самоподписанный сертификат.
            // Пробуем один раз перезапустить ядро с insecure.
            NSString *coreText = [[self coreLog] lowercaseString];
            BOOL certProblem = [coreText rangeOfString:@"x509"].location != NSNotFound ||
                               [coreText rangeOfString:@"certificate"].location != NSNotFound ||
                               [coreText rangeOfString:@"unknown authority"].location != NSNotFound;
            if (certProblem && ![options[@"forceInsecure"] boolValue]) {
                NSLog(@"[velad] сертификат узла не проходит проверку — повторяю с insecure");
                NSMutableDictionary *retry = [options mutableCopy] ?: [NSMutableDictionary dictionary];
                retry[@"forceInsecure"] = @YES;
                return [self startWithLinks:links options:retry];
            }
        }

        return @{@"ok": @YES, @"status": [self status], @"probe": _lastProbe ?: @{}};
    }
}

- (NSDictionary *)stop {
    @synchronized (self) {
        BOOL wasRunning = (_pid > 0);
        [self stopLocked];
        return @{@"ok": @YES, @"wasRunning": @(wasRunning), @"status": [self status]};
    }
}

- (NSDictionary *)status {
    @synchronized (self) {
        BOOL running = (_pid > 0) && (kill(_pid, 0) == 0);
        // Самовосстановление: если ядро не запущено, а split-маршруты остались
        // (прошлый запуск умер), интернета нет вообще. Снимаем их.
        if (!running) {
            unsigned stale = HVPNRouteInterfaceIndex(AF_INET, @"0.0.0.0", 1);
            if (stale != 0) {
                NSLog(@"[velad] найдены оставшиеся маршруты (ifindex %u), снимаю", stale);
                [HVPNTunnel cleanupStaleRoutes];
            }
        }
        NSInteger uptime = 0;
        if (running && _startedAt != nil) {
            uptime = (NSInteger)[[NSDate date] timeIntervalSinceDate:_startedAt];
            if (uptime < 0) uptime = 0;
        }
        return @{
            @"running": @(running),
            @"pid": @(_pid),
            @"utun": _utun ?: @"",
            @"node": _nodeName ?: @"",
            @"server": _nodeServer ?: @"",
            @"protocol": _nodeType ?: @"",
            @"port": @(_nodePort),
            @"uptime": @(uptime),
            @"routes": @(_ifaceRoutes.count),
            @"probe": _lastProbe ?: @{},
            @"outbound": _outboundSummary ?: @""
        };
    }
}

- (NSDictionary *)probe {
    @synchronized (self) {
        if (_pid <= 0) return @{@"ok": @NO, @"error": @"не подключено"};
        _lastProbe = HVPNRunProbe(6.0);
        NSLog(@"[velad] проба через туннель: %@",
              [_lastProbe[@"ok"] boolValue] ? _lastProbe[@"ms"] : _lastProbe[@"error"]);
        return _lastProbe;
    }
}

- (NSString *)coreLog {
    NSData *data = [NSData dataWithContentsOfFile:kCoreLogPath];
    if (data.length == 0) return @"";
    NSUInteger limit = 32 * 1024;
    if (data.length > limit) data = [data subdataWithRange:NSMakeRange(data.length - limit, limit)];
    NSString *text = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    return text ?: @"";
}

// MARK: - Внутреннее

- (NSDictionary *)failure:(NSString *)message {
    return @{@"ok": @NO, @"error": message ?: @"Неизвестная ошибка", @"status": [self status]};
}

- (NSString *)tail:(NSString *)text {
    if (text.length <= 4000) return text;
    return [text substringFromIndex:text.length - 4000];
}

- (pid_t)spawnCore {
    const char *core = kCorePath.fileSystemRepresentation;
    const char *log = kCoreLogPath.fileSystemRepresentation;

    posix_spawn_file_actions_t actions;
    posix_spawn_file_actions_init(&actions);
    posix_spawn_file_actions_addopen(&actions, STDIN_FILENO, "/dev/null", O_RDONLY, 0);
    posix_spawn_file_actions_addopen(&actions, STDOUT_FILENO, log, O_WRONLY | O_CREAT | O_APPEND, 0644);
    posix_spawn_file_actions_addopen(&actions, STDERR_FILENO, log, O_WRONLY | O_CREAT | O_APPEND, 0644);

    char *argv[] = {
        (char *)"sing-box",
        (char *)"run",
        (char *)"-c",
        (char *)kConfigPath.fileSystemRepresentation,
        NULL
    };
    char **envp = *_NSGetEnviron();

    pid_t pid = 0;
    int rc = posix_spawn(&pid, core, &actions, NULL, argv, envp);
    posix_spawn_file_actions_destroy(&actions);
    if (rc != 0) {
        NSLog(@"[happvpnd] posix_spawn failed: %d", rc);
        errno = rc;
        return -1;
    }
    return pid;
}

- (NSString *)waitForTunNamed:(NSString *)name pid:(pid_t)pid timeout:(NSTimeInterval)timeout {
    NSDate *deadline = [NSDate dateWithTimeIntervalSinceNow:timeout];
    while ([deadline timeIntervalSinceNow] > 0) {
        if (HVPNInterfaceReady(name)) return name;
        if (kill(pid, 0) != 0) return nil;   // ядро упало
        usleep(100 * 1000);
    }
    // Интерфейс мог появиться, но без адреса — для диагностики это лучше, чем nil.
    if (if_nametoindex(name.UTF8String) != 0) {
        NSLog(@"[velad] %@ существует, но без IPv4-адреса", name);
        return name;
    }
    return nil;
}

- (BOOL)addInterfaceRoute:(int)family dst:(NSString *)dst prefix:(int)prefix ifindex:(unsigned)ifindex {
    // 5 попыток: на iOS маршрут в только что созданный utun нередко отбивается
    // ENETUNREACH, пока ядро не досоздало адрес/состояние интерфейса.
    for (int attempt = 0; attempt < 5; attempt++) {
        if (HVPNRouteAddInterface(family, dst, prefix, ifindex) == 0) {
            [_ifaceRoutes addObject:@{@"family": @(family), @"dst": dst,
                                      @"prefix": @(prefix), @"ifindex": @(ifindex)}];
            return YES;
        }
        NSLog(@"[velad] маршрут %@/%d, попытка %d: %@", dst, prefix, attempt + 1, HVPNErrnoString());
        usleep(150 * 1000);
    }
    return NO;
}

- (void)addHostRoutesForServerAddresses:(NSArray<NSString *> *)addresses {
    if (addresses.count == 0) {
        NSLog(@"[happvpnd] нет IP сервера для host-маршрута");
        return;
    }
    NSString *gateway = nil;
    unsigned gatewayIndex = 0;
    if (!HVPNGetDefaultGateway(AF_INET, &gateway, &gatewayIndex)) {
        NSLog(@"[happvpnd] default gateway не найден, полагаемся на bind_interface");
        return;
    }
    for (NSString *ip in addresses) {
        if (HVPNRouteAddHost(AF_INET, ip, gateway, gatewayIndex) == 0) {
            [_hostRoutes addObject:@[@(AF_INET), ip, gateway]];
        } else {
            NSLog(@"[happvpnd] host route %@ via %@ failed: %@", ip, gateway, HVPNErrnoString());
        }
    }
}

- (void)stopLocked {
    for (NSDictionary *route in [_ifaceRoutes reverseObjectEnumerator]) {
        HVPNRouteDeleteInterface([route[@"family"] intValue],
                                 route[@"dst"],
                                 [route[@"prefix"] intValue],
                                 [route[@"ifindex"] unsignedIntValue]);
    }
    [_ifaceRoutes removeAllObjects];

    for (NSArray *host in [_hostRoutes reverseObjectEnumerator]) {
        HVPNRouteDeleteHost([host[0] intValue], host[1], host[2], 0);
    }
    [_hostRoutes removeAllObjects];

    if (_pid > 0) {
        kill(_pid, SIGTERM);
        BOOL reaped = NO;
        for (int i = 0; i < 30; i++) {
            pid_t r = waitpid(_pid, NULL, WNOHANG);
            if (r == _pid || r == -1) { reaped = YES; break; }
            usleep(100 * 1000);
        }
        if (!reaped) {
            kill(_pid, SIGKILL);
            waitpid(_pid, NULL, WNOHANG);
        }
    }

    _pid = 0;
    _utun = nil;
    _nodeName = nil;
    _nodeServer = nil;
    _nodeType = nil;
    _startedAt = nil;
}

// MARK: - Пинг

#ifndef IP_BOUND_IF
#define IP_BOUND_IF 25
#endif

static double HVPNNow(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1000000.0 + (double)ts.tv_nsec / 1000.0;   // микросекунды
}

static NSInteger HVPNPingOnce(NSString *ip, NSInteger port, unsigned ifindex,
                              NSTimeInterval timeout, NSString **errorText) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        if (errorText) *errorText = HVPNErrnoString();
        return -1;
    }

    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    // Привязка к физическому интерфейсу: иначе при поднятом tun пакет уйдёт в него.
    if (ifindex > 0) {
        int index = (int)ifindex;
        if (setsockopt(fd, IPPROTO_IP, IP_BOUND_IF, &index, sizeof(index)) != 0) {
            NSLog(@"[velad] IP_BOUND_IF(%u) не применился: %@", ifindex, HVPNErrnoString());
        }
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, ip.UTF8String, &addr.sin_addr) != 1) {
        close(fd);
        if (errorText) *errorText = @"плохой IP";
        return -1;
    }

    double started = HVPNNow();
    int rc = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    NSInteger elapsedUs = -1;

    if (rc == 0) {
        elapsedUs = (NSInteger)llround(HVPNNow() - started);
    } else if (errno == EINPROGRESS) {
        struct pollfd pfd;
        pfd.fd = fd;
        pfd.events = POLLOUT;
        pfd.revents = 0;
        rc = poll(&pfd, 1, (int)(timeout * 1000));
        if (rc > 0) {
            int soError = 0;
            socklen_t length = sizeof(soError);
            if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &soError, &length) == 0 && soError == 0) {
                elapsedUs = (NSInteger)llround(HVPNNow() - started);
            } else if (errorText) {
                *errorText = [NSString stringWithUTF8String:strerror(soError)] ?: @"connect failed";
            }
        } else if (rc == 0) {
            if (errorText) *errorText = @"таймаут";
        } else if (errorText) {
            *errorText = HVPNErrnoString();
        }
    } else if (errorText) {
        *errorText = HVPNErrnoString();
    }

    close(fd);
    // Микросекунды: 0 или отрицательное — не валидный замер.
    return elapsedUs > 0 ? elapsedUs : -1;
}

- (NSDictionary *)pingServer:(NSString *)server port:(NSInteger)port {
    if (server.length == 0 || port <= 0) {
        return @{@"ok": @NO, @"error": @"нет server/port"};
    }
    if (port > 65535) port = 65535;

    NSArray<NSString *> *addresses = HVPNResolveIPv4(server);
    if (addresses.count == 0) {
        if ([server rangeOfString:@":"].location != NSNotFound) {
            return @{@"ok": @NO, @"error": @"IPv6-сервер: пинг не реализован"};
        }
        return @{@"ok": @NO, @"error": @"не удалось отрезолвить"};
    }

    unsigned ifindex = 0;
    NSString *gateway = nil;
    if (HVPNGetDefaultGateway(AF_INET, &gateway, &ifindex)) {
        // индекс физического интерфейса уже внутри gateway-записи
    }

    NSString *lastError = nil;
    NSMutableArray<NSNumber *> *samples = [NSMutableArray array];   // микросекунды
    for (int attempt = 0; attempt < 3; attempt++) {
        NSString *error = nil;
        NSInteger us = HVPNPingOnce(addresses.firstObject, port, ifindex, 3.0, &error);
        if (us > 0) [samples addObject:@(us)];
        else if (error.length) lastError = error;
        if (attempt < 2) usleep(120 * 1000);
    }

    if (samples.count == 0) {
        return @{@"ok": @NO,
                 @"error": lastError.length ? lastError : @"нет ответа",
                 @"ip": addresses.firstObject,
                 @"attempts": @[]};
    }
    NSArray *sorted = [samples sortedArrayUsingSelector:@selector(compare:)];
    double medianUs = [sorted[sorted.count / 2] doubleValue];
    // Округляем вверх: 0 мс в интерфейсе выглядит как баг, а не как «быстро».
    NSInteger ms = (NSInteger)ceil(medianUs / 1000.0);
    if (ms < 1) ms = 1;
    return @{@"ok": @YES, @"ms": @(ms), @"ip": addresses.firstObject, @"attempts": sorted};
}

@end
