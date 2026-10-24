#import "HVPNRoute.h"
#import "HVPNRouteCompat.h"

#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stddef.h>
#include <unistd.h>
#include <spawn.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <crt_externs.h>

#define HVPN_ROUNDUP(a) ((a) > 0 ? (1 + (((a) - 1) | (sizeof(uint32_t) - 1))) : sizeof(uint32_t))

NSString *HVPNErrnoString(void) {
    return [NSString stringWithUTF8String:strerror(errno)] ?: @"unknown error";
}

static int HVPNRouteOpEx(int cmd, int family, const void *dst, int prefix,
                         unsigned ifindex, NSString *gateway, BOOL withGateway) {
    int fd = socket(PF_ROUTE, SOCK_RAW, family == AF_INET6 ? AF_INET6 : AF_INET);
    if (fd < 0) return -1;

    char buf[512];
    memset(buf, 0, sizeof(buf));

    struct hvpn_rt_msghdr *rtm = (struct hvpn_rt_msghdr *)buf;
    char *cp = buf + sizeof(struct hvpn_rt_msghdr);
    int len = (int)sizeof(struct hvpn_rt_msghdr);

    rtm->rtm_version = HVPN_RTM_VERSION;
    rtm->rtm_type = (u_char)cmd;
    rtm->rtm_flags = HVPN_RTF_UP | HVPN_RTF_STATIC;
    rtm->rtm_addrs = HVPN_RTA_DST | HVPN_RTA_NETMASK;
    if (withGateway) rtm->rtm_addrs |= HVPN_RTA_GATEWAY;

    if (family == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in *)cp;
        sin->sin_len = sizeof(struct sockaddr_in);
        sin->sin_family = AF_INET;
        memcpy(&sin->sin_addr, dst, 4);
        cp += sizeof(struct sockaddr_in);
        len += (int)sizeof(struct sockaddr_in);

        sin = (struct sockaddr_in *)cp;
        sin->sin_len = sizeof(struct sockaddr_in);
        sin->sin_family = AF_INET;
        in_addr_t mask = (prefix <= 0) ? 0 : htonl(0xFFFFFFFFu << (32 - prefix));
        sin->sin_addr.s_addr = mask;
        cp += sizeof(struct sockaddr_in);
        len += (int)sizeof(struct sockaddr_in);
    } else {
        struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)cp;
        s6->sin6_len = sizeof(struct sockaddr_in6);
        s6->sin6_family = AF_INET6;
        memcpy(&s6->sin6_addr, dst, 16);
        cp += sizeof(struct sockaddr_in6);
        len += (int)sizeof(struct sockaddr_in6);

        uint8_t mask[16];
        memset(mask, 0, sizeof(mask));
        int full = prefix / 8;
        for (int i = 0; i < full && i < 16; i++) mask[i] = 0xFF;
        if (prefix % 8 && full < 16) mask[full] = (uint8_t)(0xFF << (8 - prefix % 8));

        s6 = (struct sockaddr_in6 *)cp;
        s6->sin6_len = sizeof(struct sockaddr_in6);
        s6->sin6_family = AF_INET6;
        memcpy(&s6->sin6_addr, mask, 16);
        cp += sizeof(struct sockaddr_in6);
        len += (int)sizeof(struct sockaddr_in6);
    }

    if (!withGateway) {
        // Удаление идёт без RTA_GATEWAY: ядро ищет запись по dst+mask.
    } else if (gateway.length) {
        if (family == AF_INET) {
            struct sockaddr_in *sin = (struct sockaddr_in *)cp;
            sin->sin_len = sizeof(struct sockaddr_in);
            sin->sin_family = AF_INET;
            if (inet_pton(AF_INET, gateway.UTF8String, &sin->sin_addr) != 1) {
                close(fd);
                errno = EINVAL;
                return -1;
            }
            cp += sizeof(struct sockaddr_in);
            len += (int)sizeof(struct sockaddr_in);
        } else {
            struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)cp;
            s6->sin6_len = sizeof(struct sockaddr_in6);
            s6->sin6_family = AF_INET6;
            if (inet_pton(AF_INET6, gateway.UTF8String, &s6->sin6_addr) != 1) {
                close(fd);
                errno = EINVAL;
                return -1;
            }
            cp += sizeof(struct sockaddr_in6);
            len += (int)sizeof(struct sockaddr_in6);
        }
    } else {
        struct hvpn_sockaddr_dl *sdl = (struct hvpn_sockaddr_dl *)cp;
        memset(sdl, 0, sizeof(*sdl));
        sdl->sdl_len = sizeof(struct hvpn_sockaddr_dl);
        sdl->sdl_family = AF_LINK;
        sdl->sdl_index = (u_short)ifindex;
        cp += sizeof(struct hvpn_sockaddr_dl);
        len += (int)sizeof(struct hvpn_sockaddr_dl);
    }

    rtm->rtm_msglen = (u_short)len;
    rtm->rtm_index = (u_short)ifindex;

    ssize_t rc;
    do {
        rc = write(fd, buf, (size_t)len);
    } while (rc < 0 && errno == EINTR);

    int savedErrno = errno;
    close(fd);
    if (rc < 0) {
        errno = savedErrno;
        return -1;
    }
    return 0;
}

static BOOL HVPNParseAddr(int family, NSString *text, uint8_t out[16]) {
    memset(out, 0, 16);
    return inet_pton(family, text.UTF8String, out) == 1;
}

// Darwin отдаёт маску маршрута «коротким» sockaddr (sa_len = 5/8, а не 16),
// поэтому читаем только реально присутствующие байты и добиваем нулями.
// Иначе любой /1-маршрут выглядит как маска 0 и поиск по таблице не находит его.
static uint32_t HVPNIPv4MaskValue(struct sockaddr *sa) {
    uint8_t bytes[4] = {0, 0, 0, 0};
    if (sa != NULL) {
        size_t offset = offsetof(struct sockaddr_in, sin_addr);
        if (sa->sa_len > offset) {
            size_t count = sa->sa_len - offset;
            if (count > 4) count = 4;
            memcpy(bytes, ((uint8_t *)sa) + offset, count);
        }
    }
    // Байты маски идут в сетевом порядке, поэтому собираем вручную:
    // для короткой маски (sa_len = 6) ntohl дал бы неверный результат.
    return ((uint32_t)bytes[0] << 24) | ((uint32_t)bytes[1] << 16) |
           ((uint32_t)bytes[2] << 8) | (uint32_t)bytes[3];
}

static void HVPNIPv6MaskValue(struct sockaddr *sa, uint8_t out[16]) {
    memset(out, 0, 16);
    if (sa == NULL) return;
    size_t offset = offsetof(struct sockaddr_in6, sin6_addr);
    if (sa->sa_len <= offset) return;
    size_t count = sa->sa_len - offset;
    if (count > 16) count = 16;
    memcpy(out, ((uint8_t *)sa) + offset, count);
}

static uint32_t HVPNPrefixMask4(int prefix) {
    if (prefix <= 0) return 0;
    if (prefix >= 32) return 0xFFFFFFFFu;
    return 0xFFFFFFFFu << (32 - prefix);
}

static int HVPNRouteOp(int cmd, int family, const void *dst, int prefix,
                       unsigned ifindex, NSString *gateway) {
    return HVPNRouteOpEx(cmd, family, dst, prefix, ifindex, gateway, YES);
}

static int HVPNRouteDeleteOp(int family, const void *dst, int prefix, unsigned ifindex) {
    return HVPNRouteOpEx(HVPN_RTM_DELETE, family, dst, prefix, ifindex, nil, NO);
}

static BOOL HVPNRunRoute(NSArray<NSString *> *args) {
    static NSArray<NSString *> *candidates;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        candidates = @[@"/sbin/route", @"/usr/sbin/route", @"/bin/route"];
    });

    for (NSString *binary in candidates) {
        if (![[NSFileManager defaultManager] isExecutableFileAtPath:binary]) continue;

        NSUInteger count = args.count + 2;   // argv[0] = имя программы
        char **argv = calloc(count, sizeof(char *));
        if (argv == NULL) return NO;
        argv[0] = (char *)[binary UTF8String];
        for (NSUInteger i = 0; i < args.count; i++) argv[i + 1] = (char *)[args[i] UTF8String];
        argv[args.count + 1] = NULL;

        posix_spawn_file_actions_t actions;
        posix_spawn_file_actions_init(&actions);
        posix_spawn_file_actions_addopen(&actions, STDOUT_FILENO, "/dev/null", O_WRONLY, 0);
        posix_spawn_file_actions_addopen(&actions, STDERR_FILENO, "/dev/null", O_WRONLY, 0);

        pid_t pid = 0;
        int rc = posix_spawn(&pid, binary.fileSystemRepresentation, &actions, NULL,
                             argv, *_NSGetEnviron());
        posix_spawn_file_actions_destroy(&actions);
        free(argv);
        if (rc != 0) continue;

        int status = 0;
        if (waitpid(pid, &status, 0) == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0) {
            return YES;
        }
    }
    return NO;
}

// Резервный путь: /sbin/route. На iOS он есть и умеет -interface,
// а нам важно не зависеть от тонкостей PF_ROUTE, которые на iOS
// дают ENETUNREACH при добавлении маршрута в свежесозданный utun.
static BOOL HVPNRouteViaCommand(BOOL add, int family, NSString *dst, int prefix, unsigned ifindex) {
    char name[IFNAMSIZ];
    memset(name, 0, sizeof(name));
    if (ifindex == 0 || if_indextoname(ifindex, name) == NULL) return NO;

    NSString *target = [NSString stringWithFormat:@"%@/%d", dst, prefix];
    if (!add) {
        // Удаление по сети: ядро находит маршрут независимо от интерфейса.
        return HVPNRunRoute(@[@"delete", @"-net", target]);
    }
    return HVPNRunRoute(@[@"add", @"-net", target, @"-interface", [NSString stringWithUTF8String:name]]);
}

static int HVPNRouteOpWithFallback(int cmd, int family, NSString *dst, int prefix,
                                   unsigned ifindex, NSString *gateway) {
    uint8_t addr[16];
    if (!HVPNParseAddr(family, dst, addr)) { errno = EINVAL; return -1; }

    BOOL add = (cmd == HVPN_RTM_ADD);
    NSString *target = [NSString stringWithFormat:@"%@/%d", dst, prefix];

    int result;
    if (add) {
        result = HVPNRouteOp(HVPN_RTM_ADD, family, addr, prefix, ifindex, gateway);

        if (result != 0 && errno == EEXIST && gateway.length > 0) {
            // Host-маршрут до сервера уже стоит — это нормально.
            return 0;
        }
        if (result != 0 && errno == EEXIST) {
            // Маршрут уже есть: скорее всего остался от прошлой сессии.
            // Снимаем его (по сети, без привязки к интерфейсу) и ставим заново.
            NSLog(@"[velad] %@ уже есть (ifindex %u), снимаю и ставлю заново",
                  target, HVPNRouteInterfaceIndex(family, dst, prefix));
            HVPNRouteDeleteOp(family, addr, prefix, 0);
            HVPNRouteDeleteOp(family, addr, prefix, ifindex);
            HVPNRunRoute(@[@"delete", @"-net", target]);
            result = HVPNRouteOp(HVPN_RTM_ADD, family, addr, prefix, ifindex, gateway);
        }
    } else {
        result = HVPNRouteDeleteOp(family, addr, prefix, 0);
        if (result != 0) result = HVPNRouteDeleteOp(family, addr, prefix, ifindex);
    }
    if (result == 0) return 0;

    int saved = errno;
    BOOL fallback = NO;
    if (gateway.length == 0) {
        fallback = HVPNRouteViaCommand(add, family, dst, prefix, ifindex);
    } else {
        fallback = HVPNRunRoute(@[add ? @"add" : @"delete", @"-host", dst, gateway]);
    }

    if (fallback) {
        NSLog(@"[velad] маршрут %@ через ifindex %u выставлен через route(8) "
              @"(PF_ROUTE дал: %s)", target, ifindex, strerror(saved));
        errno = 0;
        return 0;
    }
    errno = saved;
    return -1;
}

int HVPNRouteAddInterface(int family, NSString *dst, int prefix, unsigned ifindex) {
    uint8_t addr[16];
    if (!HVPNParseAddr(family, dst, addr)) { errno = EINVAL; return -1; }
    return HVPNRouteOpWithFallback(HVPN_RTM_ADD, family, dst, prefix, ifindex, nil);
}

int HVPNRouteDeleteInterface(int family, NSString *dst, int prefix, unsigned ifindex) {
    uint8_t addr[16];
    if (!HVPNParseAddr(family, dst, addr)) { errno = EINVAL; return -1; }
    return HVPNRouteOpWithFallback(HVPN_RTM_DELETE, family, dst, prefix, ifindex, nil);
}

int HVPNRouteAddHost(int family, NSString *dst, NSString *gateway, unsigned ifindex) {
    uint8_t addr[16];
    if (!HVPNParseAddr(family, dst, addr)) { errno = EINVAL; return -1; }
    return HVPNRouteOpWithFallback(HVPN_RTM_ADD, family, dst, family == AF_INET ? 32 : 128,
                                   ifindex, gateway);
}

int HVPNRouteDeleteHost(int family, NSString *dst, NSString *gateway, unsigned ifindex) {
    uint8_t addr[16];
    if (!HVPNParseAddr(family, dst, addr)) { errno = EINVAL; return -1; }
    return HVPNRouteOpWithFallback(HVPN_RTM_DELETE, family, dst, family == AF_INET ? 32 : 128,
                                   ifindex, gateway);
}

NSString *HVPNRouteBinaryPath(void) {
    static NSArray<NSString *> *candidates;
    static dispatch_once_t once;
    static NSString *found = nil;
    dispatch_once(&once, ^{
        candidates = @[@"/sbin/route", @"/usr/sbin/route", @"/bin/route", @"/usr/local/bin/route"];
        for (NSString *path in candidates) {
            if ([[NSFileManager defaultManager] isExecutableFileAtPath:path]) {
                found = path;
                break;
            }
        }
    });
    return found;
}

// Печатает в daemon.log маршруты, которые могут конфликтовать с нашими 0/1 и 128/1.
// Нужно, чтобы по логу было видно, кто именно держит маршрут.
void HVPNRouteLogConflicts(void) {
    int mib[6] = {CTL_NET, PF_ROUTE, 0, AF_INET, NET_RT_DUMP, 0};
    size_t needed = 0;
    if (sysctl(mib, 6, NULL, &needed, NULL, 0) < 0 || needed == 0) {
        NSLog(@"[velad] таблица маршрутов недоступна: %s", strerror(errno));
        return;
    }
    char *buf = malloc(needed);
    if (buf == NULL) return;
    if (sysctl(mib, 6, buf, &needed, NULL, 0) < 0) { free(buf); return; }

    char *p = buf;
    char *end = buf + needed;
    while (p + sizeof(struct hvpn_rt_msghdr) <= end) {
        struct hvpn_rt_msghdr *rtm = (struct hvpn_rt_msghdr *)p;
        if (rtm->rtm_msglen == 0) break;
        p += rtm->rtm_msglen;
        if (rtm->rtm_type != HVPN_RTM_GET) continue;

        struct sockaddr *sa = (struct sockaddr *)(rtm + 1);
        struct sockaddr *dstSA = NULL, *maskSA = NULL;
        for (int i = 1; i <= HVPN_RTAX_MAX; i++) {
            if (!(rtm->rtm_addrs & (1 << (i - 1)))) continue;
            if (sa->sa_len == 0) break;
            if (i == 1) dstSA = sa;
            if (i == 4) maskSA = sa;
            sa = (struct sockaddr *)((char *)sa + HVPN_ROUNDUP(sa->sa_len));
        }
        if (dstSA == NULL || dstSA->sa_family != AF_INET) continue;

        struct sockaddr_in *d = (struct sockaddr_in *)dstSA;
        uint32_t dstValue = ntohl(d->sin_addr.s_addr);
        uint32_t mask = HVPNIPv4MaskValue(maskSA);
        BOOL interesting = (dstValue == 0 || dstValue == 0x80000000u) &&
                           (mask == 0 || mask == 0x80000000u);
        if (!interesting) continue;

        char name[IFNAMSIZ];
        memset(name, 0, sizeof(name));
        if (if_indextoname(rtm->rtm_index, name) == NULL) strcpy(name, "?");

        char text[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &d->sin_addr, text, sizeof(text));
        NSLog(@"[velad] в таблице: %s mask=0x%08x -> ifindex %u (%s) flags=0x%x",
              text, mask, rtm->rtm_index, name, rtm->rtm_flags);
    }
    free(buf);
}

BOOL HVPNGetDefaultGateway(int family, NSString **gateway, unsigned *ifindex) {
    int mib[6] = {CTL_NET, PF_ROUTE, 0, family, NET_RT_DUMP, 0};
    size_t needed = 0;
    if (sysctl(mib, 6, NULL, &needed, NULL, 0) < 0 || needed == 0) return NO;

    char *buf = malloc(needed);
    if (buf == NULL) return NO;
    if (sysctl(mib, 6, buf, &needed, NULL, 0) < 0) {
        free(buf);
        return NO;
    }

    BOOL found = NO;
    NSString *resultGateway = nil;
    unsigned resultIndex = 0;

    char *p = buf;
    char *end = buf + needed;
    while (p + sizeof(struct hvpn_rt_msghdr) <= end) {
        struct hvpn_rt_msghdr *rtm = (struct hvpn_rt_msghdr *)p;
        if (rtm->rtm_msglen == 0) break;
        p += rtm->rtm_msglen;

        if (rtm->rtm_type != HVPN_RTM_GET) continue;
        if (!(rtm->rtm_flags & HVPN_RTF_GATEWAY)) continue;

        struct sockaddr *sa = (struct sockaddr *)(rtm + 1);
        struct sockaddr *dstSA = NULL, *gwSA = NULL, *maskSA = NULL;
        for (int i = 1; i <= HVPN_RTAX_MAX; i++) {
            if (!(rtm->rtm_addrs & (1 << (i - 1)))) continue;
            if (sa->sa_len == 0) break;
            if (i == 1) dstSA = sa;         // RTA_DST
            if (i == 2) gwSA = sa;          // RTA_GATEWAY
            if (i == 4) maskSA = sa;        // RTA_NETMASK
            sa = (struct sockaddr *)((char *)sa + HVPN_ROUNDUP(sa->sa_len));
        }
        if (dstSA == NULL || gwSA == NULL) continue;
        if (dstSA->sa_family != family || gwSA->sa_family != family) continue;

        BOOL isDefault = NO;
        if (family == AF_INET) {
            struct sockaddr_in *d = (struct sockaddr_in *)dstSA;
            isDefault = (d->sin_addr.s_addr == INADDR_ANY);
        } else {
            struct sockaddr_in6 *d = (struct sockaddr_in6 *)dstSA;
            isDefault = IN6_IS_ADDR_UNSPECIFIED(&d->sin6_addr);
        }
        if (!isDefault) continue;
        if (maskSA && maskSA->sa_len >= sizeof(struct sockaddr_in) && family == AF_INET) {
            if (((struct sockaddr_in *)maskSA)->sin_addr.s_addr != 0) continue;
        }

        char text[INET6_ADDRSTRLEN];
        memset(text, 0, sizeof(text));
        const void *src = (family == AF_INET)
            ? (const void *)&((struct sockaddr_in *)gwSA)->sin_addr
            : (const void *)&((struct sockaddr_in6 *)gwSA)->sin6_addr;
        if (inet_ntop(family, src, text, sizeof(text)) != NULL) {
            resultGateway = [NSString stringWithUTF8String:text];
            resultIndex = rtm->rtm_index;
            found = YES;
        }
        break;
    }

    free(buf);
    if (!found) return NO;
    if (gateway) *gateway = resultGateway;
    if (ifindex) *ifindex = resultIndex;
    return YES;
}

unsigned HVPNRouteInterfaceIndex(int family, NSString *dst, int prefix) {
    int mib[6] = {CTL_NET, PF_ROUTE, 0, family, NET_RT_DUMP, 0};
    size_t needed = 0;
    if (sysctl(mib, 6, NULL, &needed, NULL, 0) < 0 || needed == 0) return 0;

    char *buf = malloc(needed);
    if (buf == NULL) return 0;
    if (sysctl(mib, 6, buf, &needed, NULL, 0) < 0) {
        free(buf);
        return 0;
    }

    uint8_t wanted[16];
    if (!HVPNParseAddr(family, dst, wanted)) {
        free(buf);
        return 0;
    }

    unsigned result = 0;
    char *p = buf;
    char *end = buf + needed;
    while (p + sizeof(struct hvpn_rt_msghdr) <= end) {
        struct hvpn_rt_msghdr *rtm = (struct hvpn_rt_msghdr *)p;
        if (rtm->rtm_msglen == 0) break;
        p += rtm->rtm_msglen;

        if (rtm->rtm_type != HVPN_RTM_GET) continue;
        if (rtm->rtm_flags & HVPN_RTF_GATEWAY) continue;   // нам нужен маршрут «в интерфейс»

        struct sockaddr *sa = (struct sockaddr *)(rtm + 1);
        struct sockaddr *dstSA = NULL, *maskSA = NULL;
        for (int i = 1; i <= HVPN_RTAX_MAX; i++) {
            if (!(rtm->rtm_addrs & (1 << (i - 1)))) continue;
            if (sa->sa_len == 0) break;
            if (i == 1) dstSA = sa;
            if (i == 4) maskSA = sa;
            sa = (struct sockaddr *)((char *)sa + HVPN_ROUNDUP(sa->sa_len));
        }
        if (dstSA == NULL || dstSA->sa_family != family) continue;

        const void *addr = (family == AF_INET)
            ? (const void *)&((struct sockaddr_in *)dstSA)->sin_addr
            : (const void *)&((struct sockaddr_in6 *)dstSA)->sin6_addr;
        size_t size = (family == AF_INET) ? 4 : 16;
        if (memcmp(addr, wanted, size) != 0) continue;

        // Проверяем маску, иначе можно поймать другой маршрут с тем же адресом.
        if (family == AF_INET) {
            if (HVPNIPv4MaskValue(maskSA) != HVPNPrefixMask4(prefix)) continue;
        } else {
            uint8_t mask[16];
            HVPNIPv6MaskValue(maskSA, mask);
            uint8_t want[16];
            memset(want, 0, sizeof(want));
            int full = prefix / 8;
            for (int i = 0; i < 16 && i < full; i++) want[i] = 0xFF;
            if (prefix % 8 && full < 16) want[full] = (uint8_t)(0xFF << (8 - prefix % 8));
            if (memcmp(mask, want, 16) != 0) continue;
        }

        result = rtm->rtm_index;
        break;
    }

    free(buf);
    return result;
}
