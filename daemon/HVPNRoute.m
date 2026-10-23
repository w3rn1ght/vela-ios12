#import "HVPNRoute.h"
#import "HVPNRouteCompat.h"

#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define HVPN_ROUNDUP(a) ((a) > 0 ? (1 + (((a) - 1) | (sizeof(uint32_t) - 1))) : sizeof(uint32_t))

NSString *HVPNErrnoString(void) {
    return [NSString stringWithUTF8String:strerror(errno)] ?: @"unknown error";
}

static int HVPNRouteOp(int cmd, int family, const void *dst, int prefix,
                       unsigned ifindex, NSString *gateway) {
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
    rtm->rtm_addrs = HVPN_RTA_DST | HVPN_RTA_NETMASK | HVPN_RTA_GATEWAY;

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

    if (gateway.length) {
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

int HVPNRouteAddInterface(int family, NSString *dst, int prefix, unsigned ifindex) {
    uint8_t addr[16];
    if (!HVPNParseAddr(family, dst, addr)) { errno = EINVAL; return -1; }
    return HVPNRouteOp(HVPN_RTM_ADD, family, addr, prefix, ifindex, nil);
}

int HVPNRouteDeleteInterface(int family, NSString *dst, int prefix, unsigned ifindex) {
    uint8_t addr[16];
    if (!HVPNParseAddr(family, dst, addr)) { errno = EINVAL; return -1; }
    return HVPNRouteOp(HVPN_RTM_DELETE, family, addr, prefix, ifindex, nil);
}

int HVPNRouteAddHost(int family, NSString *dst, NSString *gateway, unsigned ifindex) {
    uint8_t addr[16];
    if (!HVPNParseAddr(family, dst, addr)) { errno = EINVAL; return -1; }
    return HVPNRouteOp(HVPN_RTM_ADD, family, addr, family == AF_INET ? 32 : 128, ifindex, gateway);
}

int HVPNRouteDeleteHost(int family, NSString *dst, NSString *gateway, unsigned ifindex) {
    uint8_t addr[16];
    if (!HVPNParseAddr(family, dst, addr)) { errno = EINVAL; return -1; }
    return HVPNRouteOp(HVPN_RTM_DELETE, family, addr, family == AF_INET ? 32 : 128, ifindex, gateway);
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
            uint32_t mask = 0;
            if (maskSA && maskSA->sa_len >= sizeof(struct sockaddr_in))
                mask = ntohl(((struct sockaddr_in *)maskSA)->sin_addr.s_addr);
            uint32_t want = (prefix <= 0) ? 0 : (0xFFFFFFFFu << (32 - prefix));
            if (mask != want) continue;
        } else {
            uint8_t mask[16];
            memset(mask, 0, sizeof(mask));
            if (maskSA && maskSA->sa_len >= sizeof(struct sockaddr_in6))
                memcpy(mask, &((struct sockaddr_in6 *)maskSA)->sin6_addr, 16);
            int full = prefix / 8;
            for (int i = 0; i < 16; i++) {
                uint8_t want = i < full ? 0xFF : (i == full && prefix % 8 ? (uint8_t)(0xFF << (8 - prefix % 8)) : 0);
                if (mask[i] != want) { result = 0; goto next; }
            }
        }

        result = rtm->rtm_index;
        break;
    next:
        continue;
    }

    free(buf);
    return result;
}
