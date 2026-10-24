// В iPhoneOS SDK нет <net/route.h>, поэтому нужные для PF_ROUTE структуры и
// константы объявлены локально. Раскладка совпадает с macOS/iOS (4.4BSD ABI),
// размер hvpn_rt_msghdr = 92 байта на 32/64-битных ARM.
#ifndef HVPN_ROUTE_COMPAT_H
#define HVPN_ROUTE_COMPAT_H

#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>

#ifndef NET_RT_DUMP
#define NET_RT_DUMP 1
#endif

#define HVPN_RTM_ADD     0x1
#define HVPN_RTM_DELETE  0x2
#define HVPN_RTM_GET     0x4
#define HVPN_RTM_VERSION 5

#define HVPN_RTF_UP      0x1
#define HVPN_RTF_GATEWAY 0x2
#define HVPN_RTF_HOST    0x4
#define HVPN_RTF_STATIC  0x800

#define HVPN_RTA_DST     0x1
#define HVPN_RTA_GATEWAY 0x2
#define HVPN_RTA_NETMASK 0x4
#define HVPN_RTAX_MAX    8

struct hvpn_rt_metrics {
    u_int32_t rmx_locks;
    u_int32_t rmx_mtu;
    u_int32_t rmx_hopcount;
    u_int32_t rmx_expire;
    u_int32_t rmx_recvpipe;
    u_int32_t rmx_sendpipe;
    u_int32_t rmx_ssthresh;
    u_int32_t rmx_rtt;
    u_int32_t rmx_rttvar;
    u_int32_t rmx_pksent;
    u_int32_t rmx_state;
    u_int32_t rmx_filler[3];
};

struct hvpn_rt_msghdr {
    u_short rtm_msglen;
    u_char  rtm_version;
    u_char  rtm_type;
    u_short rtm_index;
    int     rtm_flags;
    int     rtm_addrs;
    pid_t   rtm_pid;
    int     rtm_seq;
    int     rtm_errno;
    int     rtm_use;
    u_int32_t rtm_inits;
    struct hvpn_rt_metrics rtm_rmx;
};

struct hvpn_sockaddr_dl {
    u_char  sdl_len;
    u_char  sdl_family;
    u_short sdl_index;
    u_char  sdl_type;
    u_char  sdl_nlen;
    u_char  sdl_alen;
    u_char  sdl_slen;
    char    sdl_data[12];
};

#endif
