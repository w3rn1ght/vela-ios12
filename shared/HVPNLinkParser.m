#import "HVPNLinkParser.h"
#import "HVPNLinkUtil.h"

#include <stdarg.h>

NSString *const HVPNErrorDomain = @"com.happvpn.error";

@implementation HVPNProxy
@end

static NSError *HVPNErr(NSString *format, ...) {
    va_list args;
    va_start(args, format);
    NSString *msg = [[NSString alloc] initWithFormat:format arguments:args];
    va_end(args);
    return [NSError errorWithDomain:HVPNErrorDomain code:1
                           userInfo:@{NSLocalizedDescriptionKey: msg}];
}

static NSString *HVPNStr(id v) {
    if (v == nil || v == (id)[NSNull null]) return nil;
    if ([v isKindOfClass:[NSString class]]) return v;
    if ([v isKindOfClass:[NSNumber class]]) return [v description];
    return nil;
}

static NSString *HVPNNodeName(NSString *fragment, NSString *host, NSInteger port) {
    if (fragment.length) return fragment;
    return [NSString stringWithFormat:@"%@:%ld", host, (long)port];
}

@implementation HVPNLinkParser

// MARK: - vmess

+ (HVPNProxy *)parseVmess:(NSString *)link error:(NSError **)error {
    NSString *body = [link substringFromIndex:@"vmess://".length];
    NSRange hash = [body rangeOfString:@"#"];
    if (hash.location != NSNotFound) body = [body substringToIndex:hash.location];
    NSRange qm = [body rangeOfString:@"?"];
    if (qm.location != NSNotFound) body = [body substringToIndex:qm.location];

    NSString *json = HVPNB64String(body) ?: body;
    NSData *jsonData = [json dataUsingEncoding:NSUTF8StringEncoding];
    NSDictionary *o = nil;
    if (jsonData) {
        id parsed = [NSJSONSerialization JSONObjectWithData:jsonData options:0 error:NULL];
        if ([parsed isKindOfClass:[NSDictionary class]]) o = parsed;
    }
    if (o == nil) {
        if (error) *error = HVPNErr(@"vmess: внутри ссылки не JSON");
        return nil;
    }

    NSString *server = HVPNStr(o[@"add"]);
    NSString *uuid = HVPNStr(o[@"id"]);
    NSInteger port = HVPNStr(o[@"port"]).integerValue;
    if (server.length == 0 || uuid.length == 0 || port <= 0) {
        if (error) *error = HVPNErr(@"vmess: нет add/id/port");
        return nil;
    }

    NSString *net = HVPNStr(o[@"net"]);
    NSString *headerType = HVPNStr(o[@"type"]);
    NSString *hostHeader = HVPNStr(o[@"host"]);
    NSString *path = HVPNStr(o[@"path"]);
    NSString *sni = HVPNStr(o[@"sni"]);
    NSString *alpn = HVPNStr(o[@"alpn"]);
    NSString *scy = HVPNStr(o[@"scy"]);
    NSString *aid = HVPNStr(o[@"aid"]);
    BOOL tlsOn = [HVPNStr(o[@"tls"]).lowercaseString isEqualToString:@"tls"];

    NSMutableDictionary *q = [NSMutableDictionary dictionary];
    if (net.length) q[@"type"] = net;
    if (hostHeader.length) q[@"host"] = hostHeader;
    if (path.length) q[@"path"] = path;
    if (alpn.length) q[@"alpn"] = alpn;
    if (tlsOn) {
        q[@"security"] = @"tls";
        if (sni.length) q[@"sni"] = sni;
    }
    if ([headerType isEqualToString:@"http"] && [net isEqualToString:@"tcp"]) {
        // vmess с HTTP-обфускацией поверх TCP: sing-box 1.8 это не умеет.
        if (error) *error = HVPNErr(@"vmess: TCP+HTTP-обфускация не поддерживается, используйте ws/grpc");
        return nil;
    }

    NSMutableDictionary *ob = [@{
        @"type": @"vmess",
        @"server": server,
        @"server_port": @(port),
        @"uuid": uuid,
        @"security": scy.length ? scy : @"auto",
        @"alter_id": @(aid.integerValue)
    } mutableCopy];

    NSMutableDictionary *tls = tlsOn ? HVPNTLSDict(q, hostHeader.length ? hostHeader : server) : nil;
    if (tls) ob[@"tls"] = tls;

    NSString *transportError = nil;
    NSDictionary *transport = HVPNTransportDict(q, &transportError);
    if (transportError) {
        if (error) *error = HVPNErr(@"vmess: %@", transportError);
        return nil;
    }
    if (transport) ob[@"transport"] = transport;

    HVPNProxy *p = [HVPNProxy new];
    p.name = HVPNStr(o[@"ps"]) ?: HVPNNodeName(nil, server, port);
    p.type = @"vmess";
    p.server = server;
    p.port = port;
    p.outbound = ob;
    return p;
}

// MARK: - vless

+ (HVPNProxy *)parseVless:(NSString *)link error:(NSError **)error {
    NSString *scheme = nil, *userinfo = nil, *host = nil, *path = nil, *fragment = nil;
    NSDictionary<NSString *, NSString *> *q = nil;
    NSInteger port = 0;
    if (!HVPNSplitURI(link, &scheme, &userinfo, &host, &port, &path, &q, &fragment)) {
        if (error) *error = HVPNErr(@"vless: не разобрать ссылку");
        return nil;
    }
    if (userinfo.length == 0) {
        if (error) *error = HVPNErr(@"vless: нет UUID");
        return nil;
    }
    if (port <= 0) {
        if (error) *error = HVPNErr(@"vless: нет порта");
        return nil;
    }

    NSMutableDictionary *ob = [@{
        @"type": @"vless",
        @"server": host,
        @"server_port": @(port),
        @"uuid": userinfo
    } mutableCopy];

    NSString *flow = q[@"flow"];
    if (flow.length) ob[@"flow"] = flow;

    NSString *packetEncoding = q[@"packetEncoding"];
    if (packetEncoding.length) ob[@"packet_encoding"] = packetEncoding;

    NSMutableDictionary *tls = HVPNTLSDict(q, host);
    if (tls) ob[@"tls"] = tls;

    NSString *transportError = nil;
    NSDictionary *transport = HVPNTransportDict(q, &transportError);
    if (transportError) {
        if (error) *error = HVPNErr(@"vless: %@", transportError);
        return nil;
    }
    if (transport) ob[@"transport"] = transport;

    HVPNProxy *p = [HVPNProxy new];
    p.name = HVPNNodeName(fragment, host, port);
    p.type = @"vless";
    p.server = host;
    p.port = port;
    p.outbound = ob;
    return p;
}

// MARK: - trojan

+ (HVPNProxy *)parseTrojan:(NSString *)link error:(NSError **)error {
    NSString *scheme = nil, *userinfo = nil, *host = nil, *path = nil, *fragment = nil;
    NSDictionary<NSString *, NSString *> *q = nil;
    NSInteger port = 0;
    if (!HVPNSplitURI(link, &scheme, &userinfo, &host, &port, &path, &q, &fragment)) {
        if (error) *error = HVPNErr(@"trojan: не разобрать ссылку");
        return nil;
    }
    if (userinfo.length == 0 || port <= 0) {
        if (error) *error = HVPNErr(@"trojan: нет пароля или порта");
        return nil;
    }

    NSMutableDictionary *ob = [@{
        @"type": @"trojan",
        @"server": host,
        @"server_port": @(port),
        @"password": userinfo
    } mutableCopy];

    NSMutableDictionary *tls = HVPNTLSDict(q, host);
    if (tls == nil) tls = [@{@"enabled": @YES, @"server_name": host} mutableCopy];
    ob[@"tls"] = tls;

    NSString *transportError = nil;
    NSDictionary *transport = HVPNTransportDict(q, &transportError);
    if (transportError) {
        if (error) *error = HVPNErr(@"trojan: %@", transportError);
        return nil;
    }
    if (transport) ob[@"transport"] = transport;

    HVPNProxy *p = [HVPNProxy new];
    p.name = HVPNNodeName(fragment, host, port);
    p.type = @"trojan";
    p.server = host;
    p.port = port;
    p.outbound = ob;
    return p;
}

// MARK: - shadowsocks

+ (HVPNProxy *)parseShadowsocks:(NSString *)link error:(NSError **)error {
    NSString *rest = [link substringFromIndex:@"ss://".length];
    NSString *fragment = nil;
    NSRange hash = [rest rangeOfString:@"#"];
    if (hash.location != NSNotFound) {
        fragment = HVPNPercent([rest substringFromIndex:hash.location + 1]);
        rest = [rest substringToIndex:hash.location];
    }
    NSDictionary *q = @{};
    NSRange qm = [rest rangeOfString:@"?"];
    if (qm.location != NSNotFound) {
        q = HVPNQuery([rest substringFromIndex:qm.location + 1]);
        rest = [rest substringToIndex:qm.location];
    }

    NSString *method = nil, *password = nil;
    NSString *hostPort = nil;

    NSRange at = [rest rangeOfString:@"@" options:NSBackwardsSearch];
    if (at.location != NSNotFound) {
        NSString *userinfo = [rest substringToIndex:at.location];
        NSString *decoded = HVPNB64String(userinfo) ?: HVPNPercent(userinfo);
        NSRange colon = [decoded rangeOfString:@":"];
        if (colon.location == NSNotFound) {
            if (error) *error = HVPNErr(@"ss: нет method:password");
            return nil;
        }
        method = [decoded substringToIndex:colon.location];
        password = [decoded substringFromIndex:colon.location + 1];
        hostPort = [rest substringFromIndex:at.location + 1];
    } else {
        NSString *decoded = HVPNB64String(rest);
        if (decoded.length == 0) {
            if (error) *error = HVPNErr(@"ss: битая base64-часть");
            return nil;
        }
        NSRange innerAt = [decoded rangeOfString:@"@" options:NSBackwardsSearch];
        if (innerAt.location == NSNotFound) {
            if (error) *error = HVPNErr(@"ss: нет @host:port");
            return nil;
        }
        NSString *cred = [decoded substringToIndex:innerAt.location];
        NSRange colon = [cred rangeOfString:@":"];
        if (colon.location == NSNotFound) {
            if (error) *error = HVPNErr(@"ss: нет method:password");
            return nil;
        }
        method = [cred substringToIndex:colon.location];
        password = [cred substringFromIndex:colon.location + 1];
        hostPort = [decoded substringFromIndex:innerAt.location + 1];
    }

    NSString *host = nil;
    NSInteger port = 0;
    NSString *synthetic = [@"ss://" stringByAppendingString:hostPort];
    if (!HVPNSplitURI(synthetic, NULL, NULL, &host, &port, NULL, NULL, NULL) || host.length == 0) {
        if (error) *error = HVPNErr(@"ss: не разобрать host:port");
        return nil;
    }
    if (port <= 0) port = 8388;

    NSMutableDictionary *ob = [@{
        @"type": @"shadowsocks",
        @"server": host,
        @"server_port": @(port),
        @"method": method,
        @"password": password ?: @""
    } mutableCopy];

    NSString *plugin = q[@"plugin"];
    if (plugin.length) {
        NSRange semi = [plugin rangeOfString:@";"];
        NSString *pluginName = semi.location == NSNotFound ? plugin : [plugin substringToIndex:semi.location];
        NSString *pluginOpts = semi.location == NSNotFound ? nil : [plugin substringFromIndex:semi.location + 1];
        if ([pluginName isEqualToString:@"obfs-local"] || [pluginName isEqualToString:@"simple-obfs"]) {
            ob[@"plugin"] = @"obfs-local";
            if (pluginOpts.length) ob[@"plugin_opts"] = pluginOpts;
        } else if ([pluginName isEqualToString:@"v2ray-plugin"]) {
            ob[@"plugin"] = @"v2ray-plugin";
            if (pluginOpts.length) ob[@"plugin_opts"] = pluginOpts;
        } else {
            if (error) *error = HVPNErr(@"ss: плагин '%@' не поддерживается", pluginName);
            return nil;
        }
    }

    HVPNProxy *p = [HVPNProxy new];
    p.name = HVPNNodeName(fragment, host, port);
    p.type = @"shadowsocks";
    p.server = host;
    p.port = port;
    p.outbound = ob;
    return p;
}

// MARK: - hysteria2

+ (HVPNProxy *)parseHysteria2:(NSString *)link error:(NSError **)error {
    NSString *scheme = nil, *userinfo = nil, *host = nil, *path = nil, *fragment = nil;
    NSDictionary<NSString *, NSString *> *q = nil;
    NSInteger port = 0;
    if (!HVPNSplitURI(link, &scheme, &userinfo, &host, &port, &path, &q, &fragment)) {
        if (error) *error = HVPNErr(@"hysteria2: не разобрать ссылку");
        return nil;
    }
    if (port <= 0) port = 443;

    NSMutableDictionary *ob = [@{
        @"type": @"hysteria2",
        @"server": host,
        @"server_port": @(port),
        @"password": userinfo ?: @""
    } mutableCopy];

    NSMutableDictionary *tls = [@{
        @"enabled": @YES,
        @"server_name": q[@"sni"].length ? q[@"sni"] : host,
        @"alpn": @[@"h3"]
    } mutableCopy];
    if (HVPNBool(q[@"insecure"]) || HVPNBool(q[@"allowInsecure"])) tls[@"insecure"] = @YES;
    ob[@"tls"] = tls;

    if ([q[@"obfs"].lowercaseString isEqualToString:@"salamander"]) {
        NSString *obfsPassword = q[@"obfs-password"] ?: q[@"obfs_password"];
        if (obfsPassword.length == 0) {
            if (error) *error = HVPNErr(@"hysteria2: obfs=salamander без пароля");
            return nil;
        }
        ob[@"obfs"] = @{@"type": @"salamander", @"password": obfsPassword};
    }

    NSString *up = q[@"upmbps"] ?: q[@"up"];
    NSString *down = q[@"downmbps"] ?: q[@"down"];
    if (up.integerValue > 0) ob[@"up_mbps"] = @(up.integerValue);
    if (down.integerValue > 0) ob[@"down_mbps"] = @(down.integerValue);

    HVPNProxy *p = [HVPNProxy new];
    p.name = HVPNNodeName(fragment, host, port);
    p.type = @"hysteria2";
    p.server = host;
    p.port = port;
    p.outbound = ob;
    return p;
}

// MARK: - tuic

+ (HVPNProxy *)parseTUIC:(NSString *)link error:(NSError **)error {
    NSString *scheme = nil, *userinfo = nil, *host = nil, *path = nil, *fragment = nil;
    NSDictionary<NSString *, NSString *> *q = nil;
    NSInteger port = 0;
    if (!HVPNSplitURI(link, &scheme, &userinfo, &host, &port, &path, &q, &fragment)) {
        if (error) *error = HVPNErr(@"tuic: не разобрать ссылку");
        return nil;
    }
    if (q[@"token"].length) {
        if (error) *error = HVPNErr(@"tuic: v4 (token) не поддерживается, нужен v5 (uuid:password)");
        return nil;
    }
    NSRange colon = [userinfo rangeOfString:@":"];
    if (colon.location == NSNotFound) {
        if (error) *error = HVPNErr(@"tuic: нужен uuid:password");
        return nil;
    }
    NSString *uuid = [userinfo substringToIndex:colon.location];
    NSString *password = [userinfo substringFromIndex:colon.location + 1];
    if (port <= 0) port = 443;

    NSMutableDictionary *ob = [@{
        @"type": @"tuic",
        @"server": host,
        @"server_port": @(port),
        @"uuid": uuid,
        @"password": password
    } mutableCopy];

    NSMutableDictionary *tls = [@{
        @"enabled": @YES,
        @"server_name": q[@"sni"].length ? q[@"sni"] : host
    } mutableCopy];
    NSString *alpn = q[@"alpn"];
    tls[@"alpn"] = alpn.length ? [alpn componentsSeparatedByString:@","] : @[@"h3"];
    if (HVPNBool(q[@"allow_insecure"]) || HVPNBool(q[@"insecure"])) tls[@"insecure"] = @YES;
    ob[@"tls"] = tls;

    NSString *cc = q[@"congestion_control"] ?: q[@"congestion"];
    ob[@"congestion_control"] = cc.length ? cc : @"bbr";
    NSString *udpMode = q[@"udp_relay_mode"];
    ob[@"udp_relay_mode"] = udpMode.length ? udpMode : @"native";

    HVPNProxy *p = [HVPNProxy new];
    p.name = HVPNNodeName(fragment, host, port);
    p.type = @"tuic";
    p.server = host;
    p.port = port;
    p.outbound = ob;
    return p;
}

// MARK: - dispatch

+ (HVPNProxy *)proxyFromLink:(NSString *)link error:(NSError **)error {
    NSString *s = [link stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
    if (s.length == 0) {
        if (error) *error = HVPNErr(@"пустая ссылка");
        return nil;
    }
    NSString *lower = s.lowercaseString;
    if ([lower hasPrefix:@"vless://"]) return [self parseVless:s error:error];
    if ([lower hasPrefix:@"vmess://"]) return [self parseVmess:s error:error];
    if ([lower hasPrefix:@"trojan://"]) return [self parseTrojan:s error:error];
    if ([lower hasPrefix:@"ss://"]) return [self parseShadowsocks:s error:error];
    if ([lower hasPrefix:@"hysteria2://"] || [lower hasPrefix:@"hy2://"]) return [self parseHysteria2:s error:error];
    if ([lower hasPrefix:@"tuic://"]) return [self parseTUIC:s error:error];
    if ([lower hasPrefix:@"happ://"]) {
        if (error) {
            *error = HVPNErr(@"happ:// ссылки зашифрованы приложением Happ и не читаются снаружи. "
                             @"Скопируйте из Happ обычную ссылку на ноду (vless://, vmess://, trojan://, ss://, "
                             @"hysteria2://) или https-подписку.");
        }
        return nil;
    }
    if (error) {
        NSString *scheme = [s componentsSeparatedByString:@"://"].firstObject ?: s;
        *error = HVPNErr(@"протокол '%@' не поддерживается", scheme);
    }
    return nil;
}

+ (BOOL)looksLikeLink:(NSString *)line {
    NSString *lower = line.lowercaseString;
    return [lower hasPrefix:@"vless://"] || [lower hasPrefix:@"vmess://"] ||
           [lower hasPrefix:@"trojan://"] || [lower hasPrefix:@"ss://"] ||
           [lower hasPrefix:@"hysteria2://"] || [lower hasPrefix:@"hy2://"] ||
           [lower hasPrefix:@"tuic://"] || [lower hasPrefix:@"happ://"];
}

+ (NSArray<NSString *> *)linksFromSubscriptionData:(NSData *)data {
    if (data.length == 0) return @[];
    NSString *text = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    if (text == nil) text = [[NSString alloc] initWithData:data encoding:NSISOLatin1StringEncoding];
    if (text.length == 0) return @[];

    NSString *trimmed = [text stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
    if ([trimmed rangeOfString:@"://"].location == NSNotFound) {
        NSString *decoded = HVPNB64String(trimmed);
        if (decoded.length) text = decoded;
    }

    NSMutableArray *out = [NSMutableArray array];
    for (NSString *raw in [text componentsSeparatedByCharactersInSet:[NSCharacterSet newlineCharacterSet]]) {
        NSString *line = [raw stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
        if (line.length == 0 || [line hasPrefix:@"#"] || [line hasPrefix:@"//"]) continue;
        if ([self looksLikeLink:line]) [out addObject:line];
    }
    return out;
}

@end

