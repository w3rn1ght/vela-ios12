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

/// Полное percent-кодирование значения query (безопасно для base64 и пробелов).
static NSString *HVPNEnc(NSString *value) {
    if (value.length == 0) return @"";
    NSCharacterSet *allowed = [NSCharacterSet characterSetWithCharactersInString:
        @"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"];
    return [value stringByAddingPercentEncodingWithAllowedCharacters:allowed] ?: value;
}

static NSString *HVPNNodeName(NSString *fragment, NSString *host, NSInteger port) {
    if (fragment.length) {
        // Панели любят дописывать к имени параметры: "🇷🇺 Россия №50?serverDescription=...".
        NSRange q = [fragment rangeOfString:@"?"];
        NSString *name = (q.location == NSNotFound) ? fragment : [fragment substringToIndex:q.location];
        name = [name stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
        if (name.length) return name;
    }
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

+ (BOOL)isPlaceholderLink:(NSString *)link {
    NSError *error = nil;
    HVPNProxy *proxy = [self proxyFromLink:link error:&error];
    if (proxy == nil) return NO;   // не заглушка, а просто неподдерживаемая ссылка
    if (proxy.port <= 1) return YES;
    NSString *host = proxy.server.lowercaseString;
    return [host isEqualToString:@"0.0.0.0"] || [host isEqualToString:@"::"] ||
           [host isEqualToString:@"127.0.0.1"] || [host isEqualToString:@"localhost"];
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

+ (NSArray<NSString *> *)linksFromXrayConfigData:(NSData *)data {
    if (data.length == 0) return @[];
    id object = [NSJSONSerialization JSONObjectWithData:data options:0 error:NULL];
    if (![object isKindOfClass:[NSDictionary class]]) return @[];
    NSArray *outbounds = ((NSDictionary *)object)[@"outbounds"];
    if (![outbounds isKindOfClass:[NSArray class]]) return @[];

    NSMutableArray<NSString *> *links = [NSMutableArray array];
    for (NSDictionary *outbound in outbounds) {
        if (![outbound isKindOfClass:[NSDictionary class]]) continue;
        NSString *protocol = HVPNStr(outbound[@"protocol"]).lowercaseString;
        NSDictionary *settings = outbound[@"settings"];
        NSDictionary *stream = outbound[@"streamSettings"];
        NSString *tag = HVPNStr(outbound[@"tag"]) ?: @"node";
        if (![settings isKindOfClass:[NSDictionary class]]) continue;

        NSString *network = HVPNStr(stream[@"network"]) ?: @"tcp";
        NSString *security = HVPNStr(stream[@"security"]) ?: @"none";
        NSDictionary *tls = [security isEqualToString:@"reality"]
            ? stream[@"realitySettings"] : stream[@"tlsSettings"];
        if (![tls isKindOfClass:[NSDictionary class]]) tls = nil;

        NSMutableArray<NSString *> *query = [NSMutableArray array];
        if (![network isEqualToString:@"tcp"]) {
            [query addObject:[@"type=" stringByAppendingString:HVPNEnc(network)]];
        }
        if (![security isEqualToString:@"none"]) {
            [query addObject:[@"security=" stringByAppendingString:HVPNEnc(security)]];
        }
        if (HVPNStr(tls[@"serverName"]).length)
            [query addObject:[@"sni=" stringByAppendingString:HVPNEnc(HVPNStr(tls[@"serverName"]))]];
        if (HVPNStr(tls[@"fingerprint"]).length)
            [query addObject:[@"fp=" stringByAppendingString:HVPNEnc(HVPNStr(tls[@"fingerprint"]))]];
        if (HVPNStr(tls[@"publicKey"]).length)
            [query addObject:[@"pbk=" stringByAppendingString:HVPNEnc(HVPNStr(tls[@"publicKey"]))]];
        if (HVPNStr(tls[@"shortId"]).length)
            [query addObject:[@"sid=" stringByAppendingString:HVPNEnc(HVPNStr(tls[@"shortId"]))]];
        NSArray *alpn = tls[@"alpn"];
        if ([alpn isKindOfClass:[NSArray class]] && alpn.count) {
            NSMutableArray *parts = [NSMutableArray array];
            for (id item in alpn) if ([item isKindOfClass:[NSString class]]) [parts addObject:item];
            if (parts.count) [query addObject:[@"alpn=" stringByAppendingString:
                                           HVPNEnc([parts componentsJoinedByString:@","])]];
        }

        if ([network isEqualToString:@"ws"]) {
            NSDictionary *ws = stream[@"wsSettings"];
            NSString *path = HVPNStr(ws[@"path"]);
            NSString *host = HVPNStr(ws[@"headers"][@"Host"]) ?: HVPNStr(ws[@"host"]);
            if (path.length) [query addObject:[@"path=" stringByAppendingString:HVPNEnc(path)]];
            if (host.length) [query addObject:[@"host=" stringByAppendingString:HVPNEnc(host)]];
        } else if ([network isEqualToString:@"grpc"]) {
            NSDictionary *grpc = stream[@"grpcSettings"];
            NSString *service = HVPNStr(grpc[@"serviceName"]);
            if (service.length) [query addObject:[@"serviceName=" stringByAppendingString:HVPNEnc(service)]];
        } else if ([network isEqualToString:@"xhttp"]) {
            NSDictionary *xhttp = stream[@"xhttpSettings"];
            NSString *path = HVPNStr(xhttp[@"path"]);
            NSString *mode = HVPNStr(xhttp[@"mode"]);
            if (path.length) [query addObject:[@"path=" stringByAppendingString:HVPNEnc(path)]];
            if (mode.length) [query addObject:[@"mode=" stringByAppendingString:HVPNEnc(mode)]];
        } else if ([network isEqualToString:@"tcp"]) {
            NSDictionary *tcp = stream[@"tcpSettings"];
            NSString *headerType = HVPNStr(tcp[@"header"][@"type"]);
            if (headerType.length && ![headerType isEqualToString:@"none"]) {
                [query addObject:[@"headerType=" stringByAppendingString:HVPNEnc(headerType)]];
                NSString *host = HVPNStr(tcp[@"header"][@"request"][@"headers"][@"Host"][0]);
                NSString *path = HVPNStr(tcp[@"header"][@"request"][@"path"][0]);
                if (host.length) [query addObject:[@"host=" stringByAppendingString:HVPNEnc(host)]];
                if (path.length) [query addObject:[@"path=" stringByAppendingString:HVPNEnc(path)]];
            }
        }

        NSString *hostText = nil, *userinfo = nil;
        NSInteger port = 0;

        if ([protocol isEqualToString:@"vless"]) {
            NSDictionary *server = [settings[@"vnext"] firstObject];
            NSDictionary *user = [server[@"users"] firstObject];
            hostText = HVPNStr(server[@"address"]);
            port = HVPNStr(server[@"port"]).integerValue;
            userinfo = HVPNStr(user[@"id"]);
            NSString *flow = HVPNStr(user[@"flow"]);
            if (flow.length) [query addObject:[@"flow=" stringByAppendingString:HVPNEnc(flow)]];
            [query addObject:@"encryption=none"];
        } else if ([protocol isEqualToString:@"vmess"]) {
            NSDictionary *server = [settings[@"vnext"] firstObject];
            NSDictionary *user = [server[@"users"] firstObject];
            hostText = HVPNStr(server[@"address"]);
            port = HVPNStr(server[@"port"]).integerValue;
            NSDictionary *ws = stream[@"wsSettings"];
            NSMutableDictionary *vmess = [@{
                @"v": @"2",
                @"ps": tag,
                @"add": hostText ?: @"",
                @"port": [@(port) stringValue],
                @"id": HVPNStr(user[@"id"]) ?: @"",
                @"aid": [@(HVPNStr(user[@"alterId"]).integerValue) stringValue],
                @"scy": @"auto",
                @"net": network,
                @"type": @"none",
                @"host": HVPNStr(ws[@"headers"][@"Host"]) ?: @"",
                @"path": HVPNStr(ws[@"path"]) ?: @"",
                @"tls": [security isEqualToString:@"tls"] ? @"tls" : @"",
                @"sni": HVPNStr(tls[@"serverName"]) ?: @""
            } mutableCopy];
            NSData *json = [NSJSONSerialization dataWithJSONObject:vmess options:0 error:NULL];
            if (json) {
                [links addObject:[@"vmess://" stringByAppendingString:
                                  [json base64EncodedStringWithOptions:0]]];
            }
            continue;
        } else if ([protocol isEqualToString:@"trojan"]) {
            NSDictionary *server = [settings[@"servers"] firstObject];
            hostText = HVPNStr(server[@"address"]);
            port = HVPNStr(server[@"port"]).integerValue;
            userinfo = HVPNStr(server[@"password"]);
            if (![security isEqualToString:@"none"])
                [query addObject:[@"security=" stringByAppendingString:HVPNEnc(security)]];
            else
                [query addObject:@"security=tls"];
        } else if ([protocol isEqualToString:@"shadowsocks"]) {
            NSDictionary *server = [settings[@"servers"] firstObject];
            hostText = HVPNStr(server[@"address"]);
            port = HVPNStr(server[@"port"]).integerValue;
            NSString *method = HVPNStr(server[@"method"]) ?: @"";
            NSString *password = HVPNStr(server[@"password"]) ?: @"";
            NSData *credentialData = [[NSString stringWithFormat:@"%@:%@", method, password]
                                      dataUsingEncoding:NSUTF8StringEncoding];
            NSString *credentials = [credentialData base64EncodedStringWithOptions:0];
            NSString *hostPart = [hostText rangeOfString:@":"].location != NSNotFound
                ? [NSString stringWithFormat:@"[%@]", hostText] : hostText;
            [links addObject:[NSString stringWithFormat:@"ss://%@@%@:%ld#%@",
                              [credentials stringByReplacingOccurrencesOfString:@"=" withString:@""],
                              hostPart, (long)port, HVPNEnc(tag)]];
            continue;
        } else {
            continue;   // freedom / blackhole / loopback / dns
        }

        if (hostText.length == 0 || userinfo.length == 0 || port <= 0) continue;
        NSString *hostPart = [hostText rangeOfString:@":"].location != NSNotFound
            ? [NSString stringWithFormat:@"[%@]", hostText] : hostText;
        NSString *link = [NSString stringWithFormat:@"%@://%@@%@:%ld?%@#%@",
                          protocol, HVPNEnc(userinfo), hostPart, (long)port,
                          [query componentsJoinedByString:@"&"], HVPNEnc(tag)];
        [links addObject:link];
    }
    return links;
}

@end

