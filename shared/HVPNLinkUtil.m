#import "HVPNLinkUtil.h"

NSString *HVPNPercent(NSString *s) {
    if (s == nil) return @"";
    NSString *r = [s stringByRemovingPercentEncoding];
    return r ?: s;
}

NSData *HVPNB64Data(NSString *s) {
    if (s.length == 0) return nil;
    NSString *t = [s stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
    NSMutableString *m = [t mutableCopy];
    [m replaceOccurrencesOfString:@"-" withString:@"+" options:0 range:NSMakeRange(0, m.length)];
    [m replaceOccurrencesOfString:@"_" withString:@"/" options:0 range:NSMakeRange(0, m.length)];
    NSUInteger rem = m.length % 4;
    if (rem == 1) return nil;
    if (rem != 0) [m appendString:[@"====" substringToIndex:(4 - rem)]];
    return [[NSData alloc] initWithBase64EncodedString:m options:0];
}

NSString *HVPNB64String(NSString *s) {
    NSData *d = HVPNB64Data(s);
    if (d == nil) return nil;
    return [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding];
}

NSDictionary<NSString *, NSString *> *HVPNQuery(NSString *query) {
    NSMutableDictionary *out = [NSMutableDictionary dictionary];
    if (query.length == 0) return out;
    for (NSString *pair in [query componentsSeparatedByString:@"&"]) {
        if (pair.length == 0) continue;
        NSRange eq = [pair rangeOfString:@"="];
        NSString *k = (eq.location == NSNotFound) ? pair : [pair substringToIndex:eq.location];
        NSString *v = (eq.location == NSNotFound) ? @"" : [pair substringFromIndex:eq.location + 1];
        k = HVPNPercent(k);
        v = HVPNPercent(v);
        if (k.length) out[k] = v;
    }
    return out;
}

BOOL HVPNBool(NSString *v) {
    if (v == nil) return NO;
    NSString *s = v.lowercaseString;
    return [s isEqualToString:@"1"] || [s isEqualToString:@"true"] ||
           [s isEqualToString:@"yes"] || [s isEqualToString:@"on"];
}

BOOL HVPNSplitURI(NSString *link,
                  NSString **schemeOut, NSString **userinfoOut, NSString **hostOut,
                  NSInteger *portOut, NSString **pathOut,
                  NSDictionary<NSString *, NSString *> **queryOut, NSString **fragmentOut) {
    NSRange sep = [link rangeOfString:@"://"];
    if (sep.location == NSNotFound) return NO;
    NSString *scheme = [[link substringToIndex:sep.location] lowercaseString];

    NSString *rest = [link substringFromIndex:NSMaxRange(sep)];
    NSString *fragment = nil;
    NSRange hash = [rest rangeOfString:@"#"];
    if (hash.location != NSNotFound) {
        fragment = HVPNPercent([rest substringFromIndex:hash.location + 1]);
        rest = [rest substringToIndex:hash.location];
    }
    NSDictionary *query = @{};
    NSRange qm = [rest rangeOfString:@"?"];
    if (qm.location != NSNotFound) {
        query = HVPNQuery([rest substringFromIndex:qm.location + 1]);
        rest = [rest substringToIndex:qm.location];
    }
    NSString *userinfo = nil;
    NSRange at = [rest rangeOfString:@"@" options:NSBackwardsSearch];
    if (at.location != NSNotFound) {
        userinfo = HVPNPercent([rest substringToIndex:at.location]);
        rest = [rest substringFromIndex:at.location + 1];
    }
    NSString *path = nil;
    NSRange slash = [rest rangeOfString:@"/"];
    if (slash.location != NSNotFound) {
        path = [rest substringFromIndex:slash.location];
        rest = [rest substringToIndex:slash.location];
    }
    NSString *host = rest;
    NSInteger port = 0;
    if ([host hasPrefix:@"["]) {
        NSRange close = [host rangeOfString:@"]"];
        if (close.location != NSNotFound) {
            NSString *tail = [host substringFromIndex:NSMaxRange(close)];
            if ([tail hasPrefix:@":"]) port = [tail substringFromIndex:1].integerValue;
            host = [host substringWithRange:NSMakeRange(1, close.location - 1)];
        }
    } else {
        NSRange colon = [host rangeOfString:@":" options:NSBackwardsSearch];
        if (colon.location != NSNotFound) {
            port = [host substringFromIndex:colon.location + 1].integerValue;
            host = [host substringToIndex:colon.location];
        }
    }
    if (host.length == 0) return NO;

    if (schemeOut) *schemeOut = scheme;
    if (userinfoOut) *userinfoOut = userinfo;
    if (hostOut) *hostOut = host;
    if (portOut) *portOut = port;
    if (pathOut) *pathOut = path;
    if (queryOut) *queryOut = query;
    if (fragmentOut) *fragmentOut = fragment;
    return YES;
}

static NSString *HVPNFirst(NSDictionary *q, NSArray<NSString *> *keys) {
    for (NSString *k in keys) {
        NSString *v = q[k];
        if (v.length) return v;
    }
    return nil;
}

// sing-box ждёт base64url без паддинга; панели иногда отдают обычный base64,
// а `+` в query легко превращается в пробел. Иначе ключ REALITY «не тот».
static NSString *HVPNNormalizeKey(NSString *key) {
    if (key.length == 0) return @"";
    NSMutableString *s = [key mutableCopy];
    NSRange all = NSMakeRange(0, s.length);
    [s replaceOccurrencesOfString:@" " withString:@"+" options:0 range:all];
    all = NSMakeRange(0, s.length);
    [s replaceOccurrencesOfString:@"+" withString:@"-" options:0 range:all];
    all = NSMakeRange(0, s.length);
    [s replaceOccurrencesOfString:@"/" withString:@"_" options:0 range:all];
    while ([s hasSuffix:@"="]) [s deleteCharactersInRange:NSMakeRange(s.length - 1, 1)];
    return s;
}

NSMutableDictionary *HVPNTLSDict(NSDictionary<NSString *, NSString *> *q, NSString *fallbackSNI) {
    NSString *security = q[@"security"].lowercaseString;
    BOOL tlsOn = [security isEqualToString:@"tls"] || [security isEqualToString:@"reality"] ||
                 [security isEqualToString:@"xtls"] || HVPNBool(q[@"tls"]);
    if (!tlsOn) return nil;

    NSMutableDictionary *tls = [NSMutableDictionary dictionary];
    tls[@"enabled"] = @YES;

    NSString *sni = HVPNFirst(q, @[@"sni", @"peer", @"serverName", @"servername"]);
    if (sni.length == 0 && fallbackSNI.length) sni = fallbackSNI;
    if (sni.length) tls[@"server_name"] = sni;

    if (HVPNBool(q[@"allowInsecure"]) || HVPNBool(q[@"allow_insecure"]) ||
        HVPNBool(q[@"insecure"]) || HVPNBool(q[@"skip-cert-verify"])) {
        tls[@"insecure"] = @YES;
    }

    NSString *alpn = HVPNFirst(q, @[@"alpn"]);
    if (alpn.length) {
        NSMutableArray *list = [NSMutableArray array];
        for (NSString *a in [alpn componentsSeparatedByString:@","]) {
            NSString *t = [a stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
            if (t.length) [list addObject:t];
        }
        if (list.count) tls[@"alpn"] = list;
    }

    NSString *fp = HVPNFirst(q, @[@"fp", @"fingerprint"]);
    if (fp.length) tls[@"utls"] = @{@"enabled": @YES, @"fingerprint": fp};

    if ([security isEqualToString:@"reality"] || q[@"pbk"].length || q[@"publicKey"].length) {
        NSMutableDictionary *reality = [NSMutableDictionary dictionary];
        reality[@"enabled"] = @YES;
        reality[@"public_key"] = HVPNNormalizeKey(q[@"pbk"] ?: q[@"publicKey"] ?: @"");
        if (q[@"sid"].length) reality[@"short_id"] = q[@"sid"];
        tls[@"reality"] = reality;

        // REALITY без uTLS не проходит проверку сервера: подменять отпечаток
        // ClientHello обязательно. Если панель не дала fp — берём chrome.
        NSMutableDictionary *utls = [tls[@"utls"] mutableCopy] ?: [NSMutableDictionary dictionary];
        utls[@"enabled"] = @YES;
        if (![utls[@"fingerprint"] isKindOfClass:[NSString class]] ||
            [utls[@"fingerprint"] length] == 0) {
            utls[@"fingerprint"] = @"chrome";
        }
        tls[@"utls"] = utls;
    }
    return tls;
}

NSDictionary *HVPNTransportDict(NSDictionary<NSString *, NSString *> *q, NSString **errMsg) {
    NSString *net = HVPNFirst(q, @[@"type", @"net", @"network"]).lowercaseString;
    if (net.length == 0 || [net isEqualToString:@"tcp"] || [net isEqualToString:@"raw"]) return nil;

    NSString *host = HVPNFirst(q, @[@"host"]);
    NSString *path = HVPNFirst(q, @[@"path"]);

    if ([net isEqualToString:@"ws"]) {
        NSMutableDictionary *t = [@{@"type": @"ws"} mutableCopy];
        t[@"path"] = path.length ? path : @"/";
        if (host.length) t[@"headers"] = @{@"Host": host};
        NSString *ed = HVPNFirst(q, @[@"ed", @"maxEarlyData"]);
        if (ed.length && ed.integerValue > 0) {
            t[@"max_early_data"] = @(ed.integerValue);
            t[@"early_data_header_name"] = @"Sec-WebSocket-Protocol";
        }
        return t;
    }
    if ([net isEqualToString:@"grpc"]) {
        NSMutableDictionary *t = [@{@"type": @"grpc"} mutableCopy];
        NSString *sn = HVPNFirst(q, @[@"serviceName", @"service_name", @"path"]);
        t[@"service_name"] = sn.length ? sn : @"";
        if (host.length) t[@"headers"] = @{@"Host": host};
        return t;
    }
    if ([net isEqualToString:@"http"] || [net isEqualToString:@"h2"] || [net isEqualToString:@"h2c"]) {
        NSMutableDictionary *t = [@{@"type": @"http"} mutableCopy];
        if (host.length) t[@"host"] = [host componentsSeparatedByString:@","];
        t[@"path"] = path.length ? path : @"/";
        return t;
    }
    if ([net isEqualToString:@"xhttp"] || [net isEqualToString:@"splithttp"]) {
        // XHTTP (бывший splithttp): так сейчас отдаёт ноды большинство панелей,
        // включая Happ-подписки. Поддерживается ядром sing-box-lx (тег with_xhttp).
        NSMutableDictionary *t = [@{@"type": @"xhttp"} mutableCopy];
        t[@"path"] = path.length ? path : @"/";
        NSString *mode = HVPNFirst(q, @[@"mode"]);
        t[@"mode"] = mode.length ? mode : @"auto";
        if (host.length) t[@"host"] = host;
        return t;
    }
    if ([net isEqualToString:@"httpupgrade"]) {
        NSMutableDictionary *t = [@{@"type": @"httpupgrade"} mutableCopy];
        t[@"path"] = path.length ? path : @"/";
        if (host.length) t[@"host"] = host;
        return t;
    }
    if (errMsg) {
        *errMsg = [NSString stringWithFormat:@"транспорт '%@' не поддерживается ядром", net];
    }
    return nil;
}
