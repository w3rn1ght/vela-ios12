// Офлайн-проверка парсера: собирается и запускается на macOS, устройство не нужно.
//   ./scripts/run-parser-tests.sh
#import <Foundation/Foundation.h>

#import "HVPNConfig.h"
#import "HVPNLinkParser.h"

static int gFailures = 0;

static void expect(BOOL condition, NSString *what) {
    if (condition) {
        printf("  ok   %s\n", what.UTF8String);
    } else {
        printf("  FAIL %s\n", what.UTF8String);
        gFailures++;
    }
}

static HVPNProxy *parse(NSString *link) {
    NSError *error = nil;
    HVPNProxy *proxy = [HVPNLinkParser proxyFromLink:link error:&error];
    if (proxy == nil) {
        printf("  FAIL parse: %s\n", error.localizedDescription.UTF8String);
        gFailures++;
    }
    return proxy;
}

int main(void) {
    @autoreleasepool {
        printf("vless + reality\n");
        HVPNProxy *vless = parse(@"vless://11111111-2222-3333-4444-555555555555@example.com:443"
                                 @"?security=reality&sni=www.microsoft.com&fp=chrome"
                                 @"&pbk=abcdefghijklmnopqrstuvwxyz0123456789ABCDEF"
                                 @"&sid=ab12&type=tcp&flow=xtls-rprx-vision#Москва");
        expect(vless != nil, @"parsed");
        expect([vless.name isEqualToString:@"Москва"], @"name from fragment");
        expect([vless.outbound[@"type"] isEqualToString:@"vless"], @"type vless");
        expect([vless.outbound[@"flow"] isEqualToString:@"xtls-rprx-vision"], @"flow");
        NSDictionary *tls = vless.outbound[@"tls"];
        expect([tls[@"server_name"] isEqualToString:@"www.microsoft.com"], @"sni");
        expect([tls[@"reality"][@"short_id"] isEqualToString:@"ab12"], @"reality short_id");
        expect([tls[@"utls"][@"enabled"] boolValue], @"reality forces utls");
        expect([tls[@"utls"][@"fingerprint"] isEqualToString:@"chrome"], @"utls fingerprint present");

        printf("reality without fp and with base64 key\n");
        HVPNProxy *noFP = parse(@"vless://11111111-2222-3333-4444-555555555555@reality.example.com:443"
                                @"?security=reality&sni=www.microsoft.com"
                                @"&pbk=ab%2Bcd/ef%3D%3D&sid=ab12&type=tcp#no-fp");
        expect(noFP != nil, @"parsed without fp");
        NSDictionary *noFPtls = noFP.outbound[@"tls"];
        expect([noFPtls[@"utls"][@"fingerprint"] isEqualToString:@"chrome"], @"default utls chrome");
        expect([noFPtls[@"reality"][@"public_key"] isEqualToString:@"ab-cd_ef"], @"pbk normalized to base64url");

        printf("vless + ws\n");
        HVPNProxy *ws = parse(@"vless://11111111-2222-3333-4444-555555555555@[2001:db8::1]:8443"
                              @"?type=ws&path=%2Fws&host=cdn.example.org&security=tls#ws-node");
        expect([[ws.outbound[@"server"] description] isEqualToString:@"2001:db8::1"], @"ipv6 host without brackets");
        NSDictionary *transport = ws.outbound[@"transport"];
        expect([transport[@"type"] isEqualToString:@"ws"], @"transport ws");
        expect([transport[@"path"] isEqualToString:@"/ws"], @"ws path decoded");
        expect([transport[@"headers"][@"Host"] isEqualToString:@"cdn.example.org"], @"ws Host header");

        printf("vmess\n");
        NSDictionary *vmessJSON = @{
            @"v": @"2", @"ps": @"vm-node", @"add": @"vm.example.net", @"port": @"443",
            @"id": @"11111111-2222-3333-4444-555555555555", @"aid": @"0", @"scy": @"auto",
            @"net": @"ws", @"type": @"none", @"host": @"vm.example.net", @"path": @"/ray",
            @"tls": @"tls", @"sni": @"vm.example.net"
        };
        NSData *jsonData = [NSJSONSerialization dataWithJSONObject:vmessJSON options:0 error:NULL];
        NSString *b64 = [jsonData base64EncodedStringWithOptions:0];
        HVPNProxy *vmess = parse([@"vmess://" stringByAppendingString:b64]);
        expect(vmess != nil, @"parsed");
        expect([vmess.name isEqualToString:@"vm-node"], @"name from ps");
        expect([vmess.outbound[@"alter_id"] intValue] == 0, @"alter_id");
        expect([vmess.outbound[@"tls"][@"enabled"] boolValue], @"tls enabled");

        printf("trojan\n");
        HVPNProxy *trojan = parse(@"trojan://secret-pass@tr.example.com:443?sni=tr.example.com&type=grpc&serviceName=GunService#tr");
        expect([trojan.outbound[@"password"] isEqualToString:@"secret-pass"], @"password");
        expect([trojan.outbound[@"transport"][@"service_name"] isEqualToString:@"GunService"], @"grpc service");

        printf("shadowsocks (sip002)\n");
        NSData *credData = [@"aes-256-gcm:pass word" dataUsingEncoding:NSUTF8StringEncoding];
        NSString *credentials = [credData base64EncodedStringWithOptions:0];
        HVPNProxy *ss = parse([NSString stringWithFormat:@"ss://%@@ss.example.com:8388#ss-node", credentials]);
        expect([ss.outbound[@"method"] isEqualToString:@"aes-256-gcm"], @"method");
        expect([ss.outbound[@"password"] isEqualToString:@"pass word"], @"password with space");

        printf("shadowsocks (legacy, whole body base64)\n");
        NSData *legacyData = [@"chacha20-ietf-poly1305:pw@ss2.example.com:8389"
            dataUsingEncoding:NSUTF8StringEncoding];
        NSString *legacy = [legacyData base64EncodedStringWithOptions:0];
        HVPNProxy *ss2 = parse([@"ss://" stringByAppendingString:legacy]);
        expect([ss2.outbound[@"server"] isEqualToString:@"ss2.example.com"], @"legacy host");
        expect(ss2.port == 8389, @"legacy port");

        printf("hysteria2\n");
        HVPNProxy *hy = parse(@"hysteria2://mypass@hy.example.com:443?sni=hy.example.com"
                              @"&insecure=1&obfs=salamander&obfs-password=obfspass#hy-node");
        expect([hy.outbound[@"type"] isEqualToString:@"hysteria2"], @"type");
        expect([hy.outbound[@"obfs"][@"type"] isEqualToString:@"salamander"], @"obfs");
        expect([hy.outbound[@"tls"][@"insecure"] boolValue], @"insecure");

        printf("tuic\n");
        HVPNProxy *tuic = parse(@"tuic://11111111-2222-3333-4444-555555555555:pw@tuic.example.com:443"
                                 @"?sni=tuic.example.com&congestion_control=bbr#tuic-node");
        expect([tuic.outbound[@"uuid"] length] > 0, @"uuid");
        expect([tuic.outbound[@"congestion_control"] isEqualToString:@"bbr"], @"congestion");

        printf("happ:// -> понятная ошибка\n");
        NSError *happError = nil;
        HVPNProxy *happ = [HVPNLinkParser proxyFromLink:@"happ://crypt5/abcdef" error:&happError];
        expect(happ == nil && happError != nil, @"rejected with message");
        expect([happError.localizedDescription containsString:@"Happ"], @"mentions Happ");

        printf("подписка base64\n");
        NSString *plain = @"vless://u@a.example.com:443#one\nvmess://bm90LWpzb24=\n# comment\n";
        NSData *subData = [[plain dataUsingEncoding:NSUTF8StringEncoding] base64EncodedDataWithOptions:0];
        NSArray<NSString *> *links = [HVPNLinkParser linksFromSubscriptionData:subData];
        expect(links.count == 2, @"two links extracted");

        printf("reality + vision (как в реальных подписках)\n");
        NSString *realityLink =
            @"vless://11111111-2222-3333-4444-555555555555@edge.example.net:443"
            @"?encryption=none&flow=xtls-rprx-vision&security=reality"
            @"&sni=edge-c11ea3.example.net&fp=firefox"
            @"&pbk=lpA3qpAdwCdzEW3ZWQxy4gSh5l380VaF3QvkchHqTD8"
            @"&sid=b8332c19da7f4603&type=tcp#Reality%20Vision";
        HVPNProxy *reality = parse(realityLink);
        expect([reality.outbound[@"flow"] isEqualToString:@"xtls-rprx-vision"], @"vision flow");
        expect([reality.outbound[@"tls"][@"reality"][@"public_key"]
                isEqualToString:@"lpA3qpAdwCdzEW3ZWQxy4gSh5l380VaF3QvkchHqTD8"], @"reality public_key");
        expect([reality.outbound[@"tls"][@"reality"][@"short_id"] isEqualToString:@"b8332c19da7f4603"], @"short_id");
        expect([reality.outbound[@"tls"][@"utls"][@"fingerprint"] isEqualToString:@"firefox"], @"utls fingerprint");
        expect(reality.outbound[@"transport"] == nil, @"no transport for tcp");
        expect(![HVPNLinkParser isPlaceholderLink:realityLink], @"real link is not a placeholder");

        printf("xhttp -> понятная ошибка (ядро 1.8 его не умеет)\n");
        NSError *xhttpError = nil;
        HVPNProxy *xhttp = [HVPNLinkParser proxyFromLink:
            @"vless://11111111-2222-3333-4444-555555555555@x.example.net:443"
            @"?encryption=none&security=tls&sni=x.example.net&fp=chrome&type=xhttp&mode=auto#xhttp"
            error:&xhttpError];
        expect(xhttp == nil && [xhttpError.localizedDescription containsString:@"xhttp"], @"xhttp rejected");

        printf("заглушка панели\n");
        NSString *stubLink =
            @"vless://00000000-0000-0000-0000-000000000000@0.0.0.0:1"
            @"?encryption=none&type=tcp&security=none#stub";
        expect([HVPNLinkParser isPlaceholderLink:stubLink], @"stub detected");

        printf("Xray-JSON подписка\n");
        NSDictionary *xray = @{
            @"outbounds": @[
                @{
                    @"tag": @"uni-ppl1",
                    @"protocol": @"vless",
                    @"settings": @{@"vnext": @[@{
                        @"address": @"95.85.250.250",
                        @"port": @443,
                        @"users": @[@{
                            @"id": @"19df57b1-5ed5-4b71-b361-37da1b856b8c",
                            @"encryption": @"none",
                            @"flow": @"xtls-rprx-vision"
                        }]
                    }]},
                    @"streamSettings": @{
                        @"network": @"tcp",
                        @"security": @"reality",
                        @"realitySettings": @{
                            @"serverName": @"edge-c11ea3.example.net",
                            @"publicKey": @"lpA3qpAdwCdzEW3ZWQxy4gSh5l380VaF3QvkchHqTD8",
                            @"shortId": @"b8332c19da7f4603",
                            @"fingerprint": @"firefox"
                        }
                    }
                },
                @{@"tag": @"direct", @"protocol": @"freedom", @"settings": @{}}
            ]
        };
        NSData *xrayData = [NSJSONSerialization dataWithJSONObject:xray options:0 error:NULL];
        NSArray<NSString *> *xrayLinks = [HVPNLinkParser linksFromXrayConfigData:xrayData];
        expect(xrayLinks.count == 1, @"один vless из JSON-конфига");
        HVPNProxy *fromJSON = parse(xrayLinks.firstObject);
        expect([fromJSON.outbound[@"flow"] isEqualToString:@"xtls-rprx-vision"], @"flow из JSON");
        expect([fromJSON.outbound[@"tls"][@"reality"][@"short_id"] isEqualToString:@"b8332c19da7f4603"],
               @"short_id из JSON");

        printf("итоговый конфиг\n");        NSMutableDictionary *opts = [@{@"bindInterface": @"en0"} mutableCopy];
        opts[@"logPath"] = @"/tmp/core.log";
        NSDictionary *config = HVPNBuildConfig(vless, opts);
        NSData *pretty = [NSJSONSerialization dataWithJSONObject:config
                                                         options:NSJSONWritingPrettyPrinted
                                                           error:NULL];
        printf("%s\n", [[[NSString alloc] initWithData:pretty encoding:NSUTF8StringEncoding] UTF8String]);
        expect([config[@"outbounds"][1][@"bind_interface"] isEqualToString:@"en0"], @"direct bound to en0");
        expect([config[@"inbounds"][0][@"address"][0] isEqualToString:@"172.19.0.1/30"], @"tun address");
        expect(config[@"outbounds"][2] == nil, @"нет dns-out (удалён в 1.13)");
        expect([config[@"route"][@"rules"][0][@"action"] isEqualToString:@"sniff"], @"sniff через действие");
        expect([config[@"route"][@"default_domain_resolver"] isEqualToString:@"local"], @"resolver по умолчанию");
        expect([config[@"route"][@"final"] isEqualToString:@"proxy"], @"route final");

        printf("\n%s (%d failures)\n", gFailures == 0 ? "ALL PASSED" : "FAILURES", gFailures);
        return gFailures == 0 ? 0 : 1;
    }
}
