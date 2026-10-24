// Офлайн-проверка парсера: собирается и запускается на macOS, устройство не нужно.
//   ./scripts/run-parser-tests.sh
#import <Foundation/Foundation.h>

#import "HVPNConfig.h"
#import "HVPNChaCha.h"
#import "HVPNHapp.h"
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

        printf("xhttp -> транспорт для ядра 1.14\n");
        NSError *xhttpError = nil;
        HVPNProxy *xhttp = [HVPNLinkParser proxyFromLink:
            @"vless://11111111-2222-3333-4444-555555555555@x.example.net:443"
            @"?encryption=none&security=tls&sni=x.example.net&fp=chrome&type=xhttp&mode=packet-up"
            @"&path=%2Fstatic#xhttp"
            error:&xhttpError];
        expect(xhttp != nil, @"xhttp parsed");
        expect([xhttp.outbound[@"transport"][@"type"] isEqualToString:@"xhttp"], @"xhttp transport type");
        expect([xhttp.outbound[@"transport"][@"mode"] isEqualToString:@"packet-up"], @"xhttp mode");
        expect([xhttp.outbound[@"transport"][@"path"] isEqualToString:@"/static"], @"xhttp path");
        expect([xhttp.name isEqualToString:@"xhttp"], @"name without query");

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
        expect([config[@"outbounds"] count] == 2, @"нет dns-out (удалён в 1.13)");
        expect([config[@"route"][@"rules"][0][@"action"] isEqualToString:@"sniff"], @"sniff через действие");
        expect([config[@"route"][@"default_domain_resolver"] isEqualToString:@"local"], @"resolver по умолчанию");
        expect([config[@"route"][@"final"] isEqualToString:@"proxy"], @"route final");

        printf("happ: ChaCha20-Poly1305 (RFC 8439)\n");
        {
            uint8_t key[32], nonce[12], ct[130], out[114];
            for (int i = 0; i < 32; i++) key[i] = (uint8_t)(0x80 + i);
            const uint8_t n[12] = {0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47};
            memcpy(nonce, n, sizeof(nonce));
        static const uint8_t body[114] = {
            0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb, 0x7b, 0x86, 0xaf, 0xbc,
            0x53, 0xef, 0x7e, 0xc2, 0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe,
            0xa9, 0xe2, 0xb5, 0xa7, 0x36, 0xee, 0x62, 0xd6, 0x3d, 0xbe, 0xa4, 0x5e,
            0x8c, 0xa9, 0x67, 0x12, 0x82, 0xfa, 0xfb, 0x69, 0xda, 0x92, 0x72, 0x8b,
            0x1a, 0x71, 0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29, 0x05, 0xd6, 0xa5, 0xb6,
            0x7e, 0xcd, 0x3b, 0x36, 0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77, 0x8b, 0x8c,
            0x98, 0x03, 0xae, 0xe3, 0x28, 0x09, 0x1b, 0x58, 0xfa, 0xb3, 0x24, 0xe4,
            0xfa, 0xd6, 0x75, 0x94, 0x55, 0x85, 0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc,
            0x3f, 0xf4, 0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d, 0xe5, 0x76, 0xd2, 0x65,
            0x86, 0xce, 0xc6, 0x4b, 0x61, 0x16,
        };
        static const uint8_t tag[16] = {
            0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a, 0x7e, 0x90, 0x2e, 0xcb,
            0xd0, 0x60, 0x06, 0x91,
        };

            memcpy(ct, body, 114);
            memcpy(ct + 114, tag, 16);
            const char *plain = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
            expect(HVPNChaCha20Poly1305Decrypt(key, nonce, ct, sizeof(ct), out) == 0, @"RFC 8439: тег сходится");
            expect(memcmp(out, plain, 114) == 0, @"RFC 8439: открытый текст совпал");
        }

        printf("happ: расшифровка ссылок\n");
        {
            NSError *happError = nil;
            NSString *crypt5 = [HVPNHapp decryptLink:@"happ://crypt5/fhsbDnHCRdyW3SLSDvqa05O1643jrL:jRE03K2+7LSOvuerT94rFuJktXhMimubB3dfba8cvMaoxLcFKeiXPhX3bYcu98epe+vSWqB0bL7WigvNLIK9HLfMXwomUZJA4fGGykPcsJq0PSP1jWUVSUvNoD0eCG7uhmxp2RrYCwxDyniQ1/ZLGsYsi1OWozIsvZ6eJKRCL08DaqOqeMVbs01puPU1KC2Pmr+rqrdfSN1pjDPjydwGbbIGJ/dWBJm65zxch31Mz5Cs/q0b0wN+HSvdgE/ba7QApNnCOZA8nGh0vINigndicLjwc2iXaM88gzmgI+a/9icDjViI14TVmZ3MElz+dvGJljFi+I2pY6XPujP7HQRcQW7yu9d1XLIHmKCe9tps4qtYkQgWTujS9FwwgRtoBnpLa2pNyiNZyStZetMjmVBjzu/ClDSceQgRLZY+HIRC9fBKqf94quW44rlImm+Ul43jB2YgL4b4Ss+WrQaAlnhbUnX4GN7uXQ1HVQ9CaECiX38dbIChGMz3ZEJeB2BiY59M043g7u6fG+VyvkYxiqqxNra0oUgXzLY2/rYPUwVuDbDnsJ0gt09kBDFnlTYlwvOX0pRfOUIlY9Xg61/z0GKavFqXEfrURl+9rDVO9s3ZZ7RnN3tzgVPohXjJIchu1qb6GwoMnCGOtKli9VMrFcY5UMCIR7BOhWf6ykk1Xtm6dDttyMzGp5eEJ75p7Wzxr6G2D8jHv9pYK0Kv1yaJj2+JBzF5gwLt+FpHWNRFPV8hggc=ch" error:&happError];
            expect([crypt5 isEqualToString:@"https://example.com/sub"], @"crypt5 -> URL подписки");
            if (crypt5.length == 0) printf("    crypt5 error: %s\n", happError.localizedDescription.UTF8String);

            NSError *happError3 = nil;
            NSString *crypt3 = [HVPNHapp decryptLink:@"happ://crypt3/AmjNmaEGMDk23LphiFTvrqbZfIWhG1l8lj1BBxN823BlHXZzAoMKBH62dOic7hvObv/ApVsh7meOSXU/aSOEfyid+Tmw4gagdyrjbB+J72TxJAvkHbhtPTZyM6ZltdRHyAPn/Rn+rSxaulRQtm++2eFxfM1XDrkDk4ay9KPdP3QT/fcr1tfiHWXmqQY2o0zSftAJPSnY5C6o1ARaaN8NR/X+rPuDyUQ/F36dti+PFt7Fim4cpd6cHZAIBty0uUzEf+OAPNRSpvgt7kFb6JBoppDEUdABqAvY3p2Yk+kPNvCRQupzWg7RFq8CxNYiiJQsfzemiBe0Z68FjXbe+td0OdMLD+NYx0Khzwdult97ogC/YxxKCFXAMybsH8YPO0+Xsrl1a36FlJApW3ug7/yUAX0tFo5NL+Nm/m00Xx4Rsl7ayrQpSiXddn85vnJKMDl4p0XSgoC6Z//2jUOCg/yhaqGwdNSkrP0htSGyfvbVtNCMXaa+hJ1RYV4XTtg/pvlJKvMsnv7ooUBDtNZjR+Rm2XwWBXiRk+ieQggH2ImvOc/ZLJULbkvaRKpeH5/QyZNuLJbRZ2UAWlbY3ma5vmHmofI/diUQmYLHZHrdh2IQ1Tl2SEbi3IPokm+db5mMwkI7VnAeGo55QfFRZ4peRBS88wuv4aSJQCdHErZIp+kgBcg=" error:&happError3];
            expect([crypt3 isEqualToString:@"https://example.com/sub"], @"crypt3 -> URL подписки");
            if (crypt3.length == 0) printf("    crypt3 error: %s\n", happError3.localizedDescription.UTF8String);

            expect([HVPNHapp looksEncrypted:@"happ://crypt5/abc"], @"looksEncrypted crypt5");
            expect(![HVPNHapp looksEncrypted:@"happ://add/https://example.com"], @"add не шифрованная");
        }

        printf("\n%s (%d failures)\n", gFailures == 0 ? "ALL PASSED" : "FAILURES", gFailures);
        return gFailures == 0 ? 0 : 1;
    }
}
