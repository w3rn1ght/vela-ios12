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

        printf("happ: ChaCha20-Poly1305 (AEAD, пустой AAD)\n");
        {
            uint8_t key[32], nonce[12], ct[42], out[26], broken[42];
            for (int i = 0; i < 32; i++) key[i] = (uint8_t)i;
            for (int i = 0; i < 12; i++) nonce[i] = (uint8_t)i;
            static const uint8_t ctBytes[42] = {
            0xdf, 0x9e, 0x64, 0x61, 0x13, 0x37, 0xcd, 0x21, 0xc7, 0xf3, 0x05, 0xdc,
            0xb7, 0x7e, 0x7c, 0x1a, 0xb9, 0x04, 0x87, 0xc7, 0x21, 0x15, 0xd4, 0xd5,
            0x89, 0xf6, 0x36, 0xa4, 0x54, 0x63, 0x8e, 0x9e, 0x88, 0x76, 0xfa, 0x61,
            0xb7, 0x66, 0x34, 0x59, 0x7b, 0x39,
            };
            const char *plain = "Vela: happ://crypt5 payloa";
            memcpy(ct, ctBytes, sizeof(ctBytes));
            expect(HVPNChaCha20Poly1305Decrypt(key, nonce, ct, sizeof(ct), out) == 0, @"тег сходится");
            expect(memcmp(out, plain, 26) == 0, @"открытый текст совпал");
            memcpy(broken, ct, sizeof(broken));
            broken[sizeof(broken) - 1] ^= 1;
            expect(HVPNChaCha20Poly1305Decrypt(key, nonce, broken, sizeof(broken), out) != 0,
                   @"подмена тега отвергнута");
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
