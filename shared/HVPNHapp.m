#import "HVPNHapp.h"
#import "HVPNHappKeys.h"
#import "HVPNChaCha.h"

#import <Security/Security.h>
#include <stdarg.h>
#include <string.h>

static NSError *HVPNHappErr(NSString *format, ...) {
    va_list args;
    va_start(args, format);
    NSString *message = [[NSString alloc] initWithFormat:format arguments:args];
    va_end(args);
    return [NSError errorWithDomain:@"HVPNHapp"
                               code:1
                           userInfo:@{NSLocalizedDescriptionKey: message}];
}

#pragma mark - base64

// Нормализация как в hpwnr: выкинуть пробелы, '-' -> '+', '_' -> '/', добрать '='.
static NSData *HVPNBase64(NSData *input) {
    if (input.length == 0) return nil;
    const uint8_t *src = input.bytes;
    NSMutableData *clean = [NSMutableData dataWithCapacity:input.length + 4];
    for (NSUInteger i = 0; i < input.length; i++) {
        uint8_t c = src[i];
        if (c == ' ' || c == '\n' || c == '\r' || c == '\t') continue;
        if (c == '-') c = '+';
        else if (c == '_') c = '/';
        [clean appendBytes:&c length:1];
    }
    while (clean.length % 4) {
        uint8_t pad = '=';
        [clean appendBytes:&pad length:1];
    }
    return [[NSData alloc] initWithBase64EncodedData:clean options:0];
}

static NSData *HVPNBase64String(NSString *string) {
    if (string.length == 0) return nil;
    NSData *raw = [string dataUsingEncoding:NSUTF8StringEncoding];
    return HVPNBase64(raw);
}

#pragma mark - побайтовые перестановки

// Меняет местами половины каждого 4-байтного блока: ABCD -> CDAB. Обратна сама себе.
static NSData *HVPNBlockPairSwap(NSData *input) {
    NSMutableData *out = [input mutableCopy];
    uint8_t *p = out.mutableBytes;
    NSUInteger full = out.length - out.length % 4;
    for (NSUInteger i = 0; i < full; i += 4) {
        uint8_t t = p[i]; p[i] = p[i + 2]; p[i + 2] = t;
        t = p[i + 1]; p[i + 1] = p[i + 3]; p[i + 3] = t;
    }
    return out;
}

// Меняет соседние байты парами: ABCD -> BADC. Обратна сама себе.
static NSData *HVPNPairSwap(NSData *input) {
    NSMutableData *out = [input mutableCopy];
    uint8_t *p = out.mutableBytes;
    for (NSUInteger i = 0; i + 1 < out.length; i += 2) {
        uint8_t t = p[i]; p[i] = p[i + 1]; p[i + 1] = t;
    }
    return out;
}

#pragma mark - DER

// Читает один TLV: тег, тело (диапазон в буфере), сдвигает курсор за тело.
static BOOL HVPNReadTLV(const uint8_t *p, NSUInteger len, NSUInteger *cursor,
                        uint8_t *tag, NSRange *body) {
    NSUInteger off = *cursor;
    if (off + 2 > len) return NO;
    uint8_t t = p[off++];
    NSUInteger length = 0;
    uint8_t first = p[off++];
    if (first & 0x80) {
        NSUInteger count = first & 0x7f;
        if (count == 0 || count > 4 || off + count > len) return NO;
        for (NSUInteger i = 0; i < count; i++) length = (length << 8) | p[off++];
    } else {
        length = first;
    }
    if (off + length > len) return NO;
    *tag = t;
    *body = NSMakeRange(off, length);
    *cursor = off + length;
    return YES;
}

// PKCS#8 PrivateKeyInfo -> внутренний PKCS#1 RSAPrivateKey.
static NSData *HVPNPKCS8ToPKCS1(NSData *der) {
    const uint8_t *p = der.bytes;
    NSUInteger len = der.length;
    NSUInteger cursor = 0;
    uint8_t tag = 0;
    NSRange seq = NSMakeRange(0, 0);
    if (!HVPNReadTLV(p, len, &cursor, &tag, &seq) || tag != 0x30) return der;

    NSUInteger inner = seq.location;
    NSRange part = NSMakeRange(0, 0);
    if (!HVPNReadTLV(p, len, &inner, &tag, &part) || tag != 0x02) return der;   // version
    if (!HVPNReadTLV(p, len, &inner, &tag, &part) || tag != 0x30) return der;   // algorithm
    if (!HVPNReadTLV(p, len, &inner, &tag, &part) || tag != 0x04) return der;   // privateKey
    return [der subdataWithRange:part];
}

#pragma mark - RSA

static SecKeyRef HVPNKeyForBase64(NSString *base64) {
    static NSMutableDictionary<NSString *, id> *cache;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        cache = [NSMutableDictionary dictionary];
    });

    @synchronized (cache) {
        id cached = cache[base64];
        if (cached) return (__bridge SecKeyRef)cached;
    }

    NSData *der = HVPNBase64String(base64);
    if (der.length == 0) return NULL;
    NSData *pkcs1 = HVPNPKCS8ToPKCS1(der);

    NSDictionary *attrs = @{
        (__bridge id)kSecAttrKeyType: (__bridge id)kSecAttrKeyTypeRSA,
        (__bridge id)kSecAttrKeyClass: (__bridge id)kSecAttrKeyClassPrivate,
    };
    CFErrorRef cfError = NULL;
    SecKeyRef key = SecKeyCreateWithData((__bridge CFDataRef)pkcs1,
                                        (__bridge CFDictionaryRef)attrs,
                                        &cfError);
    if (cfError) CFRelease(cfError);
    if (key == NULL) return NULL;

    @synchronized (cache) {
        cache[base64] = (__bridge id)key;
    }
    return key;
}

static NSData *HVPNRSADecrypt(SecKeyRef key, NSData *ciphertext) {
    if (key == NULL || ciphertext.length == 0) return nil;
    CFErrorRef cfError = NULL;
    CFDataRef plain = SecKeyCreateDecryptedData(key, kSecKeyAlgorithmRSAEncryptionPKCS1,
                                                (__bridge CFDataRef)ciphertext, &cfError);
    if (cfError) CFRelease(cfError);
    if (plain == NULL) return nil;
    return (__bridge_transfer NSData *)plain;
}

#pragma mark - crypt5

static NSString *HVPNCrypt5Body(NSData *body, SecKeyRef key, BOOL salted, NSError **error) {
    const uint8_t *b = body.bytes;
    NSUInteger len = body.length;
    NSUInteger start = salted ? 22 : 12;
    if (len < start) {
        if (error) *error = HVPNHappErr(@"crypt5: тело короче заголовка");
        return nil;
    }
    NSData *nonce = [body subdataWithRange:NSMakeRange(0, 12)];
    NSData *salt = salted ? [body subdataWithRange:NSMakeRange(14, 8)] : nil;

    NSUInteger digits = 0;
    while (start + digits < len && b[start + digits] >= '0' && b[start + digits] <= '9') digits++;
    if (digits == 0) {
        if (error) *error = HVPNHappErr(@"crypt5: нет длины сегмента");
        return nil;
    }
    unsigned long long segLength = 0;
    for (NSUInteger i = 0; i < digits; i++) {
        segLength = segLength * 10 + (unsigned long long)(b[start + i] - '0');
        if (segLength > len) {
            if (error) *error = HVPNHappErr(@"crypt5: длина сегмента больше тела");
            return nil;
        }
    }

    NSUInteger packed = start + digits;
    if (packed >= len || segLength > len - packed - 1) {
        if (error) *error = HVPNHappErr(@"crypt5: сегмент обрезан");
        return nil;
    }
    NSData *urlB64 = [body subdataWithRange:NSMakeRange(packed + 1, (NSUInteger)segLength)];
    NSUInteger rsaOff = packed + 1 + (NSUInteger)segLength;
    NSData *rsaB64 = [body subdataWithRange:NSMakeRange(rsaOff, len - rsaOff)];

    NSData *rsaCipher = HVPNBase64(rsaB64);
    if (rsaCipher.length == 0) {
        if (error) *error = HVPNHappErr(@"crypt5: RSA-блок не base64");
        return nil;
    }
    NSData *rsaPlain = HVPNRSADecrypt(key, rsaCipher);
    if (rsaPlain.length == 0) {
        if (error) *error = HVPNHappErr(@"crypt5: RSA не расшифровался");
        return nil;
    }
    NSData *rsaValue = HVPNBase64(HVPNPairSwap(rsaPlain));
    if (rsaValue.length != 32) {
        if (error) *error = HVPNHappErr(@"crypt5: длина ключа %lu", (unsigned long)rsaValue.length);
        return nil;
    }

    uint8_t chachaKey[32];
    if (salt.length == 8) {
        const uint8_t *v = rsaValue.bytes;
        const uint8_t *s = salt.bytes;
        for (int i = 0; i < 32; i++) chachaKey[i] = (uint8_t)(v[i] ^ s[i % 8]);
    } else {
        memcpy(chachaKey, rsaValue.bytes, 32);
    }

    NSData *ciphertext = HVPNBase64(urlB64);
    if (ciphertext.length < 16) {
        if (error) *error = HVPNHappErr(@"crypt5: шифротекст короче тега");
        return nil;
    }
    NSMutableData *intermediate = [NSMutableData dataWithLength:ciphertext.length - 16];
    if (HVPNChaCha20Poly1305Decrypt(chachaKey, nonce.bytes, ciphertext.bytes,
                                    ciphertext.length, intermediate.mutableBytes) != 0) {
        if (error) *error = HVPNHappErr(@"crypt5: не сошёлся Poly1305 (не тот макет или ключ)");
        return nil;
    }

    NSData *plain = HVPNBase64(HVPNPairSwap(intermediate));
    if (plain.length == 0) {
        if (error) *error = HVPNHappErr(@"crypt5: результат не base64");
        return nil;
    }
    NSString *url = [[NSString alloc] initWithData:plain encoding:NSUTF8StringEncoding];
    if (url.length == 0) {
        if (error) *error = HVPNHappErr(@"crypt5: результат не UTF-8");
        return nil;
    }
    return url;
}

static NSString *HVPNCrypt5(NSString *payload, NSError **error) {
    NSData *raw = [payload dataUsingEncoding:NSUTF8StringEncoding];
    NSData *shuffled = HVPNBlockPairSwap(raw);
    if (shuffled.length < 8) {
        if (error) *error = HVPNHappErr(@"crypt5: нагрузка слишком короткая");
        return nil;
    }
    const uint8_t *b = shuffled.bytes;
    NSUInteger n = shuffled.length;
    NSString *head = [[NSString alloc] initWithBytes:b length:4 encoding:NSASCIIStringEncoding];
    NSString *tail = [[NSString alloc] initWithBytes:(b + n - 4) length:4 encoding:NSASCIIStringEncoding];
    NSString *marker = [NSString stringWithFormat:@"%@%@", head ?: @"", tail ?: @""];

    NSString *keyB64 = HVPNCrypt5KeyMap()[marker];
    if (keyB64.length == 0) {
        if (error) *error = HVPNHappErr(@"crypt5: неизвестный маркер ключа '%@'. "
                                        @"Happ выпустил новую версию — нужны свежие ключи.", marker);
        return nil;
    }
    SecKeyRef key = HVPNKeyForBase64(keyB64);
    if (key == NULL) {
        if (error) *error = HVPNHappErr(@"crypt5: ключ не принят Security.framework");
        return nil;
    }

    NSData *body = [shuffled subdataWithRange:NSMakeRange(4, n - 8)];
    if (body.length < 13) {
        if (error) *error = HVPNHappErr(@"crypt5: тело слишком короткое");
        return nil;
    }
    // Макет угадывается по 13-му символу: в старом там цифра длины сегмента,
    // в новом (с солью) — случайный символ.
    const uint8_t *bb = body.bytes;
    BOOL digit = (bb[12] >= '0' && bb[12] <= '9');
    BOOL order[2] = { !digit, digit };

    NSError *lastError = nil;
    for (int i = 0; i < 2; i++) {
        NSError *stepError = nil;
        NSString *url = HVPNCrypt5Body(body, key, order[i], &stepError);
        if (url.length) return url;
        if (stepError) lastError = stepError;
    }
    if (error) *error = lastError;
    return nil;
}

#pragma mark - crypt..crypt4

static NSString *HVPNCryptRSA(NSInteger ordinal, NSString *payload, NSError **error) {
    NSArray<NSString *> *keys = HVPNCrypt1Keys();
    if (ordinal < 0 || (NSUInteger)ordinal >= keys.count) {
        if (error) *error = HVPNHappErr(@"crypt: нет ключа для режима %ld", (long)ordinal);
        return nil;
    }
    SecKeyRef key = HVPNKeyForBase64(keys[(NSUInteger)ordinal]);
    if (key == NULL) {
        if (error) *error = HVPNHappErr(@"crypt: ключ не принят Security.framework");
        return nil;
    }
    NSData *ciphertext = HVPNBase64String(payload);
    size_t blockSize = SecKeyGetBlockSize(key);
    if (ciphertext.length == 0 || blockSize == 0 || ciphertext.length % blockSize != 0) {
        if (error) *error = HVPNHappErr(@"crypt: шифротекст не кратен размеру ключа");
        return nil;
    }
    NSMutableData *plain = [NSMutableData data];
    for (NSUInteger off = 0; off < ciphertext.length; off += blockSize) {
        NSData *block = [ciphertext subdataWithRange:NSMakeRange(off, blockSize)];
        NSData *part = HVPNRSADecrypt(key, block);
        if (part == nil) {
            if (error) *error = HVPNHappErr(@"crypt: блок RSA не расшифровался");
            return nil;
        }
        [plain appendData:part];
    }
    NSString *url = [[NSString alloc] initWithData:plain encoding:NSUTF8StringEncoding];
    if (url.length == 0) {
        if (error) *error = HVPNHappErr(@"crypt: результат не UTF-8");
        return nil;
    }
    return url;
}

#pragma mark - публичное

@implementation HVPNHapp

+ (BOOL)looksEncrypted:(NSString *)link {
    if (link.length == 0) return NO;
    NSString *lower = link.lowercaseString;
    return [lower hasPrefix:@"happ://crypt5/"] || [lower hasPrefix:@"happ://crypt4/"] ||
           [lower hasPrefix:@"happ://crypt3/"] || [lower hasPrefix:@"happ://crypt2/"] ||
           [lower hasPrefix:@"happ://crypt/"];
}

+ (NSString *)decryptLink:(NSString *)link error:(NSError **)error {
    if (link.length == 0) {
        if (error) *error = HVPNHappErr(@"пустая ссылка");
        return nil;
    }
    NSString *lower = link.lowercaseString;
    NSArray<NSString *> *prefixes = @[@"happ://crypt5/", @"happ://crypt4/",
                                      @"happ://crypt3/", @"happ://crypt2/",
                                      @"happ://crypt/"];
    for (NSUInteger i = 0; i < prefixes.count; i++) {
        NSString *prefix = prefixes[i];
        if (![lower hasPrefix:prefix]) continue;
        NSString *payload = [link substringFromIndex:prefix.length];
        if (i == 0) return HVPNCrypt5(payload, error);
        NSInteger ordinal = (NSInteger)(4 - i);   // crypt4 -> 3, crypt3 -> 2, crypt2 -> 1, crypt -> 0
        return HVPNCryptRSA(ordinal, payload, error);
    }
    if (error) *error = HVPNHappErr(@"это не зашифрованная ссылка Happ");
    return nil;
}

@end
