// Разбор ссылок Happ: happ://add/… и зашифрованные happ://crypt…/…
// Шифрование — RSA PKCS#1 v1.5 ключами из самого приложения Happ (они давно
// извлечены сообществом: проекты hpwnr/Happwner). Внутри crypt5 дополнительно
// ChaCha20-Poly1305, поэтому нужен свой AEAD (см. HVPNChaCha.c).
#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface HVPNHapp : NSObject

/// Ссылка зашифрована Happ (happ://crypt, crypt2, crypt3, crypt4, crypt5).
+ (BOOL)looksEncrypted:(NSString *)link;

/// Расшифровывает happ://crypt…/… в обычный URL подписки. nil + error при неудаче.
+ (nullable NSString *)decryptLink:(NSString *)link error:(NSError **)error;

@end

NS_ASSUME_NONNULL_END
