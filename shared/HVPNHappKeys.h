// Сгенерировано из hpwnr (Omegaplexx/hpwnr, src/keys.rs). Не править руками.
#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/// Ключи crypt5: маркер (первые 4 + последние 4 символа нагрузки) -> PKCS#8 DER в base64.
NSDictionary<NSString *, NSString *> *HVPNCrypt5KeyMap(void);

/// Ключи crypt/crypt2/crypt3/crypt4 (PKCS#1 DER в base64), по порядку ordinal 0..3.
NSArray<NSString *> *HVPNCrypt1Keys(void);

NS_ASSUME_NONNULL_END
