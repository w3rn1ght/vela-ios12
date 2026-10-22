// Unix-сокет, через который приложение управляет демоном.
// Протокол: одна строка JSON на запрос, одна строка JSON на ответ, затем close.
#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface HVPNControlServer : NSObject
- (BOOL)startWithError:(NSError **)error;
@end

NS_ASSUME_NONNULL_END
