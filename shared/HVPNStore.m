#import "HVPNStore.h"
#import "HVPNPaths.h"
#import "HVPNLinkUtil.h"

#import <UIKit/UIKit.h>

#include <sys/utsname.h>

@implementation HVPNNode

+ (instancetype)nodeFromLink:(NSString *)link {
    HVPNNode *node = [HVPNNode new];
    node.link = link;
    node.pingMs = -1;

    NSError *error = nil;
    HVPNProxy *proxy = [HVPNLinkParser proxyFromLink:link error:&error];
    if (proxy == nil) {
        HVPNNode *fallback = [HVPNNode new];
        fallback.link = link;
        fallback.name = [self shortNameForUnparsed:link];
        fallback.type = [link componentsSeparatedByString:@"://"].firstObject ?: @"?";
        fallback.server = @"";
        fallback.port = 0;
        fallback.supported = NO;
        fallback.pingMs = -1;
        return fallback;
    }
    node.name = proxy.name;
    node.type = proxy.type;
    node.server = proxy.server;
    node.port = proxy.port;
    node.supported = ![HVPNLinkParser isPlaceholderLink:link];
    return node;
}

+ (NSString *)shortNameForUnparsed:(NSString *)link {
    NSString *fragment = nil;
    NSRange hash = [link rangeOfString:@"#"];
    if (hash.location != NSNotFound) fragment = HVPNPercent([link substringFromIndex:hash.location + 1]);
    if (fragment.length) return fragment;
    return [[link componentsSeparatedByString:@"://"].firstObject stringByAppendingString:@" (не поддерживается)"];
}

- (NSDictionary *)dictionary {
    return @{
        @"link": self.link ?: @"",
        @"name": self.name ?: @"",
        @"type": self.type ?: @"",
        @"server": self.server ?: @"",
        @"port": @(self.port),
        @"supported": @(self.supported),
        @"ping": @(self.pingMs)
    };
}

+ (instancetype)nodeFromDictionary:(NSDictionary *)dict {
    HVPNNode *node = [HVPNNode new];
    node.link = dict[@"link"] ?: @"";
    node.name = dict[@"name"] ?: @"?";
    node.type = dict[@"type"] ?: @"?";
    node.server = dict[@"server"] ?: @"";
    node.port = [dict[@"port"] integerValue];
    node.supported = [dict[@"supported"] boolValue];
    node.pingMs = [dict[@"ping"] integerValue];
    if (node.pingMs == 0) node.pingMs = -1;
    return node;
}

@end

#pragma mark -

@implementation HVPNStore {
    NSMutableArray<HVPNNode *> *_nodes;
    NSMutableArray<NSString *> *_diagnostics;
    dispatch_queue_t _workQueue;
}

+ (instancetype)shared {
    static HVPNStore *store;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ store = [HVPNStore new]; });
    return store;
}

- (instancetype)init {
    self = [super init];
    if (self) {
        _nodes = [NSMutableArray array];
        _diagnostics = [NSMutableArray array];
        _selectedIndex = -1;
        _workQueue = dispatch_queue_create("com.vela.store", DISPATCH_QUEUE_SERIAL);
    }
    return self;
}

- (NSArray<HVPNNode *> *)nodes { return [_nodes copy]; }
- (NSArray<NSString *> *)diagnostics { return [_diagnostics copy]; }
- (HVPNNode *)nodeAtIndex:(NSInteger)index {
    if (index < 0 || index >= (NSInteger)_nodes.count) return nil;
    return _nodes[(NSUInteger)index];
}

#pragma mark - Хранение

- (void)load {
    NSDictionary *json = [NSJSONSerialization JSONObjectWithData:
                          ([NSData dataWithContentsOfFile:HVPNNodesPath] ?: [NSData data])
                                                         options:0 error:NULL];
    if (![json isKindOfClass:[NSDictionary class]]) return;
    NSArray *items = json[@"nodes"];
    if ([items isKindOfClass:[NSArray class]]) {
        [_nodes removeAllObjects];
        for (NSDictionary *dict in items) {
            if (![dict isKindOfClass:[NSDictionary class]]) continue;
            [_nodes addObject:[HVPNNode nodeFromDictionary:dict]];
        }
    }
    self.selectedIndex = [json[@"selected"] integerValue];
    self.subscriptionURL = json[@"subscription"];
    self.subscriptionInfo = json[@"subscriptionInfo"];
    if (self.selectedIndex >= (NSInteger)_nodes.count) self.selectedIndex = _nodes.count ? 0 : -1;
}

- (void)save {
    NSMutableArray *items = [NSMutableArray array];
    for (HVPNNode *node in _nodes) [items addObject:[node dictionary]];
    NSMutableDictionary *json = [@{@"nodes": items, @"selected": @(self.selectedIndex)} mutableCopy];
    if (self.subscriptionURL.length) json[@"subscription"] = self.subscriptionURL;
    if (self.subscriptionInfo.length) json[@"subscriptionInfo"] = self.subscriptionInfo;

    NSData *data = [NSJSONSerialization dataWithJSONObject:json options:NSJSONWritingPrettyPrinted error:NULL];
    NSFileManager *fm = [NSFileManager defaultManager];
    if (![fm fileExistsAtPath:HVPNStateDir]) {
        [fm createDirectoryAtPath:HVPNStateDir withIntermediateDirectories:YES
                       attributes:@{NSFilePosixPermissions: @0755} error:NULL];
    }
    if (data) {
        if (![data writeToFile:HVPNNodesPath atomically:YES]) {
            NSLog(@"[Vela] не удалось записать %@", HVPNNodesPath);
        }
        [fm setAttributes:@{NSFilePosixPermissions: @0600} ofItemAtPath:HVPNNodesPath error:NULL];
    }
}

- (void)removeNodeAtIndex:(NSInteger)index {
    if (index < 0 || index >= (NSInteger)_nodes.count) return;
    [_nodes removeObjectAtIndex:(NSUInteger)index];
    if (self.selectedIndex == index) self.selectedIndex = _nodes.count ? 0 : -1;
    else if (self.selectedIndex > index) self.selectedIndex--;
    [self save];
}

- (void)clearDiagnostics {
    @synchronized (_diagnostics) {
        [_diagnostics removeAllObjects];
    }
}

- (void)notePingSummary:(NSString *)line {
    if (line.length == 0) return;
    [self log:@"%@", line];
    [self writeReport];
}

- (NSString *)diagnosticsPath {
    return [HVPNStateDir stringByAppendingPathComponent:@"last-subscription.txt"];
}

/// Отчёт в файл — чтобы можно было прислать `cat` по SSH, даже если экран не видно.
- (void)writeReport {
    NSDateFormatter *formatter = [NSDateFormatter new];
    formatter.dateFormat = @"yyyy-MM-dd HH:mm:ss";
    NSMutableString *text = [NSMutableString string];
    [text appendFormat:@"%@  hwid=%@  нод=%@\n",
     [formatter stringFromDate:[NSDate date]], HVPNStoreHWID(),
     @(_nodes.count)];
    @synchronized (_diagnostics) {
        for (NSString *line in _diagnostics) [text appendFormat:@"%@\n", line];
    }
    [text writeToFile:self.diagnosticsPath atomically:YES encoding:NSUTF8StringEncoding error:NULL];
    [[NSFileManager defaultManager] setAttributes:@{NSFilePosixPermissions: @0600}
                                     ofItemAtPath:self.diagnosticsPath error:NULL];
}

- (void)log:(NSString *)format, ... {
    va_list args;
    va_start(args, format);
    NSString *line = [[NSString alloc] initWithFormat:format arguments:args];
    va_end(args);
    NSLog(@"[Vela] %@", line);
    @synchronized (_diagnostics) {
        [_diagnostics addObject:line];
    }
}

#pragma mark - Подписки

static NSString *HVPNStoreHWID(void) {
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    NSString *hwid = [defaults stringForKey:@"VelaHWID"];
    if (hwid.length == 0) {
        hwid = [[NSUUID UUID] UUIDString];
        [defaults setObject:hwid forKey:@"VelaHWID"];
    }
    return hwid;
}

+ (NSString *)currentHWID {
    return HVPNStoreHWID();
}

+ (void)setHWID:(NSString *)hwid {
    NSString *value = [hwid stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
    if (value.length == 0) return;
    [[NSUserDefaults standardUserDefaults] setObject:value forKey:@"VelaHWID"];
}

+ (void)resetHWID {
    [[NSUserDefaults standardUserDefaults] setObject:[[NSUUID UUID] UUIDString] forKey:@"VelaHWID"];
}

static NSString *HVPNStoreDeviceModel(void) {
    struct utsname info;
    if (uname(&info) == 0) {
        NSString *machine = [NSString stringWithUTF8String:info.machine];
        if (machine.length) return machine;
    }
    return @"iPhone";
}

static NSURLRequest *HVPNStoreSubscriptionRequest(NSURL *url) {
    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:url];
    // Панели Remnawave привязывают подписку к устройству по x-hwid, а по
    // User-Agent выбирают формат: v2ray-совместимым отдают base64-ссылки.
    [request setValue:@"v2rayNG/1.8.5" forHTTPHeaderField:@"User-Agent"];
    [request setValue:HVPNStoreHWID() forHTTPHeaderField:@"x-hwid"];
    [request setValue:@"iOS" forHTTPHeaderField:@"x-device-os"];
    [request setValue:[[UIDevice currentDevice] systemVersion] forHTTPHeaderField:@"x-ver-os"];
    [request setValue:HVPNStoreDeviceModel() forHTTPHeaderField:@"x-device-model"];
    [request setValue:@"*/*" forHTTPHeaderField:@"Accept"];
    request.timeoutInterval = 25;
    return request;
}

static NSString *HVPNStoreFormatBytes(long long bytes) {
    if (bytes <= 0) return @"0";
    double value = (double)bytes;
    NSArray<NSString *> *units = @[@"Б", @"КБ", @"МБ", @"ГБ", @"ТБ"];
    NSUInteger index = 0;
    while (value >= 1024.0 && index + 1 < units.count) {
        value /= 1024.0;
        index++;
    }
    return [NSString stringWithFormat:@"%.1f %@", value, units[index]];
}

static NSString *HVPNStoreFormatUserinfo(NSString *raw) {
    if (raw.length == 0) return nil;
    long long download = 0, total = 0, expire = 0;
    for (NSString *part in [raw componentsSeparatedByString:@";"]) {
        NSRange eq = [part rangeOfString:@"="];
        if (eq.location == NSNotFound) continue;
        NSString *key = [part substringToIndex:eq.location];
        long long value = [part substringFromIndex:eq.location + 1].longLongValue;
        if ([key isEqualToString:@"download"]) download = value;
        else if ([key isEqualToString:@"total"]) total = value;
        else if ([key isEqualToString:@"expire"]) expire = value;
    }
    NSMutableString *text = [NSMutableString stringWithFormat:@"%@", HVPNStoreFormatBytes(download)];
    if (total > 0) [text appendFormat:@" / %@", HVPNStoreFormatBytes(total)];
    else [text appendString:@" (без лимита)"];
    if (expire > 0) {
        NSDateFormatter *formatter = [NSDateFormatter new];
        formatter.dateFormat = @"dd.MM.yyyy";
        [text appendFormat:@", до %@", [formatter stringFromDate:
                                       [NSDate dateWithTimeIntervalSince1970:expire]]];
    }
    return text;
}

- (void)addFromText:(NSString *)text completion:(void (^)(NSUInteger, NSError *_Nullable))completion {
    [self clearDiagnostics];
    dispatch_async(_workQueue, ^{
        NSMutableArray<NSString *> *found = [NSMutableArray array];
        NSMutableArray<NSString *> *urls = [NSMutableArray array];
        NSUInteger placeholders = 0;

        [self collectText:text depth:0 found:found urls:urls placeholders:&placeholders];
        [self fetchURLs:urls index:0 found:found placeholders:&placeholders];

        NSUInteger added = 0;
        for (NSString *link in found) {
            HVPNNode *node = [HVPNNode nodeFromLink:link];
            BOOL duplicate = NO;
            for (HVPNNode *existing in _nodes) {
                if ([existing.link isEqualToString:node.link]) { duplicate = YES; break; }
            }
            if (duplicate) continue;
            [_nodes addObject:node];
            added++;
        }
        if (_selectedIndex < 0 && _nodes.count) _selectedIndex = 0;

        NSUInteger supported = 0;
        for (HVPNNode *node in _nodes) if (node.supported) supported++;
        [self log:@"итог: +%lu нод (всего %lu, из них поддерживаемых %lu)",
              (unsigned long)added, (unsigned long)_nodes.count, (unsigned long)supported];

        if (placeholders > 0) {
            [self log:@"[!] HWID устройства: %@", HVPNStoreHWID()];
            [self log:@"[!] 0.0.0.0:1 — заглушки панели. Обычно это лимит устройств: "
                       @"удалите лишние в кабинете или введите рабочий HWID в настройках (⚙)."];
        }

        [self save];
        [self writeReport];

        NSError *error = nil;
        if (added == 0) {
            NSString *message = nil;
            if (placeholders > 0) {
                message = @"Панель отдала только заглушки (0.0.0.0:1). Обычно это значит, что подписка "
                          @"не активирована, истекла или исчерпан лимит устройств.";
            } else if (_nodes.count > 0) {
                message = @"Новых нод нет — все уже в списке.";
            } else {
                message = @"Не нашёл ни одной ссылки. Проверьте отчёт ниже.";
            }
            error = [NSError errorWithDomain:@"com.vela.store" code:1
                                    userInfo:@{NSLocalizedDescriptionKey: message}];
        }
        dispatch_async(dispatch_get_main_queue(), ^{
            completion(added, error);
        });
    });
}

- (void)collectText:(NSString *)text
              depth:(NSUInteger)depth
              found:(NSMutableArray<NSString *> *)found
               urls:(NSMutableArray<NSString *> *)urls
       placeholders:(NSUInteger *)placeholders {
    for (NSString *raw in [text componentsSeparatedByCharactersInSet:[NSCharacterSet newlineCharacterSet]]) {
        NSString *line = [raw stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
        if (line.length == 0 || [line hasPrefix:@"#"]) continue;
        NSString *lower = line.lowercaseString;
        if ([lower hasPrefix:@"http://"] || [lower hasPrefix:@"https://"]) {
            if (depth == 0) [urls addObject:line];
            continue;
        }
        if (![HVPNLinkParser looksLikeLink:line]) continue;
        if ([HVPNLinkParser isPlaceholderLink:line]) {
            (*placeholders)++;
            continue;
        }
        [found addObject:line];
    }
}

- (void)fetchURLs:(NSMutableArray<NSString *> *)urls
            index:(NSUInteger)index
            found:(NSMutableArray<NSString *> *)found
     placeholders:(NSUInteger *)placeholders {
    if (index >= urls.count) return;

    NSString *urlText = urls[index];
    NSURL *url = [NSURL URLWithString:urlText];
    if (url == nil) {
        [self log:@"[-] %@ — некорректный URL", urlText];
        [self fetchURLs:urls index:index + 1 found:found placeholders:placeholders];
        return;
    }

    [self log:@"[..] %@", url.host ?: urlText];
    __block NSData *responseData = nil;
    __block NSHTTPURLResponse *httpResponse = nil;
    __block NSError *responseError = nil;
    dispatch_semaphore_t semaphore = dispatch_semaphore_create(0);

    NSURLSessionDataTask *task = [[NSURLSession sharedSession]
        dataTaskWithRequest:HVPNStoreSubscriptionRequest(url)
          completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
        responseData = data;
        responseError = error;
        if ([response isKindOfClass:[NSHTTPURLResponse class]]) httpResponse = (NSHTTPURLResponse *)response;
        dispatch_semaphore_signal(semaphore);
    }];
    [task resume];
    dispatch_semaphore_wait(semaphore, dispatch_time(DISPATCH_TIME_NOW, 40 * NSEC_PER_SEC));

    if (responseError != nil) {
        [self log:@"[-] %@ — сеть: %@", url.host ?: @"?", responseError.localizedDescription];
        [self fetchURLs:urls index:index + 1 found:found placeholders:placeholders];
        return;
    }

    NSString *userinfo = httpResponse.allHeaderFields[@"subscription-userinfo"];
    if ([userinfo isKindOfClass:[NSString class]] && userinfo.length) {
        self.subscriptionInfo = HVPNStoreFormatUserinfo(userinfo);
        [self log:@"[i] трафик: %@", self.subscriptionInfo];
    }

    NSInteger status = httpResponse.statusCode;
    NSString *head = [[NSString alloc] initWithData:
                      [responseData subdataWithRange:NSMakeRange(0, MIN((NSUInteger)60, responseData.length))]
                                            encoding:NSUTF8StringEncoding] ?: @"";
    head = [head stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];

    NSArray<NSString *> *parsed = [HVPNLinkParser linksFromSubscriptionData:responseData];
    NSString *format = @"ссылки";
    if (parsed.count == 0) {
        parsed = [HVPNLinkParser linksFromXrayConfigData:responseData];
        format = @"Xray-JSON";
    }
    if (parsed.count == 0 && [head hasPrefix:@"{"]) format = @"JSON (не распознан)";

    [self log:@"[%ld] HTTP %ld, %lu Б, формат: %@, нод: %lu",
          (long)(status ?: 0), (long)status, (unsigned long)responseData.length,
          format, (unsigned long)parsed.count];

    if (parsed.count == 0) {
        [self log:@"     начало ответа: %@", [head length] > 0 ? head : @"(пусто)"];
    } else {
        for (NSUInteger i = 0; i < MIN((NSUInteger)3, parsed.count); i++) {
            HVPNNode *node = [HVPNNode nodeFromLink:parsed[i]];
            [self log:@"     · %@ (%@ %@:%ld)", node.name, node.type, node.server, (long)node.port];
        }
    }

    if (self.subscriptionURL.length == 0) self.subscriptionURL = urlText;

    NSMutableString *joined = [NSMutableString string];
    for (NSString *link in parsed) [joined appendFormat:@"%@\n", link];
    [self collectText:joined depth:1 found:found urls:urls placeholders:placeholders];

    [self fetchURLs:urls index:index + 1 found:found placeholders:placeholders];
}

@end
