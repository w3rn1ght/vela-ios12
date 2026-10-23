// HappVPN — минимальный GUI для демона happvpnd.
// Всё, что делает приложение: собирает ссылки (в т.ч. https-подписки),
// отправляет их демону по unix-сокету и показывает статус.
#import <UIKit/UIKit.h>
#include <dispatch/dispatch.h>

#import "HVPNConfig.h"
#import "HVPNLinkParser.h"

#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/time.h>
#include <sys/utsname.h>

static NSString *const kSocketPath = @"/var/mobile/Library/HappVPN/control.sock";
static NSString *const kLinksDefaultsKey = @"HappVPNLinks";

#pragma mark - Клиент демона

static BOOL HVPNWriteAllKey(int fd, NSData *data) {
    const char *bytes = data.bytes;
    size_t left = data.length;
    while (left > 0) {
        ssize_t n = write(fd, bytes, left);
        if (n > 0) {
            bytes += n;
            left -= (size_t)n;
            continue;
        }
        if (n < 0 && errno == EINTR) continue;
        return NO;
    }
    return YES;
}

static NSData *HVPNSendRaw(NSDictionary *request, NSError **error) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        if (error) *error = [NSError errorWithDomain:@"com.happvpn.app" code:errno
                                            userInfo:@{NSLocalizedDescriptionKey: @"socket() failed"}];
        return nil;
    }

    struct timeval tv;
    tv.tv_sec = 60;
    tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, kSocketPath.fileSystemRepresentation, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        if (error) {
            *error = [NSError errorWithDomain:@"com.happvpn.app" code:errno
                                     userInfo:@{NSLocalizedDescriptionKey:
                                                    @"Демон не отвечает. Проверьте, что пакет установлен и "
                                                    @"happvpnd запущен (launchctl list | grep happvpn)."}];
        }
        return nil;
    }

    NSError *jsonError = nil;
    NSData *payload = [NSJSONSerialization dataWithJSONObject:request options:0 error:&jsonError];
    if (payload == nil) {
        close(fd);
        if (error) *error = jsonError;
        return nil;
    }
    NSMutableData *line = [payload mutableCopy];
    [line appendBytes:"\n" length:1];
    HVPNWriteAllKey(fd, line);
    shutdown(fd, SHUT_WR);

    NSMutableData *response = [NSMutableData data];
    char buf[4096];
    while (YES) {
        ssize_t n = read(fd, buf, sizeof(buf));
        if (n > 0) {
            [response appendBytes:buf length:(NSUInteger)n];
            continue;
        }
        if (n < 0 && errno == EINTR) continue;
        break;
    }
    close(fd);

    if (response.length == 0) {
        if (error) {
            *error = [NSError errorWithDomain:@"com.happvpn.app" code:EPIPE
                                     userInfo:@{NSLocalizedDescriptionKey: @"Демон закрыл соединение без ответа"}];
        }
        return nil;
    }
    return response;
}

static NSDictionary *HVPNSend(NSDictionary *request, NSError **error) {
    NSData *data = HVPNSendRaw(request, error);
    if (data == nil) return nil;
    id parsed = [NSJSONSerialization JSONObjectWithData:data options:0 error:NULL];
    if (![parsed isKindOfClass:[NSDictionary class]]) {
        if (error) {
            *error = [NSError errorWithDomain:@"com.happvpn.app" code:EINVAL
                                     userInfo:@{NSLocalizedDescriptionKey: @"Некорректный ответ демона"}];
        }
        return nil;
    }
    return parsed;
}

#pragma mark - Подписки

static NSString *HVPNTrim(NSString *s) {
    return [s stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
}

// Панели (Remnawave и совместимые) привязывают подписку к устройству по заголовку
// x-hwid: без него вместо нод отдают заглушки 0.0.0.0:1 с просьбой «включить HWID».
// Идентификатор генерируется один раз и живёт в NSUserDefaults.
static NSString *HVPNHWID(void) {
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    NSString *hwid = [defaults stringForKey:@"HappVPNHWID"];
    if (hwid.length == 0) {
        hwid = [[NSUUID UUID] UUIDString];
        [defaults setObject:hwid forKey:@"HappVPNHWID"];
        [defaults synchronize];
    }
    return hwid;
}

static NSString *HVPNDeviceModel(void) {
    struct utsname info;
    if (uname(&info) == 0) {
        NSString *machine = [NSString stringWithUTF8String:info.machine];
        if (machine.length) return machine;
    }
    return @"iPhone";
}

static NSString *HVPNLastSubscriptionInfo = nil;

static NSString *HVPNFormatBytes(long long bytes) {
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

// subscription-userinfo: upload=0; download=16145860601; total=0; expire=1795938367
static NSString *HVPNFormatUserinfo(NSString *raw) {
    if (raw.length == 0) return nil;
    long long download = 0, total = 0, expire = 0;
    for (NSString *part in [raw componentsSeparatedByString:@";"]) {
        NSString *pair = HVPNTrim(part);
        NSRange eq = [pair rangeOfString:@"="];
        if (eq.location == NSNotFound) continue;
        NSString *key = [pair substringToIndex:eq.location];
        long long value = [pair substringFromIndex:eq.location + 1].longLongValue;
        if ([key isEqualToString:@"download"]) download = value;
        else if ([key isEqualToString:@"total"]) total = value;
        else if ([key isEqualToString:@"expire"]) expire = value;
    }
    NSMutableString *text = [NSMutableString stringWithFormat:@"Трафик: %@", HVPNFormatBytes(download)];
    [text appendFormat:(total > 0 ? @" / %@" : @" (без лимита)"), total > 0 ? HVPNFormatBytes(total) : @""];
    if (expire > 0) {
        NSDateFormatter *formatter = [NSDateFormatter new];
        formatter.dateFormat = @"dd.MM.yyyy";
        [text appendFormat:@", до %@", [formatter stringFromDate:[NSDate dateWithTimeIntervalSince1970:expire]]];
    }
    return text;
}

static NSURLRequest *HVPNSubscriptionRequest(NSURL *url) {
    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:url];
    // Панели выбирают формат ответа по User-Agent: для v2ray-совместимых клиентов
    // отдают обычный base64-список ссылок, для Happ — свой JSON.
    [request setValue:@"v2rayNG/1.8.5" forHTTPHeaderField:@"User-Agent"];
    [request setValue:HVPNHWID() forHTTPHeaderField:@"x-hwid"];
    [request setValue:@"iOS" forHTTPHeaderField:@"x-device-os"];
    [request setValue:[[UIDevice currentDevice] systemVersion] forHTTPHeaderField:@"x-ver-os"];
    [request setValue:HVPNDeviceModel() forHTTPHeaderField:@"x-device-model"];
    [request setValue:@"*/*" forHTTPHeaderField:@"Accept"];
    request.timeoutInterval = 30;
    return request;
}

static void HVPNCollectLinks(NSString *text,
                            NSUInteger depth,
                            void (^completion)(NSArray<NSString *> *links, NSError *error));

static void HVPNFetchSubscriptions(NSArray<NSString *> *urls,
                                   NSUInteger index,
                                   NSMutableArray<NSString *> *links,
                                   void (^completion)(NSArray<NSString *> *, NSError *)) {
    if (index >= urls.count) {
        completion(links, nil);
        return;
    }
    NSURL *url = [NSURL URLWithString:urls[index]];
    if (url == nil) {
        HVPNFetchSubscriptions(urls, index + 1, links, completion);
        return;
    }
    NSURLSessionDataTask *task = [[NSURLSession sharedSession]
        dataTaskWithRequest:HVPNSubscriptionRequest(url)
          completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
        if ([response isKindOfClass:[NSHTTPURLResponse class]]) {
            NSString *userinfo = [(NSHTTPURLResponse *)response allHeaderFields][@"subscription-userinfo"];
            if ([userinfo isKindOfClass:[NSString class]] && userinfo.length) {
                HVPNLastSubscriptionInfo = userinfo;
            }
        }
        NSMutableArray<NSString *> *found = [NSMutableArray array];
        if (data.length) {
            NSArray<NSString *> *parsed = [HVPNLinkParser linksFromSubscriptionData:data];
            if (parsed.count) [found addObjectsFromArray:parsed];
        }
        if (found.count == 0) {
            HVPNFetchSubscriptions(urls, index + 1, links, completion);
            return;
        }
        // Внутри подписки могут быть свои подписки — рекурсия ограничена depth.
        NSMutableString *joined = [NSMutableString string];
        for (NSString *link in found) [joined appendFormat:@"%@\n", link];
        HVPNCollectLinks(joined, 2, ^(NSArray<NSString *> *nested, NSError *nestedError) {
            [links addObjectsFromArray:nested];
            HVPNFetchSubscriptions(urls, index + 1, links, completion);
        });
    }];
    [task resume];
}

static void HVPNCollectLinks(NSString *text,
                            NSUInteger depth,
                            void (^completion)(NSArray<NSString *> *links, NSError *error)) {
    NSMutableArray<NSString *> *links = [NSMutableArray array];
    NSMutableArray<NSString *> *urls = [NSMutableArray array];
    NSUInteger placeholders = 0;

    for (NSString *line in [text componentsSeparatedByCharactersInSet:[NSCharacterSet newlineCharacterSet]]) {
        NSString *t = HVPNTrim(line);
        if (t.length == 0 || [t hasPrefix:@"#"]) continue;
        NSString *lower = t.lowercaseString;
        if ([lower hasPrefix:@"http://"] || [lower hasPrefix:@"https://"]) {
            [urls addObject:t];
        } else if ([HVPNLinkParser isPlaceholderLink:t]) {
            placeholders++;
        } else {
            [links addObject:t];
        }
    }

    if (urls.count == 0 || depth > 1) {
        if (links.count == 0 && placeholders > 0) {
            completion(links, [NSError errorWithDomain:@"com.happvpn.app" code:1
                                              userInfo:@{NSLocalizedDescriptionKey:
                @"Сервер отдал только заглушки (0.0.0.0:1) вместо нод. Обычно это значит, "
                @"что подписка не активирована/истекла или исчерпан лимит устройств."}]);
            return;
        }
        completion(links, nil);
        return;
    }

    HVPNFetchSubscriptions(urls, 0, links, ^(NSArray<NSString *> *all, NSError *error) {
        if (all.count == 0 && placeholders > 0) {
            completion(all, [NSError errorWithDomain:@"com.happvpn.app" code:1
                                            userInfo:@{NSLocalizedDescriptionKey:
                @"Сервер отдал только заглушки (0.0.0.0:1) вместо нод. Обычно это значит, "
                @"что подписка не активирована/истекла или исчерпан лимит устройств."}]);
            return;
        }
        completion(all, error);
    });
}

#pragma mark - UI

static NSString *HVPNUptime(NSInteger seconds) {
    return [NSString stringWithFormat:@"%02ld:%02ld:%02ld",
            (long)(seconds / 3600), (long)((seconds % 3600) / 60), (long)(seconds % 60)];
}

@interface HVPNViewController : UIViewController <UITextViewDelegate>
@property (nonatomic, strong) UITextView *linksView;
@property (nonatomic, strong) UIButton *connectButton;
@property (nonatomic, strong) UIButton *logButton;
@property (nonatomic, strong) UILabel *statusLabel;
@property (nonatomic, strong) UITextView *logView;
@property (nonatomic, strong) NSTimer *timer;
@property (nonatomic, strong) NSDictionary *lastStatus;
@property (nonatomic, assign) BOOL busy;
@property (nonatomic, assign) BOOL polling;
@end

@implementation HVPNViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    self.title = @"HappVPN";
    self.view.backgroundColor = [UIColor colorWithWhite:0.96 alpha:1.0];

    CGFloat width = self.view.bounds.size.width;
    CGFloat height = self.view.bounds.size.height;

    UILabel *linksCaption = [[UILabel alloc] initWithFrame:CGRectMake(16, 10, width - 32, 18)];
    linksCaption.text = @"Ссылки или https-подписки (по одной в строке)";
    linksCaption.font = [UIFont systemFontOfSize:12];
    linksCaption.textColor = [UIColor darkGrayColor];
    [self.view addSubview:linksCaption];

    self.linksView = [[UITextView alloc] initWithFrame:CGRectMake(12, 32, width - 24, 132)];
    self.linksView.font = [UIFont fontWithName:@"Menlo" size:11] ?: [UIFont systemFontOfSize:11];
    self.linksView.autocapitalizationType = UITextAutocapitalizationTypeNone;
    self.linksView.autocorrectionType = UITextAutocorrectionTypeNo;
    self.linksView.spellCheckingType = UITextSpellCheckingTypeNo;
    self.linksView.keyboardType = UIKeyboardTypeURL;
    self.linksView.text = [[NSUserDefaults standardUserDefaults] stringForKey:kLinksDefaultsKey] ?: @"";
    self.linksView.layer.borderWidth = 0.5;
    self.linksView.layer.borderColor = [UIColor colorWithWhite:0.7 alpha:1.0].CGColor;
    self.linksView.layer.cornerRadius = 6;
    self.linksView.delegate = self;
    [self.view addSubview:self.linksView];

    self.connectButton = [UIButton buttonWithType:UIButtonTypeSystem];
    self.connectButton.frame = CGRectMake(12, 174, width - 100, 44);
    self.connectButton.titleLabel.font = [UIFont boldSystemFontOfSize:17];
    [self.connectButton setTitle:@"Подключить" forState:UIControlStateNormal];
    [self.connectButton addTarget:self action:@selector(toggleConnection:)
                 forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:self.connectButton];

    self.logButton = [UIButton buttonWithType:UIButtonTypeSystem];
    self.logButton.frame = CGRectMake(width - 84, 174, 72, 44);
    [self.logButton setTitle:@"Лог" forState:UIControlStateNormal];
    [self.logButton addTarget:self action:@selector(showLog:)
             forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:self.logButton];

    self.statusLabel = [[UILabel alloc] initWithFrame:CGRectMake(16, 224, width - 32, 56)];
    self.statusLabel.numberOfLines = 0;
    self.statusLabel.font = [UIFont systemFontOfSize:12];
    self.statusLabel.text = @"Проверяю демон…";
    [self.view addSubview:self.statusLabel];

    self.logView = [[UITextView alloc] initWithFrame:CGRectMake(12, 286, width - 24, height - 300)];
    self.logView.editable = NO;
    self.logView.font = [UIFont fontWithName:@"Menlo" size:9] ?: [UIFont systemFontOfSize:9];
    self.logView.autoresizingMask = UIViewAutoresizingFlexibleHeight;
    self.logView.backgroundColor = [UIColor colorWithWhite:1.0 alpha:0.7];
    self.logView.layer.borderWidth = 0.5;
    self.logView.layer.borderColor = [UIColor colorWithWhite:0.8 alpha:1.0].CGColor;
    self.logView.text = @"";
    [self.view addSubview:self.logView];

    self.timer = [NSTimer scheduledTimerWithTimeInterval:2.0
                                                 target:self
                                               selector:@selector(refreshStatus)
                                               userInfo:nil
                                                repeats:YES];
    [self refreshStatus];
}

- (void)viewWillDisappear:(BOOL)animated {
    [super viewWillDisappear:animated];
    [[NSUserDefaults standardUserDefaults] setObject:self.linksView.text forKey:kLinksDefaultsKey];
}

- (void)textViewDidEndEditing:(UITextView *)textView {
    [[NSUserDefaults standardUserDefaults] setObject:textView.text forKey:kLinksDefaultsKey];
}

#pragma mark Действия

- (void)toggleConnection:(id)sender {
    if (self.busy) return;
    [self.view endEditing:YES];
    [[NSUserDefaults standardUserDefaults] setObject:self.linksView.text forKey:kLinksDefaultsKey];

    BOOL running = [self.lastStatus[@"running"] boolValue];
    if (running) {
        [self stop];
    } else {
        [self start];
    }
}

- (void)start {
    NSString *text = HVPNTrim(self.linksView.text);
    if (text.length == 0) {
        [self alert:@"Вставьте хотя бы одну ссылку (vless://, vmess://, trojan://, ss://, hysteria2://, tuic://) или https-подписку."];
        return;
    }

    self.busy = YES;
    [self updateButtons];
    self.logView.text = @"Читаю подписки и запускаю ядро…";

    HVPNCollectLinks(text, 0, ^(NSArray<NSString *> *links, NSError *error) {
        // Подписки тянутся в фоне — возвращаемся в main перед работой с UI.
        dispatch_async(dispatch_get_main_queue(), ^{
            if (links.count == 0) {
                self.busy = NO;
                [self updateButtons];
                self.logView.text = error.localizedDescription
                    ?: @"В подписках не найдено поддерживаемых ссылок.";
                [self alert:@"Не найдено ни одной поддерживаемой ссылки. happ:// ссылки нужно заменить на обычные (vless/vmess/trojan/ss/hysteria2)."];
                return;
            }
            NSMutableDictionary *request = [@{@"cmd": @"start", @"links": links} mutableCopy];
            request[@"options"] = @{
                @"bypassLAN": @YES,
                @"localDomains": @[@".local", @".lan", @".home", @".internal"]
            };
            self.logView.text = [NSString stringWithFormat:@"Запускаю ядро, нод: %lu…",
                                 (unsigned long)links.count];
            NSString *info = HVPNFormatUserinfo(HVPNLastSubscriptionInfo);
            if (info.length) {
                self.logView.text = [self.logView.text stringByAppendingFormat:@"\n%@", info];
            }

            dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
                NSError *sendError = nil;
                NSDictionary *response = HVPNSend(request, &sendError);
                dispatch_async(dispatch_get_main_queue(), ^{
                    self.busy = NO;
                    [self updateButtons];
                    if (response == nil) {
                        self.logView.text = sendError.localizedDescription ?: @"Нет ответа демона";
                        [self alert:self.logView.text];
                    } else if (![response[@"ok"] boolValue]) {
                        NSString *message = response[@"error"] ?: @"Не удалось подключиться";
                        self.logView.text = message;
                        [self alert:message];
                    } else {
                        self.logView.text = @"Подключено.";
                    }
                    [self refreshStatus];
                });
            });
        });
    });
}

- (void)stop {
    self.busy = YES;
    [self updateButtons];
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSError *error = nil;
        NSDictionary *response = HVPNSend(@{@"cmd": @"stop"}, &error);
        dispatch_async(dispatch_get_main_queue(), ^{
            self.busy = NO;
            [self updateButtons];
            if (response == nil) {
                self.logView.text = error.localizedDescription ?: @"Нет ответа демона";
            } else {
                self.logView.text = @"Отключено.";
            }
            [self refreshStatus];
        });
    });
}

- (void)showLog:(id)sender {
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        NSError *error = nil;
        NSDictionary *response = HVPNSend(@{@"cmd": @"log"}, &error);
        NSString *log = response[@"log"];
        dispatch_async(dispatch_get_main_queue(), ^{
            if (log.length) {
                self.logView.text = log;
            } else if (response == nil) {
                self.logView.text = error.localizedDescription ?: @"Нет ответа демона";
            } else {
                self.logView.text = @"Лог пуст.";
            }
        });
    });
}

#pragma mark Статус

- (void)refreshStatus {
    if (self.polling) return;
    self.polling = YES;
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        NSError *error = nil;
        NSDictionary *response = HVPNSend(@{@"cmd": @"status"}, &error);
        dispatch_async(dispatch_get_main_queue(), ^{
            self.polling = NO;
            if (response == nil) {
                self.lastStatus = nil;
                self.statusLabel.textColor = [UIColor grayColor];
                self.statusLabel.text = @"● демон не запущен\nпроверьте /Library/LaunchDaemons/com.happvpn.daemon.plist";
            } else {
                NSDictionary *status = [response[@"status"] isKindOfClass:[NSDictionary class]]
                    ? response[@"status"] : @{};
                self.lastStatus = status;
                BOOL running = [status[@"running"] boolValue];
                if (running) {
                    self.statusLabel.textColor = [UIColor colorWithRed:0.0 green:0.5 blue:0.1 alpha:1.0];
                    self.statusLabel.text = [NSString stringWithFormat:
                        @"● подключено: %@\n%@ %@ · %@ · uptime %@",
                        status[@"node"] ?: @"?",
                        status[@"protocol"] ?: @"",
                        status[@"server"] ?: @"",
                        status[@"utun"] ?: @"",
                        HVPNUptime([status[@"uptime"] integerValue])];
                } else {
                    self.statusLabel.textColor = [UIColor darkGrayColor];
                    self.statusLabel.text = [NSString stringWithFormat:@"○ отключено (v%@)",
                                             response[@"version"] ?: @"?"];
                }
            }
            [self updateButtons];
        });
    });
}

- (void)updateButtons {
    BOOL running = [self.lastStatus[@"running"] boolValue];
    self.connectButton.enabled = !self.busy;
    [self.connectButton setTitle:(running ? @"Отключить" : @"Подключить") forState:UIControlStateNormal];
    self.connectButton.tintColor = running
        ? [UIColor colorWithRed:0.7 green:0.1 blue:0.1 alpha:1.0]
        : [UIColor colorWithRed:0.0 green:0.4 blue:0.8 alpha:1.0];
}

- (void)alert:(NSString *)message {
    UIAlertController *controller = [UIAlertController alertControllerWithTitle:@"HappVPN"
                                                                        message:message
                                                                 preferredStyle:UIAlertControllerStyleAlert];
    [controller addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
    [self presentViewController:controller animated:YES completion:nil];
}

@end

#pragma mark - AppDelegate

@interface HVPNAppDelegate : UIResponder <UIApplicationDelegate>
@property (nonatomic, strong) UIWindow *window;
@end

@implementation HVPNAppDelegate

- (BOOL)application:(UIApplication *)application
didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
    self.window = [[UIWindow alloc] initWithFrame:[UIScreen mainScreen].bounds];
    HVPNViewController *root = [HVPNViewController new];
    UINavigationController *nav = [[UINavigationController alloc] initWithRootViewController:root];
    self.window.rootViewController = nav;
    [self.window makeKeyAndVisible];
    return YES;
}

@end

int main(int argc, char *argv[]) {
    @autoreleasepool {
        return UIApplicationMain(argc, argv, nil, @"HVPNAppDelegate");
    }
}
