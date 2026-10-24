// Vela — VPN-клиент для jailbroken iOS 12.
// UI: список нод (таблица), выбор активной, пинг, лог. Вся сеть — через демон velad.
#import <UIKit/UIKit.h>
#include <dispatch/dispatch.h>

#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/time.h>

#import "HVPNConfig.h"
#include <netdb.h>
#include <arpa/inet.h>
#import "HVPNLinkParser.h"
#import "HVPNPaths.h"
#import "HVPNStore.h"

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

static NSDictionary *HVPNSend(NSDictionary *request, NSError **error, NSTimeInterval timeout) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        if (error) *error = [NSError errorWithDomain:@"com.vela.app" code:errno
                                            userInfo:@{NSLocalizedDescriptionKey: @"socket() failed"}];
        return nil;
    }

    struct timeval tv;
    tv.tv_sec = (time_t)timeout;
    tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, HVPNControlSocketPath.fileSystemRepresentation, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        if (error) {
            *error = [NSError errorWithDomain:@"com.vela.app" code:errno
                                     userInfo:@{NSLocalizedDescriptionKey:
                @"Демон velad не отвечает. Проверьте, что пакет установлен и "
                @"`launchctl list | grep vela` показывает процесс."}];
        }
        return nil;
    }

    NSData *payload = [NSJSONSerialization dataWithJSONObject:request options:0 error:NULL];
    NSMutableData *line = [payload mutableCopy] ?: [NSMutableData data];
    [line appendBytes:"\n" length:1];
    HVPNWriteAllKey(fd, line);
    shutdown(fd, SHUT_WR);

    NSMutableData *response = [NSMutableData data];
    char buffer[4096];
    while (YES) {
        ssize_t n = read(fd, buffer, sizeof(buffer));
        if (n > 0) {
            [response appendBytes:buffer length:(NSUInteger)n];
            continue;
        }
        if (n < 0 && errno == EINTR) continue;
        break;
    }
    close(fd);

    id parsed = [NSJSONSerialization JSONObjectWithData:response options:0 error:NULL];
    if (![parsed isKindOfClass:[NSDictionary class]]) {
        if (error) *error = [NSError errorWithDomain:@"com.vela.app" code:EINVAL
                                            userInfo:@{NSLocalizedDescriptionKey: @"Некорректный ответ демона"}];
        return nil;
    }
    return parsed;
}

static NSDictionary *HVPNSendQuick(NSDictionary *request) {
    return HVPNSend(request, NULL, 60);
}

static NSString *HVPNPingText(HVPNNode *node) {
    if (!node.supported) return @"не поддерживается";
    if (node.pingMs > 0) return [NSString stringWithFormat:@"%ld мс", (long)node.pingMs];
    if (node.pingError.length) return node.pingError;
    return @"—";
}

#pragma mark - Экран добавления

@interface HVPNAddViewController : UIViewController <UITextViewDelegate>
@property (nonatomic, copy) void (^onFinish)(void);
@end

@implementation HVPNAddViewController {
    UITextView *_textView;
    UIButton *_addButton;
    UILabel *_hintLabel;
    UIActivityIndicatorView *_spinner;
}

- (void)viewDidLoad {
    [super viewDidLoad];
    self.title = @"Добавить";
    self.view.backgroundColor = [UIColor groupTableViewBackgroundColor];

    self.navigationItem.leftBarButtonItem =
        [[UIBarButtonItem alloc] initWithBarButtonSystemItem:UIBarButtonSystemItemCancel
                                                      target:self action:@selector(cancel)];
    self.navigationItem.rightBarButtonItem =
        [[UIBarButtonItem alloc] initWithTitle:@"Добавить" style:UIBarButtonItemStyleDone
                                        target:self action:@selector(add)];

    UILabel *caption = [UILabel new];
    caption.translatesAutoresizingMaskIntoConstraints = NO;
    caption.text = @"Ссылки или https-подписки — по одной в строке";
    caption.font = [UIFont systemFontOfSize:12];
    caption.textColor = [UIColor darkGrayColor];
    caption.numberOfLines = 0;
    [self.view addSubview:caption];

    _textView = [UITextView new];
    _textView.translatesAutoresizingMaskIntoConstraints = NO;
    _textView.font = [UIFont fontWithName:@"Menlo" size:12] ?: [UIFont systemFontOfSize:12];
    _textView.autocapitalizationType = UITextAutocapitalizationTypeNone;
    _textView.autocorrectionType = UITextAutocorrectionTypeNo;
    _textView.spellCheckingType = UITextSpellCheckingTypeNo;
    _textView.keyboardType = UIKeyboardTypeURL;
    _textView.backgroundColor = [UIColor whiteColor];
    _textView.layer.cornerRadius = 8;
    _textView.layer.borderWidth = 0.5;
    _textView.layer.borderColor = [UIColor colorWithWhite:0.75 alpha:1.0].CGColor;
    // Ключевое: внутренние отступы, чтобы текст не прилипал к краю и не «уезжал».
    _textView.textContainerInset = UIEdgeInsetsMake(10, 10, 10, 10);
    _textView.contentInset = UIEdgeInsetsZero;
    _textView.scrollIndicatorInsets = UIEdgeInsetsZero;
    _textView.delegate = self;
    _textView.text = @"";
    [self.view addSubview:_textView];

    _hintLabel = [UILabel new];
    _hintLabel.translatesAutoresizingMaskIntoConstraints = NO;
    _hintLabel.font = [UIFont systemFontOfSize:11];
    _hintLabel.textColor = [UIColor darkGrayColor];
    _hintLabel.numberOfLines = 0;
    _hintLabel.text = @"Поддерживаются vless, vmess, trojan, ss, hysteria2, tuic и https-подписки.";
    [self.view addSubview:_hintLabel];

    _spinner = [[UIActivityIndicatorView alloc] initWithActivityIndicatorStyle:UIActivityIndicatorViewStyleGray];
    _spinner.translatesAutoresizingMaskIntoConstraints = NO;
    _spinner.hidesWhenStopped = YES;
    [self.view addSubview:_spinner];

    UILayoutGuide *safe = self.view.safeAreaLayoutGuide;
    [NSLayoutConstraint activateConstraints:@[
        [caption.topAnchor constraintEqualToAnchor:safe.topAnchor constant:12],
        [caption.leadingAnchor constraintEqualToAnchor:safe.leadingAnchor constant:16],
        [caption.trailingAnchor constraintEqualToAnchor:safe.trailingAnchor constant:-16],

        [_textView.topAnchor constraintEqualToAnchor:caption.bottomAnchor constant:8],
        [_textView.leadingAnchor constraintEqualToAnchor:safe.leadingAnchor constant:12],
        [_textView.trailingAnchor constraintEqualToAnchor:safe.trailingAnchor constant:-12],
        [_textView.heightAnchor constraintEqualToConstant:220],

        [_hintLabel.topAnchor constraintEqualToAnchor:_textView.bottomAnchor constant:10],
        [_hintLabel.leadingAnchor constraintEqualToAnchor:safe.leadingAnchor constant:16],
        [_hintLabel.trailingAnchor constraintEqualToAnchor:safe.trailingAnchor constant:-16],

        [_spinner.topAnchor constraintEqualToAnchor:_hintLabel.bottomAnchor constant:12],
        [_spinner.centerXAnchor constraintEqualToAnchor:safe.centerXAnchor]
    ]];
}

- (void)viewDidAppear:(BOOL)animated {
    [super viewDidAppear:animated];
    [_textView becomeFirstResponder];
}

- (void)cancel {
    [self dismissViewControllerAnimated:YES completion:nil];
}

- (void)add {
    NSString *text = [_textView.text stringByTrimmingCharactersInSet:
                      [NSCharacterSet whitespaceAndNewlineCharacterSet]];
    if (text.length == 0) return;

    self.navigationItem.rightBarButtonItem.enabled = NO;
    [_spinner startAnimating];
    _hintLabel.text = @"Проверяю ссылки и подписки…";

    __weak HVPNAddViewController *weakSelf = self;
    [[HVPNStore shared] addFromText:text completion:^(NSUInteger added, NSError *error) {
        HVPNAddViewController *strongSelf = weakSelf;
        if (strongSelf == nil) return;
        [strongSelf->_spinner stopAnimating];
        strongSelf.navigationItem.rightBarButtonItem.enabled = YES;

        NSArray<NSString *> *diagnostics = [[HVPNStore shared] diagnostics];
        NSMutableString *report = [NSMutableString string];
        for (NSString *line in diagnostics) [report appendFormat:@"%@\n", line];

        if (added > 0) {
            strongSelf->_hintLabel.text = [NSString stringWithFormat:@"Добавлено нод: %lu",
                                           (unsigned long)added];
            if (strongSelf.onFinish) strongSelf.onFinish();
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.6 * NSEC_PER_SEC)),
                           dispatch_get_main_queue(), ^{
                [strongSelf dismissViewControllerAnimated:YES completion:nil];
            });
            return;
        }

        NSString *message = error.localizedDescription ?: @"Ничего не добавлено";
        UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Не получилось"
                                                                      message:[message stringByAppendingFormat:
                                                                               @"\n\n%@", report]
                                                                preferredStyle:UIAlertControllerStyleAlert];
        [alert addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
        [strongSelf presentViewController:alert animated:YES completion:nil];
        strongSelf->_hintLabel.text = message;
    }];
}

@end

#pragma mark - Настройки (HWID)

@interface HVPNSettingsViewController : UIViewController
@end

@implementation HVPNSettingsViewController {
    UILabel *_hwidLabel;
    UILabel *_statusLabel;
    UITextField *_hwidField;
    UIActivityIndicatorView *_spinner;
}

- (void)viewDidLoad {
    [super viewDidLoad];
    self.title = @"Настройки";
    self.view.backgroundColor = [UIColor groupTableViewBackgroundColor];
    self.navigationItem.rightBarButtonItem =
        [[UIBarButtonItem alloc] initWithBarButtonSystemItem:UIBarButtonSystemItemDone
                                                      target:self action:@selector(close)];

    UIScrollView *scroll = [UIScrollView new];
    scroll.translatesAutoresizingMaskIntoConstraints = NO;
    scroll.alwaysBounceVertical = YES;
    [self.view addSubview:scroll];

    UIStackView *stack = [UIStackView new];
    stack.translatesAutoresizingMaskIntoConstraints = NO;
    stack.axis = UILayoutConstraintAxisVertical;
    stack.spacing = 12;
    [scroll addSubview:stack];

    UILabel *caption = [UILabel new];
    caption.text = @"HWID устройства — заголовок x-hwid, по нему панель привязывает подписку к телефону. "
                   @"Если на подписке лимит устройств, панель отдаёт заглушки 0.0.0.0:1.";
    caption.numberOfLines = 0;
    caption.font = [UIFont systemFontOfSize:13];
    [stack addArrangedSubview:caption];

    _hwidLabel = [UILabel new];
    _hwidLabel.font = [UIFont fontWithName:@"Menlo" size:12] ?: [UIFont systemFontOfSize:12];
    _hwidLabel.numberOfLines = 0;
    _hwidLabel.text = [NSString stringWithFormat:@"текущий: %@", [HVPNStore currentHWID]];
    [stack addArrangedSubview:_hwidLabel];

    _hwidField = [UITextField new];
    _hwidField.placeholder = @"вставить HWID другого устройства";
    _hwidField.font = [UIFont fontWithName:@"Menlo" size:12] ?: [UIFont systemFontOfSize:12];
    _hwidField.borderStyle = UITextBorderStyleRoundedRect;
    _hwidField.autocapitalizationType = UITextAutocapitalizationTypeNone;
    _hwidField.autocorrectionType = UITextAutocorrectionTypeNo;
    _hwidField.clearButtonMode = UITextFieldViewModeWhileEditing;
    [stack addArrangedSubview:_hwidField];

    UIButton *apply = [UIButton buttonWithType:UIButtonTypeSystem];
    [apply setTitle:@"Применить этот HWID" forState:UIControlStateNormal];
    [apply addTarget:self action:@selector(applyHWID) forControlEvents:UIControlEventTouchUpInside];
    [stack addArrangedSubview:apply];

    UIButton *fresh = [UIButton buttonWithType:UIButtonTypeSystem];
    [fresh setTitle:@"Сгенерировать новый HWID" forState:UIControlStateNormal];
    [fresh addTarget:self action:@selector(resetHWID) forControlEvents:UIControlEventTouchUpInside];
    [stack addArrangedSubview:fresh];

    UIButton *refresh = [UIButton buttonWithType:UIButtonTypeSystem];
    [refresh setTitle:@"Обновить подписку" forState:UIControlStateNormal];
    [refresh addTarget:self action:@selector(refreshSubscription) forControlEvents:UIControlEventTouchUpInside];
    [stack addArrangedSubview:refresh];

    UIButton *routes = [UIButton buttonWithType:UIButtonTypeSystem];
    [routes setTitle:@"Сбросить маршруты (если пропал интернет)" forState:UIControlStateNormal];
    [routes addTarget:self action:@selector(resetRoutes) forControlEvents:UIControlEventTouchUpInside];
    [stack addArrangedSubview:routes];

    _spinner = [[UIActivityIndicatorView alloc] initWithActivityIndicatorStyle:UIActivityIndicatorViewStyleGray];
    _spinner.hidesWhenStopped = YES;
    [stack addArrangedSubview:_spinner];

    _statusLabel = [UILabel new];
    _statusLabel.numberOfLines = 0;
    _statusLabel.font = [UIFont systemFontOfSize:12];
    _statusLabel.textColor = [UIColor darkGrayColor];
    _statusLabel.text = [NSString stringWithFormat:@"отчёт: %@", [HVPNStore shared].diagnosticsPath];
    [stack addArrangedSubview:_statusLabel];

    UILayoutGuide *safe = self.view.safeAreaLayoutGuide;
    [NSLayoutConstraint activateConstraints:@[
        [scroll.topAnchor constraintEqualToAnchor:safe.topAnchor],
        [scroll.leadingAnchor constraintEqualToAnchor:safe.leadingAnchor],
        [scroll.trailingAnchor constraintEqualToAnchor:safe.trailingAnchor],
        [scroll.bottomAnchor constraintEqualToAnchor:safe.bottomAnchor],

        [stack.topAnchor constraintEqualToAnchor:scroll.topAnchor constant:16],
        [stack.leadingAnchor constraintEqualToAnchor:scroll.leadingAnchor constant:16],
        [stack.trailingAnchor constraintEqualToAnchor:scroll.trailingAnchor constant:-16],
        [stack.bottomAnchor constraintEqualToAnchor:scroll.bottomAnchor constant:-16],
        [stack.widthAnchor constraintEqualToAnchor:scroll.widthAnchor constant:-32]
    ]];
}

- (void)close {
    [self dismissViewControllerAnimated:YES completion:nil];
}

- (void)applyHWID {
    NSString *text = _hwidField.text;
    if (text.length == 0) return;
    [HVPNStore setHWID:text];
    _hwidField.text = @"";
    _hwidLabel.text = [NSString stringWithFormat:@"текущий: %@", [HVPNStore currentHWID]];
    _statusLabel.text = @"HWID применён. Нажмите «Обновить подписку».";
    [self.view endEditing:YES];
}

- (void)resetHWID {
    [HVPNStore resetHWID];
    _hwidLabel.text = [NSString stringWithFormat:@"текущий: %@", [HVPNStore currentHWID]];
    _statusLabel.text = @"Сгенерирован новый HWID. Нажмите «Обновить подписку».";
}

- (void)resetRoutes {
    _statusLabel.text = @"Снимаю оставшиеся маршруты…";
    __weak HVPNSettingsViewController *weakSelf = self;
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSDictionary *response = HVPNSend(@{@"cmd": @"cleanup"}, NULL, 20);
        dispatch_async(dispatch_get_main_queue(), ^{
            HVPNSettingsViewController *strongSelf = weakSelf;
            if (strongSelf == nil) return;
            strongSelf->_statusLabel.text = response
                ? @"Маршруты сброшены. Проверьте интернет (Safari)."
                : @"Демон не отвечает — маршруты не сброшены.";
        });
    });
}

- (void)refreshSubscription {
    NSString *url = [HVPNStore shared].subscriptionURL;
    if (url.length == 0) {
        _statusLabel.text = @"Сначала добавьте подписку через «＋».";
        return;
    }
    [_spinner startAnimating];
    _statusLabel.text = @"Запрашиваю подписку…";
    __weak HVPNSettingsViewController *weakSelf = self;
    [[HVPNStore shared] addFromText:url completion:^(NSUInteger added, NSError *error) {
        HVPNSettingsViewController *strongSelf = weakSelf;
        if (strongSelf == nil) return;
        [strongSelf->_spinner stopAnimating];
        NSMutableString *report = [NSMutableString string];
        NSArray<NSString *> *diagnostics = [HVPNStore shared].diagnostics;
        for (NSString *line in diagnostics) {
            [report appendFormat:@"%@\n", line];
            if (report.length > 900) break;
        }
        strongSelf->_statusLabel.text = [NSString stringWithFormat:@"%@\n%@",
                                         error.localizedDescription ?: [NSString stringWithFormat:@"+%lu нод", (unsigned long)added],
                                         report];
        [[NSNotificationCenter defaultCenter] postNotificationName:@"VelaNodesChanged" object:nil];
    }];
}

@end

#pragma mark - Лог

@interface HVPNLogViewController : UIViewController
@end

@implementation HVPNLogViewController {
    UITextView *_textView;
    UIBarButtonItem *_youtubeItem;
}

- (void)viewDidLoad {
    [super viewDidLoad];
    self.title = @"Лог";
    self.view.backgroundColor = [UIColor whiteColor];
    self.navigationItem.rightBarButtonItem =
        [[UIBarButtonItem alloc] initWithBarButtonSystemItem:UIBarButtonSystemItemDone
                                                      target:self action:@selector(close)];
    // Проверка «а проходит ли YouTube через туннель»: DNS, HTTP и Innertube.
    _youtubeItem = [[UIBarButtonItem alloc] initWithTitle:@"YouTube"
                                                    style:UIBarButtonItemStylePlain
                                                   target:self action:@selector(checkYouTube)];
    self.navigationItem.leftBarButtonItem = _youtubeItem;

    _textView = [UITextView new];
    _textView.translatesAutoresizingMaskIntoConstraints = NO;
    _textView.editable = NO;
    _textView.font = [UIFont fontWithName:@"Menlo" size:10] ?: [UIFont systemFontOfSize:10];
    _textView.textContainerInset = UIEdgeInsetsMake(10, 10, 10, 10);
    _textView.text = @"загружаю…";
    [self.view addSubview:_textView];

    UILayoutGuide *safe = self.view.safeAreaLayoutGuide;
    [NSLayoutConstraint activateConstraints:@[
        [_textView.topAnchor constraintEqualToAnchor:safe.topAnchor],
        [_textView.leadingAnchor constraintEqualToAnchor:safe.leadingAnchor],
        [_textView.trailingAnchor constraintEqualToAnchor:safe.trailingAnchor],
        [_textView.bottomAnchor constraintEqualToAnchor:safe.bottomAnchor]
    ]];

    NSMutableString *text = [NSMutableString string];
    for (NSString *line in [HVPNStore shared].diagnostics) [text appendFormat:@"%@\n", line];
    if (text.length == 0) [text appendString:@"(отчётов о подписках нет)\n"];

    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        NSDictionary *response = HVPNSend(@{@"cmd": @"log"}, NULL, 10);
        NSString *coreLog = [response[@"log"] isKindOfClass:[NSString class]] ? response[@"log"] : nil;
        NSDictionary *status = [response[@"status"] isKindOfClass:[NSDictionary class]]
            ? response[@"status"] : nil;
        NSMutableString *state = [NSMutableString string];
        if (status) {
            [state appendFormat:@"демон: v%@\n", response[@"version"] ?: @"?"];
            [state appendFormat:@"нода: %@ (%@)\n",
                status[@"node"] ?: @"-", status[@"protocol"] ?: @"-"];
            [state appendFormat:@"адрес: %@:%@\n", status[@"server"] ?: @"-",
                status[@"port"] ?: @"-"];
            [state appendFormat:@"интерфейс: %@, маршрутов %@\n",
                status[@"utun"] ?: @"-", status[@"routes"] ?: @"0"];
            NSDictionary *probe = [status[@"probe"] isKindOfClass:[NSDictionary class]]
                ? status[@"probe"] : nil;
            if (probe) {
                [state appendFormat:@"проба: %@%@\n",
                    [probe[@"ok"] boolValue] ? @"ok " : @"НЕТ ТРАФИКА ",
                    [probe[@"ok"] boolValue] ? [NSString stringWithFormat:@"%@ мс", probe[@"ms"] ?: @"?"]
                                            : (probe[@"error"] ?: @"")];
            }
            if ([status[@"outbound"] length]) {
                [state appendFormat:@"outbound: %@\n", status[@"outbound"]];
            }
        } else {
            [state appendString:@"демон не отвечает\n"];
        }
        dispatch_async(dispatch_get_main_queue(), ^{
            [text appendString:@"\n— состояние —\n"];
            [text appendString:state];
            [text appendString:@"\n— ядро —\n"];
            [text appendString:coreLog.length ? coreLog : @"(лог пуст или демон не запущен)"];
            self->_textView.text = text;
        });
    });
}

- (void)close {
    [self dismissViewControllerAnimated:YES completion:nil];
}

- (void)appendLogText:(NSString *)text {
    _textView.text = [_textView.text stringByAppendingString:text];
    NSRange end = NSMakeRange(_textView.text.length, 0);
    [_textView scrollRangeToVisible:end];
}

- (NSString *)probeURL:(NSString *)urlString
               session:(NSURLSession *)session
                  post:(NSString *)body {
    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:urlString]];
    request.timeoutInterval = 15;
    [request setValue:@"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                       @"(KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36"
   forHTTPHeaderField:@"User-Agent"];
    if (body.length) {
        request.HTTPMethod = @"POST";
        [request setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];
        request.HTTPBody = [body dataUsingEncoding:NSUTF8StringEncoding];
    }

    __block NSData *data = nil;
    __block NSHTTPURLResponse *http = nil;
    __block NSError *error = nil;
    dispatch_semaphore_t semaphore = dispatch_semaphore_create(0);
    [[session dataTaskWithRequest:request
               completionHandler:^(NSData *body2, NSURLResponse *raw, NSError *taskError) {
        data = body2;
        error = taskError;
        if ([raw isKindOfClass:[NSHTTPURLResponse class]]) http = (NSHTTPURLResponse *)raw;
        dispatch_semaphore_signal(semaphore);
    }] resume];
    dispatch_semaphore_wait(semaphore, dispatch_time(DISPATCH_TIME_NOW, 20 * NSEC_PER_SEC));

    NSString *host = request.URL.host ?: urlString;
    if (error) {
        return [NSString stringWithFormat:@"%@: ошибка — %@\n", host, error.localizedDescription];
    }
    NSString *head = @"";
    if (data.length) {
        NSUInteger take = MIN((NSUInteger)80, data.length);
        head = [[NSString alloc] initWithData:[data subdataWithRange:NSMakeRange(0, take)]
                                     encoding:NSUTF8StringEncoding] ?: @"";
        head = [head stringByReplacingOccurrencesOfString:@"\n" withString:@" "];
    }
    return [NSString stringWithFormat:@"%@: HTTP %ld, %lu Б%@\n", host, (long)http.statusCode,
            (unsigned long)data.length,
            (http.statusCode >= 400 && head.length) ? [@" — " stringByAppendingString:head] : @""];
}

- (NSString *)dnsProbe:(NSString *)name qtype:(int)qtype {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return @"socket() не удался";
    struct timeval tv = {5, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(53);
    inet_pton(AF_INET, "1.1.1.1", &addr.sin_addr);

    uint8_t query[512];
    NSUInteger n = 0;
    uint16_t ident = (uint16_t)arc4random_uniform(0xffff);
    query[n++] = (uint8_t)(ident >> 8);
    query[n++] = (uint8_t)(ident & 0xff);
    query[n++] = 0x01;   // RD
    query[n++] = 0x00;
    query[n++] = 0x00;   // QDCOUNT
    query[n++] = 0x01;
    for (int i = 0; i < 6; i++) query[n++] = 0;   // AN/NS/AR

    for (NSString *part in [name componentsSeparatedByString:@"."]) {
        NSData *chunk = [part dataUsingEncoding:NSUTF8StringEncoding];
        if (chunk.length == 0 || chunk.length > 63) { close(fd); return @"плохое имя"; }
        query[n++] = (uint8_t)chunk.length;
        memcpy(query + n, chunk.bytes, chunk.length);
        n += chunk.length;
    }
    query[n++] = 0;
    query[n++] = (uint8_t)(qtype >> 8);
    query[n++] = (uint8_t)(qtype & 0xff);
    query[n++] = 0;
    query[n++] = 1;

    sendto(fd, query, n, 0, (struct sockaddr *)&addr, sizeof(addr));
    uint8_t reply[1024];
    ssize_t got = recv(fd, reply, sizeof(reply), 0);
    close(fd);
    if (got < 12) return @"нет ответа за 5 с";
    int rcode = reply[3] & 0x0f;
    int answers = (reply[6] << 8) | reply[7];
    return [NSString stringWithFormat:@"rcode=%d, ответов=%d%s", rcode, answers,
            rcode == 3 ? " (NXDOMAIN)" : (rcode == 2 ? " (SERVFAIL)" : "")];
}

- (void)checkYouTube {
    _youtubeItem.enabled = NO;
    [self appendLogText:@"\n— проверка YouTube —\n"];
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSMutableString *out = [NSMutableString string];

        struct addrinfo hints;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        struct addrinfo *res = NULL;
        if (getaddrinfo("www.youtube.com", "443", &hints, &res) == 0) {
            NSMutableArray *v4 = [NSMutableArray array];
            NSMutableArray *v6 = [NSMutableArray array];
            for (struct addrinfo *p = res; p != NULL; p = p->ai_next) {
                char buf[INET6_ADDRSTRLEN] = {0};
                if (p->ai_family == AF_INET) {
                    inet_ntop(AF_INET, &((struct sockaddr_in *)p->ai_addr)->sin_addr, buf, sizeof(buf));
                    [v4 addObject:@(buf)];
                } else if (p->ai_family == AF_INET6) {
                    inet_ntop(AF_INET6, &((struct sockaddr_in6 *)p->ai_addr)->sin6_addr, buf, sizeof(buf));
                    [v6 addObject:@(buf)];
                }
            }
            freeaddrinfo(res);
            [out appendFormat:@"DNS www.youtube.com: A=%lu AAAA=%lu", (unsigned long)v4.count,
                              (unsigned long)v6.count];
            if (v4.count) [out appendFormat:@"\n  A: %@", [v4 componentsJoinedByString:@", "]];
            if (v6.count) [out appendFormat:@"\n  AAAA: %@", [v6 componentsJoinedByString:@", "]];
            [out appendString:@"\n"];
        } else {
            [out appendString:@"DNS www.youtube.com: не разрешился\n"];
        }

        [out appendFormat:@"DNS-модуль (запрос в 1.1.1.1:53 через туннель):\n"];
        [out appendFormat:@"  www.youtube.com A:    %@\n", [self dnsProbe:@"www.youtube.com" qtype:1]];
        [out appendFormat:@"  www.youtube.com AAAA: %@\n", [self dnsProbe:@"www.youtube.com" qtype:28]];
        [out appendFormat:@"  i.ytimg.com A:        %@\n", [self dnsProbe:@"i.ytimg.com" qtype:1]];
        [out appendFormat:@"  admin.fixcord.gg A:   %@\n", [self dnsProbe:@"admin.fixcord.gg" qtype:1]];

        NSURLSessionConfiguration *config = [NSURLSessionConfiguration ephemeralSessionConfiguration];
        config.timeoutIntervalForRequest = 15;
        NSURLSession *session = [NSURLSession sessionWithConfiguration:config];
        [out appendString:[self probeURL:@"https://www.youtube.com/generate_204" session:session post:nil]];
        [out appendString:[self probeURL:@"https://i.ytimg.com/generate_204" session:session post:nil]];
        NSString *body = @"{\"context\":{\"client\":{\"clientName\":\"WEB\",\"clientVersion\":\"2.20240101.00.00\",\"hl\":\"en\",\"gl\":\"US\"}},\"browseId\":\"FEwhat_to_watch\"}";
        [out appendString:[self probeURL:@"https://www.youtube.com/youtubei/v1/browse?key=AIzaSyAO_FJ2SlqU8Q4STEHLGCilw_Y9_11qcW8"
                                 session:session post:body]];

        // Что ядро само говорит про DNS — если транспорт падает, тут будет причина.
        NSDictionary *logResponse = HVPNSend(@{@"cmd": @"log"}, NULL, 10);
        NSString *coreLog = [logResponse[@"log"] isKindOfClass:[NSString class]] ? logResponse[@"log"] : nil;
        if (coreLog.length) {
            NSMutableArray<NSString *> *dnsLines = [NSMutableArray array];
            for (NSString *line in [coreLog componentsSeparatedByString:@"\n"]) {
                if ([line.lowercaseString rangeOfString:@"dns"].location != NSNotFound) {
                    [dnsLines addObject:line];
                }
            }
            [out appendFormat:@"\nядро, строки про DNS: %lu\n", (unsigned long)dnsLines.count];
            NSUInteger take = MIN((NSUInteger)8, dnsLines.count);
            for (NSUInteger i = dnsLines.count - take; i < dnsLines.count; i++) {
                [out appendFormat:@"  %@\n", dnsLines[i]];
            }
        }

        dispatch_async(dispatch_get_main_queue(), ^{
            self->_youtubeItem.enabled = YES;
            [self appendLogText:out];
        });
    });
}

@end

#pragma mark - Список нод

@interface HVPNNodesViewController : UITableViewController


@end

@implementation HVPNNodesViewController {
    UILabel *_statusLabel;
    UIButton *_connectButton;
    NSDictionary *_lastStatus;
    BOOL _busy;
    BOOL _pinging;
    BOOL _polling;
    NSTimer *_timer;
    NSUInteger _pingRemaining;
}

- (void)viewDidLoad {
    [super viewDidLoad];
    self.title = @"Vela";
    self.tableView.rowHeight = 58;
    self.tableView.tableFooterView = [UIView new];

    UIBarButtonItem *addItem =
        [[UIBarButtonItem alloc] initWithBarButtonSystemItem:UIBarButtonSystemItemAdd
                                                      target:self action:@selector(showAdd)];
    UIBarButtonItem *gearItem =
        [[UIBarButtonItem alloc] initWithTitle:@"⚙" style:UIBarButtonItemStylePlain
                                        target:self action:@selector(showSettings)];
    UIBarButtonItem *autoItem =
        [[UIBarButtonItem alloc] initWithTitle:@"🔍" style:UIBarButtonItemStylePlain
                                        target:self action:@selector(autoPick)];
    self.navigationItem.rightBarButtonItems = @[addItem, gearItem, autoItem];
    self.navigationItem.leftBarButtonItem =
        [[UIBarButtonItem alloc] initWithTitle:@"Лог" style:UIBarButtonItemStylePlain
                                        target:self action:@selector(showLogAction:)];

    [[NSNotificationCenter defaultCenter] addObserver:self
                                             selector:@selector(nodesChanged)
                                                 name:@"VelaNodesChanged"
                                               object:nil];

    UIView *header = [[UIView alloc] initWithFrame:CGRectMake(0, 0, self.view.bounds.size.width, 56)];
    _statusLabel = [[UILabel alloc] initWithFrame:CGRectMake(16, 6, header.bounds.size.width - 32, 44)];
    _statusLabel.autoresizingMask = UIViewAutoresizingFlexibleWidth;
    _statusLabel.numberOfLines = 2;
    _statusLabel.font = [UIFont systemFontOfSize:12];
    _statusLabel.text = @"Проверяю демон…";
    _statusLabel.textColor = [UIColor darkGrayColor];
    _statusLabel.userInteractionEnabled = YES;
    [_statusLabel addGestureRecognizer:
        [[UITapGestureRecognizer alloc] initWithTarget:self action:@selector(probeTapped)]];
    [header addSubview:_statusLabel];
    self.tableView.tableHeaderView = header;

    UIView *footer = [[UIView alloc] initWithFrame:CGRectMake(0, 0, self.view.bounds.size.width, 68)];
    footer.backgroundColor = [UIColor clearColor];
    _connectButton = [UIButton buttonWithType:UIButtonTypeSystem];
    _connectButton.frame = CGRectMake(12, 10, footer.bounds.size.width - 24, 48);
    _connectButton.autoresizingMask = UIViewAutoresizingFlexibleWidth;
    _connectButton.titleLabel.font = [UIFont boldSystemFontOfSize:17];
    _connectButton.layer.cornerRadius = 10;
    _connectButton.backgroundColor = [UIColor whiteColor];
    [_connectButton setTitle:@"Подключить" forState:UIControlStateNormal];
    [_connectButton addTarget:self action:@selector(toggleConnection)
             forControlEvents:UIControlEventTouchUpInside];
    [footer addSubview:_connectButton];
    // Кнопка живёт внизу экрана, а не в конце списка из 150 нод.
    footer.autoresizingMask = UIViewAutoresizingFlexibleWidth;
    footer.tag = 555;
    [self.view addSubview:footer];

    self.tableView.contentInset = UIEdgeInsetsMake(0, 0, 76, 0);
    self.tableView.scrollIndicatorInsets = UIEdgeInsetsMake(0, 0, 76, 0);

    self.refreshControl = [[UIRefreshControl alloc] init];
    [self.refreshControl addTarget:self action:@selector(pingAllAction:)
                  forControlEvents:UIControlEventValueChanged];

    _timer = [NSTimer scheduledTimerWithTimeInterval:2.0 target:self
                                            selector:@selector(refreshStatus)
                                            userInfo:nil repeats:YES];
    [self refreshStatus];
}

- (void)viewWillAppear:(BOOL)animated {
    [super viewWillAppear:animated];
    [self.tableView reloadData];
    [self refreshStatus];
}

- (void)viewDidLayoutSubviews {
    [super viewDidLayoutSubviews];
    UIView *bar = [self.view viewWithTag:555];
    if (bar == nil) return;
    CGRect safe = self.view.bounds;
    if (@available(iOS 11.0, *)) {
        safe = self.view.safeAreaLayoutGuide.layoutFrame;
    }
    bar.frame = CGRectMake(0, CGRectGetMaxY(safe) - 68, self.view.bounds.size.width, 68);
}

- (void)showLog {
    HVPNLogViewController *log = [HVPNLogViewController new];
    UINavigationController *nav = [[UINavigationController alloc] initWithRootViewController:log];
    [self presentViewController:nav animated:YES completion:nil];
}

- (void)showLogAction:(id)sender {
    [self showLog];
}

- (void)pingAllAction:(id)sender {
    [self pingAll];
}

- (void)reloadAndPing {
    [self.tableView reloadData];
    [self pingAll];
}

#pragma mark Действия

- (void)showAdd {
    HVPNAddViewController *add = [HVPNAddViewController new];
    add.onFinish = ^{ [self reloadAndPing]; };
    UINavigationController *nav = [[UINavigationController alloc] initWithRootViewController:add];
    [self presentViewController:nav animated:YES completion:nil];
}

- (void)showSettings {
    HVPNSettingsViewController *settings = [HVPNSettingsViewController new];
    UINavigationController *nav = [[UINavigationController alloc] initWithRootViewController:settings];
    [self presentViewController:nav animated:YES completion:nil];
}

- (void)nodesChanged {
    [self.tableView reloadData];
}

- (void)dealloc {
    [[NSNotificationCenter defaultCenter] removeObserver:self];
}

- (void)toggleConnection {
    if (_busy) return;
    BOOL running = [_lastStatus[@"running"] boolValue];

    if (running) {
        _busy = YES;
        [self updateUI];
        dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
            HVPNSendQuick(@{@"cmd": @"stop"});
            dispatch_async(dispatch_get_main_queue(), ^{
                self->_busy = NO;
                [self refreshStatus];
            });
        });
        return;
    }

    HVPNStore *store = [HVPNStore shared];
    [self connectToNode:[store nodeAtIndex:store.selectedIndex]];
}

- (void)connectToNode:(HVPNNode *)node {
    if (_busy) return;
    if (node == nil) {
        [self alert:@"Список пуст — добавьте ссылку или подписку."];
        return;
    }
    if (!node.supported) {
        [self alert:@"Эта нода использует неподдерживаемый транспорт (например xhttp). Выберите другую."];
        return;
    }

    _busy = YES;
    [self updateUI];
    NSDictionary *request = @{
        @"cmd": @"start",
        @"link": node.link,
        @"options": @{
            @"bypassLAN": @YES,
            @"localDomains": @[@".local", @".lan", @".home", @".internal"]
        }
    };
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSError *error = nil;
        NSDictionary *response = HVPNSend(request, &error, 90);
        dispatch_async(dispatch_get_main_queue(), ^{
            self->_busy = NO;
            if (response == nil) {
                [self alert:error.localizedDescription ?: @"Демон не отвечает"];
            } else if (![response[@"ok"] boolValue]) {
                [self alert:response[@"error"] ?: @"Не удалось подключиться"];
            } else {
                NSDictionary *probe = response[@"probe"];
                if ([probe isKindOfClass:[NSDictionary class]] &&
                    !([probe[@"ok"] boolValue])) {
                    [self alert:[NSString stringWithFormat:
                        @"Подключено, но трафик через туннель не идёт.\n%@\n\n"
                        @"Откройте «Журнал» — там лог ядра (sing-box).",
                        probe[@"error"] ?: @"причина неизвестна"]];
                }
            }
            [self refreshStatus];
        });
    });
}

// Автоподбор: перебираем ноды с хорошим пингом, пока какая-нибудь не пропустит трафик.
- (void)autoPick {
    if (_busy) return;
    NSArray<HVPNNode *> *all = [HVPNStore shared].nodes;
    NSMutableArray<NSNumber *> *plain = [NSMutableArray array];   // без REALITY
    NSMutableArray<NSNumber *> *reality = [NSMutableArray array];
    for (NSUInteger i = 0; i < all.count; i++) {
        HVPNNode *node = all[i];
        if (!node.supported) continue;
        BOOL isReality = [node.link rangeOfString:@"security=reality"].location != NSNotFound;
        // У нод без REALITY пинг часто не проходит, но работать они могут,
        // поэтому берём их все; остальные — по возрастанию пинга.
        if (isReality) {
            if (node.pingMs > 0) [reality addObject:@(i)];
        } else {
            [plain addObject:@(i)];
        }
    }
    [reality sortUsingComparator:^NSComparisonResult(NSNumber *a, NSNumber *b) {
        HVPNNode *na = all[a.unsignedIntegerValue];
        HVPNNode *nb = all[b.unsignedIntegerValue];
        return [@(na.pingMs) compare:@(nb.pingMs)];
    }];
    NSMutableArray<NSNumber *> *candidates = [NSMutableArray array];
    [candidates addObjectsFromArray:plain];
    [candidates addObjectsFromArray:reality];
    if (candidates.count == 0) {
        [self alert:@"Список пуст."];
        return;
    }

    NSUInteger limit = MIN(candidates.count, 16);
    _busy = YES;
    [self updateUI];

    NSDictionary *options = @{@"bypassLAN": @YES,
                              @"localDomains": @[@".local", @".lan", @".home", @".internal"]};
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSInteger found = -1;
        NSInteger foundMs = 0;
        NSString *lastError = nil;
        for (NSUInteger i = 0; i < limit; i++) {
            NSUInteger index = candidates[i].unsignedIntegerValue;
            HVPNNode *node = all[index];
            dispatch_async(dispatch_get_main_queue(), ^{
                self->_statusLabel.textColor = [UIColor darkGrayColor];
                self->_statusLabel.text = [NSString stringWithFormat:@"подбор %lu/%lu: %@",
                                           (unsigned long)(i + 1), (unsigned long)limit, node.name];
            });
            NSDictionary *response = HVPNSend(@{@"cmd": @"start",
                                                @"link": node.link,
                                                @"options": options}, NULL, 90);
            NSDictionary *probe = [response[@"probe"] isKindOfClass:[NSDictionary class]]
                ? response[@"probe"] : nil;
            if ([response[@"ok"] boolValue] && [probe[@"ok"] boolValue]) {
                found = (NSInteger)index;
                foundMs = [probe[@"ms"] integerValue];
                break;
            }
            lastError = probe[@"error"] ?: response[@"error"] ?: @"нет трафика";
        }

        dispatch_async(dispatch_get_main_queue(), ^{
            self->_busy = NO;
            if (found >= 0) {
                HVPNNode *node = all[(NSUInteger)found];
                [HVPNStore shared].selectedIndex = found;
                [[HVPNStore shared] save];
                [self.tableView reloadData];
                [self alert:[NSString stringWithFormat:@"Работает: %@\nтрафик через туннель, %ld мс.",
                             node.name, (long)foundMs]];
            } else {
                HVPNSendQuick(@{@"cmd": @"stop"});
                [self alert:[NSString stringWithFormat:
                    @"Ни одна из %lu проверенных нод не пропускает трафик.\nПоследняя причина: %@",
                    (unsigned long)limit, lastError ?: @"неизвестна"]];
            }
            [self refreshStatus];
        });
    });
}

// Тап по строке состояния — повторная сквозная проверка туннеля.
- (void)probeTapped {
    if (_busy) return;
    if (![_lastStatus[@"running"] boolValue]) {
        [self alert:@"Сначала подключитесь."];
        return;
    }
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        NSDictionary *response = HVPNSend(@{@"cmd": @"probe"}, NULL, 20);
        dispatch_async(dispatch_get_main_queue(), ^{
            if (response == nil) {
                [self alert:@"Демон не отвечает"];
                return;
            }
            if ([response[@"ok"] boolValue]) {
                [self alert:[NSString stringWithFormat:@"Трафик через туннель идёт (%@ мс).",
                              response[@"ms"] ?: @"?"]];
            } else {
                [self alert:[NSString stringWithFormat:@"Трафика нет: %@\n\nПодробности — «Лог».",
                              response[@"error"] ?: @"причина неизвестна"]];
            }
            [self refreshStatus];
        });
    });
}

- (void)pingAll {
    if (_pinging) return;
    NSArray<HVPNNode *> *nodes = [HVPNStore shared].nodes;
    if (nodes.count == 0) {
        [self.refreshControl endRefreshing];
        return;
    }

    _pinging = YES;
    _pingRemaining = nodes.count;
    [self.tableView reloadData];

    __block NSDictionary *sampleResponse = nil;
    __block NSString *sampleName = nil;
    __block NSUInteger okCount = 0;

    dispatch_semaphore_t semaphore = dispatch_semaphore_create(6);
    for (NSUInteger index = 0; index < nodes.count; index++) {
        HVPNNode *node = nodes[index];
        dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
            dispatch_semaphore_wait(semaphore, DISPATCH_TIME_FOREVER);
            NSDictionary *response = nil;
            if (node.supported && node.server.length && node.port > 0) {
                response = HVPNSend(@{@"cmd": @"ping",
                                      @"server": node.server,
                                      @"port": @(node.port)}, NULL, 15);
            }
            dispatch_async(dispatch_get_main_queue(), ^{
                BOOL ok = [response[@"ok"] boolValue];
                node.pingMs = ok ? [response[@"ms"] integerValue] : -1;
                node.pingError = ok
                    ? nil : (response[@"error"] ?: (response ? @"нет ответа" : @"демон не отвечает"));
                if (ok) {
                    okCount++;
                    if (sampleResponse == nil) {
                        sampleResponse = response;
                        sampleName = node.name;
                    }
                }
                NSIndexPath *path = [NSIndexPath indexPathForRow:(NSInteger)index inSection:0];
                [self.tableView reloadRowsAtIndexPaths:@[path]
                                     withRowAnimation:UITableViewRowAnimationNone];
                dispatch_semaphore_signal(semaphore);
                if (--self->_pingRemaining == 0) {
                    self->_pinging = NO;
                    [[HVPNStore shared] save];
                    NSString *summary = [NSString stringWithFormat:
                        @"[ping] нод %lu, ответили %lu, пример: %@ -> %@",
                        (unsigned long)nodes.count, (unsigned long)okCount,
                        sampleName ?: @"-",
                        sampleResponse ? [sampleResponse description] : @"нет успешных"];
                    [[HVPNStore shared] notePingSummary:summary];
                    [self.refreshControl endRefreshing];
                    [self updateUI];
                }
            });
        });
    }
}

- (void)refreshStatus {
    if (_polling) return;
    _polling = YES;
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        NSDictionary *response = HVPNSend(@{@"cmd": @"status"}, NULL, 8);
        dispatch_async(dispatch_get_main_queue(), ^{
            self->_polling = NO;
            if (response == nil) {
                self->_lastStatus = nil;
                self->_statusLabel.textColor = [UIColor grayColor];
                self->_statusLabel.text = @"● демон не запущен\nпроверьте /Library/LaunchDaemons/com.vela.daemon.plist";
            } else {
                NSDictionary *status = [response[@"status"] isKindOfClass:[NSDictionary class]]
                    ? response[@"status"] : @{};
                self->_lastStatus = status;
                NSString *daemonVersion = response[@"version"] ?: @"?";
                BOOL versionMismatch = ![daemonVersion isEqualToString:HVPNVersionString];
                NSString *warn = versionMismatch
                    ? [NSString stringWithFormat:@"⚠ демон v%@ ≠ приложение v%@ — переустановите пакет\n",
                       daemonVersion, HVPNVersionString]
                    : @"";
                NSDictionary *probe = [status[@"probe"] isKindOfClass:[NSDictionary class]]
                    ? status[@"probe"] : nil;
                BOOL noTraffic = probe != nil && !([probe[@"ok"] boolValue]);
                if ([status[@"running"] boolValue]) {
                    if (noTraffic) {
                        self->_statusLabel.textColor = [UIColor colorWithRed:0.7 green:0.1 blue:0.1 alpha:1.0];
                        self->_statusLabel.text = [NSString stringWithFormat:@"%@● %@ · нет трафика: %@",
                                                   warn, status[@"node"] ?: @"?",
                                                   probe[@"error"] ?: @"?"];
                        [self updateUI];
                        return;
                    }
                    self->_statusLabel.textColor = [UIColor colorWithRed:0.0 green:0.5 blue:0.15 alpha:1.0];
                    NSString *traffic = probe[@"ms"]
                        ? [NSString stringWithFormat:@" · %@ мс", probe[@"ms"]] : @"";
                    NSString *endpoint = status[@"server"]
                        ? [NSString stringWithFormat:@"%@:%@", status[@"server"],
                           status[@"port"] ?: @"?"]
                        : @"";
                    self->_statusLabel.text = [NSString stringWithFormat:@"%@● %@ · %@ · %@ · %@%@",
                                               warn,
                                               status[@"node"] ?: @"?",
                                               status[@"protocol"] ?: @"",
                                               endpoint,
                                               status[@"utun"] ?: @"", traffic];
                } else {
                    self->_statusLabel.textColor = versionMismatch
                        ? [UIColor colorWithRed:0.7 green:0.1 blue:0.1 alpha:1.0]
                        : [UIColor darkGrayColor];
                    NSString *info = [HVPNStore shared].subscriptionInfo;
                    self->_statusLabel.text = [NSString stringWithFormat:@"%@%@",
                        warn,
                        info.length
                            ? [NSString stringWithFormat:@"○ отключено · трафик %@", info]
                            : [NSString stringWithFormat:@"○ отключено (v%@)", daemonVersion]];
                }
            }
            [self updateUI];
        });
    });
}

- (void)updateUI {
    BOOL running = [_lastStatus[@"running"] boolValue];
    _connectButton.enabled = !_busy;
    [_connectButton setTitle:(_busy ? @"Подождите…" : (running ? @"Отключить" : @"Подключить"))
                    forState:UIControlStateNormal];
    _connectButton.tintColor = running
        ? [UIColor colorWithRed:0.72 green:0.1 blue:0.12 alpha:1.0]
        : [UIColor colorWithRed:0.0 green:0.42 blue:0.86 alpha:1.0];
}

#pragma mark Таблица

- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section {
    return (NSInteger)[HVPNStore shared].nodes.count;
}

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath {
    static NSString *identifier = @"node";
    UITableViewCell *cell = [tableView dequeueReusableCellWithIdentifier:identifier];
    if (cell == nil) {
        cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleSubtitle
                                      reuseIdentifier:identifier];
    }
    HVPNNode *node = [[HVPNStore shared] nodeAtIndex:indexPath.row];
    cell.textLabel.text = node.name;
    cell.textLabel.textColor = node.supported ? [UIColor blackColor] : [UIColor lightGrayColor];

    NSString *security = [node.link rangeOfString:@"security=reality"].location != NSNotFound
        ? @"reality"
        : ([node.link rangeOfString:@"security=tls"].location != NSNotFound ? @"tls" : @"");
    NSString *detail = security.length
        ? [NSString stringWithFormat:@"%@·%@ · %@:%ld · %@",
           node.type, security, node.server, (long)node.port, HVPNPingText(node)]
        : [NSString stringWithFormat:@"%@ · %@:%ld · %@",
           node.type, node.server, (long)node.port, HVPNPingText(node)];
    cell.detailTextLabel.text = detail;
    UIColor *detailColor = [UIColor grayColor];
    if (!node.supported) {
        detailColor = [UIColor lightGrayColor];
    } else if (node.pingMs >= 0 && node.pingMs < 150) {
        detailColor = [UIColor colorWithRed:0.0 green:0.5 blue:0.1 alpha:1.0];
    }
    cell.detailTextLabel.textColor = detailColor;
    cell.accessoryType = (indexPath.row == [HVPNStore shared].selectedIndex)
        ? UITableViewCellAccessoryCheckmark : UITableViewCellAccessoryNone;
    return cell;
}

- (void)tableView:(UITableView *)tableView didSelectRowAtIndexPath:(NSIndexPath *)indexPath {
    [tableView deselectRowAtIndexPath:indexPath animated:YES];
    HVPNNode *node = [[HVPNStore shared] nodeAtIndex:indexPath.row];
    if (node == nil) return;
    if (!node.supported) {
        [self alert:@"Нода не поддерживается ядром (транспорт xhttp или битая ссылка)."];
        return;
    }
    [HVPNStore shared].selectedIndex = indexPath.row;
    [[HVPNStore shared] save];
    [tableView reloadData];

    if ([_lastStatus[@"running"] boolValue]) {
        // Переподключаемся сразу: иначе туннель остался бы на старой ноде,
        // а галочка уже стояла бы на новой.
        [self connectToNode:node];
    }
}

- (BOOL)tableView:(UITableView *)tableView canEditRowAtIndexPath:(NSIndexPath *)indexPath {
    return YES;
}

- (void)tableView:(UITableView *)tableView
commitEditingStyle:(UITableViewCellEditingStyle)editingStyle
forRowAtIndexPath:(NSIndexPath *)indexPath {
    if (editingStyle != UITableViewCellEditingStyleDelete) return;
    [[HVPNStore shared] removeNodeAtIndex:indexPath.row];
    [tableView deleteRowsAtIndexPaths:@[indexPath] withRowAnimation:UITableViewRowAnimationAutomatic];
    [tableView reloadData];
}

#pragma mark Прочее

- (void)alert:(NSString *)message {
    UIAlertController *controller = [UIAlertController alertControllerWithTitle:@"Vela"
                                                                        message:message
                                                                 preferredStyle:UIAlertControllerStyleAlert];
    [controller addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
    [self presentViewController:controller animated:YES completion:nil];
}

@end

#pragma mark - AppDelegate

@interface VelaAppDelegate : UIResponder <UIApplicationDelegate>
@property (nonatomic, strong) UIWindow *window;
@end

@implementation VelaAppDelegate

- (BOOL)application:(UIApplication *)application
didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
    [[HVPNStore shared] load];

    self.window = [[UIWindow alloc] initWithFrame:[UIScreen mainScreen].bounds];
    HVPNNodesViewController *root = [HVPNNodesViewController new];
    UINavigationController *nav = [[UINavigationController alloc] initWithRootViewController:root];
    self.window.rootViewController = nav;
    [self.window makeKeyAndVisible];
    return YES;
}

@end

int main(int argc, char *argv[]) {
    @autoreleasepool {
        return UIApplicationMain(argc, argv, nil, @"VelaAppDelegate");
    }
}
