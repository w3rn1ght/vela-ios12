#import "HVPNControlServer.h"
#import "HVPNTunnel.h"
#import "HVPNConfig.h"
#import "HVPNPaths.h"

#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>

static NSString *const kSocketPath = HVPNControlSocketPath;
static const size_t kMaxRequest = 4 * 1024 * 1024;

static NSData *HVPNReadAll(int fd) {
    NSMutableData *data = [NSMutableData data];
    char buf[8192];
    while (data.length < kMaxRequest) {
        ssize_t n = read(fd, buf, sizeof(buf));
        if (n > 0) {
            [data appendBytes:buf length:(NSUInteger)n];
            continue;
        }
        if (n < 0 && errno == EINTR) continue;
        break;
    }
    return data;
}

static BOOL HVPNWriteAll(int fd, NSData *data) {
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

static NSDictionary *HVPNHandleRequest(NSDictionary *request) {
    NSString *cmd = request[@"cmd"];
    HVPNTunnel *tunnel = [HVPNTunnel shared];

    if ([cmd isEqualToString:@"status"]) {
        return @{@"ok": @YES, @"version": HVPNVersionString, @"status": [tunnel status]};
    }
    if ([cmd isEqualToString:@"start"]) {
        NSArray *links = nil;
        id single = request[@"link"];
        if ([single isKindOfClass:[NSString class]] && [(NSString *)single length] > 0) {
            links = @[single];
        } else {
            id list = request[@"links"];
            if ([list isKindOfClass:[NSArray class]]) links = list;
        }
        if (links.count == 0) {
            return @{@"ok": @NO, @"error": @"нужен link (строка) или links (массив)"};
        }
        id options = request[@"options"];
        NSDictionary *result = [tunnel startWithLinks:links
                                             options:[options isKindOfClass:[NSDictionary class]] ? options : nil];
        NSMutableDictionary *response = [result mutableCopy];
        response[@"version"] = HVPNVersionString;
        return response;
    }
    if ([cmd isEqualToString:@"ping"]) {
        NSString *server = request[@"server"];
        NSInteger port = [request[@"port"] integerValue];
        if (![server isKindOfClass:[NSString class]] || server.length == 0) {
            return @{@"ok": @NO, @"error": @"нет server"};
        }
        NSMutableDictionary *result = [[tunnel pingServer:server port:port] mutableCopy];
        result[@"server"] = server;
        result[@"port"] = @(port);
        return result;
    }
    if ([cmd isEqualToString:@"probe"]) {
        NSMutableDictionary *result = [[tunnel probe] mutableCopy];
        result[@"version"] = HVPNVersionString;
        return result;
    }
    if ([cmd isEqualToString:@"stop"]) {
        NSMutableDictionary *result = [[tunnel stop] mutableCopy];
        result[@"version"] = HVPNVersionString;
        return result;
    }
    if ([cmd isEqualToString:@"cleanup"]) {
        [HVPNTunnel cleanupStaleRoutes];
        return @{@"ok": @YES, @"version": HVPNVersionString, @"status": [tunnel status]};
    }
    if ([cmd isEqualToString:@"log"]) {
        return @{@"ok": @YES, @"log": [tunnel coreLog], @"status": [tunnel status]};
    }
    return @{@"ok": @NO, @"error": [NSString stringWithFormat:@"неизвестная команда: %@", cmd ?: @"(null)"]};
}

@implementation HVPNControlServer {
    int _listenFD;
    dispatch_source_t _source;
    dispatch_queue_t _queue;
}

- (BOOL)startWithError:(NSError **)error {
    NSString *dir = [kSocketPath stringByDeletingLastPathComponent];
    [[NSFileManager defaultManager] createDirectoryAtPath:dir
                              withIntermediateDirectories:YES
                                               attributes:@{NSFilePosixPermissions: @0755}
                                                    error:NULL];

    unlink(kSocketPath.fileSystemRepresentation);

    _listenFD = socket(AF_UNIX, SOCK_STREAM, 0);
    if (_listenFD < 0) {
        if (error) *error = [NSError errorWithDomain:@"com.happvpn.control" code:errno
                                            userInfo:@{NSLocalizedDescriptionKey:
                                                           [NSString stringWithFormat:@"socket: %s", strerror(errno)]}];
        return NO;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, kSocketPath.fileSystemRepresentation, sizeof(addr.sun_path) - 1);

    if (bind(_listenFD, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        if (error) *error = [NSError errorWithDomain:@"com.happvpn.control" code:errno
                                            userInfo:@{NSLocalizedDescriptionKey:
                                                           [NSString stringWithFormat:@"bind: %s", strerror(errno)]}];
        close(_listenFD);
        _listenFD = -1;
        return NO;
    }
    chmod(kSocketPath.fileSystemRepresentation, 0666);

    if (listen(_listenFD, 8) < 0) {
        if (error) *error = [NSError errorWithDomain:@"com.happvpn.control" code:errno
                                            userInfo:@{NSLocalizedDescriptionKey:
                                                           [NSString stringWithFormat:@"listen: %s", strerror(errno)]}];
        close(_listenFD);
        _listenFD = -1;
        return NO;
    }

    _queue = dispatch_queue_create("com.happvpn.control", DISPATCH_QUEUE_SERIAL);
    _source = dispatch_source_create(DISPATCH_SOURCE_TYPE_READ, (uintptr_t)_listenFD, 0, _queue);
    __weak HVPNControlServer *weakSelf = self;
    dispatch_source_set_event_handler(_source, ^{
        [weakSelf acceptOne];
    });
    dispatch_resume(_source);
    return YES;
}

- (void)acceptOne {
    int client = accept(_listenFD, NULL, NULL);
    if (client < 0) return;
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        @autoreleasepool {
            [self serveClient:client];
        }
    });
}

- (void)serveClient:(int)client {
    struct timeval tv;
    tv.tv_sec = 90;
    tv.tv_usec = 0;
    setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(client, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    NSData *raw = HVPNReadAll(client);
    NSDictionary *response = nil;

    if (raw.length == 0) {
        response = @{@"ok": @NO, @"error": @"пустой запрос"};
    } else {
        id parsed = [NSJSONSerialization JSONObjectWithData:raw options:0 error:NULL];
        if ([parsed isKindOfClass:[NSDictionary class]]) {
            response = HVPNHandleRequest(parsed);
        } else {
            response = @{@"ok": @NO, @"error": @"запрос не JSON-объект"};
        }
    }

    NSData *payload = [NSJSONSerialization dataWithJSONObject:response options:0 error:NULL];
    NSMutableData *out = [payload mutableCopy] ?: [NSMutableData data];
    [out appendBytes:"\n" length:1];
    HVPNWriteAll(client, out);

    shutdown(client, SHUT_WR);
    close(client);
}

@end
