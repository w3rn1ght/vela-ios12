// happvpnd — демон под launchd (root). Держит ядро sing-box и маршруты.
#import <Foundation/Foundation.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include <dispatch/dispatch.h>

#import "HVPNControlServer.h"
#import "HVPNTunnel.h"

// launchctl unload / перезагрузка шлют SIGTERM: важно снять маршруты,
// иначе устройство останется без интернета до ребута.
static void HVPNInstallSignalHandlers(void) {
    static dispatch_source_t sources[2];
    int signals[2] = {SIGTERM, SIGINT};
    for (int i = 0; i < 2; i++) {
        int signo = signals[i];
        signal(signo, SIG_IGN);
        sources[i] = dispatch_source_create(DISPATCH_SOURCE_TYPE_SIGNAL, (uintptr_t)signo, 0,
                                            dispatch_get_main_queue());
        dispatch_source_set_event_handler(sources[i], ^{
            NSLog(@"[happvpnd] получен сигнал %d, снимаю маршруты", signo);
            [[HVPNTunnel shared] stop];
            exit(0);
        });
        dispatch_resume(sources[i]);
    }
}

int main(int argc, char **argv) {
    @autoreleasepool {
        setvbuf(stdout, NULL, _IOLBF, 0);
        signal(SIGPIPE, SIG_IGN);
        HVPNInstallSignalHandlers();

        // Подчищаем маршруты, если предыдущий запуск умер в подключённом состоянии.
        [HVPNTunnel cleanupStaleRoutes];

        NSError *error = nil;
        HVPNControlServer *server = [HVPNControlServer new];
        if (![server startWithError:&error]) {
            NSLog(@"[happvpnd] control socket: %@", error.localizedDescription);
            return 1;
        }

        NSLog(@"[happvpnd] started (pid %d)", getpid());
        dispatch_main();
    }
    return 0;
}
