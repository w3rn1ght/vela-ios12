// Управление таблицей маршрутов через PF_ROUTE-сокет.
// Нужно, чтобы завернуть весь трафик в utun, который создаёт ядро sing-box:
// ставим 0.0.0.0/1 + 128.0.0.0/1 (перекрывают default по longest-prefix),
// плюс host-маршрут до самого прокси-сервера через физический шлюз.
#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

int HVPNRouteAddInterface(int family, NSString *dst, int prefix, unsigned ifindex);
int HVPNRouteDeleteInterface(int family, NSString *dst, int prefix, unsigned ifindex);
int HVPNRouteAddHost(int family, NSString *dst, NSString *gateway, unsigned ifindex);
int HVPNRouteDeleteHost(int family, NSString *dst, NSString *gateway, unsigned ifindex);

/// Шлюз по умолчанию (например 192.168.1.1) и индекс его интерфейса.
BOOL HVPNGetDefaultGateway(int family, NSString *_Nullable *_Nullable gateway, unsigned *_Nullable ifindex);

/// Индекс интерфейса, через который идёт маршрут dst/prefix (0 — не найден).
unsigned HVPNRouteInterfaceIndex(int family, NSString *dst, int prefix);

/// Текст последней ошибки (errno), для логов.
NSString *HVPNErrnoString(void);

NS_ASSUME_NONNULL_END
