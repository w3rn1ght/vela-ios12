# HappVPN — VPN-клиент для джейлбрейкнутого iOS 12

Клиент в стиле Shadowrocket/Kitsunebi, но собранный из двух частей: GUI-приложение
и root-демон, который держит ядро [sing-box](https://github.com/SagerNet/sing-box)
и заворачивает трафик в `utun` без `NetworkExtension`.

**Готовая сборка:** https://github.com/w3rn1ght/happvpn-ios12/releases/tag/v0.1.1
(`com.happvpn.jb_0.1.1_iphoneos-arm.deb`, собрана GitHub Actions из этого кода,
все бинари arm64 / platform ios / minos 12.0).

```
[HappVPN.app]  --unix socket-->  [happvpnd]  --fork-->  [sing-box]
                                     |                      |
                                     |                      +--> utunN --> трафик
                                     +--> route add 0.0.0.0/1, 128.0.0.0/1 --> utunN
```

> **Важно.** Код в этом репозитории **не компилировался и не запускался на
> устройстве** — он написан «с нуля» под iOS 12 и требует сборки на macOS
> (или в GitHub Actions) и обкатки на телефоне. Первый запуск почти наверняка
> потребует 1–2 правки, для этого в конце есть чек-лист и раздел диагностики.

---

## Почему не NetworkExtension

`NEPacketTunnelProvider` требует provisioning profile, подписи Apple и
entitlement `packet-tunnel-provider`, которого у самоподписанного приложения
нет. На джейлбрейке проще (и так делают большинство твиков): создать `utun`
обычным `PF_SYSTEM`-сокетом, поднять в нём tun-стек и переписать маршруты.
Именно это делает `happvpnd`:

1. собирает конфиг sing-box из вашей ссылки;
2. запускает `/usr/libexec/happvpn/sing-box run -c core.json`;
3. ждёт появления нового `utunN`;
4. добавляет маршруты `0.0.0.0/1` + `128.0.0.0/1` (и `::/1` + `8000::/1`) в этот tun —
   они перекрывают `default` по longest-prefix, поэтому весь трафик уходит в прокси;
5. host-маршрут до самого прокси-сервера оставляет через физический шлюз,
   чтобы ядро не ушло в собственный tun (петля).

При остановке маршруты снимаются, ядро убивается. Если демон упал — при
следующем старте он сам удаляет «осиротевшие» маршруты.

---

## Поддерживаемые ссылки

| Схема | Протокол | Примечания |
|---|---|---|
| `vless://` | VLESS | TLS, Reality (`pbk`/`sid`/`fp`), WS, gRPC, HTTP/2, HTTPUpgrade, `flow=xtls-rprx-vision` |
| `vmess://` | VMess | base64-JSON (v2rayN), WS/gRPC/HTTP2/TCP, TLS |
| `trojan://` | Trojan | TLS, WS/gRPC |
| `ss://` | Shadowsocks | оба формата ссылок, плагины `obfs-local` / `v2ray-plugin` |
| `hysteria2://`, `hy2://` | Hysteria2 | TLS, `obfs=salamander` |
| `tuic://` | TUIC v5 | `uuid:password` |
| `https://…` | подписка | base64 или plain-список ссылок |

Из приложения **Happ** подходят обычные ссылки на ноды (`vless://`, `vmess://`,
`trojan://`, `ss://`, `hysteria2://`) и обычные https-подписки — они там
стандартные.

**Не поддерживается:**

* `happ://crypt…`, `happ://routing…` — Happ шифрует свои подписки/профили
  маршрутизации собственным ключом, формат не документирован. В Happ возьмите
  ссылку на конкретную ноду или обычную https-подписку.
  Подробнее: [что делать с `happ://crypt…`](#если-у-вас-ссылка-happcrypt).
* TUIC v4 (`token=` вместо `uuid:password`).
* VMess с `net=tcp` + HTTP-обфускацией, mKCP, QUIC-транспорт.
* Одна активная нода: переключение = переподключение (первая валидная ссылка из
  списка).

---

## Требования

* iPhone/iPad **arm64**, iOS **12.x**, джейлбрейк с рабочим `launchd`
  (unc0ver / checkra1n). Root-доступ.
* Для сборки: **macOS** + Xcode Command Line Tools + Go 1.21+ + Theos + `ldid`.
* Либо без Mac: workflow `.github/workflows/build.yml` соберёт `.deb` в
  GitHub Actions и отдаст артефактом.

Windows/Linux-машина сама по себе не соберёт: нужен iPhoneOS SDK и `ldid`.

---

## Быстрая проверка парсера (без устройства)

Самую рискованную часть — разбор ссылок и сборку конфига — можно прогнать
на Mac без iPhone:

```bash
./scripts/run-parser-tests.sh
```

Скрипт компилирует `shared/*.m` обычным clang'ом, парсит примеры vless (reality,
ws, IPv6), vmess, trojan, ss (оба формата), hysteria2, tuic, проверяет
`happ://`-ошибку и печатает итоговый JSON конфига. Так вы увидите, что именно
уйдёт в `core.json`, ещё до установки пакета.

---

## Сборка

### 1. Ядро sing-box (обязательно)

```bash
brew install go ldid
./scripts/build-core.sh          # -> layout/usr/libexec/happvpn/sing-box
```

Скрипт клонирует sing-box `v1.8.14`, собирает `GOOS=ios GOARCH=arm64` с
`-miphoneos-version-min=12.0`, подписывает `entitlements/core.plist`
(utun + route) и печатает `vtool -show-build` — там `minos` должен быть `12.0`.

Если `GOOS=ios` не заводится, запасной вариант:

```bash
cd build/sing-box
GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build -trimpath \
  -tags with_gvisor,with_quic,with_utls,with_wireguard \
  -o ../../layout/usr/libexec/happvpn/sing-box ./cmd/sing-box
vtool -set-build-version ios 12.0 12.0 -replace \
  -output ../../layout/usr/libexec/happvpn/sing-box \
  ../../layout/usr/libexec/happvpn/sing-box
ldid -S../../entitlements/core.plist ../../layout/usr/libexec/happvpn/sing-box
```

### 2. Пакет

```bash
export THEOS=~/theos
make package                     # -> packages/com.happvpn.jb_0.1.0_iphoneos-arm.deb
```

Theos и SDK:

```bash
git clone --recursive https://github.com/theos/theos.git ~/theos
git clone --depth 1 https://github.com/theos/sdks.git ~/theos/sdks
```

`make` сам вызовет `scripts/build-core.sh`, если ядра ещё нет.

Установка сразу на устройство (OpenSSH на телефоне):

```bash
make install THEOS_DEVICE_IP=192.168.1.50
```

---

## Установка .deb

```bash
scp packages/*.deb root@IPHONE:/var/root/
ssh root@IPHONE
dpkg -i /var/root/com.happvpn.jb_0.1.0_iphoneos-arm.deb
uicache -p /Applications/HappVPN.app     # иконка появится на весенней доске
```

`postinst` сам создаёт каталоги, выставляет права и загружает демон:

```bash
launchctl list | grep happvpn
```

Ожидаемо: `com.happvpn.daemon` с PID.

Приложение тоже подписывается с `platform-application` (`entitlements/app.plist`) —
без этого песочница iOS 12 не пустит его к unix-сокету демона.

---

## Использование

1. Открыть **HappVPN**.
2. Вставить ссылку (или несколько, по одной в строке) либо https-подписку.
3. Нажать **Подключить** — приложение отправит ссылки демону, тот поднимет ядро.
4. Индикатор: `● подключено: <нода> <протокол> <сервер> · utunN · uptime`.
5. **Лог** — последние строки `core.log` (там же видно, почему не поднялось).

Ссылки сохраняются в `NSUserDefaults` приложения.

---

## Если у вас ссылка `happ://crypt…`

Такая ссылка **не подойдёт** — и это не ограничение нашего клиента, а формат:
`happ://crypt5/<base64>` — это не адрес сервера, а зашифрованный контейнер
(в типичном случае 12-байтовый nonce + ciphertext + 16-байтовый тег AES-GCM,
внутри — URL подписки и заголовки). Ключ находится внутри приложения Happ,
поэтому распаковать её снаружи нельзя, а поддерживать её в клиенте — значит
обходить защиту чужого формата. Наш парсер такую строку отклоняет с понятным
сообщением (это поведение закреплено тестом `happ:// -> понятная ошибка`).

Что делать вместо этого:

1. **Взять ссылку на ноду.** В Happ: список серверов → нужный сервер →
   «Поделиться»/«Копировать ссылку». Получится обычная `vless://…` (или
   `vmess://`/`trojan://`/`ss://`) — её наш клиент понимает.
2. **Взять обычную подписку.** У провайдера в личном кабинете почти всегда есть
   обычный `https://…/sub/…` (иногда с `?token=…`). Вставьте её в приложение —
   оно само развернёт base64/plain-список ссылок.
3. **Попросить у провайдера plain-ссылку**, если выдаётся только Happ-вариант.

Одна ссылка `happ://crypt5/…` может содержать много нод сразу, но нам нужен
её открытый источник (https-подписка), а не зашифрованная обёртка.

---

## Подписки с HWID (панели Remnawave и совместимые)

Многие панели привязывают подписку к устройству по заголовку `x-hwid`. Если
клиент его не передаёт, вместо нод приходит **заглушка**: 4 ссылки вида
`vless://00000000-…@0.0.0.0:1` с названиями «Включите передачу HWID…».
Именно так выглядит «подписка не работает» на первый взгляд.

Что делает приложение (с 0.1.1):

* при первом запуске генерирует UUID и хранит его в `NSUserDefaults` как HWID;
* запрашивает подписку с заголовками `x-hwid`, `x-device-os: iOS`,
  `x-ver-os`, `x-device-model` (`uname -m`, например `iPhone10,6`);
* ставит `User-Agent: v2rayNG/1.8.5` — по нему панель отдаёт обычный
  base64-список ссылок, а не свой Happ-JSON;
* отбрасывает заглушки и показывает остаток трафика/срок из
  `subscription-userinfo`;
* если нод не осталось — пишет, что панель отдала только заглушки.

Проверено на реальной подписке такого типа: без HWID — 4 заглушки, с HWID —
157 нод (148 `vless` + 9 `ss`). Из них 139 разбираются нашим ядром, 18
используют транспорт `xhttp`, который sing-box 1.8 не умеет, — они молча
пропускаются (см. «Ограничения»).

---

## Диагностика

| Что | Где |
|---|---|
| Лог демона | `/var/mobile/Library/Logs/HappVPN/daemon.log` |
| Лог ядра | `/var/mobile/Library/HappVPN/core.log` |
| Итоговый конфиг | `/var/mobile/Library/HappVPN/core.json` |
| Маршруты | `netstat -rn | head -20` — должны быть `0/1`, `128/1` на `utunN` |
| Процессы | `ps aux | grep -E "happvpnd|sing-box"` |
| Права/подпись | `ldid -e /usr/libexec/happvpn/sing-box` |

Типичные проблемы:

* **«Ядро не создало tun-интерфейс»** — почти всегда entitlement `utun`.
  Проверьте, что бинарь подписан `entitlements/core.plist`, и попробуйте
  запустить вручную:
  `/usr/libexec/happvpn/sing-box run -c /var/mobile/Library/HappVPN/core.json`.
* **«Не удалось поставить маршруты»** — нет entitlement `com.apple.private.net.route`
  или демон не root.
* **Соединение есть, сайты не открываются** — DNS. Ядро перехватывает запросы
  на 53-й порт, но если в сети DNS отдаётся по IPv6 или DoH-профилем,
  пропишите `dnsRemote`/`dnsLocal` в `options` (см. `shared/HVPNConfig.h`).
* **После падения демона нет интернета** — вручную:
  `route delete -net 0.0.0.0/1; route delete -net 128.0.0.0/1`
  (в норме это делает демон при старте и по SIGTERM).
* **Приложение не видит демон («Демон не отвечает»)** — либо `happvpnd` не
  запущен, либо приложение собрано без `entitlements/app.plist` и сидит в
  песочнице. Проверьте: `ls -l /var/mobile/Library/HappVPN/control.sock`
  (должен быть `srw-rw-rw-`).
* **Ядро падает с «bad CPU type»/не запускается** — проверьте
  `vtool -show-build layout/usr/libexec/happvpn/sing-box`: `minos` должен быть
  не выше вашей iOS.

---

## Чек-лист первого запуска

1. `./scripts/build-core.sh` — ядро собирается, `vtool` показывает `minos 12.0`.
2. `make package` — `.deb` собирается без ошибок.
3. После установки `launchctl list | grep happvpn` показывает демон.
4. В приложении «Подключить» → `netstat -rn` показывает `0/1` и `128/1` на `utun`.
5. `curl https://ifconfig.me` в SSH показывает IP сервера.
6. «Отключить» → маршруты исчезли, интернет вернулся.

Если что-то из этого падает — смотрите два лога выше, там 90 % ответов.

---

## Ограничения

* Нет kill switch и защиты от утечек при смене сети: при переходе Wi-Fi ↔ LTE
  host-маршрут до сервера и `utun`-маршруты нужно переставлять (см.
  «Что дальше»).
* Переключения нод в UI нет — используется первая поддерживаемая ссылка из
  подписки.
* Транспорт `xhttp` не поддерживается ядром sing-box 1.8: такие ноды
  пропускаются (в проверочной подписке это 18 из 157). Поддержка потребует
  переезда на ядро 1.11+ и миграции формата конфига.
* UDP идёт через прокси настолько, насколько его поддерживает протокол
  (VLESS/VMess/Trojan — через UDP-over-TCP, Hysteria2/TUIC — нативно).
* IPv6 заворачивается split-маршрутами, но v6-only сети не тестировались.
* Иконки и локализации нет; UI минимальный.
* Никакой проверки обновлений и телеметрии — приложение вообще не ходит в сеть,
  кроме загрузки подписок.

## Что дальше

* Селектор нод: отдать sing-box `experimental.clash_api` и дергать
  `/proxies/proxy` из приложения.
* `SCDynamicStore`-монитор смены интерфейса → перезапуск ядра и переустановка
  маршрутов.
* IPv6 host-route до сервера (сейчас только IPv4).
* Иконка, тёмная тема, импорт из буфера обмена по `happvpn://`-схеме.

## Права и безопасность

Инструмент предназначен для подключения **к вашему собственному** серверу.
Весь трафик устройства доверяется прокси-серверу, который вы указали; ключи
и UUID лежат в `core.json` с правами `0644` в `/var/mobile/Library/HappVPN` —
не выкладывайте этот файл и не коммитьте конфиги.
