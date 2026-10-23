#!/usr/bin/env bash
# Сборка ядра sing-box под iOS 12 / arm64 и упаковка его в layout.
# Запускать ТОЛЬКО на macOS (нужны Xcode Command Line Tools и Go 1.21+).
set -euo pipefail

SING_BOX_VERSION="${SING_BOX_VERSION:-v1.8.14}"
MIN_IOS="${MIN_IOS:-12.0}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_DIR="$ROOT/build"
SRC_DIR="$BUILD_DIR/sing-box"
OUT_DIR="$ROOT/layout/usr/libexec/happvpn"
OUT_BIN="$OUT_DIR/sing-box"
TAGS="with_gvisor,with_quic,with_utls,with_wireguard,with_dhcp"

die() { echo "ошибка: $*" >&2; exit 1; }

[ "$(uname -s)" = "Darwin" ] || die "сборка ядра требует macOS (Darwin). На Linux/Windows используйте CI-воркфлоу."
command -v go >/dev/null 2>&1 || die "не найден go. Установите Go 1.21+: brew install go"
command -v xcrun >/dev/null 2>&1 || die "не найден xcrun. Установите Xcode Command Line Tools."

SDK_PATH="$(xcrun --sdk iphoneos --show-sdk-path)"
CLANG_BIN="$(xcrun --sdk iphoneos -f clang)"
[ -d "$SDK_PATH" ] || die "не найден iPhoneOS.sdk"

mkdir -p "$BUILD_DIR" "$OUT_DIR"

if [ ! -d "$SRC_DIR/.git" ]; then
	echo ">> клонирую sing-box $SING_BOX_VERSION"
	git clone --depth 1 --branch "$SING_BOX_VERSION" \
		https://github.com/SagerNet/sing-box.git "$SRC_DIR"
else
	cd "$SRC_DIR"
	CURRENT="$(git describe --tags --exact-match 2>/dev/null || true)"
	if [ "$CURRENT" != "$SING_BOX_VERSION" ]; then
		echo ">> переключаюсь на $SING_BOX_VERSION"
		git fetch --depth 1 origin "refs/tags/$SING_BOX_VERSION:refs/tags/$SING_BOX_VERSION"
		git checkout -f "$SING_BOX_VERSION"
	fi
fi

cd "$SRC_DIR"
export GOOS=ios
export GOARCH=arm64
export CGO_ENABLED=1
export CC="$CLANG_BIN"
export CGO_CFLAGS="-arch arm64 -isysroot $SDK_PATH -miphoneos-version-min=$MIN_IOS"
export CGO_LDFLAGS="-arch arm64 -isysroot $SDK_PATH -miphoneos-version-min=$MIN_IOS"

echo ">> go build (ios/arm64, min iOS $MIN_IOS)"
go build -buildvcs=false -trimpath -tags "$TAGS" \
	-ldflags "-s -w" \
	-o "$OUT_BIN" ./cmd/sing-box

cd "$ROOT"

echo ">> проверяю Mach-O"
if command -v vtool >/dev/null 2>&1; then
	vtool -show-build "$OUT_BIN" || true
fi
if command -v otool >/dev/null 2>&1; then
	otool -l "$OUT_BIN" | grep -A4 -E "LC_BUILD_VERSION|LC_VERSION_MIN_IPHONEOS" || true
fi

echo ">> подписываю entitlement'ами (utun + route)"
if command -v ldid >/dev/null 2>&1; then
	ldid -S"$ROOT/entitlements/core.plist" "$OUT_BIN"
else
	echo "!! ldid не найден (brew install ldid). Ядро не подписано —"
	echo "!! на джейлбрейке это часто работает, но лучше подписать вручную:"
	echo "!!   ldid -S entitlements/core.plist $OUT_BIN"
fi

chmod 755 "$OUT_BIN"
echo ">> готово: $OUT_BIN ($(du -h "$OUT_BIN" | cut -f1))"
