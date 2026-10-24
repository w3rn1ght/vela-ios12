#!/usr/bin/env bash
# Офлайн-тест парсера ссылок и сборки конфига (macOS, устройство не нужно).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
mkdir -p "$ROOT/build"

clang -fobjc-arc -Wall -Wextra -Wno-unused-parameter \
	-I"$ROOT/shared" -I"$ROOT/daemon" \
	"$ROOT/shared/HVPNLinkParser.m" \
	"$ROOT/shared/HVPNLinkUtil.m" \
	"$ROOT/shared/HVPNConfig.m" \
	"$ROOT/shared/HVPNHapp.m" \
	"$ROOT/shared/HVPNHappKeys.m" \
	"$ROOT/shared/HVPNChaCha.c" \
	"$ROOT/tests/parser_test.m" \
	-framework Foundation \
	-framework Security \
	-o "$ROOT/build/parser_test"

"$ROOT/build/parser_test"
