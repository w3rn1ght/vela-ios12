export TARGET = iphone:clang:latest:12.0
export ARCHS = arm64
export PACKAGE_VERSION = 1.0.0
export FINALPACKAGE = 1

include $(THEOS)/makefiles/common.mk

# ---------------------------------------------------------------- приложение
APPLICATION_NAME = Vela

Vela_FILES = \
	app/main.m \
	shared/HVPNStore.m \
	shared/HVPNLinkParser.m \
	shared/HVPNLinkUtil.m \
	shared/HVPNConfig.m \
	shared/HVPNHapp.m \
	shared/HVPNHappKeys.m \
	shared/HVPNChaCha.c

Vela_FRAMEWORKS = UIKit Foundation Security
Vela_CFLAGS = -fobjc-arc -Wno-deprecated-declarations \
	-I$(THEOS_PROJECT_DIR)/shared -I$(THEOS_PROJECT_DIR)/daemon
Vela_CODESIGN_FLAGS = -Sentitlements/app.plist

include $(THEOS_MAKE_PATH)/application.mk

# --------------------------------------------------------------------- демон
TOOL_NAME = velad

velad_FILES = \
	daemon/main.m \
	daemon/HVPNControlServer.m \
	daemon/HVPNTunnel.m \
	daemon/HVPNRoute.m \
	shared/HVPNLinkParser.m \
	shared/HVPNLinkUtil.m \
	shared/HVPNConfig.m

velad_FRAMEWORKS = Foundation SystemConfiguration
velad_CFLAGS = -fobjc-arc -Wno-deprecated-declarations \
	-I$(THEOS_PROJECT_DIR)/shared -I$(THEOS_PROJECT_DIR)/daemon
velad_INSTALL_PATH = /usr/libexec
velad_CODESIGN_FLAGS = -Sentitlements/daemon.plist

include $(THEOS_MAKE_PATH)/tool.mk

# ---------------------------------------------------------------------- ядро
before-all::
	@if [ ! -x layout/usr/libexec/vela/sing-box ]; then \
		echo ">> ядро sing-box не найдено, запускаю scripts/build-core.sh"; \
		./scripts/build-core.sh; \
	fi

# Git на Windows не сохраняет exec-бит, а dpkg без него пакет не соберёт.
before-package::
	@chmod 755 layout/DEBIAN/postinst layout/DEBIAN/postrm scripts/*.sh 2>/dev/null || true

after-install::
	install.exec "launchctl unload /Library/LaunchDaemons/com.vela.daemon.plist 2>/dev/null; launchctl load /Library/LaunchDaemons/com.vela.daemon.plist; uicache -p /Applications/Vela.app 2>/dev/null; true"
