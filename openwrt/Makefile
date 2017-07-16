include $(TOPDIR)/rules.mk

PKG_NAME:=xterminal
PKG_VERSION:=2017-7-12
PKG_RELEASE:=$(PKG_SOURCE_VERSION)

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/zhaojh329/xterminal.git
PKG_SOURCE_VERSION:=9295b67b49cb30c58a92dfea30d2079e03233c77
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/cmake.mk

define Package/xterminal
  SECTION:=utils
  CATEGORY:=Utilities
  TITLE:=multi device remote web shell tool 
  URL:=https://github.com/zhaojh329/xterminal
  DEPENDS:=+evmongoose
  SUBMENU:=Terminal
endef

define Package/xterminal/description
	Xterminal is a multi device remote web shell tool
endef

define Package/xterminal/install
	$(INSTALL_DIR) $(1)/usr/sbin $(1)/etc/init.d $(1)/etc/config
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/xterminal_device $(1)/usr/sbin
	$(INSTALL_BIN) ./files/xterminal.init $(1)/etc/init.d/xterminal
	$(INSTALL_CONF) ./files/xterminal.config $(1)/etc/config/xterminal
endef

$(eval $(call BuildPackage,xterminal))
