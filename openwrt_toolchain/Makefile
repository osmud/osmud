# Copyright 2018 osMUD
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

include $(TOPDIR)/rules.mk

# Name, version and release number
# The name and version of your package are used to define the variable to point to the build directory of your package: $(PKG_BUILD_DIR)
PKG_NAME:=osMUD
PKG_VERSION:=0.2.0
PKG_RELEASE:=1

# Source settings (i.e. where to find the source codes)
# This is a custom variable, used below
SOURCE_DIR:=/home/lede/osmud/src

include $(INCLUDE_DIR)/package.mk

# Package definition; instructs on how and where our package will appear in the overall configuration menu ('make menuconfig')
define Package/osmud
  SECTION:=net
  CATEGORY:=Base system
  TITLE:=OpenWRT osmud
  DEPENDS:=+libcurl +ca-bundle +libjson-c +openssl-util +ca-certificates +libpcap +libpthread
#NEED TO ADD SOMETHING ABOUT osmud-dnsmasq and copy osmud-dnsmasq based on dnsmasq
endef

# Package description; a more verbose description on what our package does
define Package/osmud/description
  osMUD- see osmud.org.
endef

# Package preparation instructions; create the build directory and copy the source code. 
# The last command is necessary to ensure our preparation instructions remain compatible with the patching system.
define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	cp -R $(SOURCE_DIR)/* $(PKG_BUILD_DIR)
	$(Build/Patch)
endef

# Package build instructions; invoke the target-specific compiler to first compile the source file, and then to link the file into the final executable
define Build/Compile
	$(MAKE) -C $(PKG_BUILD_DIR) \
		CC="$(TARGET_CC)" \
		CFLAGS="$(TARGET_CFLAGS)" \
#		CFLAGS="$(TARGET_CFLAGS) -Wall -g" \
		LDFLAGS="$(TARGET_LDFLAGS)"
endef

# Package install instructions; create a directory inside the package to hold our executable, and then copy the executable we built previously into the folder
define Package/osmud/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_DIR) $(1)/etc/osmud
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/osmud $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/openwrt/commit_ip_fw_rules.sh $(1)/etc/osmud
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/openwrt/rollback_ip_fw_rules.sh $(1)/etc/osmud
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/openwrt/create_ip_fw_rule.sh $(1)/etc/osmud
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/openwrt/remove_ip_fw_rule.sh $(1)/etc/osmud
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/openwrt/create_mud_db_entry.sh $(1)/etc/osmud
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/openwrt/create_mud_db_entry.sh $(1)/etc/osmud
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/dnsmasq/detect_new_device.sh $(1)/etc/osmud
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/dnsmasq/dnsmasq.sample.conf $(1)/etc/osmud
	
	$(INSTALL_DIR) $(1)/etc/init.d/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/openwrt/osmud.init $(1)/etc/init.d/osmud	
endef

define Package/osmud/postinst
#!/bin/sh
# check if we are on real system
if [ -z "$${IPKG_INSTROOT}" ]; then
        echo "Enabling rc.d symlink for osmud"
        /etc/init.d/osmud enable
fi
exit 0
endef

define Package/osmud/prerm
#!/bin/sh
# check if we are on real system
if [ -z "$${IPKG_INSTROOT}" ]; then
        echo "Removing rc.d symlink for osmud"
        /etc/init.d/osmud disable
fi
exit 0
endef
# This command is always the last, it uses the definitions and variables we give above in order to get the job done
$(eval $(call BuildPackage,osmud))
