# Changelog

OSMud change history

## 0.2.0 (2018-09-28)

- #100 Update logging messages
- #100 Batch firewall change fix applying commit or rollback
- #53 ensure duplicate firewall rules are not applied
- #100 Batch firewall changes and only commit changes when full mud file is applied or rollback changes
- #99 add support for another key alias

## 0.1.1 (2018-09-25)

- #99 Add support for alternate key names when parsing mud files
- #98 Add command line options -i and -m to not fail when mud validation fails and set log level
- #39 Create firewall rule to block everything by default if we have a valid mudfile
- adding initial code of conduct (#96)
- #97 Add -pupose any option to the openssl cms verify to allow more certificate types
- #43 Support for MUD url extraction and added DHCP-Vendor information
- #91 removing openwrt uci reference syntax that breaks the create_ip_fw_rule.sh script (#92)
- #64 removing controller references and replacing with manager (#84)
- #81 updating README to remove wording about not validating p7s, and include 2 more future works coming to osmud. Also expands upon usage of -b argument (#82)
- #30 setting accept, accept-language and useragent headers to follow the mud spec on request to mud file server (#80)
- #74: Added utilities for creating directory paths and use during… (#75)

## 0.1.0 (2018-07-16)

- Set version to v0.1.0 and update README for repository location
- #69 turn on SSL server verification
- updating to compile on Ubuntu
- removing test certs.c
- Adding Apache License, Version 2.0
- Making the instructions clearer to read & updating openwrt file to use osMUD annotation
- Moving non osmud instructions to wiki pages
- Add ca-certificates to opkg install deps
- Add initial openssl cms verify for mud file signatures
- Removing original old makefile
- remove references of openmud and update to be osmud
- adding README updates to known limitations and future work. Also updating mud/osmud definitions to make it more clear. Made the instructions more clear to instruct how to build/install osMUD. - Removed instructions for running osMUD in compile DEBUG mode
- Merge branch 'master' of github.com:MasterPeace/osmud
- removing instructions for auto starting osmud upon reboot & updating to explain how dnsmasq works with osmud better
- Updating README to reference MUD manager, change name to osMUD, and add instructions for setting up osmud to work with dnsmasq
- Updates to put hostName in firewall rule and db entry. Fixes for optional args to scripts
- add script to remove firewall rules by ip address. Will remove src or dest ip's that match. Also removing / so that path in mudDBDevice will concatonate properly
- Add port range, toDevice firewall property fix, protect use of char buffers
- Additional changes for openwrt firewall rule application
- Added more options required to call the create-firewall-rule script
- Minor updates to get firewall/db scripts to execute
- Fixes for ipk build
- Sync detect-dhcp-event script with OSMUD. Add scripts to ipk package
- 10: Create basic mud file mapping to device management
- Merge branch 'master' of https://github.com/MasterPeace/osmud
- Add support for options -k, -d; log levels; trim log msgs; heartbeat stats
- updating readme to make code parts easier to read and add instructions to make script executable
- Initial commit for build that will continue to use scripts while openwrt moves to UCI library integration
- Router startup instructions
- Init.d startup script and base runtime configuration - see src/openwrt/osmud
- removing predns.sh to use isMudBlocking.sh script instead.
- Fixed startup message that should not use logging framework
