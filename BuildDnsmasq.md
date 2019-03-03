## Build osmud-dnsmasq in OpenWRT
1. Clone https://github.com/osmud/osmud-dnsmasq
1. Rename the directory to dnsmasq-2.80 (or whatever the latest is at http://www.thekelleys.org.uk/dnsmasq/)
1. Package the project by running the command `tar -cJf dnsmasq-2.80.tar.xz dnsmasq-2.80/` (note its important to be at this directory level so that the tar.xz is compressed the same way as the original dnsmasq)
1. Move the `dnsmasq-2.80.tar.xz` file to the openwrt build space in directory `openwrt/dl` where openwrt is the root of the project
1. Ensure the dnsmasq Makefile located in openwrt at `package/network/services/dnsmasq/Makefile` has the correct `PKG_VERSION` & `PKG_SOURCE_URL` is commented out.
1. Run `make package/network/services/dnsmasq/compile` to compile only dnsmasq

This builds dnsmasq to be something like `bin/packages/mips_24kc/base/dnsmasq_2.80-1_mips_24kc.ipk`

## Install osmud-dnsmasq on the router
1. scp osmud-dnsmasq to the router `scp dnsmasq_2.80-1_mips_24kc.ipk root@192.168.1.1:/tmp`
1. Remove the old dnsmasq `opkg remove dnsmasq`
1. Install your new dnsmasq `opkg install /tmp/dnsmasq_2.80-1_mips_24kc.ipk`
