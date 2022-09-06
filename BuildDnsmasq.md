# Build and install osMUD-dnsmasq 

## Build osMUD-dnsmasq in OpenWRT

1. Clone https://github.com/osmud/dnsmasq
1. Rename the directory to dnsmasq-2.86 (or whatever the latest is at http://www.thekelleys.org.uk/dnsmasq/)
1. Package the project by running the command `tar -cJf dnsmasq-2.86.tar.xz dnsmasq-2.86/` (note its important to be at this directory level so that the tar.xz is compressed the same way as the original dnsmasq)
1. Move the `dnsmasq-2.86.tar.xz` file to the openwrt build space in directory `openwrt/dl` where openwrt is the root of the project
1. Ensure the dnsmasq Makefile located in openwrt at `package/network/services/dnsmasq/Makefile` has the correct `PKG_VERSION` & `PKG_SOURCE_URL` is commented out.
1. Run `make package/network/services/dnsmasq/compile` to compile only dnsmasq
1. If you are trying to build only this package you will need to configure the compile environment according to the target device
	- For a docker container use x86_64 architecture

This builds dnsmasq to be something like `bin/packages/x86_64/base/dnsmasq_2.86-1_x86_64.ipk`

## Install osMUD-dnsmasq on the router

1. scp osmud-dnsmasq to the router `scp dnsmasq_2.86-1_x86_64.ipk root@192.168.1.1:/tmp`
1. Remove the old dnsmasq `opkg remove dnsmasq`
1. Install your new dnsmasq `opkg install /tmp/dnsmasq_2.86-1_x86_64.ipk`

## Configure osMUD-dnsmasq

Follow the instruction stored in [this other file](https://github.com/osmud/osmud/tree/master/src/dnsmasq)
