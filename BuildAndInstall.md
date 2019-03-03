One easy way to manage an OpenWRT build is to do it in a docker container. This will let you easily work with different toolchain configurations without having to build from scratch every time you change a config (change routers).

## Create Docker OpenWRT build image
1. Build the Dockerfile located at osmud/build/Dockerfile `docker build -t osmud/build-env .`
1. Run & download docker image and components as a daemon `docker run -d -ti --name=osmud-build-env osmud/build-env`
1. Find docker container id: `docker ps -a`
1. Enter running docker container: `docker exec -i -t container_ID_from_docker_ps /bin/bash`
1. Change directory to the "lede" directory: `cd lede`
1. If this is your first time into the docker image you will need to update and install all feeds.
    * Update all feeds: `./scripts/feeds update -a`
    * Install all source feeds: `./scripts/feeds install -a`
1. Determine the hardware architecture for the next step using this site.
    1. View https://wiki.openwrt.org/toh/start and search for your device
    1. View the "Device Techdata" column.
    1. Make a note of the Brand, Model, Platform & Target entries. You will need this in the next step.
1. Create make config file: `make menuconfig`
    1. Select your target system. Use the Platform & Target entry from the previous step to figure out which one to select.
    1. Select your target profile. Use the Brand & Model entry from the previous step to figure out which one to select.
    1. Tab over to the `<Exit>` command and save the configuration
    * Note: You can also google openwrt <device_name> to find the device info page.
1. Build only openwrt: `make`
1. View the compiled binaries `~/lede/bin/targets/<target_name_from_Device_Techdata>/generic`
    * You need to remember the processor architecture from this step to locate the installation artifacts from the build.

For example, a Linksys WRT1200AC router used these options:
* Target System: Marvell Armada 37x/38x/XP
* Target Profile: Linksys WRT1200AC
* These settings will create build artifacts in a directory similar to: `~/lede/bin/targets/mvebu/generic`

## Install OpenWRT on the router
If you followed the OpenWRT Docker build instructions- the container will have the build artifacts that can be installed on the router. 

Note: the instructions are a little different depending on if you've already installed OpenWRT and this is an upgrade or if you are flashing the router to OpenWRT for the first time.

### Flash on an existing OpenWRT OS:
1. scp the OpenWRT binary to the router `scp lede-ar71xx-generic-wzr-600dhp-squashfs-sysupgrade.bin root@192.168.1.1:/tmp`
1. ssh into the router `ssh root@192.168.1.1`
1. Flash the firmware `mtd -r write /tmp/lede-ar71xx-generic-wzr-600dhp-squashfs-sysupgrade.bin firmware`

Note: You can also flash the router via the OpenWRT Luci gui.

More information on upgrading a router is here:
* https://wiki.openwrt.org/doc/howto/generic.sysupgrade

### Flash OpenWRT on a device for the first time
1. Search https://wiki.openwrt.org/toh/start for your device.
1. Open Device Techdata page
1. Open Device Page
1. Follow the install instructions listed
