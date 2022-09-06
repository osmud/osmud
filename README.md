# osMUD- Open Source MUD Manager

The open source Manufacturer Usage Description project (osMUD for short) is working to improve the security of connected things and their networks. osMUD implements the MUD specification, is free to use, and you can help improve it!

## What is MUD?

MUD, or Manufacture Usage Description, is the RFC-8520 published by the Internet Engineering Task Force (IETF) that allows manufactures to specify the intended network behaviors of the devices they build.
The full specification can be found at  https://tools.ietf.org/html/rfc8520.

## How to Contribute to osMUD

Code contributions can be made through the pull request process. The software is constantly being updated and extended. We would like a community of developers to help add features from the IETF specification into osMUD as well as provide ideas and extensions to other devices. We encourage you to fork the repository and investigate the code. When the implementation of the feature is complete, enter an issue into the project to identify the capability that is being requested to be included in the source base. Then, use the pull request and target the "develop" branch. We will make every attempt to review and accept the capability. The pull request documentation can be found here:

* https://help.github.com/articles/creating-a-pull-request-from-a-fork/

## How to use osMUD?

osMUD is designed to easily build, deploy, and run on the OpenWRT platform. Additionally, there are integrations with the *dnsmasq* and *OpenWRT firewall* services. In the OpenWRT deployment, osMUD is intended to be run as a service and by default uses typical locations under the `/var` filesystem. There are multiple configuration options, including where downloaded MUD files are stored, that must be configured when the application is run. When osMUD is installed the service startup script installed under `/etc/init.d/osmud` contains these default locations. These options can changed depending on the needs of a particular deployment.

Additionally, osMUD can be compiled and executed from a Linux command line. If osMUD is not being run as root or as a user that has write access under the `/var` filesystem, then command line arguments need to be set to directory locations with write access. When running from the command line, use the `-d` argument to keep osMUD from running as a service and to keep the process in the foreground. The other options are:

* `-l <osMUD-log-file-name>`
* `-x <pid-file>`
* `-b <mud-file-storage-directory>` (ensure you do not have a trailing `/` or it will break. Example of good argument: `-b /tmp/osmud`)

Another important option is used to configure where DHCP events are written to and used as input for osMUD. These events are used to notify the system of when devices enter and leave the network when using DHCP. The osMUD option `-e <dhcp-event-log-file>` is intended to point to these events. osMUD opens this file for read and monitors the file for new events. An integration is included for configuring the "dnsmasq" service to emit these events and more information can be found in `src/dnsmasq/README.md`.

Our intention in the future is for osMUD to have the ability to run in other environments with different DHCP/DNS servers and firewalls. Please feel free to suggest future service integrations. 

## Building osMUD Generic

```sh
$ cd src/
$ make
```

## Build OpenWRT, osMUD for OpenWRT, & osmud-dnsmasq for OpenWRT inside a Docker image

This process sets up the OpenWRT build environment in a docker image to build the artifacts required to install on the router. The steps (that will be better explained in the nexts paragraphs) are:

1. Create Docker image with required components for build environment
1. Build osMUD-dnsmasq (dnsmasq with osMUD changes)
1. Build osMUD
1. Install the built code on the (physical or virtual) router

### 1. Build OpenWRT

For building OpenWRT have a look at [this file](https://github.com/osmud/osmud/BuildAndInstall-OpenWRT.md#Create-Docker-OpenWRT-build-image).

### 2. Build osMUD-dnsmasq in OpenWRT

**Note**: Skip osmud-dnsmasq instructions until we have made the change for dnsmasq to read the DHCP MUD header option.

To build the integration among osMUD and dnsmasq follow the instruction in [this other file](https://github.com/osmud/osmud/BuildAndInstall-dnsmasq.md#Build-osMUD-dnsmasq-in-OpenWRT)

### 3. Build osmud for OpenWRT

The build process requires:

1. cloning the osMUD project into the Docker container (default directory: `~/osmud`;
1. installing the Makefile into the OpenWRT build environment;
1. then building the application.

The project can be cloned into any directory within the Docker container, but if it's put anywhere other than `~/osmud` (off of the root directory), the Makefile will need to be edited to point to the correct directory location of the source code.

Steps for building osMUD:

1. Clone https://github.com/osmud/osmud
1. Create an osmud directory for OpenWRT at `~/lede/package/network/config/osmud`
1. Copy `~/osmud/openwrt_toolchain/Makefile` to `~/lede/package/network/config/osmud/Makefile`
1. `cd ~/lede`
1. Run `make menuconfig`
1. Select osmud in  under `Base System -> osmud` (move to the osmud line and hit "y" to include in the build)
1. Run `make package/network/config/osmud/compile` to compile only osMUD

This builds osMUD to be something like `bin/packages/x86_64/base/osmud_0.2.0-1_x86_64.ipk`

## Install OpenWRT, osmud-dnsmasq in OpenWRT, & osMUD in OpenWRT 

### Install OpenWRT

For installing OpenWRT have a look at [this file]
(https://github.com/osmud/osmud/wiki/BuildAndInstall-OpenWRT.md#install-openwrt-on-the-router)

**Note**: installing OpenWRT is not necessary if you want to use a [dockerized version of OpenWRT](https://github.com/openwrt/docker)

### Install osMUD-dnsmasq

**Note: Skip osmud-dnsmasq instructions until we have made the change for dnsmasq to read the DHCP MUD header option.**

To install the integration among osMUD and dnsmasq follow the [instructions stored here](https://github.com/osmud/osmud/BuildAndInstall-dnsmasq.md#install-osmud-dnsmasq-on-the-router)

### Install osMUD

1. Scp osmud to the router `scp osmud_0.2.0-1_x86_64.ipk root@192.168.1.1:/tmp/
osmud_0.2.0-1_x86_64.ipk`
1. Ensure you have updated the router `opkg update`
1. Install osmud `opkg install /tmp/osmud_0.2.0-1_x86_64.ipk`
1. If in you have cloned also the source code, for testing, you can copy the file `~/osmud/test/textfile` to `/var/log/dhcpmasq.txt`. This is the log file osMUD knows how to read containing DHCP events for osMUD processing. 
1. If you need to add CA-certificates to the router (like Let's Encrypt) do the following:
    1. Download the intermediate cert (it gets the root cert by default too) with the name "lets-encrypt-x3-cross-signed.crt".
		- E.g., `curl -o lets-encrypt-x3-cross-signed.crt https://letsencrypt.org/certs/lets-encrypt-x3-cross-signed.pem.txt`
		- E.g., `curl -o lets-encrypt-r3.crt https://letsencrypt.org/certs/lets-encrypt-r3.pem`
    1. For more certs see: https://letsencrypt.org/certificates/
    1. Append the certificate to the router's ca-certificates: `cat lets-encrypt-x3-cross-signed.crt >> /etc/ssl/certs/ca-certificates.crt`
1. Copy the `osmud.init` script from `~/osmud/src/openwrt/` into the file `/etc/init.d/osmud` on the router. This script by default uses this startup configuration:
    * DNS_FILE_NAME_WITH_PATH="/var/state/osmud/dnswhitelist"
    * MUD_FILE_DIRECTORY="/var/state/osmud/mudfiles/"
    * BASECONFIGFILE="/var/etc/osmud.conf"
    * DHCP_EVENT_FILE="/var/log/dhcpmasq.txt"
    * PID_FILE="/var/run/osmud.pid"
    * OSMUD_LOG_FILE="/var/log/osmud.log"
1. Ensure the osmud startup script is executable `chmod 755 /etc/init.d/osmud`
1. Verify if the directory `/etc/osmud` was already created. If not:
	1. Create the directory on the rounter `mkdir /etc/osmud`.
	1. Install the file `~/osmud/src/openwrt/create_ip_fw_rule.sh` into `/etc/osmud/create_ip_fw_rule.sh` on the router.
	1. Make the firewall script executable using `chmod +x /etc/osmud/create_ip_fw_rule.sh`
	
### Execute osMUD

1. Start the osmud service using the command line `service osmud start` or using LUCI under the menu `System->Startup`
1. It could happen that you need *libjson-c2* to start osMUD, you could need to install it manually.
	1. To download it: `curl -o /tmp/libjson-c2_0.12.1-3.1_x86_64.ipk https://downloads.openwrt.org/releases/packages-19.07/x86_64/base/libjson-c2_0.12.1-3.1_x86_64.ipk`
	1. Make it executable `chmod 755 /tmp/libjson-c2_0.12.1-3.1_x86_64.ipk`
	1. Install it `opkg install /tmp/libjson-c2_0.12.1-3.1_x86_64.ipk`
1. Verify the service has started using an ssh shell into the router and the command `ps | grep osmud`. You can also verify the startup looking at the log file with the command `cat /var/log/osmud.log`.

You should see the MUD files and ".p7s" certs in `/var/state/osmud/mudfiles/` when the osmud process is running and downloads a MUD file. 

## How osMUD communicates with dnsmasq

osMUD will poll for a log file which dnsmasq writes to. This file is located at `/var/log/dhcpmasq.txt`. dnsmasq will write to this file after a device is connected to the DHCP server. This means when a device is new, old, or deleted to/from the DHCP server.

### Configure dnsmasq to write out DHCP devices

Edit `/etc/dnsmasq.conf` to include the line `dhcp-script=/etc/osmud/detect_new_device.sh`. This will allow dnsmasq to run the script after a device is connected to the DHCP server.

Note: You can find an example of this in `/etc/osmud/dnsmasq.sample.conf` after you have installed osMUD (`opkg install osmud`).

The detect_new_device.sh script will log device information to `/var/log/dhcpmasq.txt` when DHCP does something.

## Known Limitations

osMUD is currently immature. Here is a list of some important things to be aware of with the current state of osMUD

* Blocking process
* Does NOT implement MUD via LLDP
* Does NOT implement MUD via protocols supporting X509 certificates
* Reads DHCP input from text file
* Ignores MUD rules for lateral movement
* Must use OpenWRT Firewall
* Must use osmud-dnsmasq to read DHCP header option for MUD

## Future

* Run osMUD as non-blocking process
* DHCP client interface
* Firewall client interface
* Lateral movement will be locked down based on MUD file attributes
* Local MUD file support
* MUD file cache with cache expiration

We will be tackling the above limitations (?).

View the [milestones](https://github.com/osmud/osmud/milestones) to see what is being worked on next!
