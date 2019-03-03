# osMUD- Open Source MUD Manager
The open source Manufacturer Usage Description project (osMUD for short) is working to improve the security of connected things and their networks. osMUD implements the MUD specification, is free to use, and you can help improve it!

## What is MUD?
MUD, or Manufacture Usage Description, is an RFC published by the Internet Engineering Task Force (IETF) that allows manufactures to specify the intended network behaviors of the devices they build. The full specification can be found at https://tools.ietf.org/html/draft-ietf-opsawg-mud.

## How to Contribute to osMUD
Code contributions can be made through the pull request process. The software is constantly being updated and extended. We would like a community of developers to help add features from the IETF specification into osMUD as well as provide ideas and extensions to other devices. We encourage you to fork the repository and investigate the code. When the implementation of the feature is complete, enter an issue into the project to identify the capability that is being requested to be included in the source base. Then, use the pull request and target the "develop" branch. We will make every attempt to review and accept the capability. The pull request documentation can be found here:
 * https://help.github.com/articles/creating-a-pull-request-from-a-fork/

## How to use osMUD?
osMUD is designed to easily build, deploy, and run on the OpenWRT platform. Additionally, there are integrations with the dnsmasq and OpenWRT firewall services. In the OpenWRT deployment, osMUD is intended to be run as a service and by default uses typical locations under the /var filesystem. There are multiple configuration options, including where downloaded MUD files are stored, that must be configured when the application is run. When osMUD is installed the service startup script installed under "/etc/init.d/osmud" contains these default locations. These options can changed depending on the needs of a particular deployment.

Additionally, osMUD can be compiled and executed from a Linux command line. If osMUD is not being run as root or as a user that has write access under the /var filesystem, then command line arguments need to be set to directory locations with write access. When running from the command line, use the "-d" argument to keep osMUD from running as a service and to keep the process in the foreground. The other options are:
* -l osMUD-log-file-name
* -x pid-file
* -b mud file storage directory (ensure you do not have a trailing `/` or it will break. Example of good argument: `-b /tmp/osmud`)

Another important option is used to configure where DHCP events are written to and used as input for osMUD. These events are used to notify the system of when devices enter and leave the network when using DHCP. The osMUD option "-e <dhcp-event-log-file" is intended to point to these events. osMUD opens this file for read and monitors the file for new events. An integration is included for configuring the "dnsmasq" service to emit these events and more information can be found in "src/dnsmasq/README.md". 

Our intention in the future is for osMUD to have the ability to run in other environments with different DHCP/DNS servers and firewalls. Please feel free to suggest future service integrations. 

## Building osMUD

### Build osMUD Generic
```sh
$ cd src/
$ make
```

### Build OpenWRT, osMUD for OpenWRT, & osmud-dnsmasq for OpenWRT in Docker image
This process sets up the OpenWRT build environment in a docker image to build the artifacts required to install on the router. The steps are:

1. Create Docker image with required components for build environment
1. Build osmud-dnsmasq (dnsmasq with osMUD changes)
1. Build osmud
1. Install on router

[Build OpenWRT](https://github.com/osmud/osmud/wiki/Build-&-Install-OpenWRT#create-docker-openwrt-build-image)

**Note: Skip osmud-dnsmasq instructions until we have made the change for dnsmasq to read the DHCP MUD header option.**

[Build osmud-dnsmasq in OpenWRT](https://github.com/osmud/osmud/wiki/Build-&-Install-osmud-dnsmasq#build-osmud-dnsmasq-in-openwrt)

### Build osmud for OpenWRT
The build process requires cloning the osMUD project into the Docker container, installing the Makefile into the OpenWRT build environment, and then building the application. The project can be cloned into any directory within the Docker container, but if it's put anywhere other than "~/osmud" (off of the root directory), the Makefile will need to be edited to point to the correct directory location of the source code.

1. Clone https://github.com/osmud/osmud
1. Create an osmud directory for OpenWRT at `lede/package/network/config/osmud`
1. Copy `osmud/openwrt_toolchain/Makefile` to `lede/package/network/config/osmud/Makefile`
1. Run `make menuconfig`
1. Select osmud in  under `Base System -> osmud` (move to the osmud line and hit "y" to include in the build)
1. Run `make package/network/config/osmud/compile` to compile only osMUD

This builds osMUD to be something like `bin/packages/mips_24kc/base/osmud_1.0-1_mips_24kc.ipk`

## Install OpenWRT, osMUD in OpenWRT, & osmud-dnsmasq in OpenWRT

[Install OpenWRT](https://github.com/osmud/osmud/wiki/Build-&-Install-OpenWRT#install-openwrt-on-the-router)

**Note: Skip osmud-dnsmasq instructions until we have made the change for dnsmasq to read the DHCP MUD header option.**

[Install osmud-dnsmasq on the router](https://github.com/osmud/osmud/wiki/Build-&-Install-osmud-dnsmasq#install-osmud-dnsmasq-on-the-router)

### Install osmud on the router
1. Scp osmud to the router `scp osmud_1.0.0-1_mips_24kc.ipk root@192.168.1.1:/tmp/
osmud_1.0.0-1_mips_24kc.ipk`
1. Ensure you have updated the router `opkg update`
1. Install osmud `opkg install /tmp/osmud_1.0.0-1_mips_24kc.ipk`
1. For testing, Copy the file `osmud/test/textfile` to `/var/log/dhcpmasq.txt`. This is the log file osMUD knows how to read containing DHCP events for osMUD processing. 
1. If you need to add ca-certificates to the router (like lets encrypt) do the following:
    1. Download the intermediate cert (it gets the root cert by default too) https://letsencrypt.org/certs/lets-encrypt-x3-cross-signed.pem.txt and name it `lets-encrypt-x3-cross-signed.crt`
    1. For more certs see: https://letsencrypt.org/certificates/
    1. Append the certificate to the router's ca-certificates: `cat lets-encrypt-x3-cross-signed.crt >> /etc/ssl/certs/ca-certificates.crt`
1. Copy the init.d script from osmud/src/openwrt/osmud into the file /etc/init.d/osmud on the router. This script by default uses this startup configuration:
    * DNS_FILE_NAME_WITH_PATH="/var/state/osmud/dnswhitelist"
    * MUD_FILE_DIRECTORY="/var/state/osmud/mudfiles/"
    * BASECONFIGFILE="/var/etc/osmud.conf"
    * DHCP_EVENT_FILE="/var/log/dhcpmasq.txt"
    * PID_FILE="/var/run/osmud.pid"
    * OSMUD_LOG_FILE="/var/log/osmud.log"
1. Ensure the osmud startup script is executable `chmod 755 /etc/init.d/osmud`
1. Create the directory on the rounter `mkdir /etc/osmud`.
1. Install the file osmud/src/openwrt/create_ip_fw_rule.sh into /etc/osmud/create_ip_fw_rule.sh on the router.
1. Make the firewall script executable using `chmod +x /etc/osmud/create_ip_fw_rule.sh`
1. Start the osmud service using the command line `service osmud start` or using UCI under the menu System->Startup
1. Verify the service has started using an ssh shell into the router and the command `ps | grep osmud`. You can also verify the startup looking at the log file with the command "cat /var/log/osmud.log".

You should see the MUD files and .p7s certs in `/var/state/osmud/mudfiles/` when the osmud process is running and downloads a MUD file. 

## How osMUD communicates with dnsmasq
osMUD will poll for a log file which dnsmasq writes to. This file is located at `/var/log/dhcpmasq.txt`. dnsmasq will write to this file after a device is connected to the DHCP server. This means when a device is new, old, or deleted to/from the DHCP server.

### Configure dnsmasq to write out DHCP devices
Edit `/etc/dnsmasq.conf` to include the line `dhcp-script=/etc/osmud/detect_new_device.sh`. This will allow dnsmasq to run the script after a device is connected to the DHCP server.

Note: You can find an example of this in `/etc/osmud/dnsmasq.sample.conf` after you have installed osMUD (opkg install osmud).

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

We will be tackling the above limitations very soon.

View the [milestones](https://github.com/osmud/osmud/milestones) to see what is being worked on next!
