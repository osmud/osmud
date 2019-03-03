# osMUD - OpenWRT dnsmasq integration

One source of events for osMUD to be made aware of MUD enabled devices entering or leaving the network is through leveraging the dnsmasq subsystem within OpenWRT. DHCP events are collected using an dnsmasq configuration and written out to an output file for consumption by osMUD.

## Configuring dnsmasq for osMUD

A configuration to execute a script when DHCP events are processed must be installed in the dnsmasq configuration. This normally done by modifying the file "/etc/dnsmasq.conf" and adding an entry for "dhcp-script". A sample configuration is provided here:
* src/dnsmasq/dnsmasq.sample.conf

Simply edit the /etc/dnsmasq.conf file and add the following lines to the end of the file.

`dhcp-script=/etc/osmud/detect_new_device.sh`

The "detect_new_device.sh" script is installed automatically when osMUD is installed through the OpenWRT package installation process. When executed, this script writes its output to:
* /var/log/dhcpmasq.txt

The osMUD option "-e dhcp-event-log-file" is intended to point to this file. If the location needs to be moved, change the detect script and and the osMUD startup configuration to create the linkage.  

## Notes

osMUD expect each line in this file to follow a specific format. Each line represents DHCP event that should be processed by osMUD. osMUD can process DHCP events from both MUD enabled devices and non-MUD devices (although non-MUD events are logged, but ignored).

Format:

Fields are SPACE delimited! No embedded spaces allowed.
* Field1: Date
* Field2: Action [NEW|OLD|DEL]
* Field3: --info only--
* Field4: Lan device where activated
* Field 5: DHCP options flag - info only
* Field 6: DHCP flags provided for fingerprinting or "-" if not available
* Field 7: MUD flag - info only
* Field 8: MUD url or "-" if not available
* Field9: MAC Address
* Field10: IP Address provided by DHCP server
* Field11: Host name *IF* Available

