#!/bin/sh

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

#./remove_ip_fw_rule.sh -i 192.168.1.147 -m 00:00:00:00:00:00

# Removes all firewall rules involving the IP address
#
# Issues UCI commands at the command line to remove the device and restart the firewall

# example- mudfile nest.json for nest Thermostat:
# First we block everything:
#uci set firewall.@rule[-1].target=REJECT
#uci set firewall.@rule[-1].proto=all
#uci set firewall.@rule[-1].src=*
#uci set firewall.@rule[-1].src_ip=192.168.2.254
#uci set firewall.@rule[-1].src_port=*
#uci set firewall.@rule[-1].dest=*
#uci set firewall.@rule[-1].dest_ip=*
#uci set firewall.@rule[-1].dest_port=*


BASEDIR=`dirname "$0"`
usage() { 
  echo "Usage: 
Required: -i <ip-addr> -m <mac-addr>" 1>&2; 
  exit 0; 
}

DEVICE_IP=""
MAC_ADDR=""

while getopts 'hi:m:' option; do
    case "${option}" in
        i) DEVICE_IP=$OPTARG;;
        m) MAC_ADDR=$OPTARG;;
	h | *) usage;;
    esac
done

if [[ -z "${DEVICE_IP/ //}" ]]; then
    echo -e "ERROR: Please specify the source ip!\n"
    exit 1
fi

if [[ -z "${MAC_ADDR/ //}" ]]; then
    echo "ERROR: Please specify source MAC address!\n"
    exit 1
fi

FIREWALL_MATCHING_RULE="uci show firewall | awk '/$DEVICE_IP/' | awk -F [ '{print \$2}' | awk -F ] '{print \$1}'"
RULES_TO_DELETE=$(eval $FIREWALL_MATCHING_RULE)
SORTED_RULES=$(echo "$RULES_TO_DELETE" | sort -r)

for number in $SORTED_RULES
do 
    uci delete firewall.@rule[$number]
done

#NOTE: We are now batching changes and as long as all MODs are applied without issue, we will issue the commit and restart
#uci commit firewall
#/etc/init.d/firewall restart

exit 0
