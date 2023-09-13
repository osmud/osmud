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

# old example- block osmud.org:
#./create_ip_fw_rule.sh -t REJECT -s lan -d wan -i 192.168.1.147 -t 198.71.233.87 -p 80

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

# Then create rules based on mudfile
# TO-acl
#./create_ip_fw_rule.sh -t ACCEPT -p any -s lan -i 192.168.2.254 -a 9543 -d wan -j 34.234.205.19 -b 9543
#./create_ip_fw_rule.sh -t ACCEPT -p any -s lan -i 192.168.2.254 -a 9543 -d wan -j 52.72.253.175 -b 9543
#./create_ip_fw_rule.sh -t ACCEPT -p any -s lan -i 192.168.2.254 -a 9543 -d wan -j 54.173.245.126 -b 9543
# FROM-acl
#./create_ip_fw_rule.sh -t ACCEPT -p any -s wan -i 34.234.205.19 -a 9543 -d lan -j 192.168.2.254 -b 9543
#./create_ip_fw_rule.sh -t ACCEPT -p any -s wan -i 52.72.253.175 -a 9543 -d lan -j 192.168.2.254 -b 9543
#./create_ip_fw_rule.sh -t ACCEPT -p any -s wan -i 54.173.245.126 -a 9543 -d lan -j 192.168.2.254 -b 9543 -n

# dest-ip, dest-port, src-port can have a value of "any". This will note write an entry for this feature that blocks everything
# family and protocol can have value of "all"
# in these cases, these UCI values are not set which triggers the rule on any value for these settings

BASEDIR=`dirname "$0"`
usage() { 
  echo "Usage: 
Required: -t <target_firewall_action> -n <rule-name> -i <src-ip> -a <src-port> 
Optional: -p <proto> -s <src-zone>  -d <dest-zone> -j <dest-ip> -b <dest-port> -c <device host name>" 1>&2; 
  exit 0; 
}

TARGET=""
PROTO=""
SRC=""
SRC_IP=""
SRC_PORT=""
DEST=""
DEST_IP=""
DEST_PORT=""
RULE_NAME=""
HOST_NAME=""
FAMILY=""

while getopts 'ht:p:s:i:a:d:j:b:n:f:c:' option; do
    case "${option}" in
	t) TARGET=$OPTARG;;
	f) FAMILY=$OPTARG;;
	n) RULE_NAME=$OPTARG;;
	p) PROTO=$OPTARG;;
    s) SRC=$OPTARG;;
    i) SRC_IP=$OPTARG;;
    a) SRC_PORT=$OPTARG;;
    d) DEST=$OPTARG;;
    j) DEST_IP=$OPTARG;;
    b) DEST_PORT=$OPTARG;;
    c) HOST_NAME=$OPTARG;;
	h | *) usage;;
    esac
done

if [[ -z "${TARGET/ //}" ]]; then
    echo -e "ERROR: Plese specify target firewall action [ACCEPT|REJECT|DROP]!\n"
    exit 1
fi

if [[ -z "${HOST_NAME/ //}" ]]; then
    echo -e "ERROR: Plese specify target device host name action!\n"
    exit 1
fi

if [[ -z "${FAMILY/ //}" ]]; then
    echo -e "ERROR: Plese specify firewall protocol family [ipv4|ipv6|all]!\n"
    exit 1
fi

if [[ -z "${PROTO/ //}" ]]; then
    echo -e "ERROR: Plese specify protocol [tcp|udp|all].\n"
    exit 1
fi

if [[ -z "${SRC/ //}" ]]; then
    echo -e "ERROR: Plese specify source zone!\n"
    exit 1
fi

if [[ -z "${SRC_IP/ //}" ]]; then
    echo -e "ERROR: Please specify source ip!\n"
    exit 1
fi

if [[ -z "${SRC_PORT/ //}" ]]; then
    echo -e "ERROR: Please specify source port or 'any'.\n"
    exit 1
fi

if [[ -z "${DEST/ //}" ]]; then
    echo -e "ERROR: Plese specify dest zone!\n"
    exit 1
fi

if [[ -z "${DEST_IP/ //}" ]]; then
    echo -e "ERROR: Please specify dest ip or 'any'.\n"
    exit 1
fi

if [[ -z "${DEST_PORT/ //}" ]]; then
    echo "ERROR: Please specify dest port or 'any'\n"
    exit 1
fi

FINAL_HOST_NAME="mud_${HOST_NAME}_${RULE_NAME}"

uci add firewall rule
uci set firewall.@rule[-1].enabled='1'
uci set firewall.@rule[-1].name=${FINAL_HOST_NAME}
uci set firewall.@rule[-1].target=${TARGET}
uci set firewall.@rule[-1].src=${SRC}
uci set firewall.@rule[-1].src_ip=${SRC_IP}
uci set firewall.@rule[-1].dest=${DEST}

if [ ${PROTO} != 'all' ]; then
    uci set firewall.@rule[-1].proto=${PROTO}
fi

if [ ${FAMILY} != 'all' ]; then
    uci set firewall.@rule[-1].family=${FAMILY}
fi

if [ ${SRC_PORT} != 'any' ]; then
    uci set firewall.@rule[-1].src_port=${SRC_PORT}
fi

if [ ${DEST_IP} != 'any' ]; then
    uci set firewall.@rule[-1].dest_ip=${DEST_IP}
fi

if [ ${DEST_PORT} != 'any' ]; then
    uci set firewall.@rule[-1].dest_port=${DEST_PORT}
fi

#NOTE: We are now batching changes and as long as all MODs are applied without issue, we will issue the commit and restart
#uci commit firewall
#/etc/init.d/firewall restart

exit 0
