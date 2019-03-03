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

# script to detect new dhcp lease

# this will be called by dnsmasq everytime a new device is connected
# with the following arguments
# $1 = add | old
# $2 = mac address
# $3 = ip address
# $4 = device name

# If you are interested in seeing other environment variables that DNSMASQ makes available
# so they can be added into the event log, these two lines can be uncommented.

# env >> /tmp/dhcpmasq.log
# echo "-----" >> /tmp/dhcpmasq.log

if [[ -z "${DNSMASQ_REQUESTED_OPTIONS/ //}" ]]; then
    DNSMASQ_REQUESTED_OPTIONS="-"
fi

if [[ -z "${DNSMASQ_VENDOR_CLASS/ //}" ]]; then
    DNSMASQ_VENDOR_CLASS="-"
fi

if [[ -z "${DNSMASQ_MUD_URL/ //}" ]]; then
    DNSMASQ_MUD_URL="-"
fi

if [ "$1" == "add" ]; then
  msg="|NEW|`uci get system.@system[0].hostname`.`uci get dhcp.@dnsmasq[0].domain`|DHCP|${DNSMASQ_REQUESTED_OPTIONS}|MUD|${DNSMASQ_MUD_URL}|${DNSMASQ_VENDOR_CLASS}|$2|$3|$4|"
  echo `date +%FT%T`$msg >> /var/log/dhcpmasq.txt
fi

if [ "$1" == "old" ]; then
  msg="|OLD|`uci get system.@system[0].hostname`.`uci get dhcp.@dnsmasq[0].domain`|DHCP|${DNSMASQ_REQUESTED_OPTIONS}|MUD|${DNSMASQ_MUD_URL}|${DNSMASQ_VENDOR_CLASS}|$2|$3|$4|"
  echo `date +%FT%T`$msg >> /var/log/dhcpmasq.txt
fi

if [ "$1" == "del" ]; then                                                                     
  msg="|DEL|`uci get system.@system[0].hostname`.`uci get dhcp.@dnsmasq[0].domain`|DHCP|${DNSMASQ_REQUESTED_OPTIONS}|MUD|${DNSMASQ_MUD_URL}|${DNSMASQ_VENDOR_CLASS}|$2|$3|$4|"
  echo `date +%FT%T`$msg >> /var/log/dhcpmasq.txt                                   
fi
