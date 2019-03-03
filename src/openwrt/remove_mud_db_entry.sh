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

#./remove_mud_db_entry.sh -d /tmp/mudDbFile.txt -i 192.168.1.147 -m 00:00:00:00:00
#
# Removes an entry for a device in the osmud database file. An entry in this file means it has been
# seen by the mud contoller
#
# The database file has the format:
# <IP>|<MAC>|<remote-mud-url>|<local-mud-file-location>

BASEDIR=`dirname "$0"`
usage() { 
  echo "Usage: 
Required: -d <mud-file-database-file> -i <device-ip-address> -m <device-mac-address>" 1>&2; 
  exit 0; 
}

MUD_DB_FILE=""
SRC_IP=""
SRC_MAC_ADDR=""
MUD_URL=""
MUD_LOCAL_FILE=""

while getopts 'hd:i:m:u:f:' option; do
    case "${option}" in
        d) MUD_DB_FILE=$OPTARG;;
        i) SRC_IP=$OPTARG;;
        m) SRC_MAC_ADDR=$OPTARG;;
        u) MUD_URL=$OPTARG;;
        f) MUD_LOCAL_FILE=$OPTARG;;
	h | *) usage;;
    esac
done

if [[ -z "${MUD_DB_FILE/ //}" ]]; then
	echo -e "ERROR: Please specify MUD device database file!\n"
    exit 1
fi

if [[ -z "${SRC_IP/ //}" ]]; then
    echo -e "ERROR: Please specify device ip!\n"
    exit 1
fi

if [[ -z "${SRC_MAC_ADDR/ //}" ]]; then
    echo "ERROR: Please specify device MAC address!\n"
    exit 1
fi

# TODO: There is an opportunity for verification to look up the MAC addr and see it still maps to the same IP
# TODO: We should check line counts of each to make sure we're not removing the entire DB

cat ${MUD_DB_FILE} | grep -v ${SRC_MAC_ADDR} > /tmp/mudmaint
rm ${MUD_DB_FILE}
mv /tmp/mudmaint ${MUD_DB_FILE}

exit 0
