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

#./create_mud_db_entry.sh -d /tmp/mudDbFile.txt -i 192.168.1.147 -m 00:00:00:00:00 -u <mud-url> -f <local-mud-file-path> -h <hostName>
#
# Creates an entry for a device in the osmud database file. An entry in this file means it has been
# seen by the mud contoller
#
# The database file has the format:
# <IP>|<MAC>|<remote-mud-url>|<local-mud-file-location>

BASEDIR=`dirname "$0"`
usage() { 
  echo "Usage: 
Required: -d <mud-file-database-file> -i <device-ip-address> -m <device-mac-address> 
Optional: -u <mud-url> -f <local-mud-file> -c <target host name>" 1>&2; 
  exit 0; 
}

MUD_DB_FILE=""
SRC_IP=""
SRC_MAC_ADDR=""
MUD_URL=""
MUD_LOCAL_FILE=""
HOST_NAME=""

while getopts 'hd:i:m:u:f:c:' option; do
    case "${option}" in
        d) MUD_DB_FILE=$OPTARG;;
        i) SRC_IP=$OPTARG;;
        m) SRC_MAC_ADDR=$OPTARG;;
        u) MUD_URL=$OPTARG;;
        f) MUD_LOCAL_FILE=$OPTARG;;
        c) HOST_NAME=$OPTARG;;
	h | *) usage;;
    esac
done

if [[ -z "${MUD_DB_FILE/ //}" ]]; then
echo -e "ERROR: Please specify the MUD DB file!\n"
    exit 1
fi

if [[ -z "${HOST_NAME/ //}" ]]; then
    echo -e "ERROR: Please specify the target device host name!\n"
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

echo "${SRC_IP}|${SRC_MAC_ADDR}|${MUD_URL}|${MUD_LOCAL_FILE}|${HOST_NAME}" >> ${MUD_DB_FILE}

exit 0
