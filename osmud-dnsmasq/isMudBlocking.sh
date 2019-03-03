#!/bin/bash

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

deviceIp=$1
deviceDomain=$2
#outFile="/etc/osmud/outputPreDNS.log"

#echo "Client IP in shell script is: $deviceIp" | sudo tee --append $outFile
#echo "Domain in shell script is: $deviceDomain" | sudo tee --append $outFile

#if domain is in struct file then it is not blocked
input="/etc/osmud/mudExampleStruct.txt"
while IFS=" " read -r domain host ip mac
do
  echo "$domain :: $host :: $ip :: $mac" | sudo tee --append $outFile

  blocked=true
  if [ "$deviceIp" = "$ip" ]; then
    echo "Found same device! Use MUD! Checking to see if $domain is inside mudstruct" | sudo tee --append $outFile
    if [ "$deviceDomain" = "$domain" ]; then
      blocked=false
    fi

    if [ "$blocked" = true ]; then
      echo "domain blocked" | sudo tee --append $outFile
    else
      echo "domain not blocked" | sudo tee --append $outFile
    fi
    exit 1
  fi

done < "$input"

#don't block by default if MUD rule is not in place
echo "domain not blocked" | sudo tee --append $outFile
