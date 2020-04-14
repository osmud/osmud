/* Copyright 2018 osMUD
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef _OMS_DEVICE_INT
#define _OMS_DEVICE_INT

#include "json-c/json.h"
#include "mudparser.h"

#define LAN_DEVICE_NAME "lan"
#define WAN_DEVICE_NAME "wan"
#define DNS_FILE_NAME_WITH_PATH "/etc/dnswhitelist"

#define MUD_FILE_SIGNATURE_EXTENSION "p7s"
#define MUD_FILE_DEFAULT_EXTENSION   "json"

/* 0 indicates a valid mud file signature */
#define VALID_MUD_FILE_SIG 0
#define INVALID_MUD_FILE_SIG 1

#ifdef DEBUG
#define DNS_FILENAME_WITH_PATH "/tmp/mudStruct.txt"
#else
#define DNS_FILENAME_WITH_PATH "/usr/local/mudStruct.txt"
#endif

extern char *dnsWhiteListFile;
extern char *mudFileDataDirectory;
extern char *osmudConfigFile;
extern char *dhcpEventFile;
extern char *osmudPidFile;
extern char *osMudLogFile;

/* These prototypes are intended to be implemented by a device specific implementation and not in the mud manager */
int installFirewallIPRule(char *srcIp, char *destIp, char *destPort, char *srcDevice, char *destDevice, char *protocol, char *ruleName, char *fwAction, char *aclType, char* hostName);
int installFirewallIPRulePortRange(char *srcIp, char *destIp, char *lowerPort, char *upperPort, char *srcDevice, char *destDevice, char *protocol, char *ruleName, char *fwAction, char *aclType, char* hostName);
int removeFirewallIPRule(char *ipAddr, char *macAddress);
int reorderFirewallRejectAllIPRule(char *ipAddr);
int installMudDbDeviceEntry(char *mudDbDir, char *ipAddr, char *macAddress, char *mudUrl, char *mudLocalFile, char *hostName);
int removeMudDbDeviceEntry(char *mudDbDir, char *ipAddr, char *macAddress);
int verifyCmsSignature(char *mudFileLocation, char *mudSigFileLocation);
int commitAndApplyFirewallRules();
int rollbackFirewallConfiguration();
/* END Device Specific Prototypes */


DomainResolutions *resolveDnsEntryToIp(char *hostname);
void freeDnsInfo(DomainResolutions *dnsInfo);

int installDnsRule(char *targetDomainName, char *srcIpAddr, char *srcMacAddr, char *srcHostName, char *dnsFileNameWithPath);
int removeDnsRule(char *targetDomainName, char *srcIpAddr, char *srcMacAddr, char *dnsFileNameWithPath);

void resetDhcpCounters();
void buildDhcpEventsLogMsg(char *buf, int bufSize);

int createMudfileStorage(char *mudFileDataLocationInfo);
#endif
