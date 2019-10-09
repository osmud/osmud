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

/*
 * OpenWRT specific implementation of MUD rulesets
 */


/* Import function prototypes acting as the implementation interface
 * from the osmud manager to a specific physical device.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <json-c/json.h>
#include "../mudparser.h"
#include "../mud_manager.h"
#include "../oms_utils.h"
#include "../oms_messages.h"
#include "openwrt.h"

#define BUFSIZE 4096

//TODO: This needs to change into a custom UCI c-library implementation

char *getProtocolName(const char *protocolNumber)
{
    if (!protocolNumber)
        return "all";

    if (!strcmp(protocolNumber, "all")) {
        return "all";
    } else if (!strcmp(protocolNumber, "6")) {
        return "tcp";
    } else if (!strcmp(protocolNumber, "17")) {
        return "udp";
    } else {
        return "none";
    }
}

char *getActionString(const char *mudAction)
{
    if (!strcmpi(mudAction, "reject")) {
        return "REJECT";
    } else if (!strcmpi(mudAction, "accept")) {
        return "ACCEPT";
    } else {
        return "DROP";
    }
}

char *getProtocolFamily(const char *aclType)
{
    if (!aclType)
        return "all";

    if (!strcmpi(aclType, "all")) {
        return "all";
    } else if (!strcmpi(aclType, "ipv6-acl")) {
        return "ipv6";
    } else {
        return "ipv4";
    }
}

int installFirewallIPRule(char *srcIp, char *destIp, char *destPort, char *srcDevice,
        char *destDevice, char *protocol, char *ruleName, char *fwAction, char *aclType,
        char *hostName)
{
    char execBuf[BUFSIZE];
    int retval;

    /* TODO: We need to turn srcDevice and destDevice into the real values on the router */
    /*       by default they are "lan" and "wan" but can be changed. You can find this   */
    /*       with command "uci show dhcp.lan.interface" ==> dhcp.lan.interface='lan'     */
    /*       We should update the script to pull this value from UCI                     */
    /*       EX: uci show dhcp.lan.interface | awk -F = '{print $2}'                     */
    /* NOTE: Currently we are not restricting by source-port. If needed, add this as an arg */
    snprintf(execBuf, BUFSIZE, "%s -s %s -d %s -i %s -a any -j %s -b %s -p %s -n %s -t %s -f %s -c %s", UCI_FIREWALL_SCRIPT, srcDevice, destDevice, srcIp,
            destIp, destPort, getProtocolName(protocol),
            ruleName,
            getActionString(fwAction),
            getProtocolFamily(aclType),
            hostName);
    execBuf[BUFSIZE-1] = '\0';

    logOmsGeneralMessage(OMS_DEBUG, OMS_SUBSYS_GENERAL, execBuf);
    retval = system(execBuf);

    if (retval) {
        logOmsGeneralMessage(OMS_ERROR, OMS_SUBSYS_DEVICE_INTERFACE, execBuf);
    }
    return retval;
}

int commitAndApplyFirewallRules()
{
    int retval;

    logOmsGeneralMessage(OMS_DEBUG, OMS_SUBSYS_GENERAL, UCI_FIREWALL_COMMIT_SCRIPT);
    retval = system(UCI_FIREWALL_COMMIT_SCRIPT);

    if (retval) {
        logOmsGeneralMessage(OMS_ERROR, OMS_SUBSYS_DEVICE_INTERFACE, UCI_FIREWALL_COMMIT_SCRIPT);
    }
    return retval;
}

int rollbackFirewallConfiguration()
{
    int retval;

    logOmsGeneralMessage(OMS_DEBUG, OMS_SUBSYS_GENERAL, UCI_FIREWALL_ROLLBACK_SCRIPT);
    retval = system(UCI_FIREWALL_ROLLBACK_SCRIPT);

    if (retval) {
        logOmsGeneralMessage(OMS_ERROR, OMS_SUBSYS_DEVICE_INTERFACE, UCI_FIREWALL_ROLLBACK_SCRIPT);
    }
    return retval;
}

int removeFirewallIPRule(char *ipAddr, char *macAddress)
{
    char execBuf[BUFSIZE];
    int retval;

    snprintf(execBuf, BUFSIZE, "%s -i %s -m %s", UCI_FIREWALL_REMOVE_SCRIPT, ipAddr, macAddress);
    execBuf[BUFSIZE-1] = '\0';

    logOmsGeneralMessage(OMS_DEBUG, OMS_SUBSYS_GENERAL, execBuf);
    retval = system(execBuf);

    if (retval) {
        logOmsGeneralMessage(OMS_ERROR, OMS_SUBSYS_DEVICE_INTERFACE, execBuf);
    }
    return retval;

}

int installMudDbDeviceEntry(char *mudDbDir, char *ipAddr, char *macAddress, char *mudUrl, char *mudLocalFile, char *hostName)
{
    char execBuf[BUFSIZE];
    int retval;

    snprintf(execBuf, BUFSIZE, "%s -d %s%s -i %s -m %s -c %s -u %s -f %s", MUD_DB_CREATE_SCRIPT, mudDbDir, MUD_STATE_FILE, ipAddr,
            macAddress,
            (hostName?hostName:"-"),
            (mudUrl?mudUrl:"-"),
            (mudLocalFile?mudLocalFile:"-"));
    execBuf[BUFSIZE-1] = '\0';

    logOmsGeneralMessage(OMS_DEBUG, OMS_SUBSYS_GENERAL, execBuf);
    retval = system(execBuf);

    if (retval) {
        logOmsGeneralMessage(OMS_ERROR, OMS_SUBSYS_DEVICE_INTERFACE, execBuf);
    }
    return retval;
}

int removeMudDbDeviceEntry(char *mudDbDir, char *ipAddr, char *macAddress)
{
    char execBuf[BUFSIZE];
    int retval;

    snprintf(execBuf, BUFSIZE, "%s -d %s/%s -i %s -m %s", MUD_DB_REMOVE_SCRIPT, mudDbDir, MUD_STATE_FILE, ipAddr, macAddress);
    execBuf[BUFSIZE-1] = '\0';

    logOmsGeneralMessage(OMS_DEBUG, OMS_SUBSYS_GENERAL, execBuf);
    retval = system(execBuf);
    /* retval = run_command_with_output_logged(execBuf); */

    if (retval) {
        logOmsGeneralMessage(OMS_ERROR, OMS_SUBSYS_DEVICE_INTERFACE, execBuf);
    }
    return retval;
}


// TODO: Both of these need to be threadsafe with regard to read/write operations on the dnsFileName

// Appends a DNS entry to the DNS whitelist
int installDnsRule(char *targetDomainName, char *srcIpAddr, char *srcMacAddr, char *srcHostName, char *dnsFileNameWithPath)
{
    FILE *fp= NULL;
    int retval = 0;
    fp = fopen (dnsFileNameWithPath, "a");

    if (fp != NULL)
        {
            fprintf(fp, "%s %s %s %s\n", targetDomainName, srcHostName, srcIpAddr, srcMacAddr);

            fflush(fp);
            fclose(fp);
        }
        else
    {
            logOmsGeneralMessage(OMS_CRIT, OMS_SUBSYS_DEVICE_INTERFACE, "Could not write DNS rule to file.");
            retval = 1;
    }

    return retval;
}


// Removes a DNS entry from the DNS whitelist
int removeDnsRule(char *targetDomainName, char *srcIpAddr, char *srcMacAddr, char *dnsFileNameWithPath)
{

    return 0;
}

int verifyCmsSignature(char *mudFileLocation, char *mudSigFileLocation)
{
    /* openssl cms -verify -in mudfile.p7s -inform DER -content badtxt */

    char execBuf[BUFSIZE];
    int retval, sigStatus;

    snprintf(execBuf, BUFSIZE, "openssl cms -verify -in %s -inform DER -content %s -purpose any", mudSigFileLocation, mudFileLocation);
    execBuf[BUFSIZE-1] = '\0';

    logOmsGeneralMessage(OMS_DEBUG, OMS_SUBSYS_GENERAL, execBuf);
    retval = system(execBuf);

    /* A non-zero return value indicates the signature on the mud file was invalid */
    if (retval) {
        logOmsGeneralMessage(OMS_ERROR, OMS_SUBSYS_DEVICE_INTERFACE, execBuf);
        sigStatus = INVALID_MUD_FILE_SIG;
    }
    else {
        sigStatus = VALID_MUD_FILE_SIG;
    }

    return sigStatus;

}

/*
 * Creates the MUD storage location on the device filesystem
 * Return non-zero in the event the creation fails.
 */
int createMudfileStorage(char *mudFileDataLocationInfo)
{
    return mkdir_path(mudFileDataLocationInfo);
}

