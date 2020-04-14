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
#include <sys/types.h>
#include <sys/stat.h>
#include <json-c/json.h>
#include "../mudparser.h"
#include "../mud_manager.h"
#include "../oms_utils.h"
#include "../oms_messages.h"
#include "testDevice.h"

/*
 * This uses the blocking call system() to run a shell script. This is for testing only
 */
int installFirewallIPRule(char *srcIp, char *destIp, char *destPort, char *srcDevice, char *destDevice, char *protocol, char *ruleName, char *fwAction, , char *aclType)
{
    char execBuf[1024];
    int retval;

    sprintf(execBuf, "%s -s %s -d %s -i %s -a all -j %s -b %s -p %s -n %s -t %s -f %s", UCI_FIREWALL_SCRIPT, srcDevice, destDevice, srcIp, destIp, destPort,
            protocol, ruleName, fwAction, aclType);

    retval = system(execBuf);

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

    snprintf(execBuf, BUFSIZE, "openssl cms -verify -in %s -inform DER -content %s", mudSigFileLocation, mudFileLocation);
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
