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

#ifndef _DHCP_EVENT
#define _DHCP_EVENT

typedef enum {NONE,NEW,OLD,DEL} DHCP_ACTIONS;

typedef struct {
    char *date;
    DHCP_ACTIONS action; /* NEW | OLD | DEL */
    char *lanDevice;
    char *macAddress;
    char *ipAddress;
    char *hostName;
    char *dhcpRequestFlags;
    char *dhcpVendor;
    char *mudFileURL;
    char *mudSigURL;
    char *mudFileStorageLocation;
    char *mudSigFileStorageLocation;
} DhcpEvent;

void executeOpenMudDhcpAction(DhcpEvent *event);
const char* getDhcpEventText(DHCP_ACTIONS actionClass);
DHCP_ACTIONS getDhcpEventActionClass(char *);
int processDhcpEventFromLog(char *logMessage, DhcpEvent *dhcpEvent);
void clearDhcpEventRecord(DhcpEvent *dhcpEvent);
char *createSigUrlFromMudUrl(char *mudFileURL);
char *createStorageLocation(char *mudURL);
int validateMudFileWithSig(DhcpEvent *dhcpEvent);
void doDhcpLegacyAction(DhcpEvent *dhcpEvent);
void buildDhcpEventContext(char *logMsgBuf, char *action, DhcpEvent *dhcpEvent);


#endif
