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

#ifndef _MUD_PARSER
#define _MUD_PARSER

/*
 * This file contains the token definitions for identifying the structure of a MUD JSON file
 * when scanning the file
 */

#define MAX_DEVICE_POLICIES 50
#define MAX_ACES 50
#define MAX_ACLS 10
#define MAX_DNS_RESOLUTIONS 50

#define IETF_MUD_STATE 1
#define IETF_ACCESS_CONTROL_LISTS_STATE 2
#define FROM_DEVICE_POLICY_STATE 3
#define TO_DEVICE_POLICY_STATE 4
#define ACL_STATE 5
#define ACES_STATE 6
//
// MUD FILE STRUCTURE DEFINITIONS
#define IETF_MUD "ietf-mud:mud"
#define IETF_ACCESS_CONTROL_LISTS "ietf-access-control-list:access-lists"
#define IETF_ACCESS_CONTROL_ACLS "ietf-access-control-list:acls"
#define FROM_DEVICE_POLICY "from-device-policy"
#define TO_DEVICE_POLICY "to-device-policy"
#define ACCESS_LISTS "access-lists"
#define ACCESS_LIST "access-list"
#define ACL_NAME "acl-name"
#define ACL_TYPE "acl-type"
#define NAME "name"
#define TYPE "type"
#define ACL "acl"
#define ACES "aces"
#define ACE "ace"


// description "This is the version of the MUDspecification.  This memo specifies version 1
#define MUD_VERSION "mud-version"

// This is the MUD URL associated with the entry found in a MUD file.
#define MUD_URL "mud-url"

// This is intended to be when the current MUD file
// was generated.  MUD Controllers SHOULD NOT check
// for updates between this time plus cache validity";
#define LAST_UPDATE "last-update"

// A URI that resolves to a signature as described in this specification
#define MUD_SIGNATURE "mud-signature"

// The information retrieved from the MUD server is
// valid for these many hours, after which it should
// be refreshed.  N.B. MUD controller implementations
// need not discard MUD files beyond this period
#define CACHE_VALIDITY "cache-validity"

// This boolean indicates whether or not the Thing is
// currently supported by the manufacturer.";
#define IS_SUPPORTED "is-supported"

// A UTF-8 description of this Thing.  This
// should be a brief description that may be
// displayed to the user to determine whether
// to allow the Thing on the
// network.";
#define SYSTEMINFO "systeminfo"

// Manufacturer name, as described in
// the ietf-hardware yang module.";
#define MFG_NAME "mfg-name"

// Model name, as described in the
// ietf-hardware yang module.";
#define MODEL_NAME "model-name"

// description "firmware-rev, as described in the
// ietf-hardware yang module.  Note this field MUST
// NOT be included when the device can be updated
// but the MUD-URL cannot.";
#define FIRMWARE_REV "firmware-rev"

//description "software-rev, as described in the
//ietf-hardware yang module.  Note this field MUST
//NOT be included when the device can be updated
//but the MUD-URL cannot.";
#define SOFTWARE_REV "software-rev"

#define EXTENSIONS "extensions"

#define RULE_NAME "rule-name"
#define PROTOCOL "protocol"
#define DNS_NAME_SRC "ietf-acldns:src-dnsname"
#define DNS_NAME_DST "ietf-acldns:dst-dnsname"
#define DIRECTION_INITIATED "ietf-mud:direction-initiated"

#define PORT "port"
#define UPPER_PORT "upper-port"
#define LOWER_PORT "lower-port"
#define FORWARDING "forwarding"
#define IETF_MUD_ACL "ietf-mud:mud-acl"

// description
// "This node matches the authority section of the MUD URL
// of a Thing.  It is intended to grant access to all
// devices with the same authority section.";
#define IETF_SAME_MANUFACTURER "ietf-mud:same-manufacturer"

// description
// "Devices of the specified  model type will match if
// they have an identical MUD URL.
#define INET_URI "inet:uri"
         
// description "IP addresses will match this node if they are
// considered local addresses.  A local address may be
// a list of locally defined prefixes and masks
// that indicate a particular administrative scope.
#define IETF_LOCAL_NETWORKS "ietf-mud:local-networks"

// description "This node names a class that has associated with it
// zero or more IP addresses to match against.  These
// may be scoped to a manufacturer or via a standard URN.
//#define IETF_CONTROLLER "ietf-mud:controller"
#define IETF_CONTROLLER "controller"

// "This node matches one or more network elements that
// have been configured to be the controller for this
// Thing, based on its MUD URL.";
//#define IETF_MY_CONTROLLER "ietf-mud:my-controller"
#define IETF_MY_CONTROLLER "my-controller"

typedef enum {UNKNOWN,ACLDNS,SAME_MANUFACTURER,CONTROLLER,MY_CONTROLLER,LOCAL_NETWORK} ACE_TYPE;

typedef struct {
	ACE_TYPE aceType;
	char *ruleName;
	char *protocol;
	char *dnsName;
	char *lowerPort;
	char *upperPort;
	char *actionsForwarding;
	char *directionInitiated;
} AceEntry;

typedef struct {
	char *aclName;
	char *aclType;
	AceEntry aceList[MAX_ACES];
	int aceCount;
} AclEntry;

typedef struct {
	char *aclName;
	char *aclType;
} MudAccessList;

typedef struct {
	char *description;
	char *mudVersion;
	char *mudUrl;
	char *lastUpdate;
	char *cacheValidity;
	char *isSupported;
	char *systeminfo;
	char *mfgName;
	char *modelName;
	char *firmwareRev;
	char *softwareRev;
	char *extensions;

	MudAccessList toAccessList[MAX_DEVICE_POLICIES];
	MudAccessList fromAccessList[MAX_DEVICE_POLICIES];
    int toAccessListCount;
	int fromAccessListCount;

	AclEntry acls[MAX_ACLS];
	int aclListCount;
} MudFileInfo;

typedef struct {
	char *domainName;
	char *ipList[MAX_DNS_RESOLUTIONS];
	int ipCount;
} DomainResolutions;

int parse_mud_file(char *fullCommandLine);
void extract_mud_info(json_object *jobj, MudFileInfo *mfi);
MudFileInfo* parseMudFile(char *mudFileWithPath);
void freeMudFileInfo(MudFileInfo* mfi);
AclEntry *getMudFileAcl(char *aclName, MudFileInfo *mudFile);

#endif
