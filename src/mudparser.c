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

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "json-c/json.h"
#include "oms_utils.h"
#include "mudparser.h"


AclEntry *getMudFileAcl(char *aclName, MudFileInfo *mudFile) {
	int i;
	AclEntry *locatedAcl = (AclEntry *)0;

	if (!aclName) {
		return (AclEntry *)0;
	}

    for (i = 0; i < mudFile->aclListCount; i++) {
    	if (!strcmp(mudFile->acls[i].aclName, aclName)) {
    		locatedAcl = &(mudFile->acls[i]);
    		break;
    	}
    }

    return locatedAcl;
}

void process_string(char *key, json_object *val, char *context, MudFileInfo *mfi, int state) {

        if (!strcmp(key, MUD_VERSION)) {
            mfi->mudVersion = copystring(json_object_get_string(val));
        } else if (!strcmp(key, MUD_URL)) {
            mfi->mudUrl = copystring(json_object_get_string(val));
        } else if (!strcmp(key, LAST_UPDATE)) {
            mfi->lastUpdate = copystring(json_object_get_string(val));
        } else if (!strcmp(key, MUD_SIGNATURE)) {
            mfi->mudVersion = copystring(json_object_get_string(val));
        } else if (!strcmp(key, CACHE_VALIDITY)) {
            mfi->cacheValidity = copystring(json_object_get_string(val));
        } else if (!strcmp(key, IS_SUPPORTED)) {
            mfi->isSupported = copystring(json_object_get_string(val));
        } else if (!strcmp(key, SYSTEMINFO)) {
            mfi->systeminfo = copystring(json_object_get_string(val));
        } else if (!strcmp(key, MFG_NAME)) {
            mfi->mfgName = copystring(json_object_get_string(val));
        } else if (!strcmp(key, MODEL_NAME)) {
            mfi->modelName = copystring(json_object_get_string(val));
        } else if (!strcmp(key, FIRMWARE_REV)) {
            mfi->firmwareRev = copystring(json_object_get_string(val));
        } else if (!strcmp(key, SOFTWARE_REV)) {
            mfi->softwareRev = copystring(json_object_get_string(val));
        } else if (!strcmp(key, EXTENSIONS)) {
            mfi->extensions = copystring(json_object_get_string(val));
        } else if ((!strcmp(key, ACL_NAME)) || (!strcmp(key, NAME)) || (!strcmp(key, RULE_NAME))) {
            if (state == FROM_DEVICE_POLICY_STATE) {
                mfi->fromAccessList[mfi->fromAccessListCount-1].aclName = copystring(json_object_get_string(val));
            } else if (state == TO_DEVICE_POLICY_STATE) {
                mfi->toAccessList[mfi->toAccessListCount-1].aclName = copystring(json_object_get_string(val));
            } else if (state == ACL_STATE) {
                mfi->acls[mfi->aclListCount-1].aclName = copystring(json_object_get_string(val));
            } else if (state == ACES_STATE) {
                mfi->acls[mfi->aclListCount-1].aceList[mfi->acls[mfi->aclListCount-1].aceCount-1].ruleName = copystring(json_object_get_string(val));
            }
        } else if ((!strcmp(key, ACL_TYPE)) || (!strcmp(key, TYPE))) {
            if (state == FROM_DEVICE_POLICY_STATE) {
                mfi->fromAccessList[mfi->fromAccessListCount-1].aclType = copystring(json_object_get_string(val));
            } else if (state == TO_DEVICE_POLICY_STATE) {
                mfi->toAccessList[mfi->toAccessListCount-1].aclType = copystring(json_object_get_string(val));
            } else if (state == ACL_STATE) {
                mfi->acls[mfi->aclListCount-1].aclType= copystring(json_object_get_string(val));
            }
        } else if (!strcmp(key, PROTOCOL)) {
            mfi->acls[mfi->aclListCount-1].aceList[mfi->acls[mfi->aclListCount-1].aceCount-1].protocol = copystring(json_object_get_string(val));
        } else if (!strcmp(key, DNS_NAME_SRC)) {  // TODO: There should never be both a SRC and DST DNS-NAME in the same object
            mfi->acls[mfi->aclListCount-1].aceList[mfi->acls[mfi->aclListCount-1].aceCount-1].aceType = ACLDNS;
            mfi->acls[mfi->aclListCount-1].aceList[mfi->acls[mfi->aclListCount-1].aceCount-1].dnsName = copystring(json_object_get_string(val));
        } else if (!strcmp(key, DNS_NAME_DST)) {
            mfi->acls[mfi->aclListCount-1].aceList[mfi->acls[mfi->aclListCount-1].aceCount-1].aceType = ACLDNS;
            mfi->acls[mfi->aclListCount-1].aceList[mfi->acls[mfi->aclListCount-1].aceCount-1].dnsName = copystring(json_object_get_string(val));
        } else if (!strcmp(key, PORT)) {
            mfi->acls[mfi->aclListCount-1].aceList[mfi->acls[mfi->aclListCount-1].aceCount-1].upperPort = copystring(json_object_get_string(val));
            mfi->acls[mfi->aclListCount-1].aceList[mfi->acls[mfi->aclListCount-1].aceCount-1].lowerPort = copystring(json_object_get_string(val));
        } else if (!strcmp(key, UPPER_PORT)) {
            mfi->acls[mfi->aclListCount-1].aceList[mfi->acls[mfi->aclListCount-1].aceCount-1].upperPort = copystring(json_object_get_string(val));
        } else if (!strcmp(key, LOWER_PORT)) {
            mfi->acls[mfi->aclListCount-1].aceList[mfi->acls[mfi->aclListCount-1].aceCount-1].lowerPort = copystring(json_object_get_string(val));
        } else if (!strcmp(key, FORWARDING)) {
            mfi->acls[mfi->aclListCount-1].aceList[mfi->acls[mfi->aclListCount-1].aceCount-1].actionsForwarding = copystring(json_object_get_string(val));
        } else if (!strcmp(key, DIRECTION_INITIATED)) {
            mfi->acls[mfi->aclListCount-1].aceList[mfi->acls[mfi->aclListCount-1].aceCount-1].directionInitiated = copystring(json_object_get_string(val));
/*
        } else if (!strcmp(key, IETF_MUD_ACL)) {
            mfi->acls[mfi->aclListCount-1].aceList[mfi->acls[mfi->aclListCount-1].aceCount-1].ruleName = copystring(json_object_get_string(val));
        } else if (!strcmp(key, IETF_SAME_MANUFACTURER)) {
            mfi->acls[mfi->aclListCount-1].aceList[mfi->acls[mfi->aclListCount-1].aceCount-1].ruleName = copystring(json_object_get_string(val));
*/
        }
#ifdef DEBUG_OSMUD
        else {
            printf("in final else in mud-info strings\n");
        }
#endif
}

void incrementState(int state, MudFileInfo *mfi) {
    if (state == FROM_DEVICE_POLICY_STATE) {
        mfi->fromAccessListCount++;
    } else if (state == TO_DEVICE_POLICY_STATE) {
        mfi->toAccessListCount++;
    } else if (state == ACL_STATE) {
        mfi->aclListCount++;
        mfi->acls[mfi->aclListCount-1].aceCount = 0;
    } else if (state == ACES_STATE) {
        mfi->acls[mfi->aclListCount-1].aceCount++;
    }
}

void processJson(json_object *jobj, char *context, int level, int state, MudFileInfo *mfi) {
    enum json_type type;
    int arraylen, i;

    json_object_object_foreach(jobj, key, val) {
#ifdef DEBUG_OSMUD
        printf("Level: %d, State: %d, Context: %s, key=%s value = %s\n", level, state, context, key, json_object_get_string(val));
#endif
        type = json_object_get_type(val);
        switch (type) {
            case json_type_null:
#ifdef DEBUG_OSMUD
                printf("Null\n\n");
#endif
                break;
            case json_type_boolean:
                process_string(key, val, context, mfi, state);
                break;
            case json_type_double:
                process_string(key, val, context, mfi, state);
                break;
            case json_type_int:
                process_string(key, val, context, mfi, state);
                break;
            case json_type_string:
                process_string(key, val, context, mfi, state);
                break;
            case json_type_object:
                {
                    int newState;
                    if (!strcmp(key, IETF_MUD)) {
                        newState = IETF_MUD_STATE;
                    } else if ((!strcmp(key, IETF_ACCESS_CONTROL_LISTS)) || (!strcmp(key, IETF_ACCESS_CONTROL_ACLS))) {
                        newState = ACL_STATE;
                    } else if (!strcmp(key, FROM_DEVICE_POLICY)) {
                        newState = FROM_DEVICE_POLICY_STATE;
                    } else if (!strcmp(key, TO_DEVICE_POLICY)) {
                        newState = TO_DEVICE_POLICY_STATE;
                    } else if (!strcmp(key, ACES)) {
                        newState = ACES_STATE;
                    } else if (!strcmp(key, ACL)) {
                        newState = ACL_STATE;
                    } else {
                        newState = state;
                    }

                    processJson(val, key, level + 1, newState, mfi);
                }
                break;
            case json_type_array:
                if (!strcmp(key, IETF_SAME_MANUFACTURER)) {
                	mfi->acls[mfi->aclListCount-1].aceList[mfi->acls[mfi->aclListCount-1].aceCount-1].aceType = SAME_MANUFACTURER;
                } else if (!strcmp(key, IETF_MY_CONTROLLER)) {
                	mfi->acls[mfi->aclListCount-1].aceList[mfi->acls[mfi->aclListCount-1].aceCount-1].aceType = MY_CONTROLLER;
                } else if (!strcmp(key, IETF_CONTROLLER)) {
                	mfi->acls[mfi->aclListCount-1].aceList[mfi->acls[mfi->aclListCount-1].aceCount-1].aceType = CONTROLLER;
                } else if (!strcmp(key, IETF_LOCAL_NETWORKS)) {
                	mfi->acls[mfi->aclListCount-1].aceList[mfi->acls[mfi->aclListCount-1].aceCount-1].aceType = LOCAL_NETWORK;
                }

                char *foo = copystring(json_object_get_string(val));
                if (strcmp(json_object_get_string(val), "[ null ]")) {
                    arraylen = json_object_array_length(val);

                    json_object *medi_array_obj;
                    for (i = 0; i < arraylen; i++) {
                        incrementState(state, mfi);

                        // get the i-th object in medi_array
                        medi_array_obj = json_object_array_get_idx(val, i);
                        processJson(medi_array_obj, context, level + 1, state, mfi);
                    }
                }
#ifdef DEBUG_OSMUD
                else {
                    printf("in null else\n");
                }
#endif
                safe_free(foo);
                break;
        }
    }
}

void freeMudFileInfo(MudFileInfo *mfi) {
	int i,j;

    safe_free(mfi->description);
    safe_free(mfi->mudVersion);
    safe_free(mfi->mudUrl);
    safe_free(mfi->lastUpdate);
    safe_free(mfi->cacheValidity);
    safe_free(mfi->isSupported);
    safe_free(mfi->systeminfo);
    safe_free(mfi->mfgName);
    safe_free(mfi->modelName);
    safe_free(mfi->firmwareRev);
    safe_free(mfi->softwareRev);
    safe_free(mfi->extensions);

    for (i = 0; i < mfi->fromAccessListCount; i++) {
        safe_free(mfi->fromAccessList[i].aclName);
        safe_free(mfi->fromAccessList[i].aclType);
    }

    for (i = 0; i < mfi->toAccessListCount; i++) {
        safe_free(mfi->toAccessList[i].aclName);
        safe_free(mfi->toAccessList[i].aclType);
    }

    for (i = 0; i < mfi->aclListCount; i++) {
        safe_free(mfi->acls[i].aclName);
        safe_free(mfi->acls[i].aclType);

        for (j = 0; j < mfi->acls[i].aceCount; j++) {
            safe_free(mfi->acls[i].aceList[j].actionsForwarding);
            safe_free(mfi->acls[i].aceList[j].dnsName);
            safe_free(mfi->acls[i].aceList[j].lowerPort);
            safe_free(mfi->acls[i].aceList[j].protocol);
            safe_free(mfi->acls[i].aceList[j].ruleName);
            safe_free(mfi->acls[i].aceList[j].upperPort);
        }
    }

    safe_free((char *)mfi);
}

MudFileInfo *createMfi() {
    MudFileInfo *mfi = (MudFileInfo *)safe_malloc(sizeof(MudFileInfo));
    mfi->description = (char *)0;
    mfi->mudVersion = (char *)0;
    mfi->mudUrl = (char *)0;
    mfi->lastUpdate = (char *)0;
    mfi->cacheValidity = (char *)0;
    mfi->isSupported = (char *)0;
    mfi->systeminfo = (char *)0;
    mfi->mfgName = (char *)0;
    mfi->modelName = (char *)0;
    mfi->firmwareRev = (char *)0;
    mfi->softwareRev = (char *)0;
    mfi->extensions = (char *)0;

    mfi->toAccessListCount = 0;
    mfi->fromAccessListCount = 0;
    mfi->aclListCount = 0;

	int i,j;

    for (i = 0; i < MAX_DEVICE_POLICIES; i++) {
        mfi->fromAccessList[i].aclName = (char *)0;
        mfi->fromAccessList[i].aclType = (char *)0;
    }

    for (i = 0; i < MAX_DEVICE_POLICIES; i++) {
        mfi->toAccessList[i].aclName = (char *)0;
        mfi->toAccessList[i].aclType = (char *)0;
    }

    for (i = 0; i < MAX_ACLS; i++) {
        mfi->acls[i].aclName = (char *)0;
        mfi->acls[i].aclType = (char *)0;
        mfi->acls[i].aceCount = 0;

        for (j = 0; j < MAX_ACES; j++) {
        	mfi->acls[i].aceList[j].aceType = UNKNOWN;
            mfi->acls[i].aceList[j].actionsForwarding = (char *)0;
            mfi->acls[i].aceList[j].dnsName = (char *)0;
            mfi->acls[i].aceList[j].lowerPort = (char *)0;
            mfi->acls[i].aceList[j].protocol = (char *)0;
            mfi->acls[i].aceList[j].ruleName = (char *)0;
            mfi->acls[i].aceList[j].upperPort = (char *)0;
        }
    }

    return mfi;
}


MudFileInfo* parseMudFile(char *mudFileWithPath) {

	MudFileInfo *mfi = createMfi();

    char * string = readFileToString(mudFileWithPath);
    json_object * jobj = json_tokener_parse(string);

    processJson(jobj, "<root>", 0, 0, mfi);

    return mfi;
}

