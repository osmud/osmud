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

#ifndef _OMS_OPENWRT
#define _OMS_OPENWRT

#define UCI_FIREWALL_SCRIPT "/etc/osmud/create_ip_fw_rule.sh"
#define UCI_FIREWALL_REMOVE_SCRIPT "/etc/osmud/remove_ip_fw_rule.sh"
#define UCI_FIREWALL_REORDER_REJECT_SCRIPT "/etc/osmud/reorder_ip_fw_reject_all_rule.sh"

#define MUD_DB_CREATE_SCRIPT "/etc/osmud/create_mud_db_entry.sh"
#define MUD_DB_REMOVE_SCRIPT "/etc/osmud/create_mud_db_entry.sh"

#define UCI_FIREWALL_COMMIT_SCRIPT "/etc/osmud/commit_ip_fw_rules.sh"
#define UCI_FIREWALL_ROLLBACK_SCRIPT "/etc/osmud/rollback_ip_fw_rules.sh"


#define MUD_STATE_FILE "mudStateFile.txt"

#endif
