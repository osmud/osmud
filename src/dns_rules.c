#include <netinet/in.h>
#include <arpa/inet.h>

#include "common.h"
#include "dns_rules.h"
#include "mud_manager.h"

typedef struct
{
    GHashTable  *dns_to_rules_tbl;
    GRWLock     rw_lock;
} dns_rules_map_t;

dns_rules_map_t g_dns_rules = {0};


bool dns_rules_init(void)
{
    logOmsGeneralMessage(OMS_DEBUG, OMS_SUBSYS_DNSR, "Initializing dns rules module");

    g_dns_rules.dns_to_rules_tbl = g_hash_table_new(g_str_hash, g_str_equal);
    if (g_dns_rules.dns_to_rules_tbl == NULL)
        return false;

    g_rw_lock_init(&g_dns_rules.rw_lock);

    return true;
}


void dns_rules_free(void)
{
    g_rw_lock_clear(&g_dns_rules.rw_lock);
    return;
}


void dns_rules_add(const char *dns_name, dns_rule_data_t *rule_data)
{
    GList *rules_list = NULL;

    logOmsGeneralMessage(OMS_DEBUG, OMS_SUBSYS_DNSR, "Inserting rule for (" FORMAT_IP ") - (%s)",
                         IP_TO_FORMAT(htonl(rule_data->src_ip_addr)), dns_name);

    g_rw_lock_writer_lock(&g_dns_rules.rw_lock);

    rules_list = g_hash_table_lookup(g_dns_rules.dns_to_rules_tbl, dns_name);
    rules_list = g_list_append(rules_list, rule_data);
    g_hash_table_insert(g_dns_rules.dns_to_rules_tbl, (char *)dns_name, rules_list);

    g_rw_lock_writer_unlock(&g_dns_rules.rw_lock);
}


void dns_rules_lookup_and_install(const osm_dns_packet_t *dns_pkt, uint32_t ip)
{
    GList *rules_list = NULL;
    dns_rule_data_t *rule_data = NULL;
    const char *dns_name;
    struct in_addr src_ip_addr;
    char *src_ip_addr_str;
    bool should_commit = false;
    bool should_rollback = false;
    int i;

    dns_name = dns_pkt->queries[0].name;
    src_ip_addr.s_addr = ip;
    src_ip_addr_str = g_strdup(inet_ntoa(src_ip_addr));

    g_rw_lock_reader_lock(&g_dns_rules.rw_lock);

    rules_list = g_hash_table_lookup(g_dns_rules.dns_to_rules_tbl, dns_name);
    while (rules_list != NULL)
    {
        rule_data = rules_list->data;
        if (ip != rule_data->src_ip_addr)
            goto next_rule;

        logOmsGeneralMessage(OMS_DEBUG, OMS_SUBSYS_DNSR, "Found a matching rule for (" FORMAT_IP ") - (%s)",
                             IP_TO_FORMAT(htonl(rule_data->src_ip_addr)), dns_name);

        for (i = 0; i < dns_pkt->num_answers; i++)
        {
            uint32_t *ip = NULL;
            struct in_addr dns_ip_addr;
            bool action_result;

            if (dns_pkt->answers[i].type != OSM_DNS_TYPE_A)
                continue;

            ip = (uint32_t *)dns_pkt->answers[i].data.raw.data;
            dns_ip_addr.s_addr = *ip;

            action_result = installFirewallIPRulePortRange(src_ip_addr_str,
                                                           inet_ntoa(dns_ip_addr),
                                                           rule_data->lower_port,
                                                           rule_data->upper_port,
                                                           LAN_DEVICE_NAME,
                                                           WAN_DEVICE_NAME,
                                                           rule_data->protocol,
                                                           rule_data->rule_name,
                                                           rule_data->action,
                                                           rule_data->acl_type,
                                                           rule_data->hostname);
            if (action_result)
            {
                logOmsGeneralMessage(OMS_CRIT, OMS_SUBSYS_DNSR, "Firewall rule installation failed");
                should_rollback = true;
                should_commit = false;
                goto commit_or_rollback;
            }
            else
            {
                should_commit = true;
            }
        }

next_rule:
        rules_list = rules_list->next;
    }

    g_rw_lock_reader_unlock(&g_dns_rules.rw_lock);

    if (should_commit)
    {
        /* push the reject-all rule to the end of the list */
        if (reorderFirewallRejectAllIPRule(src_ip_addr_str))
        {
            logOmsGeneralMessage(OMS_CRIT, OMS_SUBSYS_DNSR, "Failed reordering reject all rule");
            should_rollback = true;
            should_commit = false;
        }
    }

commit_or_rollback:
    if (should_rollback)
        rollbackFirewallConfiguration();
    else if (should_commit)
        commitAndApplyFirewallRules();

    g_free(src_ip_addr_str);
}
