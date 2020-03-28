#include <glib.h>
#include <gmodule.h>

#include "common.h"
#include "dns_dissect.h"

typedef struct {
    uint32_t src_ip_addr;
    char *lower_port;
    char *upper_port;
    char *protocol;
    char *rule_name;
    char *action;
    char *acl_type;
    char *hostname;
} dns_rule_data_t;

bool dns_rules_init(void);
void dns_rules_free(void);
void dns_rules_add(const char *dns_name, dns_rule_data_t *rule_data);
void dns_rules_lookup_and_install(const osm_dns_packet_t *dns_pkt, uint32_t ip);
