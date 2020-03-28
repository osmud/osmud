#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <features.h>
#include <arpa/inet.h>
#include <pcap/pcap.h>

#include "common.h"
#include "ip_dissect.h"
#include "dns_dissect.h"
#include "oms_messages.h"

static bool osm_dns_parse_name(const u_char *udp_payload,
                               size_t udp_payload_length,
                               size_t *off,
                               char *name,
                               size_t name_len);
static bool osm_dns_parse_record(const u_char *udp_payload,
                                 size_t udp_payload_length,
                                 size_t *off,
                                 osm_dns_record_t *r);
static bool osm_dns_parse_query(const u_char *udp_payload,
                                size_t udp_payload_length,
                                size_t *off,
                                osm_dns_query_t *q);


/*
 * Parse a UDP payload of a DNS packet in to a nice struct for further
 * processing and manipulation.
 * cpu should already be held (using osm_get_cpu())
 *
 * @param udp_payload wire-format of the DNS packet
 * @param udp_payload_length number of bytes in @a udp_payload
 * @return NULL on error, otherwise the parsed packet
 */
bool dissect_dns(const u_char *udp_payload,
                 size_t udp_payload_length,
                 osm_dns_packet_t *parsed_packet)
{
    const osm_dnshdr_t *dns;
    size_t off;
    unsigned int n;
    unsigned int i;

    CHECK_NOT_NULL(udp_payload, false);
    CHECK_NOT_NULL(parsed_packet, false);

    if (udp_payload_length < sizeof(osm_dnshdr_t))
    {
        logOmsGeneralMessage(OMS_WARN, OMS_SUBSYS_DNSD, "udp payload is too short: %" FMT_SIZE_T, udp_payload_length);
        goto error;
    }

    dns = (const osm_dnshdr_t *)udp_payload;
    off = sizeof(osm_dnshdr_t);
    parsed_packet->flags = dns->flags;
    parsed_packet->id = dns->id;
    n = ntohs(dns->query_count);

    if (OSM_DNS_MAX_SUP_RECORDS < n)
    {
        logOmsGeneralMessage(OMS_WARN, OMS_SUBSYS_DNSD, "too many queries in packet: %u", n);
        goto error;
    }

    parsed_packet->num_queries = n;
    if (n > 0)
    {
        for (i = 0; i < n; i++)
        {
            if (!osm_dns_parse_query(udp_payload,
                                      udp_payload_length,
                                      &off,
                                      &parsed_packet->queries[i]))
            {
                goto error;
            }
        }
    }
    n = ntohs(dns->answer_rcount);
    if (OSM_DNS_MAX_SUP_RECORDS < n)
    {
        logOmsGeneralMessage(OMS_WARN, OMS_SUBSYS_DNSD, "too many answers in packet: %u", n);
        goto error;
    }

    parsed_packet->num_answers = n;
    if (n > 0)
    {
        for (i = 0; i < n; i++)
        {
            if (!osm_dns_parse_record(udp_payload,
                udp_payload_length,
                &off,
                &parsed_packet->answers[i]))
            {
                goto error;
            }
        }
    }

    parsed_packet->num_authority_records = ntohs(dns->authority_rcount);
    parsed_packet->num_additional_records = ntohs(dns->additional_rcount);

    return true;
error:
    return false;
}


/*
 * Parse a DNS query entry.
 *
 * @param udp_payload entire UDP payload
 * @param udp_payload_length length of @a udp_payload
 * @param off pointer to the offset of the query to parse in the udp_payload (to be
 *                    incremented by the size of the query)
 * @param q where to write the query information
 * @return #GNUNET_OK on success, #GNUNET_SYSERR if the query is malformed
 */
static bool osm_dns_parse_query(const u_char *udp_payload,
                                size_t udp_payload_length,
                                size_t *off,
                                osm_dns_query_t *q)
{
    bool res;
    osm_dns_query_line_t *ql = NULL;

    CHECK_NOT_NULL(udp_payload, false);
    CHECK_NOT_NULL(off, false);
    CHECK_NOT_NULL(q, false);

    res = osm_dns_parse_name(udp_payload,
                              udp_payload_length,
                              off,
                              q->name,
                              sizeof(q->name));
    if (!res)
    {
        logOmsGeneralMessage(OMS_WARN, OMS_SUBSYS_DNSD, "failed parsing query name");
        return false;
    }

    if (*off + sizeof(osm_dns_query_line_t) > udp_payload_length)
    {
        logOmsGeneralMessage(OMS_WARN, OMS_SUBSYS_DNSD, "query metadata is too long");
        return false;
    }
    ql = (osm_dns_query_line_t *)&udp_payload[*off];

    *off += sizeof(osm_dns_query_line_t);
    q->type = ntohs(ql->type);
    q->dns_traffic_class = ntohs(ql->dns_traffic_class);

    return true;
}


/*
 * Parse a DNS record entry.
 *
 * @param udp_payload entire UDP payload
 * @param udp_payload_length length of @a udp_payload
 * @param off pointer to the offset of the record to parse in the udp_payload (to be
 *                    incremented by the size of the record)
 * @param r where to write the record information
 * @return #GNUNET_OK on success, #GNUNET_SYSERR if the record is malformed
 */
static bool osm_dns_parse_record(const u_char *udp_payload,
                                  size_t udp_payload_length,
                                  size_t *off,
                                  osm_dns_record_t *r)
{
    bool res;
    osm_dns_record_line_t *rl;
    size_t old_off;
    uint16_t data_len;

    res = osm_dns_parse_name(udp_payload,
                              udp_payload_length,
                              off,
                              r->name,
                              sizeof(r->name));
    if (!res)
    {
        logOmsGeneralMessage(OMS_WARN, OMS_SUBSYS_DNSD, "failed parsing record name");
        return false;
    }

    if (*off + sizeof(osm_dns_record_line_t) > udp_payload_length)
    {
        logOmsGeneralMessage(OMS_WARN, OMS_SUBSYS_DNSD, "record metadata is too long");
        return false;
    }
    rl = (osm_dns_record_line_t *)&udp_payload[*off];

    *off += sizeof(osm_dns_record_line_t);
    r->type = ntohs(rl->type);
    r->dns_traffic_class = ntohs(rl->dns_traffic_class);
    r->expiration_time = ntohl(rl->ttl);
    data_len = ntohs(rl->data_len);
    if (*off + data_len > udp_payload_length)
    {
        logOmsGeneralMessage(OMS_WARN, OMS_SUBSYS_DNSD, "record data length is out of udp payload bounds. "
                     "offset: %" FMT_SIZE_T ", data_len: %" PRIu16 ", udp_payload_len: %" FMT_SIZE_T,
                     *off, data_len, udp_payload_length);
        return false;
    }
    old_off = *off;
    switch (r->type)
    {
    case OSM_DNS_TYPE_NS:
    case OSM_DNS_TYPE_CNAME:
    case OSM_DNS_TYPE_PTR:
        res = osm_dns_parse_name(udp_payload,
                                  udp_payload_length,
                                  off,
                                  r->data.hostname,
                                  sizeof(r->data.hostname));
        if (!res || (old_off + data_len != *off))
        {
            return false;
        }

        return true;
    default:
        r->data.raw.data_len = data_len;
        if (data_len > sizeof(r->data.raw.data))
        {
            logOmsGeneralMessage(OMS_WARN, OMS_SUBSYS_DNSD, "raw data is too long %" PRIu16, data_len);
            return false;
        }
        memcpy(r->data.raw.data, &udp_payload[*off], data_len);
        break;
    }
    *off += data_len;
    return true;
}


/*
 * Parse name inside of a DNS query or record.
 *
 * @param udp_payload entire UDP payload
 * @param udp_payload_length length of @a udp_payload
 * @param off pointer to the offset of the name to parse in the udp_payload (to be
 *                    incremented by the size of the name)
 * @param depth current depth of our recursion (to prevent stack overflow)
 * @return name as 0-terminated C string on success, NULL if the payload is malformed
 */
static bool parse_name(const u_char *udp_payload, size_t udp_payload_length, size_t *off,
                       unsigned int depth, char *name, uint64_t name_len, uint16_t *name_off)
{
    uint8_t len;
    uint64_t written;
    size_t xoff;
    const uint8_t *input;

    input = (const uint8_t *)udp_payload;

    while (1)
    {
        if (*off >= udp_payload_length)
        {
            logOmsGeneralMessage(OMS_WARN, OMS_SUBSYS_DNSD, "overflowed udp_payload while parsing name. "
                         "payload len: %" FMT_SIZE_T ", offset: %" FMT_SIZE_T ", name: %s",
                         udp_payload_length, *off, name);
            goto error;
        }
        len = input[*off];
        if (0 == len)
        {
            (*off)++;
            break;
        }
        if (len < 64)
        {
            if (*off + 1 + len > udp_payload_length)
            {
                logOmsGeneralMessage(OMS_WARN, OMS_SUBSYS_DNSD, "overflowed udp_payload while parsing name len. "
                             "payload len: %" FMT_SIZE_T ", offset: %" FMT_SIZE_T ", name len: %u, name: %s",
                             udp_payload_length, *off, len, name);
                goto error;
            }

            if (*name_off + len + 2 > name_len)
            {
                logOmsGeneralMessage(OMS_WARN, OMS_SUBSYS_DNSD, "overflowed name buffer while parsing name. "
                             "payload len: %" FMT_SIZE_T ", offset: %" FMT_SIZE_T ", name len: %u, name: %s",
                             udp_payload_length, *off, len, name);
                goto error;
            }

            written = strlcpy((void *)&name[*name_off], (char *)&udp_payload[*off + 1], (int)len + 1);
            if (written != len)
            {
                logOmsGeneralMessage(OMS_WARN, OMS_SUBSYS_DNSD, "found null in the middle of a label. "
                             "payload len : %" FMT_SIZE_T ", offset : %" FMT_SIZE_T ", label len : %u, written : %" PRIu64 ", name : %s",
                             udp_payload_length, *off, len, written, name);
                goto error;
            }

            name[*name_off + len] = '.';
            name[*name_off + len + 1] = '\0';
            *name_off += 1 + len;
            *off += 1 + len;
        }
        else if ((64 | 128) == (len & (64 | 128)))
        {
            if (depth > 16)
            {
                /* hard bound on stack to prevent "infinite" recursion, disallow! */
                logOmsGeneralMessage(OMS_WARN, OMS_SUBSYS_DNSD, "recursion depth crossed 16");
                goto error;
            }

            /* pointer to string */
            if (*off + 1 > udp_payload_length)
            {
                logOmsGeneralMessage(OMS_WARN, OMS_SUBSYS_DNSD, "string pointer is out of udp payload");
                goto error;
            }
            xoff = ((len - (64 | 128)) << 8) + input[*off + 1];
            if (!parse_name(udp_payload,
                            udp_payload_length,
                            &xoff,
                            depth + 1,
                            name,
                            name_len,
                            name_off))
            {
                logOmsGeneralMessage(OMS_WARN, OMS_SUBSYS_DNSD, "failed parsing xstr");
                goto error;
            }

            if (*name_off > udp_payload_length)
            {
                logOmsGeneralMessage(OMS_WARN, OMS_SUBSYS_DNSD, "we are looping (building an infinite string)");
                goto error;
            }
            *off += 2;
            /* pointers always terminate names */
            break;
        }
        else
        {
            logOmsGeneralMessage(OMS_WARN, OMS_SUBSYS_DNSD, "neither pointer nor inline string, not supported... %u", len);
            goto error;
        }
    }

    if (0 < *name_off)
        name[*name_off - 1] = '\0'; /* eat tailing '.' */
    return true;

error:
    return false;
}


/*
 * Parse name inside of a DNS query or record.
 *
 * @param udp_payload entire UDP payload
 * @param udp_payload_length length of @a udp_payload
 * @param off pointer to the offset of the name to parse in the udp_payload (to be
 *                    incremented by the size of the name)
 * @return name as 0-terminated C string on success, NULL if the payload is malformed
 */
static bool osm_dns_parse_name(const u_char *udp_payload,
                                size_t udp_payload_length,
                                size_t *off,
                                char *name,
                                size_t name_len)
{
    bool ret;
    uint16_t name_offset = 0;

    memset(name, 0, name_len);
    ret = parse_name(udp_payload, udp_payload_length, off, 0, name, name_len, &name_offset);
    return ret;
}


const char *osm_dnsdissect_get_type(uint16_t type)
{
    switch (type)
    {
    case OSM_DNS_TYPE_A: return "A";
    case OSM_DNS_TYPE_NS: return "NS";
    case OSM_DNS_TYPE_CNAME: return "CNAME";
    case OSM_DNS_TYPE_SOA: return "SOA";
    case OSM_DNS_TYPE_PTR: return "PTR";
    case OSM_DNS_TYPE_MX: return "MX";
    case OSM_DNS_TYPE_TXT: return "TXT";
    case OSM_DNS_TYPE_RP: return "RP";
    case OSM_DNS_TYPE_AFSDB: return "AFSDB";
    case OSM_DNS_TYPE_SIG: return "SIG";
    case OSM_DNS_TYPE_KEY: return "KEY";
    case OSM_DNS_TYPE_AAAA: return "AAAA";
    case OSM_DNS_TYPE_LOC: return "LOC";
    case OSM_DNS_TYPE_SRV: return "SRV";
    case OSM_DNS_TYPE_NAPTR: return "NAPTR";
    case OSM_DNS_TYPE_KX: return "KX";
    case OSM_DNS_TYPE_CERT: return "CERT";
    case OSM_DNS_TYPE_DNAME: return "DNAME";
    case OSM_DNS_TYPE_APL: return "APL";
    case OSM_DNS_TYPE_DS: return "DS";
    case OSM_DNS_TYPE_SSHFP: return "SSHFP";
    case OSM_DNS_TYPE_IPSECKEY: return "IPSECKEY";
    case OSM_DNS_TYPE_RRSIG: return "RRSIG";
    case OSM_DNS_TYPE_NSEC: return "NSEC";
    case OSM_DNS_TYPE_DNSKEY: return "DNSKEY";
    case OSM_DNS_TYPE_DHCID: return "DHCID";
    case OSM_DNS_TYPE_NSEC3: return "NSEC3";
    case OSM_DNS_TYPE_NSEC3PARAM: return "NSEC3PARAM";
    case OSM_DNS_TYPE_TLSA: return "TLSA";
    case OSM_DNS_TYPE_HIP: return "HIP";
    case OSM_DNS_TYPE_CDS: return "CDS";
    case OSM_DNS_TYPE_CDNSKEY: return "CDNSKEY";
    case OSM_DNS_TYPE_OPENPGPKEY: return "OPENPGPKEY";
    case OSM_DNS_TYPE_TKEY: return "TKEY";
    case OSM_DNS_TYPE_TSIG: return "TSIG";
    case OSM_DNS_TYPE_URI: return "URI";
    case OSM_DNS_TYPE_TA: return "TA";
    }
    return "UNKNOWN";
}
