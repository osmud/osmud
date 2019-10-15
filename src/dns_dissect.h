#ifndef _DNS_DISSECT
#define _DNS_DISSECT

#include <pcap/pcap.h>
#include "ip_dissect.h"

#define OSM_DNS_PORT                       (53)
#define OSM_DNS_MAX_PAYLOAD_SIZE           (512)
#define OSM_DNS_MAX_SUP_RECORDS            (30)
#define OSM_DNS_A_REC_LEN                  (4)

/*
 * The term "domain name" is a name consisting of two or more levels, such as,
 * for instance, "trademark-clearinghouse.com". A label is a part of a domain name,
 * such as, for instance, "trademark-clearinghouse" from the domain name "trademark-clearinghouse.com".
 */

/*
 * Maximum length of a label in DNS.
 */
#define OSM_DNS_MAX_LABEL_LENGTH           (63)

/*
 * Maximum length of a name in DNS.
 * Maximum name in the RFC is 253.
 * We add 2 bytes for a trailing '.' and a null terminator.
 */
#define OSM_DNS_MAX_NAME_LENGTH            (255)

/*
 * A few common DNS types.
 */
#define OSM_DNS_TYPE_ANY 0
#define OSM_DNS_TYPE_A 1
#define OSM_DNS_TYPE_NS 2
#define OSM_DNS_TYPE_CNAME 5
#define OSM_DNS_TYPE_SOA 6
#define OSM_DNS_TYPE_PTR 12
#define OSM_DNS_TYPE_MX 15
#define OSM_DNS_TYPE_TXT 16
#define OSM_DNS_TYPE_RP 17
#define OSM_DNS_TYPE_AFSDB 18
#define OSM_DNS_TYPE_SIG 24
#define OSM_DNS_TYPE_KEY 25
#define OSM_DNS_TYPE_AAAA 28
#define OSM_DNS_TYPE_LOC 29
#define OSM_DNS_TYPE_SRV 33
#define OSM_DNS_TYPE_NAPTR 35
#define OSM_DNS_TYPE_KX 36
#define OSM_DNS_TYPE_CERT 37
#define OSM_DNS_TYPE_DNAME 39
#define OSM_DNS_TYPE_APL 42
#define OSM_DNS_TYPE_DS 43
#define OSM_DNS_TYPE_SSHFP 44
#define OSM_DNS_TYPE_IPSECKEY 45
#define OSM_DNS_TYPE_RRSIG 46
#define OSM_DNS_TYPE_NSEC 47
#define OSM_DNS_TYPE_DNSKEY 48
#define OSM_DNS_TYPE_DHCID 49
#define OSM_DNS_TYPE_NSEC3 50
#define OSM_DNS_TYPE_NSEC3PARAM 51
#define OSM_DNS_TYPE_TLSA 52
#define OSM_DNS_TYPE_HIP 55
#define OSM_DNS_TYPE_CDS 59
#define OSM_DNS_TYPE_CDNSKEY 60
#define OSM_DNS_TYPE_OPENPGPKEY 61
#define OSM_DNS_TYPE_TKEY 249
#define OSM_DNS_TYPE_TSIG 250
#define OSM_DNS_TYPE_URI 256
#define OSM_DNS_TYPE_TA 32768

/*
 * A DNS query.
 */
typedef struct osm_dns_query
{

    /*
     * Name of the record that the query is for (0-terminated).
     * In UTF-8 format.  The library will convert from and to DNS-IDNA
     * as necessary.  Use #GNUNET_DNSPARSER_check_label() to test if an
     * individual label is well-formed.  If a given name is not well-formed,
     * creating the DNS packet will fail.
     */
    char name[OSM_DNS_MAX_NAME_LENGTH];

    /*
     * See GNUNET_DNSPARSER_TYPE_*.
     */
    uint16_t type;

    /*
     * See GNUNET_TUN_DNS_CLASS_*.
     */
    uint16_t dns_traffic_class;

} osm_dns_query_t;

/*
 * Information from MX records (RFC 1035).
 */
typedef struct osm_dns_mx_record
{

    /*
     * Preference for this entry (lower value is higher preference).
     */
    uint16_t preference;

    /*
     * Name of the mail server.
     * In UTF-8 format.  The library will convert from and to DNS-IDNA
     * as necessary.  Use #GNUNET_DNSPARSER_check_label() to test if an
     * individual label is well-formed.  If a given name is not well-formed,
     * creating the DNS packet will fail.
     */
    char mxhost[OSM_DNS_MAX_NAME_LENGTH];

} osm_dns_mx_record_t;

/*
 * Information from SRV records (RFC 2782).
 */
typedef struct osm_dns_srv_record
{

    /*
     * Hostname offering the service.
     * In UTF-8 format.  The library will convert from and to DNS-IDNA
     * as necessary.  Use #GNUNET_DNSPARSER_check_label() to test if an
     * individual label is well-formed.  If a given name is not well-formed,
     * creating the DNS packet will fail.
     */
    char target[OSM_DNS_MAX_NAME_LENGTH];

    /*
     * Preference for this entry (lower value is higher preference).  Clients
     * will contact hosts from the lowest-priority group first and fall back
     * to higher priorities if the low-priority entries are unavailable.
     */
    uint16_t priority;

    /*
     * Relative weight for records with the same priority.  Clients will use
     * the hosts of the same (lowest) priority with a probability proportional
     * to the weight given.
     */
    uint16_t weight;

    /*
     * TCP or UDP port of the service.
     */
    uint16_t port;

} osm_dns_srv_record_t;

/*
 * Information from SOA records (RFC 1035).
 */
typedef struct osm_dns_soa_record
{

    /*
     * The domainname of the name server that was the
     * original or primary source of data for this zone.
     * In UTF-8 format.  The library will convert from and to DNS-IDNA
     * as necessary.  Use #GNUNET_DNSPARSER_check_label() to test if an
     * individual label is well-formed.  If a given name is not well-formed,
     * creating the DNS packet will fail.
     */
    char mname[OSM_DNS_MAX_NAME_LENGTH];

    /*
     * A domainname which specifies the mailbox of the
     * person responsible for this zone.
     * In UTF-8 format.  The library will convert from and to DNS-IDNA
     * as necessary.  Use #GNUNET_DNSPARSER_check_label() to test if an
     * individual label is well-formed.  If a given name is not well-formed,
     * creating the DNS packet will fail.
     */
    char rname[OSM_DNS_MAX_NAME_LENGTH];

    /*
     * The version number of the original copy of the zone.
     */
    uint32_t serial;

    /*
     * Time interval before the zone should be refreshed.
     */
    uint32_t refresh;

    /*
     * Time interval that should elapse before a failed refresh should
     * be retried.
     */
    uint32_t retry;

    /*
     * Time value that specifies the upper limit on the time interval
     * that can elapse before the zone is no longer authoritative.
     */
    uint32_t expire;

    /*
     * The bit minimum TTL field that should be exported with any RR
     * from this zone.
     */
    uint32_t minimum_ttl;

} osm_dns_soa_record_t;

/*
 * Binary record information (unparsed).
 */
typedef struct osm_dns_raw_record
{

    /*
     * Binary record data.
     */
    char data[OSM_DNS_MAX_PAYLOAD_SIZE];

    /*
     * Number of bytes in data.
     */
    size_t data_len;
} osm_dns_raw_record_t;

/*
 * DNS flags (largely RFC 1035 / RFC 2136).
 */
typedef struct osm_dns_flags
{
#ifdef _WIN32
#pragma warning(push)
#pragma warning (disable:4214) /* nonstandard extension used : bit field types other than int */
#endif
#if (OSM_BYTE_ORDER == OSM_LITTLE_ENDIAN)
    /*
     * Set to 1 if recursion is desired (client -> server)
     */
    uint16_t recursion_desired : 1;

    /*
     * Set to 1 if message is truncated
     */
    uint16_t message_truncated : 1;

    /*
     * Set to 1 if this is an authoritative answer
     */
    uint16_t authoritative_answer : 1;

    /*
     * See GNUNET_TUN_DNS_OPCODE_ defines.
     */
    uint16_t opcode : 4;

    /*
     * query:0, response:1
     */
    uint16_t query_or_response : 1;

    /*
     * See GNUNET_TUN_DNS_RETURN_CODE_ defines.
     */
    uint16_t return_code : 4;

    /*
     * See RFC 4035.
     */
    uint16_t checking_disabled : 1;

    /*
     * Response has been cryptographically verified, RFC 4035.
     */
    uint16_t authenticated_data : 1;

    /*
     * Always zero.
     */
    uint16_t zero : 1;

    /*
     * Set to 1 if recursion is available (server -> client)
     */
    uint16_t recursion_available : 1;
#elif (OSM_BYTE_ORDER == OSM_BIG_ENDIAN)
    /*
     * query:0, response:1
     */
    uint16_t query_or_response : 1;

    /*
     * See GNUNET_TUN_DNS_OPCODE_ defines.
     */
    uint16_t opcode : 4;

    /*
     * Set to 1 if this is an authoritative answer
     */
    uint16_t authoritative_answer : 1;

    /*
     * Set to 1 if message is truncated
     */
    uint16_t message_truncated : 1;

    /*
     * Set to 1 if recursion is desired (client -> server)
     */
    uint16_t recursion_desired : 1;


    /*
     * Set to 1 if recursion is available (server -> client)
     */
    uint16_t recursion_available : 1;

    /*
     * Always zero.
     */
    uint16_t zero : 1;

    /*
     * Response has been cryptographically verified, RFC 4035.
     */
    uint16_t authenticated_data : 1;

    /*
     * See RFC 4035.
     */
    uint16_t checking_disabled : 1;

    /*
     * See GNUNET_TUN_DNS_RETURN_CODE_ defines.
     */
    uint16_t return_code : 4;
#endif /* BIG ENDIAN */
#ifdef _WIN32
#pragma warning(pop)
#endif
} __attribute__((packed)) osm_dns_flags_t;

/*
 * DNS header.
 */
typedef struct osm_dnshdr
{
    /*
     * Unique identifier for the request/response.
     */
    uint16_t id;

    /*
     * Flags.
     */
    osm_dns_flags_t flags;

    /*
     * Number of queries.
     */
    uint16_t query_count;

    /*
     * Number of answers.
     */
    uint16_t answer_rcount;

    /*
     * Number of authoritative answers.
     */
    uint16_t authority_rcount;

    /*
     * Number of additional records.
     */
    uint16_t additional_rcount;
} __attribute__((packed)) osm_dnshdr_t;

/*
 * DNS query prefix.
 */
typedef struct osm_dns_query_line
{
    /*
     * Desired type (GNUNET_DNSPARSER_TYPE_XXX). (NBO)
     */
    uint16_t type;

    /*
     * Desired class (usually GNUNET_TUN_DNS_CLASS_INTERNET). (NBO)
     */
    uint16_t dns_traffic_class;
} __attribute__((packed)) osm_dns_query_line_t;

/*
 * General DNS record prefix.
 */
typedef struct osm_dns_record_line
{
    /*
     * Record type (GNUNET_DNSPARSER_TYPE_XXX). (NBO)
     */
    uint16_t type;

    /*
     * Record class (usually GNUNET_TUN_DNS_CLASS_INTERNET). (NBO)
     */
    uint16_t dns_traffic_class;

    /*
     * Expiration for the record (in seconds). (NBO)
     */
    uint32_t ttl;

    /*
     * Number of bytes of data that follow. (NBO)
     */
    uint16_t data_len;
} __attribute__((packed)) osm_dns_record_line_t;

/*
 * A DNS response record.
 */
typedef struct osm_dns_record
{

    /*
     * Name of the record that the query is for (0-terminated).
     * In UTF-8 format.  The library will convert from and to DNS-IDNA
     * as necessary.  Use #GNUNET_DNSPARSER_check_label() to test if an
     * individual label is well-formed.  If a given name is not well-formed,
     * creating the DNS packet will fail.
     */
    char name[OSM_DNS_MAX_NAME_LENGTH];

    /*
     * Payload of the record (which one of these is valid depends on the 'type').
     */
    union
    {

        /*
         * For NS, CNAME and PTR records, this is the uncompressed 0-terminated hostname.
         * In UTF-8 format.  The library will convert from and to DNS-IDNA
         * as necessary.  Use #GNUNET_DNSPARSER_check_label() to test if an
         * individual label is well-formed.  If a given name is not well-formed,
         * creating the DNS packet will fail.
         */
        char hostname[OSM_DNS_MAX_NAME_LENGTH];

        /*
         * SOA data for SOA records.
         */
        osm_dns_soa_record_t soa;

        /*
         * MX data for MX records.
         */
        osm_dns_mx_record_t mx;

        /*
         * SRV data for SRV records.
         */
        osm_dns_srv_record_t srv;

        /*
         * Raw data for all other types.
         */
        osm_dns_raw_record_t raw;

    } data;


    /*
     * When does the record expire?
     */
    uint64_t expiration_time;

    /*
     * See GNUNET_DNSPARSER_TYPE_*.
     */
    uint16_t type;

    /*
     * See GNUNET_TUN_DNS_CLASS_*.
     */
    uint16_t dns_traffic_class;
} osm_dns_record_t;

/*
 * Easy-to-process, parsed version of a DNS packet.
 */
typedef struct osm_dns_packet
{
    /*
     * Array of all queries in the packet, must contain "num_queries" entries.
     */
    osm_dns_query_t queries[OSM_DNS_MAX_SUP_RECORDS];

    /*
     * Array of all answers in the packet, must contain "num_answers" entries.
     */
    osm_dns_record_t answers[OSM_DNS_MAX_SUP_RECORDS];

    /*
     * Number of queries in the packet.
     */
    unsigned int num_queries;

    /*
     * Number of answers in the packet, should be 0 for queries.
     */
    unsigned int num_answers;

    /*
     * Number of authoritative answers in the packet, should be 0 for queries.
     */
    unsigned int num_authority_records;

    /*
     * Number of additional records in the packet, should be 0 for queries.
     */
    unsigned int num_additional_records;

    /*
     * Bitfield of DNS flags.
     */
    struct osm_dns_flags flags;

    /*
     * DNS ID (to match replies to requests).
     */
    uint16_t id;

} osm_dns_packet_t;

const char *osm_dnsdissect_get_type(uint16_t type);

bool dissect_dns(const u_char *udp_payload,
                 size_t udp_payload_length,
                 osm_dns_packet_t *parsed_packet);

#endif /* _DNS_DISSECT */
