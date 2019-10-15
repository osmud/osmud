#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <net/if.h>
#include <pcap/pcap.h>
#include <arpa/inet.h>

#include "common.h"
#include "sniffer.h"
#include "ip_dissect.h"
#include "dns_dissect.h"
#include "oms_messages.h"

#define DNS_OP_FMT(dns_packet)    ((0 == dns_packet->flags.query_or_response) ? "QUERY" :   \
                                  ((1 == dns_packet->flags.query_or_response) ? "RESPONSE" :  "UNKNOWN" ))

static pthread_t dns_thread;

/*
 * Filter for packets on port 53, presumably DNS packets,
 * with the QR bit set (response).
 */
static const char *filter =
    "port 53 and ("
    "(udp and (not udp[10] & 128 = 0)) or"
    "(tcp and (not tcp[((tcp[12] & 0xf0) >> 2) + 2] & 128 = 0))"
    ")";

static char errbuf[PCAP_ERRBUF_SIZE] = {0};

/* Command-line Args */
static char intf[IFNAMSIZ] = { 'b', 'r', '-', 'l', 'a', 'n', '\0' };
static int snaplen = 2048;
static int timeout = 100;
static int promisc = 0;
static pcap_t *g_session = NULL;
static int g_link_type = 0;
static struct bpf_program g_bpf = {0};
static bool g_pcap_initialized = false;

static bool sniffer_create_pcap(void);
static void sniffer_free_pcap(void);
static bool sniffer_create_thread(void);


static void dns_record_debug(osm_dns_record_t *dns_record)
{
    uint32_t *ip = NULL;
    struct in_addr ip_addr;

    logOmsGeneralMessage(OMS_DEBUG, OMS_SUBSYS_DNSD, "type: %s for query name %s",
               osm_dnsdissect_get_type(dns_record->type), dns_record->name);

    switch (dns_record->type)
    {
        case OSM_DNS_TYPE_A:
            if (OSM_DNS_A_REC_LEN != dns_record->data.raw.data_len)
            {
                logOmsGeneralMessage(OMS_DEBUG, OMS_SUBSYS_DNSD, "A record len is %" FMT_SIZE_T ". should be %d.",
                           dns_record->data.raw.data_len, OSM_DNS_A_REC_LEN);
                return;
            }
            ip = (uint32_t *)dns_record->data.raw.data;
            ip_addr.s_addr = *ip;
            logOmsGeneralMessage(OMS_DEBUG, OMS_SUBSYS_DNSD, "%s", inet_ntoa(ip_addr));
            break;

        case OSM_DNS_TYPE_NS:
        case OSM_DNS_TYPE_CNAME:
        case OSM_DNS_TYPE_PTR:
            logOmsGeneralMessage(OMS_DEBUG, OMS_SUBSYS_DNSD, "%s", dns_record->data.hostname);
            break;
    }
}


static void dns_pkt_debug(osm_dns_packet_t *dns_packet)
{
    unsigned int i;

    logOmsGeneralMessage(OMS_DEBUG, OMS_SUBSYS_DNSD, "new dns %s. id: %u, query count: %u, answer count: %u, authority: %u, additional: %u",
               DNS_OP_FMT(dns_packet), dns_packet->id, dns_packet->num_queries, dns_packet->num_answers,
               dns_packet->num_authority_records, dns_packet->num_additional_records);

    for (i = 0; i < dns_packet->num_queries; i++)
    {
        logOmsGeneralMessage(OMS_DEBUG, OMS_SUBSYS_DNSD, "query %d: type: %s, name: %s", i + 1,
                   osm_dnsdissect_get_type(dns_packet->queries[i].type), dns_packet->queries[i].name);
    }
    for (i = 0; i < dns_packet->num_answers; i++)
    {
        logOmsGeneralMessage(OMS_DEBUG, OMS_SUBSYS_DNSD, "answer %d:", i + 1);
        dns_record_debug(&dns_packet->answers[i]);
    }
}



static void *sniffer_thread_func(void *arg)
{
    struct pcap_pkthdr *packet_hdr = NULL;
    struct dispkt dpkt = {{{{{0}}}}};
    osm_dns_packet_t *dns_packet = NULL;
	const u_char *packet_data = NULL;
	int i;

    logOmsGeneralMessage(OMS_DEBUG, OMS_SUBSYS_SNIFFER, "Inside sniffer thread");
    while (true)
    {
        i = pcap_next_ex(g_session, &packet_hdr, &packet_data);
        if (i < 0)
        {
            logOmsGeneralMessage(OMS_ERROR, OMS_SUBSYS_SNIFFER, "Error capturing packet: ", pcap_geterr(g_session));
            continue;
        }
        else if (!i)
        {
            continue;
        }

        if ((packet_hdr == NULL) || (packet_data == NULL))
        {
            logOmsGeneralMessage(OMS_ERROR, OMS_SUBSYS_SNIFFER, "Could not get packet header or packet data");
            continue;
        }

        /*
         * caplen should always be <= len, otherwise it's likely
         * that the packet that pcap received was somehow corrupted.
         *
         * This should never happen, unless there's memory corruption
         * going on, or a really nasty bug in libpcap.
         */
        if (packet_hdr->caplen > packet_hdr->len)
        {
            logOmsGeneralMessage(OMS_ERROR, OMS_SUBSYS_SNIFFER, "packet is malformed");
            continue;
        }

        logOmsGeneralMessage(OMS_DEBUG, OMS_SUBSYS_SNIFFER, "got good packet");

        /* Dissect the link/IP/IP_PROTO layers of the packet */
        if (!dissect_ip_packet(g_link_type, packet_hdr, packet_data, &dpkt))
        {
            logOmsGeneralMessage(OMS_WARN, OMS_SUBSYS_SNIFFER, "Failed dissecting packet's IP");
            continue;
        }

        dns_packet = calloc(1, sizeof(osm_dns_packet_t));
        if (dns_packet == NULL)
        {
            logOmsGeneralMessage(OMS_ERROR, OMS_SUBSYS_SNIFFER, "Failed to allocate dns packet struct");
            continue;
        }

        /* Output a representation of the DNS payload */
        if (!dissect_dns(dpkt.payload, dpkt.udp_payload_len, dns_packet))
        {
            logOmsGeneralMessage(OMS_WARN, OMS_SUBSYS_SNIFFER, "Failed dissecting packet's DNS");
            goto free_continue;
        }

        dns_pkt_debug(dns_packet);

free_continue:
        free(dns_packet);
    }

    return NULL;
}


bool sniffer_init(void)
{
    g_pcap_initialized = false;

    logOmsGeneralMessage(OMS_DEBUG, OMS_SUBSYS_SNIFFER, "Initializing pcap");
    if (!sniffer_create_pcap())
        goto err0;

    logOmsGeneralMessage(OMS_DEBUG, OMS_SUBSYS_SNIFFER, "Initializing sniffer thread");
    if (!sniffer_create_thread())
        goto err1;

    return true;
err1:
    sniffer_free_pcap();
err0:
    return false;
}


void sniffer_free(void)
{
    //TODO: free thread stuff
    sniffer_free_pcap();
}


static bool sniffer_create_pcap(void)
{
    bpf_u_int32 netmask, ip;

    g_session = pcap_open_live(intf, snaplen, promisc, timeout, errbuf);
	if (g_session == NULL)
	{
	    logOmsGeneralMessage(OMS_CRIT, OMS_SUBSYS_SNIFFER, "Unable to open '%s': %s", intf, errbuf);
		goto err0;
	}

	/* Ensure that we support the interface's link-level header */
	g_link_type = pcap_datalink(g_session);
	if (g_link_type != DLT_LINUX_SLL && g_link_type != DLT_EN10MB &&
	    g_link_type != DLT_IPV4 && g_link_type != DLT_IPV6)
	{
		logOmsGeneralMessage(OMS_ERROR, OMS_SUBSYS_SNIFFER, "Unsupported link type: %d", g_link_type);
		goto err1;
	}

	/* Get the IP and netmask (for the filter) */
	if (pcap_lookupnet(intf, &ip, &netmask, errbuf) == -1)
    {
		ip = 0;
		netmask = 0;
	}

    /* Compile and apply our filter (without BPF optimization) */
    if (pcap_compile(g_session, &g_bpf, filter, 0, netmask) == -1)
    {
        logOmsGeneralMessage(OMS_ERROR, OMS_SUBSYS_SNIFFER, "Error compiling filter: ", pcap_geterr(g_session));
        goto err1;
    }

	if (pcap_setfilter(g_session, &g_bpf) == -1)
	{
	    logOmsGeneralMessage(OMS_ERROR, OMS_SUBSYS_SNIFFER, "Error installing filter: ", pcap_geterr(g_session));
	    goto err2;
	}

    return true;

err2:
    pcap_freecode(&g_bpf);
err1:
    pcap_close(g_session);
err0:
    return false;
}


static void sniffer_free_pcap(void)
{
    if (g_pcap_initialized)
    {
        g_pcap_initialized = false;
        pcap_freecode(&g_bpf);
        pcap_close(g_session);
    }
}


static bool sniffer_create_thread(void)
{
    int ret;

    ret = pthread_create(&dns_thread, NULL, &sniffer_thread_func, NULL);
    if(ret != 0)
    {
        logOmsGeneralMessage(OMS_CRIT, OMS_SUBSYS_SNIFFER, "Error creating sniffer thread: %d", ret);
        goto err;
    }

    return true;
err:
    return false;
}
