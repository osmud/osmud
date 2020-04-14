#ifndef _IP_DISSECT
#define _IP_DISSECT

#include <stdint.h>
#include <stdbool.h>
#include <netinet/in.h>
#include <pcap/pcap.h>

/*
 * Representation of a dissected TCP/UDP packet.
 */
struct dispkt
{
	union
	{ /* Source address */
		struct in6_addr ip6;
		uint32_t        ip;
	} sa;

	union { /* Destination address */
		struct in6_addr ip6;
		uint32_t        ip;
	} da;

	uint16_t sp;             /* Source port */
	uint16_t dp;             /* Destination port */
	int      family;         /* Address family */
	uint8_t  ip_proto;       /* IP protocol */
	size_t payload_offset;   /* Payload offset within the packet */
	size_t udp_payload_len;  /* The size of the udp payload */
	const u_char *payload;   /* Packet payload */
};

/*
 * Dissect a captured TCP/UDP packet.
 *
 * Because of the filter we're using, we can safely assume that
 * this is either TCP or UDP on top of IP. We also handle the case
 * where the packet may have become corrupted in several places,
 * by checking the bounds of \a data, and by double-checking the
 * protocol identifier(s).
 */
bool dissect_ip_packet(int lnk, struct pcap_pkthdr *hdr,
                      const u_char *data, struct dispkt *dpkt);

/*
 * Determine if the destination address given
 * in a dpkt belongs to an interface local to
 * this machine.
 */
bool dissect_is_destination_local(struct dispkt *dpkt);

#endif /* _IP_DISSECT */
