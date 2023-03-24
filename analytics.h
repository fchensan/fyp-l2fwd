#include <stdint.h>
#include <rte_mbuf.h>
#include <rte_ethdev.h>

#define FLOW_NUM 65536

#define UDP 0
#define TCP 1

#define SLOTS 1

#define uint32_t_to_char(ip, a, b, c, d) do {\
    *a = (unsigned char)(ip >> 24 & 0xff);\
    *b = (unsigned char)(ip >> 16 & 0xff);\
    *c = (unsigned char)(ip >> 8 & 0xff);\
    *d = (unsigned char)(ip & 0xff);\
} while (0)

extern int hwts_dynfield_offset;

inline rte_mbuf_timestamp_t *
hwts_field(struct rte_mbuf *mbuf)
{
	return RTE_MBUF_DYNFIELD(mbuf,
			hwts_dynfield_offset, rte_mbuf_timestamp_t *);
}

struct pkt_count
{
	uint16_t hi_f1;
	uint16_t hi_f2;
	uint32_t ctr[SLOTS+1];

	uint64_t max_packet_len[SLOTS];
	uint64_t min_packet_len[SLOTS];

	double mean_packet_len[SLOTS];
	double variance_packet_len[SLOTS];

	uint64_t first_seen[SLOTS];
	uint64_t last_seen[SLOTS];
	uint64_t min_interarrival_time[SLOTS];
	uint64_t max_interarrival_time[SLOTS];

	double mean_interarrival_time[SLOTS];
	double variance_interarrival_time[SLOTS];

	unsigned char ip_src[SLOTS][4];
	unsigned char ip_dst[SLOTS][4];

	uint16_t src_port[SLOTS];
	uint16_t dst_port[SLOTS];

	unsigned char protocol[SLOTS];

	// bool expired[SLOTS];

} __rte_cache_aligned;

struct pkt_count pkt_ctr[FLOW_NUM] __rte_cache_aligned;

void print_features_extracted();

void init_counters(uint16_t index_l, uint16_t index_h, 
	uint16_t bucket, struct rte_mbuf *m, uint64_t packet_len, struct rte_ipv4_hdr *ipv4_hdr);

void perform_analytics(struct rte_mbuf *m);