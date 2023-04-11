#include <stdint.h>
#include <rte_mbuf.h>
#include <rte_ethdev.h>
#include <rte_hash.h>
#include <rte_vect.h>

#define DATA_STRUCTURE_NAIVE // Possible values: NAIVE, CUCKOO
#define BUCKET_FULL 255 // Change this to the max of uint8_t

#define NAIVE_MATCH_TAG 1

#define HASH_RSS 1 // Possible values HASH_CRC, HASH_RSS

#define MEASURE_LOOKUP_TIME 1
#define MEASURE_INSERT_TIME 1

#define FLOW_NUM 131072
#define NOT_FOUND FLOW_NUM-1
#define INSERT_FAILED FLOW_NUM-1

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

union ipv4_5tuple_host {
	struct {
		uint8_t  pad0;
		uint8_t  proto;
		uint16_t pad1;
		uint32_t ip_src;
		uint32_t ip_dst;
		uint16_t port_src;
		uint16_t port_dst;
	};
	xmm_t xmm;
};

struct pkt_count
{
	uint16_t hi_f1;
	uint16_t hi_f2;

	#if defined(DATA_STRUCTURE_NAIVE)
	union ipv4_5tuple_host key;
	#endif

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

#ifdef DATA_STRUCTURE_CUCKOO
struct rte_hash *lookup_struct;
#endif

void initialize_flow_table();

void print_features_extracted();
void print_flow_count();
void print_timing_stats();

void perform_analytics(struct rte_mbuf *m);
