#include "analytics.h"

#include <rte_common.h>
#include <rte_hash.h>
#include <rte_vect.h>
uint32_t insert_count = 0;
uint32_t lookup_count = 0;
int init_count = 0;
uint32_t manual_count[FLOW_NUM] = {0};

#define ALL_32_BITS 0xffffffff
#define BIT_8_TO_15 0x0000ff00

#if defined(MEASURE_LOOKUP_TIME)
static uint64_t total_lookup_ticks = 0;
static uint64_t prev_lookup_ticks = 0;
#endif

#if defined(MEASURE_INSERT_TIME)
static uint64_t total_insert_ticks = 0;
static uint64_t prev_insert_ticks = 0;
#endif

#if defined(RTE_ARCH_X86) || defined(__ARM_FEATURE_CRC32)
#define EM_HASH_CRC 1
#endif

#ifdef EM_HASH_CRC
#include <rte_hash_crc.h>
#define DEFAULT_HASH_FUNC       rte_hash_crc
#else
#include <rte_jhash.h>
#define DEFAULT_HASH_FUNC       rte_jhash
#endif

#if defined(__SSE2__)
static inline xmm_t
em_mask_key(void *key, xmm_t mask)
{
	__m128i data = _mm_loadu_si128((__m128i *)(key));

	return _mm_and_si128(data, mask);
}
#elif defined(__ARM_NEON)
static inline xmm_t
em_mask_key(void *key, xmm_t mask)
{
	int32x4_t data = vld1q_s32((int32_t *)key);

	return vandq_s32(data, mask);
}
#else
#error No vector engine (NEON) available, check your toolchain
#endif

int hwts_dynfield_offset = -1;

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

static rte_xmm_t mask0 = (rte_xmm_t){.u32 = {BIT_8_TO_15, ALL_32_BITS,
				ALL_32_BITS, ALL_32_BITS} };

static inline uint32_t
ipv4_hash_crc(const void *data, __rte_unused uint32_t data_len,
		uint32_t init_val)
{
	const union ipv4_5tuple_host *k;
	uint32_t t;
	const uint32_t *p;

	k = data;
	t = k->proto;
	p = (const uint32_t *)&k->port_src;

#ifdef EM_HASH_CRC
	init_val = rte_hash_crc_4byte(t, init_val);
	init_val = rte_hash_crc_4byte(k->ip_src, init_val);
	init_val = rte_hash_crc_4byte(k->ip_dst, init_val);
	init_val = rte_hash_crc_4byte(*p, init_val);
#else
	init_val = rte_jhash_1word(t, init_val);
	init_val = rte_jhash_1word(k->ip_src, init_val);
	init_val = rte_jhash_1word(k->ip_dst, init_val);
	init_val = rte_jhash_1word(*p, init_val);
#endif

	return init_val;
}

void
initialize_flow_table()
{
	#if defined(DATA_STRUCTURE_CUCKOO)
	struct rte_hash_parameters hash_params = {
		.name = "test",
		.entries = FLOW_NUM,
		.key_len = sizeof(union ipv4_5tuple_host),
		.hash_func = ipv4_hash_crc,
		.hash_func_init_val = 0,
		.socket_id = rte_socket_id(),
	};

	lookup_struct = rte_hash_create(&hash_params);

	for(int i = 0; i< FLOW_NUM; i++)
	{
		for(int j = 0; j <= SLOTS; j++)
		{
			pkt_ctr[i].ctr[j] = 0;
		}
	}
	#elif defined(DATA_STRUCTURE_NAIVE)
	for(int i = 0; i< FLOW_NUM; i++)
	{
		pkt_ctr[i].hi_f1 = pkt_ctr[i].hi_f2 = 0;
		for(int j = 0; j <= SLOTS; j++)
		{
			pkt_ctr[i].ctr[j] = 0;
		}
	}
	#endif
}

void
print_features_extracted()
{
	int i, bucket;
	for(i=0; i< FLOW_NUM; i++)
	{
		for (bucket=0; bucket<SLOTS; bucket++) {
			if (pkt_ctr[i].ctr[bucket] > 0) {
				// continue;
				char *protocol_name;
				switch (pkt_ctr[i].protocol[bucket]) {
					case TCP:
						protocol_name = "TCP";
						break;
					case UDP:
						protocol_name = "UDP";
						break;
					default:
						protocol_name = "?";
						break;
				}

				// if (pkt_ctr[i].expired[bucket]) {
				// 	printf("[Expired] ");
				// }

				printf("Flow %d | %hhu.%hhu.%hhu.%hhu (%d) --> %hhu.%hhu.%hhu.%hhu (%d) | %s | first seen: %ld | count: %d, max packet len: %ld, min packet leng: %ld", i,
					pkt_ctr[i].ip_src[bucket][0],pkt_ctr[i].ip_src[bucket][1],pkt_ctr[i].ip_src[bucket][2],pkt_ctr[i].ip_src[bucket][3],
					pkt_ctr[i].src_port[bucket],
					pkt_ctr[i].ip_dst[bucket][0],pkt_ctr[i].ip_dst[bucket][1],pkt_ctr[i].ip_dst[bucket][2],pkt_ctr[i].ip_dst[bucket][3],
					pkt_ctr[i].dst_port[bucket],
					protocol_name,
					pkt_ctr[i].first_seen[bucket],
					pkt_ctr[i].ctr[bucket], pkt_ctr[i].max_packet_len[bucket], pkt_ctr[i].min_packet_len[bucket]);

				printf("mean packet len: %f, variance packet len: %f", pkt_ctr[i].mean_packet_len[bucket], pkt_ctr[i].variance_packet_len[bucket]);

				printf("mean interarrival time: %f, variance interarrival time: %f", pkt_ctr[i].mean_interarrival_time[bucket], pkt_ctr[i].variance_interarrival_time[bucket]);

				printf("\n");
			}
		}
	}
}

void
print_flow_count()
{
	int i, bucket;
	int count = 0;
	int count_more_than_one = 0;
	for(i=0; i< FLOW_NUM; i++)
	{
		for (bucket=0; bucket<SLOTS; bucket++) {
			if (pkt_ctr[i].ctr[bucket] > 0) {
				count++;
			}
			if (pkt_ctr[i].ctr[bucket] > 1) {
				count_more_than_one++;
			}
		}
	}
	printf("Total flows, based on packet count: %d\n", count);
	// printf("Total flows, based on key count: %d\n", rte_hash_count(lookup_struct));
	printf("Total flows with more than one packet: %d\n", count_more_than_one);
}

void print_timing_stats()
{
	#if defined(MEASURE_LOOKUP_TIME)
	printf("Lookup total ticks: %ld\n", total_lookup_ticks);
	#endif
	printf("Lookup count: %d \n", lookup_count);
	#if defined(MEASURE_INSERT_TIME)
	printf("Insert total ticks: %ld\n", total_insert_ticks);
	#endif
	printf("Insert count: %d \n", insert_count);
	printf("Init count: %d \n", init_count);
	printf("Flow num: %d \n", FLOW_NUM);
	int total = 0;
	for (int i = 0; i < FLOW_NUM; i++)
		if (manual_count[i] == 1)
			total++;		
	printf("%d\n", total);
}

static void get_key(union ipv4_5tuple_host *key, struct rte_mbuf *m) {
	struct rte_ether_hdr *eth_hdr;
	uint16_t ether_type;
	void *l3;
	int hdr_len;
	void *ipv4_hdr;

	eth_hdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
	ether_type = eth_hdr->ether_type;
	l3 = (uint8_t *)eth_hdr + sizeof(struct rte_ether_hdr);
	if (ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
		ipv4_hdr = (struct rte_ipv4_hdr *)l3;
	}

	ipv4_hdr = (uint8_t *)ipv4_hdr +
		offsetof(struct rte_ipv4_hdr, time_to_live);

	/*
	 * Get 5 tuple: dst port, src port, dst IP address,
	 * src IP address and protocol.
	 */
	key->xmm = em_mask_key(ipv4_hdr, mask0.x);
}

static inline uint32_t
get_crc_hash(struct rte_mbuf *m) {
	union ipv4_5tuple_host key;

	get_key(&key, m);

	return ipv4_hash_crc(&key, 0, 0);
}

uint32_t lookup_index(struct rte_mbuf *m) {
	lookup_count++;
	#if defined(DATA_STRUCTURE_NAIVE)
	#if defined(HASH_RSS)
	uint32_t bucket = m->hash.rss & 0xfffff;
	uint32_t tag = (m->hash.rss & 0xfff00000)>>20;

	#elif defined(HASH_CRC)

	union ipv4_5tuple_host key;

	get_key(&key, m);
	uint32_t hash = ipv4_hash_crc(&key, 0, 0);
	uint32_t bucket = hash & 0xfffff;
	uint32_t tag = (hash & 0xfff00000)>>20;

	#endif

	if (pkt_ctr[bucket].hi_f1 == tag)
		return bucket;
	else
		return NOT_FOUND;

	#elif defined(DATA_STRUCTURE_CUCKOO)
	int ret;
	union ipv4_5tuple_host key;

	get_key(&key, m);

	// /* Find destination port */
	ret = rte_hash_lookup(lookup_struct, (const void *)&key);
	
	return (ret < 0) ? NOT_FOUND : ret;
	#endif
}

uint32_t insert_flow_table(struct rte_mbuf *m) {
	insert_count++;
	#if defined(DATA_STRUCTURE_NAIVE)

	#if defined(HASH_RSS)
	uint32_t bucket = m->hash.rss & 0xfffff;
	#elif defined(HASH_CRC)
	union ipv4_5tuple_host key;

	get_key(&key, m);
	uint32_t bucket = ipv4_hash_crc(&key, 0, 0) & 0xfffff;
	#endif

	if (pkt_ctr[bucket].hi_f1 == 0)
		return bucket;
	else
		return INSERT_FAILED;

	#elif defined(DATA_STRUCTURE_CUCKOO)
	int ret;
	union ipv4_5tuple_host key;

	get_key(&key, m);

	ret = rte_hash_add_key(lookup_struct, (void *) &key);
	
	if (ret < 0) {
		rte_exit(EXIT_FAILURE, "Unable to add entry");
	} else {
		return ret;
	}
	#endif
}

void
init_counters(uint32_t index, uint16_t tag, uint16_t slot, struct rte_mbuf *m) {
	init_count++;
	struct rte_tcp_hdr *tcp_hdr;
	struct rte_udp_hdr *udp_hdr;

	struct rte_ether_hdr *eth_hdr;
	struct rte_ipv4_hdr *ipv4_hdr;
	// struct rte_ipv6_hdr *ipv6_hdr;
	// struct rte_tcp_hdr *tcp_hdr;
	// struct rte_udp_hdr *udp_hdr;
	uint64_t l2_len;
	uint64_t l3_len;
	// uint64_t l4_len;
	uint64_t packet_len = 0;
	// uint64_t content_len;
	// uint8_t *content;
	uint16_t src_port;
	uint16_t dst_port;
	// uint32_t seq;
	// uint32_t ack;
	// char str[64] = {};
	// char hash_value[64] = {};
	// int diff = 0;
	// bool recalc_checksum = false;

	eth_hdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
	l2_len = sizeof(struct rte_ether_hdr);

	if (RTE_ETH_IS_IPV4_HDR(m->packet_type)) { // IPv4
		ipv4_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);
		l3_len = sizeof(struct rte_ipv4_hdr);
		packet_len = rte_be_to_cpu_16(ipv4_hdr->total_length) + l2_len + 4;
		// packet_len = rte_pktmbuf_pkt_len(m);
	}

	pkt_ctr[index].hi_f1 = tag;
	pkt_ctr[index].ctr[slot]++;

	pkt_ctr[index].max_packet_len[slot] = packet_len;
	pkt_ctr[index].min_packet_len[slot] = packet_len;

	pkt_ctr[index].mean_packet_len[slot] = packet_len;
	pkt_ctr[index].variance_packet_len[slot] = 0;

	uint64_t now = *hwts_field(m);
	pkt_ctr[index].first_seen[slot] = now;
	pkt_ctr[index].last_seen[slot] = now;
	pkt_ctr[index].max_interarrival_time[slot] = 0;
	pkt_ctr[index].min_interarrival_time[slot] = 0xFFFFFFFF;

	pkt_ctr[index].mean_interarrival_time[slot] = 0;
	pkt_ctr[index].variance_interarrival_time[slot] = 0;

	if (RTE_ETH_IS_IPV4_HDR(m->packet_type)) { // IPv4
		uint32_t_to_char(rte_bswap32(ipv4_hdr->src_addr),
		&(pkt_ctr[index].ip_src[slot][0]),
		&(pkt_ctr[index].ip_src[slot][1]),
		&(pkt_ctr[index].ip_src[slot][2]),
		&(pkt_ctr[index].ip_src[slot][3]));

		uint32_t_to_char(rte_bswap32(ipv4_hdr->dst_addr),
		&(pkt_ctr[index].ip_dst[slot][0]),
		&(pkt_ctr[index].ip_dst[slot][1]),
		&(pkt_ctr[index].ip_dst[slot][2]),
		&(pkt_ctr[index].ip_dst[slot][3]));

		if (ipv4_hdr->next_proto_id == IPPROTO_TCP) {
                        tcp_hdr = (struct rte_tcp_hdr *)((unsigned char *)ipv4_hdr + sizeof(struct rte_ipv4_hdr));
                        pkt_ctr[index].src_port[slot] = rte_be_to_cpu_16(tcp_hdr->src_port);
                        pkt_ctr[index].dst_port[slot] = rte_be_to_cpu_16(tcp_hdr->dst_port);
			pkt_ctr[index].protocol[slot] = TCP;
		} else {
			udp_hdr = (struct rte_udp_hdr *)((unsigned char *)ipv4_hdr + sizeof(struct rte_ipv4_hdr));
                        pkt_ctr[index].src_port[slot] = rte_be_to_cpu_16(udp_hdr->src_port);
                        pkt_ctr[index].dst_port[slot] = rte_be_to_cpu_16(udp_hdr->dst_port);
			pkt_ctr[index].protocol[slot] = UDP;
		}
	}
}

void
perform_analytics(struct rte_mbuf *m)
{
	if (!RTE_ETH_IS_IPV4_HDR(m->packet_type)) { // IPv4
		return;
	}

	#if defined(MEASURE_LOOKUP_TIME)
	prev_lookup_ticks = rte_rdtsc();
	#endif
	uint32_t index = lookup_index(m);
	#if defined(MEASURE_LOOKUP_TIME)
	total_lookup_ticks += rte_rdtsc() - prev_lookup_ticks;
	#endif

	if (index == NOT_FOUND) {
		#if defined(MEASURE_INSERT_TIME)
		prev_insert_ticks = rte_rdtsc();
		#endif
		index = insert_flow_table(m);
		#if defined(MEASURE_INSERT_TIME)
		total_insert_ticks += rte_rdtsc() - prev_insert_ticks;
		#endif

		if (index != INSERT_FAILED)
			init_counters(index, (m->hash.rss & 0xfff0000) >> 20, 0, m);
	} else {
		pkt_ctr[index].ctr[0]++;

		#if defined(COUNT_ONLY)
		return;
		#endif

		uint64_t packet_len = rte_pktmbuf_pkt_len(m);

		if (pkt_ctr[index].max_packet_len[0] < packet_len)
			pkt_ctr[index].max_packet_len[0] = packet_len;

		if (pkt_ctr[index].min_packet_len[0] > packet_len)
			pkt_ctr[index].min_packet_len[0] = packet_len;

		double old_mean = pkt_ctr[index].mean_packet_len[0];
		pkt_ctr[index].mean_packet_len[0] += (packet_len - old_mean) / pkt_ctr[index].ctr[0];
		pkt_ctr[index].variance_packet_len[0] = (
			(pkt_ctr[index].ctr[0] - 1) * pkt_ctr[index].variance_packet_len[0] + (packet_len - old_mean) * (packet_len - pkt_ctr[index].mean_packet_len[0])
			) / pkt_ctr[index].ctr[0];

		uint64_t now = *hwts_field(m);

		uint64_t delta = now - pkt_ctr[index].last_seen[0];
		pkt_ctr[index].last_seen[0] = now;

		if (pkt_ctr[index].max_interarrival_time[0] < delta)
			pkt_ctr[index].max_interarrival_time[0] = delta;

		if (pkt_ctr[index].min_interarrival_time[0] > delta)
			pkt_ctr[index].min_interarrival_time[0] = delta;

		double old_variance_mean = pkt_ctr[index].mean_interarrival_time[0];

		if (pkt_ctr[index].mean_interarrival_time[0] == 0)
			pkt_ctr[index].mean_interarrival_time[0] = delta;
		else
			pkt_ctr[index].mean_interarrival_time[0] += (delta - old_variance_mean) / (pkt_ctr[index].ctr[0] - 1);

		pkt_ctr[index].variance_interarrival_time[0] = (
			(pkt_ctr[index].ctr[0] - 1) * pkt_ctr[index].variance_interarrival_time[0] + (delta - old_variance_mean) * (delta - pkt_ctr[index].mean_interarrival_time[0])
			) / pkt_ctr[index].ctr[0];
	}
}

// static void
// mark_expired_flows()
// {
// 	int i, bucket;
// 	int count = 0;
// 	for(i=0; i< FLOW_NUM; i++)
// 	{
// 		for (bucket=0; bucket<SLOTS; bucket++) {
// 			if (pkt_ctr[i].ctr[bucket] > 0) {
// 				if (pkt_ctr[i].last_seen[bucket] - pkt_ctr[i].first_seen[bucket] > 234658398*5) {
// 					pkt_ctr[i].expired[bucket] = true;
// 				}
// 			}
// 		}
// 	}
// }
