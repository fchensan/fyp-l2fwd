#include "analytics.h"

int hwts_dynfield_offset = -1;

void
initialize_flow_table()
{
	for(int i = 0; i< FLOW_NUM; i++)
	{
		pkt_ctr[i].hi_f1 = pkt_ctr[i].hi_f2 = 0;
		for(int j = 0; j <= SLOTS; j++)
		{
			pkt_ctr[i].ctr[j] = 0;
		}
	}
}

void
print_features_extracted()
{
	int i, bucket;
	int count = 0;
	for(i=0; i< FLOW_NUM; i++)
	{
		for (bucket=0; bucket<SLOTS; bucket++) {
			if (pkt_ctr[i].ctr[bucket] > 0) {
				count++;
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
	printf("Total flows: %d\n", count);
}

uint32_t get_bucket(struct rte_mbuf *m) {
	return m->hash.rss & 0xffff;
}

uint32_t get_tag(struct rte_mbuf *m) {
	return (m->hash.rss & 0xffff0000)>>16;
}

bool check_slot_match(uint32_t bucket, uint32_t tag) {
	return pkt_ctr[bucket].hi_f1 == tag;
}

void
init_counters(uint16_t index_l, uint16_t index_h, uint16_t bucket, struct rte_mbuf *m, uint64_t packet_len, struct rte_ipv4_hdr *ipv4_hdr) {
	struct rte_tcp_hdr *tcp_hdr;
	struct rte_udp_hdr *udp_hdr;

	pkt_ctr[index_l].hi_f1 = index_h;
	pkt_ctr[index_l].ctr[bucket]++;

	pkt_ctr[index_l].max_packet_len[bucket] = packet_len;
	pkt_ctr[index_l].min_packet_len[bucket] = packet_len;

	pkt_ctr[index_l].mean_packet_len[bucket] = packet_len;
	pkt_ctr[index_l].variance_packet_len[bucket] = 0;

	uint64_t now = *hwts_field(m);
	pkt_ctr[index_l].first_seen[bucket] = now;
	pkt_ctr[index_l].last_seen[bucket] = now;
	pkt_ctr[index_l].max_interarrival_time[bucket] = 0;
	pkt_ctr[index_l].min_interarrival_time[bucket] = 0xFFFFFFFF;

	pkt_ctr[index_l].mean_interarrival_time[bucket] = 0;
	pkt_ctr[index_l].variance_interarrival_time[bucket] = 0;

	if (RTE_ETH_IS_IPV4_HDR(m->packet_type)) { // IPv4
		uint32_t_to_char(rte_bswap32(ipv4_hdr->src_addr),
		&(pkt_ctr[index_l].ip_src[bucket][0]),
		&(pkt_ctr[index_l].ip_src[bucket][1]),
		&(pkt_ctr[index_l].ip_src[bucket][2]),
		&(pkt_ctr[index_l].ip_src[bucket][3]));

		uint32_t_to_char(rte_bswap32(ipv4_hdr->dst_addr),
		&(pkt_ctr[index_l].ip_dst[bucket][0]),
		&(pkt_ctr[index_l].ip_dst[bucket][1]),
		&(pkt_ctr[index_l].ip_dst[bucket][2]),
		&(pkt_ctr[index_l].ip_dst[bucket][3]));

		if (ipv4_hdr->next_proto_id == IPPROTO_TCP) {
                        tcp_hdr = (struct rte_tcp_hdr *)((unsigned char *)ipv4_hdr + sizeof(struct rte_ipv4_hdr));
                        pkt_ctr[index_l].src_port[bucket] = rte_be_to_cpu_16(tcp_hdr->src_port);
                        pkt_ctr[index_l].dst_port[bucket] = rte_be_to_cpu_16(tcp_hdr->dst_port);
			pkt_ctr[index_l].protocol[bucket] = TCP;
		} else {
			udp_hdr = (struct rte_udp_hdr *)((unsigned char *)ipv4_hdr + sizeof(struct rte_ipv4_hdr));
                        pkt_ctr[index_l].src_port[bucket] = rte_be_to_cpu_16(udp_hdr->src_port);
                        pkt_ctr[index_l].dst_port[bucket] = rte_be_to_cpu_16(udp_hdr->dst_port);
			pkt_ctr[index_l].protocol[bucket] = UDP;
		}
	}
}

void
perform_analytics(struct rte_mbuf *m)
{

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

	uint32_t index_h, index_l;

	index_l = get_bucket(m);
	index_h = get_tag(m);

	if(pkt_ctr[index_l].hi_f1 == 0)
	{
		init_counters(index_l, index_h, 0, m, packet_len, ipv4_hdr);
	} 
	else
	{
		if(check_slot_match(index_l, index_h))
		{
			pkt_ctr[index_l].ctr[0]++;

			if (pkt_ctr[index_l].max_packet_len[0] < packet_len)
				pkt_ctr[index_l].max_packet_len[0] = packet_len;

			if (pkt_ctr[index_l].min_packet_len[0] > packet_len)
			 	pkt_ctr[index_l].min_packet_len[0] = packet_len;

			double old_mean = pkt_ctr[index_l].mean_packet_len[0];
			pkt_ctr[index_l].mean_packet_len[0] += (packet_len - old_mean) / pkt_ctr[index_l].ctr[0];
			pkt_ctr[index_l].variance_packet_len[0] = (
				(pkt_ctr[index_l].ctr[0] - 1) * pkt_ctr[index_l].variance_packet_len[0] + (packet_len - old_mean) * (packet_len - pkt_ctr[index_l].mean_packet_len[0])
				) / pkt_ctr[index_l].ctr[0];

			uint64_t now = *hwts_field(m);

			uint64_t delta = now - pkt_ctr[index_l].last_seen[0];
			pkt_ctr[index_l].last_seen[0] = now;

			if (pkt_ctr[index_l].max_interarrival_time[0] < delta)
			 	pkt_ctr[index_l].max_interarrival_time[0] = delta;

			if (pkt_ctr[index_l].min_interarrival_time[0] > delta)
			 	pkt_ctr[index_l].min_interarrival_time[0] = delta;

			double old_variance_mean = pkt_ctr[index_l].mean_interarrival_time[0];

			if (pkt_ctr[index_l].mean_interarrival_time[0] == 0)
				pkt_ctr[index_l].mean_interarrival_time[0] = delta;
			else
				pkt_ctr[index_l].mean_interarrival_time[0] += (delta - old_variance_mean) / (pkt_ctr[index_l].ctr[0] - 1);

			pkt_ctr[index_l].variance_interarrival_time[0] = (
				(pkt_ctr[index_l].ctr[0] - 1) * pkt_ctr[index_l].variance_interarrival_time[0] + (delta - old_variance_mean) * (delta - pkt_ctr[index_l].mean_interarrival_time[0])
				) / pkt_ctr[index_l].ctr[0];
		}
		else
			pkt_ctr[index_l].ctr[SLOTS+1]++;
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
