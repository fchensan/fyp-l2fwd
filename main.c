/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2016 Intel Corporation
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <netinet/in.h>
#include <setjmp.h>
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>

#include <rte_common.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_eal.h>
#include <rte_launch.h>
#include <rte_atomic.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_random.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_string_fns.h>

static volatile bool force_quit;

/* MAC updating enabled by default */
static int mac_updating = 1;

#define RTE_LOGTYPE_L2FWD RTE_LOGTYPE_USER1

#define MAX_PKT_BURST 32
#define BURST_TX_DRAIN_US 100 /* TX drain every ~100us */
#define MEMPOOL_CACHE_SIZE 256

/*
 * Configurable number of RX/TX ring descriptors
 */
#define RTE_TEST_RX_DESC_DEFAULT 1024
#define RTE_TEST_TX_DESC_DEFAULT 1024
static uint16_t nb_rxd = RTE_TEST_RX_DESC_DEFAULT;
static uint16_t nb_txd = RTE_TEST_TX_DESC_DEFAULT;

/* ethernet addresses of ports */
static struct rte_ether_addr l2fwd_ports_eth_addr[RTE_MAX_ETHPORTS];

/* mask of enabled ports */
static uint32_t l2fwd_enabled_port_mask = 0;

/* list of enabled ports */
static uint32_t l2fwd_dst_ports[RTE_MAX_ETHPORTS];

struct port_pair_params {
#define NUM_PORTS	2
	uint16_t port[NUM_PORTS];
} __rte_cache_aligned;

static struct port_pair_params port_pair_params_array[RTE_MAX_ETHPORTS / 2];
static struct port_pair_params *port_pair_params;
static uint16_t nb_port_pair_params;

static unsigned int l2fwd_rx_queue_per_lcore = 1;

#define MAX_RX_QUEUE_PER_LCORE 16
#define MAX_TX_QUEUE_PER_PORT 16
/* List of queues to be polled for a given lcore. 8< */
struct lcore_queue_conf {
	unsigned n_rx_port;
	unsigned rx_port_list[MAX_RX_QUEUE_PER_LCORE];
} __rte_cache_aligned;
struct lcore_queue_conf lcore_queue_conf[RTE_MAX_LCORE];
/* >8 End of list of queues to be polled for a given lcore. */

static struct rte_eth_dev_tx_buffer *tx_buffer[RTE_MAX_ETHPORTS];

static struct rte_eth_conf port_conf = {
	.rxmode = {
		.split_hdr_size = 0,
		.mq_mode = ETH_MQ_RX_RSS,
	},
	.rx_adv_conf = {
		.rss_conf = {
			.rss_key = NULL,
			.rss_hf = ETH_RSS_IP | ETH_RSS_UDP | ETH_RSS_TCP //ETH_RSS_PROTO_MASK,
		}
	},
	.txmode = {
		.mq_mode = ETH_MQ_TX_NONE,
	},
};

struct rte_mempool * l2fwd_pktmbuf_pool = NULL;

/* Per-port statistics struct */
struct l2fwd_port_statistics {
	uint64_t tx;
	uint64_t rx;
	uint64_t dropped;
} __rte_cache_aligned;
struct l2fwd_port_statistics port_statistics[RTE_MAX_ETHPORTS];

#define MAX_TIMER_PERIOD 86400 /* 1 day max */
/* A tsc-based timer responsible for triggering statistics printout */
static uint64_t timer_period = 3; /* default period is 3 seconds */

#define FLOW_NUM 65536

struct pkt_count
{
	uint16_t hi_f1;
	uint16_t hi_f2;
	uint32_t ctr[3];

	uint64_t max_packet_len[2];
	uint64_t min_packet_len[2];

	#ifdef MEAN_PACKET_LEN
	double mean_packet_len[2];
	double variance_packet_len[2];
	#endif

	uint64_t last_seen[2];
	uint64_t min_interarrival_time[2];
	uint64_t max_interarrival_time[2];

	#ifdef MEAN_IAT_TIME
	double mean_interarrival_time[2];
	double variance_interarrival_time[2];
	#endif

	unsigned char ip_src[2][4];
	unsigned char ip_dst[2][4];

	#ifdef IPG
	uint64_t ipg[2];
	double avg[2];
	#endif

} __rte_cache_aligned;

static struct pkt_count pkt_ctr[FLOW_NUM] __rte_cache_aligned;

static int hwts_dynfield_offset = -1;

static inline rte_mbuf_timestamp_t *
hwts_field(struct rte_mbuf *mbuf)
{
	return RTE_MBUF_DYNFIELD(mbuf,
			hwts_dynfield_offset, rte_mbuf_timestamp_t *);
}

typedef uint64_t tsc_t;
static int tsc_dynfield_offset = -1;

#define uint32_t_to_char(ip, a, b, c, d) do {\
    *a = (unsigned char)(ip >> 24 & 0xff);\
    *b = (unsigned char)(ip >> 16 & 0xff);\
    *c = (unsigned char)(ip >> 8 & 0xff);\
    *d = (unsigned char)(ip & 0xff);\
} while (0)

static void
print_features_extracted()
{
	int i, bucket;
	int count = 0;
	for(i=0; i< FLOW_NUM; i++)
	{
		for (bucket=0; bucket<2; bucket++) {
			if (pkt_ctr[i].ctr[bucket] > 0) {
				count++;
				printf("Flow %d | %hhu.%hhu.%hhu.%hhu --> %hhu.%hhu.%hhu.%hhu | count: %d, max packet len: %ld, min packet leng: %ld", i,
					pkt_ctr[i].ip_src[bucket][0],pkt_ctr[i].ip_src[bucket][1],pkt_ctr[i].ip_src[bucket][2],pkt_ctr[i].ip_src[bucket][3],
					pkt_ctr[i].ip_dst[bucket][0],pkt_ctr[i].ip_dst[bucket][1],pkt_ctr[i].ip_dst[bucket][2],pkt_ctr[i].ip_dst[bucket][3],
					pkt_ctr[i].ctr[bucket], pkt_ctr[i].max_packet_len[bucket], pkt_ctr[i].min_packet_len[bucket]);

				#ifdef MEAN_PACKET_LEN
				printf("mean packet len: %f, variance packet len: %f", pkt_ctr[i].mean_packet_len[bucket], pkt_ctr[i].variance_packet_len[bucket]);
				#endif

				#ifdef MEAN_IAT_TIME
				printf("mean interarrival time: %f, variance interarrival time: %f", pkt_ctr[i].mean_interarrival_time[bucket], pkt_ctr[i].variance_interarrival_time[bucket]);
				#endif

				printf("\n");
			}
		}
	}
	printf("Total flows: %d\n", count);
}

/* Print out statistics on packets dropped */
static void
print_stats(void)
{
	uint64_t total_packets_dropped, total_packets_tx, total_packets_rx;
	unsigned portid;

	total_packets_dropped = 0;
	total_packets_tx = 0;
	total_packets_rx = 0;

	const char clr[] = { 27, '[', '2', 'J', '\0' };
	const char topLeft[] = { 27, '[', '1', ';', '1', 'H','\0' };

		/* Clear screen and move to top left */
	printf("%s%s", clr, topLeft);

	printf("\nPort statistics ====================================");

	for (portid = 0; portid < RTE_MAX_ETHPORTS; portid++) {
		/* skip disabled ports */
		if ((l2fwd_enabled_port_mask & (1 << portid)) == 0)
			continue;
		printf("\nStatistics for port %u ------------------------------"
			   "\nPackets sent: %24"PRIu64
			   "\nPackets received: %20"PRIu64
			   "\nPackets dropped: %21"PRIu64,
			   portid,
			   port_statistics[portid].tx,
			   port_statistics[portid].rx,
			   port_statistics[portid].dropped);

		total_packets_dropped += port_statistics[portid].dropped;
		total_packets_tx += port_statistics[portid].tx;
		total_packets_rx += port_statistics[portid].rx;
	}
	printf("\nAggregate statistics ==============================="
		   "\nTotal packets sent: %18"PRIu64
		   "\nTotal packets received: %14"PRIu64
		   "\nTotal packets dropped: %15"PRIu64,
		   total_packets_tx,
		   total_packets_rx,
		   total_packets_dropped);
	printf("\n====================================================\n");

	print_features_extracted();

	fflush(stdout);
}

static void
l2fwd_mac_updating(struct rte_mbuf *m, unsigned dest_portid)
{
	struct rte_ether_hdr *eth;
	void *tmp;

	eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);

	/* 02:00:00:00:00:xx */
	tmp = &eth->d_addr.addr_bytes[0];
	*((uint64_t *)tmp) = 0x000000000002 + ((uint64_t)dest_portid << 40);

	/* src addr */
	rte_ether_addr_copy(&l2fwd_ports_eth_addr[dest_portid], &eth->s_addr);
}

/* Simple forward. 8< */
static void
l2fwd_simple_forward(struct rte_mbuf *m, unsigned portid)
{
	unsigned dst_port;
	int sent;
	struct rte_eth_dev_tx_buffer *buffer;

	dst_port = l2fwd_dst_ports[portid];

	if (mac_updating)
		l2fwd_mac_updating(m, dst_port);

	buffer = tx_buffer[dst_port];
	sent = rte_eth_tx_buffer(dst_port, 0, buffer, m);
	if (sent)
		port_statistics[dst_port].tx += sent;
}
/* >8 End of simple forward. */

static void
init_counters(uint16_t index_l, uint16_t index_h, uint16_t bucket, struct rte_mbuf *m, uint64_t packet_len, struct rte_ipv4_hdr *ipv4_hdr) {
	pkt_ctr[index_l].hi_f1 = index_h;
	pkt_ctr[index_l].ctr[bucket]++;

	pkt_ctr[index_l].max_packet_len[bucket] = packet_len;
	pkt_ctr[index_l].min_packet_len[bucket] = packet_len;

	#ifdef MEAN_PACKET_LEN
	pkt_ctr[index_l].mean_packet_len[bucket] = packet_len;
	pkt_ctr[index_l].variance_packet_len[bucket] = 0;
	#endif

	uint64_t now = *hwts_field(m);
	pkt_ctr[index_l].last_seen[bucket] = now;
	pkt_ctr[index_l].max_interarrival_time[bucket] = 0;
	pkt_ctr[index_l].min_interarrival_time[bucket] = 0xFFFFFFFF;

	#ifdef MEAN_IAT_TIME
	pkt_ctr[index_l].mean_interarrival_time[bucket] = 0;
	pkt_ctr[index_l].variance_interarrival_time[bucket] = 0;
	#endif

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
	}

	#ifdef IPG
	pkt_ctr[index].avg[bucket] = pkt_ctr[index].ipg[bucket];
	#endif
}

static void
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
	// uint16_t src_port;
	// uint16_t dst_port;
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
	}

	uint32_t index_h, index_l;

	index_l = m->hash.rss & 0xffff;
	index_h = (m->hash.rss & 0xffff0000)>>16;

	#ifdef TIMESTAMP
	uint64_t timestamp = m->timestamp;
	RTE_SET_USED(timestamp);
	#endif

	// rte_pktmbuf_free(m);
	if(pkt_ctr[index_l].hi_f1 == 0)
	{
		init_counters(index_l, index_h, 0, m, packet_len, ipv4_hdr);
	}
	else if(pkt_ctr[index_l].hi_f2 == 0 && pkt_ctr[index_l].hi_f1 != index_h)
	{
		init_counters(index_l, index_h, 1, m, packet_len, ipv4_hdr);
	}
	else
	{
		if(pkt_ctr[index_l].hi_f1 == index_h)
		{
			pkt_ctr[index_l].ctr[0]++;

			if (pkt_ctr[index_l].max_packet_len[0] < packet_len)
				pkt_ctr[index_l].max_packet_len[0] = packet_len;

			if (pkt_ctr[index_l].min_packet_len[0] > packet_len)
			 	pkt_ctr[index_l].min_packet_len[0] = packet_len;

			#ifdef MEAN_PACKET_LEN
			double old_mean = pkt_ctr[index_l].mean_packet_len[0];
			pkt_ctr[index_l].mean_packet_len[0] += (packet_len - old_mean) / pkt_ctr[index_l].ctr[0];
			pkt_ctr[index_l].variance_packet_len[0] = (
				(pkt_ctr[index_l].ctr[0] - 1) * pkt_ctr[index_l].variance_packet_len[0] + (packet_len - old_mean) * (packet_len - pkt_ctr[index_l].mean_packet_len[0])
				) / pkt_ctr[index_l].ctr[0];
			#endif

			uint64_t now = *hwts_field(m);

			uint64_t delta = now - pkt_ctr[index_l].last_seen[0];
			pkt_ctr[index_l].last_seen[0] = now;


			if (pkt_ctr[index_l].max_interarrival_time[0] < delta)
			 	pkt_ctr[index_l].max_interarrival_time[0] = delta;

			if (pkt_ctr[index_l].min_interarrival_time[0] > delta)
			 	pkt_ctr[index_l].min_interarrival_time[0] = delta;

			#ifdef MEAN_IAT_TIME
			double old_variance_mean = pkt_ctr[index_l].mean_interarrival_time[0];

			if (pkt_ctr[index_l].mean_interarrival_time[0] == 0)
				pkt_ctr[index_l].mean_interarrival_time[0] = delta;
			else
				pkt_ctr[index_l].mean_interarrival_time[0] += (delta - old_variance_mean) / (pkt_ctr[index_l].ctr[0] - 1);

			pkt_ctr[index_l].variance_interarrival_time[0] = (
				(pkt_ctr[index_l].ctr[0] - 1) * pkt_ctr[index_l].variance_interarrival_time[0] + (delta - old_variance_mean) * (delta - pkt_ctr[index_l].mean_interarrival_time[0])
				) / pkt_ctr[index_l].ctr[0];
			#endif

			#ifdef IPG
			curr = global - 1 - pkt_ctr[index_l].ipg[0];

			pkt_ctr[index_l].avg[0] =
				(pkt_ctr[index_l].avg[0] * (pkt_ctr[index_l].ctr[0] - 1) + curr)/pkt_ctr[index_l].ctr[0];

			//if (pkt_ctr[index_l].ctr[0] < 10000 && index_l == 65246)
			//	printf("%lf %lu %ld\n", pkt_ctr[index_l].avg[0], pkt_ctr[index_l].ctr[0], curr);

			pkt_ctr[index_l].ipg[0] = global;
			#endif
		}
		else if(pkt_ctr[index_l].hi_f2 == index_h)
		{
			pkt_ctr[index_l].ctr[1]++;

			if (pkt_ctr[index_l].max_packet_len[1] < packet_len)
			 	pkt_ctr[index_l].max_packet_len[1] = packet_len;

			if (pkt_ctr[index_l].min_packet_len[1] > packet_len)
			 	pkt_ctr[index_l].min_packet_len[1] = packet_len;

			#ifdef MEAN_PACKET_LEN
			double old_mean = pkt_ctr[index_l].mean_packet_len[1];
			pkt_ctr[index_l].mean_packet_len[1] += (packet_len - old_mean) / pkt_ctr[index_l].ctr[1];
			pkt_ctr[index_l].variance_packet_len[0] = (
				(pkt_ctr[index_l].ctr[0] - 1) * pkt_ctr[index_l].variance_packet_len[0] + (packet_len - old_mean) * (packet_len - pkt_ctr[index_l].mean_packet_len[0])
				) / pkt_ctr[index_l].ctr[0];
			#endif

			uint64_t now = *hwts_field(m);

			uint64_t delta = now - pkt_ctr[index_l].last_seen[1];
			pkt_ctr[index_l].last_seen[1] = now;


			if (pkt_ctr[index_l].max_interarrival_time[1] < delta)
			 	pkt_ctr[index_l].max_interarrival_time[1] = delta;

			if (pkt_ctr[index_l].min_interarrival_time[1] > delta)
			 	pkt_ctr[index_l].min_interarrival_time[1] = delta;


			#ifdef MEAN_IAT_TIME
			double old_variance_mean = pkt_ctr[index_l].mean_interarrival_time[1];
			if (pkt_ctr[index_l].mean_interarrival_time[1] == 0)
				pkt_ctr[index_l].mean_interarrival_time[1] = delta;
			else
				pkt_ctr[index_l].mean_interarrival_time[1] += (delta - old_variance_mean) / (pkt_ctr[index_l].ctr[1] - 1);

			pkt_ctr[index_l].variance_interarrival_time[1] = (
				(pkt_ctr[index_l].ctr[1] - 1) * pkt_ctr[index_l].variance_interarrival_time[1] + (delta - old_variance_mean) * (delta - pkt_ctr[index_l].mean_interarrival_time[1])
				) / pkt_ctr[index_l].ctr[1];
			#endif

			#ifdef IPG
				curr = global - 1 - pkt_ctr[index_l].ipg[1];
			pkt_ctr[index_l].avg[1] =
				((pkt_ctr[index_l].avg[1] * (pkt_ctr[index_l].ctr[1] - 1)) + curr)/(float)pkt_ctr[index_l].ctr[1];

			pkt_ctr[index_l].ipg[1] = global;
			#endif
		}
		else
			pkt_ctr[index_l].ctr[2]++;
	}
}


/* main processing loop */
static void
l2fwd_main_loop(void)
{
	struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
	struct rte_mbuf *m;
	int sent;
	unsigned lcore_id;
	uint64_t prev_tsc, diff_tsc, cur_tsc, timer_tsc;
	unsigned i, j, portid, nb_rx;
	struct lcore_queue_conf *qconf;
	const uint64_t drain_tsc = (rte_get_tsc_hz() + US_PER_S - 1) / US_PER_S *
			BURST_TX_DRAIN_US;
	struct rte_eth_dev_tx_buffer *buffer;

	prev_tsc = 0;
	timer_tsc = 0;

	lcore_id = rte_lcore_id();
	qconf = &lcore_queue_conf[lcore_id];

	if (qconf->n_rx_port == 0) {
		RTE_LOG(INFO, L2FWD, "lcore %u has nothing to do\n", lcore_id);
		return;
	}

	RTE_LOG(INFO, L2FWD, "entering main loop on lcore %u\n", lcore_id);

	for (i = 0; i < qconf->n_rx_port; i++) {

		portid = qconf->rx_port_list[i];
		RTE_LOG(INFO, L2FWD, " -- lcoreid=%u portid=%u\n", lcore_id,
			portid);

	}

	while (!force_quit) {

		/* Drains TX queue in its main loop. 8< */
		cur_tsc = rte_rdtsc();

		/*
		 * TX burst queue drain
		 */
		diff_tsc = cur_tsc - prev_tsc;
		if (unlikely(diff_tsc > drain_tsc)) {

			for (i = 0; i < qconf->n_rx_port; i++) {

				portid = l2fwd_dst_ports[qconf->rx_port_list[i]];
				buffer = tx_buffer[portid];

				sent = rte_eth_tx_buffer_flush(portid, 0, buffer);
				if (sent)
					port_statistics[portid].tx += sent;

			}

			/* if timer is enabled */
			if (timer_period > 0) {

				/* advance the timer */
				timer_tsc += diff_tsc;

				/* if timer has reached its timeout */
				if (unlikely(timer_tsc >= timer_period)) {

					/* do this only on main core */
					if (lcore_id == rte_get_main_lcore()) {
						print_stats();
						/* reset the timer */
						timer_tsc = 0;
					}
				}
			}

			prev_tsc = cur_tsc;
		}
		/* >8 End of draining TX queue. */

		/* Read packet from RX queues. 8< */
		for (i = 0; i < qconf->n_rx_port; i++) {

			portid = qconf->rx_port_list[i];
			nb_rx = rte_eth_rx_burst(portid, 0,
						 pkts_burst, MAX_PKT_BURST);

			/* TODO: clarify the deletion
			if (unlikely(nb_rx == 0))
				continue;
			*/

			port_statistics[portid].rx += nb_rx;

			for (j = 0; j < nb_rx; j++) {
				m = pkts_burst[j];

				perform_analytics(m);

				rte_prefetch0(rte_pktmbuf_mtod(m, void *));
				l2fwd_simple_forward(m, portid);
			}
		}
		/* >8 End of read packet from RX queues. */
	}
}

static int
l2fwd_launch_one_lcore(__rte_unused void *dummy)
{
	l2fwd_main_loop();
	return 0;
}

/* display usage */
static void
l2fwd_usage(const char *prgname)
{
	printf("%s [EAL options] -- -p PORTMASK [-q NQ]\n"
	       "  -p PORTMASK: hexadecimal bitmask of ports to configure\n"
	       "  -q NQ: number of queue (=ports) per lcore (default is 1)\n"
	       "  -T PERIOD: statistics will be refreshed each PERIOD seconds (0 to disable, 10 default, 86400 maximum)\n"
	       "  --[no-]mac-updating: Enable or disable MAC addresses updating (enabled by default)\n"
	       "      When enabled:\n"
	       "       - The source MAC address is replaced by the TX port MAC address\n"
	       "       - The destination MAC address is replaced by 02:00:00:00:00:TX_PORT_ID\n"
	       "  --portmap: Configure forwarding port pair mapping\n"
	       "	      Default: alternate port pairs\n\n",
	       prgname);
}

static int
l2fwd_parse_portmask(const char *portmask)
{
	char *end = NULL;
	unsigned long pm;

	/* parse hexadecimal string */
	pm = strtoul(portmask, &end, 16);
	if ((portmask[0] == '\0') || (end == NULL) || (*end != '\0'))
		return 0;

	return pm;
}

static int
l2fwd_parse_port_pair_config(const char *q_arg)
{
	enum fieldnames {
		FLD_PORT1 = 0,
		FLD_PORT2,
		_NUM_FLD
	};
	unsigned long int_fld[_NUM_FLD];
	const char *p, *p0 = q_arg;
	char *str_fld[_NUM_FLD];
	unsigned int size;
	char s[256];
	char *end;
	int i;

	nb_port_pair_params = 0;

	while ((p = strchr(p0, '(')) != NULL) {
		++p;
		p0 = strchr(p, ')');
		if (p0 == NULL)
			return -1;

		size = p0 - p;
		if (size >= sizeof(s))
			return -1;

		memcpy(s, p, size);
		s[size] = '\0';
		if (rte_strsplit(s, sizeof(s), str_fld,
				 _NUM_FLD, ',') != _NUM_FLD)
			return -1;
		for (i = 0; i < _NUM_FLD; i++) {
			errno = 0;
			int_fld[i] = strtoul(str_fld[i], &end, 0);
			if (errno != 0 || end == str_fld[i] ||
			    int_fld[i] >= RTE_MAX_ETHPORTS)
				return -1;
		}
		if (nb_port_pair_params >= RTE_MAX_ETHPORTS/2) {
			printf("exceeded max number of port pair params: %hu\n",
				nb_port_pair_params);
			return -1;
		}
		port_pair_params_array[nb_port_pair_params].port[0] =
				(uint16_t)int_fld[FLD_PORT1];
		port_pair_params_array[nb_port_pair_params].port[1] =
				(uint16_t)int_fld[FLD_PORT2];
		++nb_port_pair_params;
	}
	port_pair_params = port_pair_params_array;
	return 0;
}

static unsigned int
l2fwd_parse_nqueue(const char *q_arg)
{
	char *end = NULL;
	unsigned long n;

	/* parse hexadecimal string */
	n = strtoul(q_arg, &end, 10);
	if ((q_arg[0] == '\0') || (end == NULL) || (*end != '\0'))
		return 0;
	if (n == 0)
		return 0;
	if (n >= MAX_RX_QUEUE_PER_LCORE)
		return 0;

	return n;
}

static int
l2fwd_parse_timer_period(const char *q_arg)
{
	char *end = NULL;
	int n;

	/* parse number string */
	n = strtol(q_arg, &end, 10);
	if ((q_arg[0] == '\0') || (end == NULL) || (*end != '\0'))
		return -1;
	if (n >= MAX_TIMER_PERIOD)
		return -1;

	return n;
}

static const char short_options[] =
	"p:"  /* portmask */
	"q:"  /* number of queues */
	"T:"  /* timer period */
	;

#define CMD_LINE_OPT_MAC_UPDATING "mac-updating"
#define CMD_LINE_OPT_NO_MAC_UPDATING "no-mac-updating"
#define CMD_LINE_OPT_PORTMAP_CONFIG "portmap"

enum {
	/* long options mapped to a short option */

	/* first long only option value must be >= 256, so that we won't
	 * conflict with short options */
	CMD_LINE_OPT_MIN_NUM = 256,
	CMD_LINE_OPT_PORTMAP_NUM,
};

static const struct option lgopts[] = {
	{ CMD_LINE_OPT_MAC_UPDATING, no_argument, &mac_updating, 1},
	{ CMD_LINE_OPT_NO_MAC_UPDATING, no_argument, &mac_updating, 0},
	{ CMD_LINE_OPT_PORTMAP_CONFIG, 1, 0, CMD_LINE_OPT_PORTMAP_NUM},
	{NULL, 0, 0, 0}
};

/* Parse the argument given in the command line of the application */
static int
l2fwd_parse_args(int argc, char **argv)
{
	int opt, ret, timer_secs;
	char **argvopt;
	int option_index;
	char *prgname = argv[0];

	argvopt = argv;
	port_pair_params = NULL;

	while ((opt = getopt_long(argc, argvopt, short_options,
				  lgopts, &option_index)) != EOF) {

		switch (opt) {
		/* portmask */
		case 'p':
			l2fwd_enabled_port_mask = l2fwd_parse_portmask(optarg);
			if (l2fwd_enabled_port_mask == 0) {
				printf("invalid portmask\n");
				l2fwd_usage(prgname);
				return -1;
			}
			break;

		/* nqueue */
		case 'q':
			l2fwd_rx_queue_per_lcore = l2fwd_parse_nqueue(optarg);
			if (l2fwd_rx_queue_per_lcore == 0) {
				printf("invalid queue number\n");
				l2fwd_usage(prgname);
				return -1;
			}
			break;

		/* timer period */
		case 'T':
			timer_secs = l2fwd_parse_timer_period(optarg);
			if (timer_secs < 0) {
				printf("invalid timer period\n");
				l2fwd_usage(prgname);
				return -1;
			}
			timer_period = timer_secs;
			break;

		/* long options */
		case CMD_LINE_OPT_PORTMAP_NUM:
			ret = l2fwd_parse_port_pair_config(optarg);
			if (ret) {
				fprintf(stderr, "Invalid config\n");
				l2fwd_usage(prgname);
				return -1;
			}
			break;

		default:
			l2fwd_usage(prgname);
			return -1;
		}
	}

	if (optind >= 0)
		argv[optind-1] = prgname;

	ret = optind-1;
	optind = 1; /* reset getopt lib */
	return ret;
}

/*
 * Check port pair config with enabled port mask,
 * and for valid port pair combinations.
 */
static int
check_port_pair_config(void)
{
	uint32_t port_pair_config_mask = 0;
	uint32_t port_pair_mask = 0;
	uint16_t index, i, portid;

	for (index = 0; index < nb_port_pair_params; index++) {
		port_pair_mask = 0;

		for (i = 0; i < NUM_PORTS; i++)  {
			portid = port_pair_params[index].port[i];
			if ((l2fwd_enabled_port_mask & (1 << portid)) == 0) {
				printf("port %u is not enabled in port mask\n",
				       portid);
				return -1;
			}
			if (!rte_eth_dev_is_valid_port(portid)) {
				printf("port %u is not present on the board\n",
				       portid);
				return -1;
			}

			port_pair_mask |= 1 << portid;
		}

		if (port_pair_config_mask & port_pair_mask) {
			printf("port %u is used in other port pairs\n", portid);
			return -1;
		}
		port_pair_config_mask |= port_pair_mask;
	}

	l2fwd_enabled_port_mask &= port_pair_config_mask;

	return 0;
}

/* Check the link status of all ports in up to 9s, and print them finally */
static void
check_all_ports_link_status(uint32_t port_mask)
{
#define CHECK_INTERVAL 100 /* 100ms */
#define MAX_CHECK_TIME 90 /* 9s (90 * 100ms) in total */
	uint16_t portid;
	uint8_t count, all_ports_up, print_flag = 0;
	struct rte_eth_link link;
	int ret;
	char link_status_text[RTE_ETH_LINK_MAX_STR_LEN];

	printf("\nChecking link status");
	fflush(stdout);
	for (count = 0; count <= MAX_CHECK_TIME; count++) {
		if (force_quit)
			return;
		all_ports_up = 1;
		RTE_ETH_FOREACH_DEV(portid) {
			if (force_quit)
				return;
			if ((port_mask & (1 << portid)) == 0)
				continue;
			memset(&link, 0, sizeof(link));
			ret = rte_eth_link_get_nowait(portid, &link);
			if (ret < 0) {
				all_ports_up = 0;
				if (print_flag == 1)
					printf("Port %u link get failed: %s\n",
						portid, rte_strerror(-ret));
				continue;
			}
			/* print link status if flag set */
			if (print_flag == 1) {
				rte_eth_link_to_str(link_status_text,
					sizeof(link_status_text), &link);
				printf("Port %d %s\n", portid,
				       link_status_text);
				continue;
			}
			/* clear all_ports_up flag if any link down */
			if (link.link_status == ETH_LINK_DOWN) {
				all_ports_up = 0;
				break;
			}
		}
		/* after finally printing all link status, get out */
		if (print_flag == 1)
			break;

		if (all_ports_up == 0) {
			printf(".");
			fflush(stdout);
			rte_delay_ms(CHECK_INTERVAL);
		}

		/* set the print_flag if all ports up or timeout */
		if (all_ports_up == 1 || count == (MAX_CHECK_TIME - 1)) {
			print_flag = 1;
			printf("done\n");
		}
	}
}


static void
print_welcome(void)
{
	printf("\n   _____                      __  _   ____________   ___                __      __  _          \n"
	       "  / ___/____ ___  ____ ______/ /_/ | / /  _/ ____/  /   |  ____  ____ _/ /_  __/ /_(_)_________\n"
	       "  \\__ \\/ __ `__ \\/ __ `/ ___/ __/  |/ // // /      / /| | / __ \\/ __ `/ / / / / __/ / ___/ ___/\n"
	       " ___/ / / / / / / /_/ / /  / /_/ /|  // // /___   / ___ |/ / / / /_/ / / /_/ / /_/ / /__(__  ) \n"
	       "/____/_/ /_/ /_/\\__,_/_/   \\__/_/ |_/___/\\____/  /_/  |_/_/ /_/\\__,_/_/\\__, /\\__/_/\\___/____/  \n"
	       "                                                                      /____/                   \n");
}


static void
signal_handler(int signum)
{
	print_welcome();
	if (signum == SIGINT || signum == SIGTERM) {
		printf("\n\nSignal %d received, preparing to exit...\n",
				signum);
		force_quit = true;
	}
}

int
main(int argc, char **argv)
{
	struct lcore_queue_conf *qconf;
	int ret;
	uint16_t nb_ports;
	uint16_t nb_ports_available = 0;
	uint16_t portid, last_port;
	unsigned lcore_id, rx_lcore_id;
	unsigned nb_ports_in_mask = 0;
	unsigned int nb_lcores = 0;
	unsigned int nb_mbufs;

	/* Init EAL. 8< */
	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid EAL arguments\n");
	argc -= ret;
	argv += ret;

	force_quit = false;
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	/* parse application arguments (after the EAL ones) */
	ret = l2fwd_parse_args(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid L2FWD arguments\n");
	/* >8 End of init EAL. */

	printf("MAC updating %s\n", mac_updating ? "enabled" : "disabled");

	/* convert to number of cycles */
	timer_period *= rte_get_timer_hz();

	nb_ports = rte_eth_dev_count_avail();
	if (nb_ports == 0)
		rte_exit(EXIT_FAILURE, "No Ethernet ports - bye\n");

	if (port_pair_params != NULL) {
		if (check_port_pair_config() < 0)
			rte_exit(EXIT_FAILURE, "Invalid port pair config\n");
	}

	/* check port mask to possible port mask */
	if (l2fwd_enabled_port_mask & ~((1 << nb_ports) - 1))
		rte_exit(EXIT_FAILURE, "Invalid portmask; possible (0x%x)\n",
			(1 << nb_ports) - 1);

	/* Initialization of the driver. 8< */

	/* reset l2fwd_dst_ports */
	for (portid = 0; portid < RTE_MAX_ETHPORTS; portid++)
		l2fwd_dst_ports[portid] = 0;
	last_port = 0;

	/* populate destination port details */
	if (port_pair_params != NULL) {
		uint16_t idx, p;

		for (idx = 0; idx < (nb_port_pair_params << 1); idx++) {
			p = idx & 1;
			portid = port_pair_params[idx >> 1].port[p];
			l2fwd_dst_ports[portid] =
				port_pair_params[idx >> 1].port[p ^ 1];
		}
	} else {
		RTE_ETH_FOREACH_DEV(portid) {
			/* skip ports that are not enabled */
			if ((l2fwd_enabled_port_mask & (1 << portid)) == 0)
				continue;

			if (nb_ports_in_mask % 2) {
				l2fwd_dst_ports[portid] = last_port;
				l2fwd_dst_ports[last_port] = portid;
			} else {
				last_port = portid;
			}

			nb_ports_in_mask++;
		}
		if (nb_ports_in_mask % 2) {
			printf("Notice: odd number of ports in portmask.\n");
			l2fwd_dst_ports[last_port] = last_port;
		}
	}
	/* >8 End of initialization of the driver. */

	rx_lcore_id = 0;
	qconf = NULL;

	/* Initialize the port/queue configuration of each logical core */
	RTE_ETH_FOREACH_DEV(portid) {
		/* skip ports that are not enabled */
		if ((l2fwd_enabled_port_mask & (1 << portid)) == 0)
			continue;

		/* get the lcore_id for this port */
		while (rte_lcore_is_enabled(rx_lcore_id) == 0 ||
		       lcore_queue_conf[rx_lcore_id].n_rx_port ==
		       l2fwd_rx_queue_per_lcore) {
			rx_lcore_id++;
			if (rx_lcore_id >= RTE_MAX_LCORE)
				rte_exit(EXIT_FAILURE, "Not enough cores\n");
		}

		if (qconf != &lcore_queue_conf[rx_lcore_id]) {
			/* Assigned a new logical core in the loop above. */
			qconf = &lcore_queue_conf[rx_lcore_id];
			nb_lcores++;
		}

		qconf->rx_port_list[qconf->n_rx_port] = portid;
		qconf->n_rx_port++;
		printf("Lcore %u: RX port %u TX port %u\n", rx_lcore_id,
		       portid, l2fwd_dst_ports[portid]);
	}

	nb_mbufs = RTE_MAX(nb_ports * (nb_rxd + nb_txd + MAX_PKT_BURST +
		nb_lcores * MEMPOOL_CACHE_SIZE), 8192U);

	/* Create the mbuf pool. 8< */
	l2fwd_pktmbuf_pool = rte_pktmbuf_pool_create("mbuf_pool", nb_mbufs,
		MEMPOOL_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE,
		rte_socket_id());
	if (l2fwd_pktmbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot init mbuf pool\n");
	/* >8 End of create the mbuf pool. */

	/* TODO: what is this for? 8< */
	static const struct rte_mbuf_dynfield tsc_dynfield_desc = {
		.name = "example_bbdev_dynfield_tsc",
		.size = sizeof(tsc_t),
		.align = __alignof__(tsc_t),
	};

	tsc_dynfield_offset =
		rte_mbuf_dynfield_register(&tsc_dynfield_desc);
	if (tsc_dynfield_offset < 0)
		rte_exit(EXIT_FAILURE, "Cannot register mbuf field\n");
	/* >8 end TODO */

	/* Initialise each port */
	RTE_ETH_FOREACH_DEV(portid) {
		struct rte_eth_rxconf rxq_conf;
		struct rte_eth_txconf txq_conf;
		struct rte_eth_conf local_port_conf = port_conf;
		struct rte_eth_dev_info dev_info;

		/* skip ports that are not enabled */
		if ((l2fwd_enabled_port_mask & (1 << portid)) == 0) {
			printf("Skipping disabled port %u\n", portid);
			continue;
		}
		nb_ports_available++;

		/* init port */
		printf("Initializing port %u... ", portid);
		fflush(stdout);

		ret = rte_eth_dev_info_get(portid, &dev_info);
		if (ret != 0)
			rte_exit(EXIT_FAILURE,
				"Error during getting device (port %u) info: %s\n",
				portid, strerror(-ret));

		if (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_MBUF_FAST_FREE)
			local_port_conf.txmode.offloads |=
				DEV_TX_OFFLOAD_MBUF_FAST_FREE;
		/* Configure the number of queues for a port. */
		if (!(dev_info.rx_offload_capa & DEV_RX_OFFLOAD_TIMESTAMP)) {
			printf("\nERROR: Port %u does not support hardware timestamping\n"
					, portid);
			return -1;
		}
		local_port_conf.rxmode.offloads |= DEV_RX_OFFLOAD_TIMESTAMP;
		rte_mbuf_dyn_rx_timestamp_register(&hwts_dynfield_offset, NULL);
		if (hwts_dynfield_offset < 0) {
			printf("ERROR: Failed to register timestamp field\n");
			return -rte_errno;
		}

		ret = rte_eth_dev_configure(portid, 1, 1, &local_port_conf);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "Cannot configure device: err=%d, port=%u\n",
				  ret, portid);
		/* >8 End of configuration of the number of queues for a port. */

		ret = rte_eth_dev_adjust_nb_rx_tx_desc(portid, &nb_rxd,
						       &nb_txd);
		if (ret < 0)
			rte_exit(EXIT_FAILURE,
				 "Cannot adjust number of descriptors: err=%d, port=%u\n",
				 ret, portid);

		ret = rte_eth_macaddr_get(portid,
					  &l2fwd_ports_eth_addr[portid]);
		if (ret < 0)
			rte_exit(EXIT_FAILURE,
				 "Cannot get MAC address: err=%d, port=%u\n",
				 ret, portid);

		/* init one RX queue */
		fflush(stdout);
		rxq_conf = dev_info.default_rxconf;
		rxq_conf.offloads = local_port_conf.rxmode.offloads;
		/* RX queue setup. 8< */
		ret = rte_eth_rx_queue_setup(portid, 0, nb_rxd,
					     rte_eth_dev_socket_id(portid),
					     &rxq_conf,
					     l2fwd_pktmbuf_pool);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "rte_eth_rx_queue_setup:err=%d, port=%u\n",
				  ret, portid);
		/* >8 End of RX queue setup. */

		/* Init one TX queue on each port. 8< */
		fflush(stdout);
		txq_conf = dev_info.default_txconf;
		txq_conf.offloads = local_port_conf.txmode.offloads;
		ret = rte_eth_tx_queue_setup(portid, 0, nb_txd,
				rte_eth_dev_socket_id(portid),
				&txq_conf);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "rte_eth_tx_queue_setup:err=%d, port=%u\n",
				ret, portid);
		/* >8 End of init one TX queue on each port. */

		/* Initialize TX buffers */
		tx_buffer[portid] = rte_zmalloc_socket("tx_buffer",
				RTE_ETH_TX_BUFFER_SIZE(MAX_PKT_BURST), 0,
				rte_eth_dev_socket_id(portid));
		if (tx_buffer[portid] == NULL)
			rte_exit(EXIT_FAILURE, "Cannot allocate buffer for tx on port %u\n",
					portid);

		rte_eth_tx_buffer_init(tx_buffer[portid], MAX_PKT_BURST);

		ret = rte_eth_tx_buffer_set_err_callback(tx_buffer[portid],
				rte_eth_tx_buffer_count_callback,
				&port_statistics[portid].dropped);
		if (ret < 0)
			rte_exit(EXIT_FAILURE,
			"Cannot set error callback for tx buffer on port %u\n",
				 portid);

		ret = rte_eth_dev_set_ptypes(portid, RTE_PTYPE_UNKNOWN, NULL,
					     0);
		if (ret < 0)
			printf("Port %u, Failed to disable Ptype parsing\n",
					portid);
		/* Start device */
		ret = rte_eth_dev_start(portid);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "rte_eth_dev_start:err=%d, port=%u\n",
				  ret, portid);

		printf("done: \n");

		ret = rte_eth_promiscuous_enable(portid);
		if (ret != 0)
			rte_exit(EXIT_FAILURE,
				 "rte_eth_promiscuous_enable:err=%s, port=%u\n",
				 rte_strerror(-ret), portid);

		printf("Port %u, MAC address: %02X:%02X:%02X:%02X:%02X:%02X\n\n",
				portid,
				l2fwd_ports_eth_addr[portid].addr_bytes[0],
				l2fwd_ports_eth_addr[portid].addr_bytes[1],
				l2fwd_ports_eth_addr[portid].addr_bytes[2],
				l2fwd_ports_eth_addr[portid].addr_bytes[3],
				l2fwd_ports_eth_addr[portid].addr_bytes[4],
				l2fwd_ports_eth_addr[portid].addr_bytes[5]);

		/* initialize port stats */
		memset(&port_statistics, 0, sizeof(port_statistics));
	}

	if (!nb_ports_available) {
		rte_exit(EXIT_FAILURE,
			"All available ports are disabled. Please set portmask.\n");
	}

	check_all_ports_link_status(l2fwd_enabled_port_mask);

	uint32_t i;
	int j;

	for(i=0; i< FLOW_NUM; i++)
	{
		pkt_ctr[i].hi_f1 = pkt_ctr[i].hi_f2 = 0;
		for(j=0; j<=2; j++)
		{
			pkt_ctr[i].ctr[j] = 0;

			#ifdef IPG
			if (j == 2) break;
			pkt_ctr[i].avg[j] = pkt_ctr[i].ipg[j] = 0;
			#endif
		}
	}

	ret = 0;
	/* launch per-lcore init on every lcore */
	rte_eal_mp_remote_launch(l2fwd_launch_one_lcore, NULL, CALL_MAIN);
	RTE_LCORE_FOREACH_WORKER(lcore_id) {
		if (rte_eal_wait_lcore(lcore_id) < 0) {
			ret = -1;
			break;
		}
	}

	RTE_ETH_FOREACH_DEV(portid) {
		if ((l2fwd_enabled_port_mask & (1 << portid)) == 0)
			continue;
		printf("Closing port %d...", portid);
		ret = rte_eth_dev_stop(portid);
		if (ret != 0)
			printf("rte_eth_dev_stop: err=%d, port=%d\n",
			       ret, portid);
		rte_eth_dev_close(portid);
		printf(" Done\n");
	}

	/* TODO: clarify the deletion
	// clean up the EAL
	rte_eal_cleanup();
	*/
	printf("Bye...\n");

	return ret;
}
