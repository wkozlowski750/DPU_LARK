/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2015 Intel Corporation
 */
#define _POSIX_C_SOURCE 199309L
#include <stdint.h>
#include <stdlib.h>
#include <inttypes.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_ring.h>
#include <rte_hash.h>
#include <rte_jhash.h>


#include <cmdline_rdline.h>
#include <cmdline_parse.h>
#include <cmdline_socket.h>
#include <cmdline.h>
#include <time.h>
#include "ra_ver.h"

#include <openssl/hmac.h>
#include <openssl/evp.h>

// #define RX_RING_SIZE 8192
// #define TX_RING_SIZE 1024

#define NUM_MBUFS 64000
#define MBUF_CACHE_SIZE 250
// #define BURST_SIZE 32

struct rte_mempool *mbuf_pool;
struct rte_ring *ring;
bool quit = 0;
// int8_t core_q_mapping[RTE_MAX_LCORE] = {-1};
uint64_t nonce[SWIFT_NONCE_LEN/8];
uint16_t ctr_val = 0;
uint16_t *ctr = &ctr_val;
const char *prover_table_name = "_PROV_TBL";
const char *starting_addr = "02:00:00:00:00:00";
struct rte_hash *prover_keys;
// volatile struct prover_props *provers[128];
volatile struct prover_props **provers;
volatile struct timespec *start_times;
volatile struct timespec *stop_times;

struct rte_hash *mbuf_keys;
volatile struct timespec start_times_mbuf[RX_RING_SIZE + 1];

uint32_t total_completions;
volatile struct timespec first_start_time;
volatile struct timespec final_stop_time;
bool got_first_packet;
uint32_t *ver_ctrs[64];

uint32_t prover_quant;

uint64_t app_hash[KEY_LEN/sizeof(uint64_t)/8] = {
	0x8a8f60ecb09b7e64,
	0xc6d5214a8043865e,
	0x608507db8c3f61f9,
	0x95eae6d078875901,
};
/* basicfwd.c: Basic DPDK skeleton forwarding example. */

/*
 * Initializes a given port using global settings and with the RX buffers
 * coming from the mbuf_pool passed as a parameter.
 */

/* Main functional part of port initialization. 8< */
static inline int
port_init(uint16_t port)//, struct rte_mempool *mbuf_pool)
{
	struct rte_eth_conf port_conf;
	const uint16_t rx_rings = 1, tx_rings = 1;
	uint16_t nb_rxd = RX_RING_SIZE;
	uint16_t nb_txd = TX_RING_SIZE;
	int retval;
	// uint16_t q;
	struct rte_eth_dev_info dev_info;
	struct rte_eth_txconf txconf;

	if (!rte_eth_dev_is_valid_port(port))
		return -1;

	memset(&port_conf, 0, sizeof(struct rte_eth_conf));
	retval = rte_eth_dev_info_get(port, &dev_info);
	if (retval != 0) {
		printf("Error during getting device (port %u) info: %s\n",
				port, strerror(-retval));
		return retval;
	}

	if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE)
		port_conf.txmode.offloads |=
			RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;


	struct rte_eth_rxq_info q_info;

	printf("Max ring size, %hu\n", dev_info.rx_desc_lim.nb_max);

	// port_conf.rxmode.mq_mode = RTE_ETH_MQ_RX_RSS;
	// port_conf.rx_adv_conf.rss_conf.rss_key = NULL;
	// port_conf.rx_adv_conf.rss_conf.rss_hf = RTE_ETH_RSS_LEVEL_OUTERMOST;
	/* Configure the Ethernet device. */
	printf("Configuring port\n");
	retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
	if (retval != 0)
		return retval;

	printf("Configured port\n");
	retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
	if (retval != 0)
		return retval;
	printf("Adjusted number of ring descriptors\n");
	/* Allocate and set up 1 RX queue per worker core. */
	uint16_t q;
	for (q = 0; q < rx_rings; q++) {
		retval = rte_eth_rx_queue_setup(port, q, nb_rxd,
				rte_eth_dev_socket_id(port), NULL, mbuf_pool);
		if (retval < 0)
			return retval;
	}

	rte_eth_rx_queue_info_get(port, 0, &q_info);

	printf("Configured number of rx queue descriptors: %hu\n", q_info.nb_desc);
	// uint16_t core_id;
	// uint16_t q = 0;
	// RTE_LCORE_FOREACH_WORKER(core_id) {
	// 	retval = rte_eth_rx_queue_setup(port, q, nb_rxd, rte_eth_dev_socket_id(port), NULL, mbuf_pool);
	// 	printf("Setup 2 queues for port\n");
	// 	if (retval < 0) return retval;
	// 	core_q_mapping[core_id] = q;
	// 	q++;
	// }

	txconf = dev_info.default_txconf;
	// txconf.offloads = port_conf.txmode.offloads;
	/* Allocate and set up 1 TX queue per Ethernet port. */
	for (q = 0; q < tx_rings; q++) {
		retval = rte_eth_tx_queue_setup(port, q, nb_txd,
				rte_eth_dev_socket_id(port), &txconf);
		if (retval < 0)
			return retval;
	}

	/* Starting Ethernet port. 8< */
	retval = rte_eth_dev_start(port);
	/* >8 End of starting of ethernet port. */
	if (retval < 0)
		return retval;

	/* Display the port MAC address. */
	struct rte_ether_addr addr;
	retval = rte_eth_macaddr_get(port, &addr);
	if (retval != 0)
		return retval;

	printf("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
			   " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
			port, RTE_ETHER_ADDR_BYTES(&addr));

	/* Enable RX in promiscuous mode for the Ethernet device. */
	// retval = rte_eth_dev_set_vlan_ether_type(port, RTE_ETH_VLAN_TYPE_OUTER, 0xFFFF);
	retval = rte_eth_promiscuous_enable(port);
	// /* End of setting RX port in promiscuous mode. */
	if (retval != 0)
		return retval;

	return 0;
}

static void lcore_main(struct lcore_args *function_args) {
	struct rte_mbuf *burst_rx[BURST_SIZE];
	uint16_t core_id = rte_lcore_id();
	uint64_t total_processed = 0;
	uint16_t *ctr = function_args->ctr;
	uint64_t *nonce = function_args->nonce;
	uint64_t *key = function_args->key;
	uint64_t app_hash_local[KEY_LEN/sizeof(uint64_t)/8];
	for (uint64_t i = 0; i < KEY_LEN/sizeof(uint64_t)/8; i++) {
		app_hash_local[i] = function_args->app_hash[i];
	}


	uint64_t mask = 0;
	uint64_t *mask_ptr = &mask;
	// uint32_t *mask_ptr = &mask;
	int ret = -1;
	int *ret_ptr = &ret;

	uint32_t ver_ctr = 0;
	uint32_t *ver_ctr_ptr = &ver_ctr;
	ver_ctrs[core_id] = ver_ctr_ptr;
	// int *ret_ptr = &ret;

	// retval = rte_pktmbuf_alloc_bulk(mbuf_pool, burst_rx, BURST_SIZE);
	// if (retval != 0) {
	// 	printf("Core: %hu Not able to allocatte memory for recieve buffers\n", core_id);
	// 	return;
	// }
	OpenSSL_add_all_algorithms();
	printf("Core: %hu Starting recieve loop. mask pointer %p\n", core_id, mask_ptr);
	while(!quit) {
		uint16_t nb_rx = 0;

		// nb_rx = rte_eth_rx_burst(0, core_q_mapping[core_id], burst_rx, BURST_SIZE);
		nb_rx = rte_ring_dequeue_bulk(ring, burst_rx, BURST_SIZE, NULL);


		if (nb_rx == 0) continue;
		//begin hashing
		// else if(1) goto skip;
		else {
			// printf("Core: %u parsing %hu packets\n", core_id, nb_rx);
			verify(burst_rx, ctr, nonce, nb_rx, key, mask_ptr, ret_ptr, ver_ctr_ptr);
			// printf("Core: %u finished verify funtion\n", core_id);
			if (ret < 0) {
				printf("Core: %hu Verification function failed with err: %d\n", core_id, ret);
				break;
			}

			// for (long int j = 0; j < nb_rx; j++) {
			// 	if (!(mask && (1 << j))) {
			// 		printf("core: %u pkt not processed\n", core_id);
			// 		rte_pktmbuf_free(burst_rx[j]);
			// 	} else total_processed++;
			// }

			// total_completions += ver_ctr;
			rte_pktmbuf_free_bulk(burst_rx, nb_rx);
			total_processed += nb_rx;
		}
	// skip:
	// 	rte_pktmbuf_free_bulk(burst_rx, nb_rx);

	}
	EVP_cleanup();
	printf("Core: %u total processed packets: %lu, total verified correctly: %u\n", core_id, total_processed, ver_ctr);
	return;
}


/*
 * The main function, which does initialization and calls the per-lcore
 * functions.
 */
int
main(int argc, char *argv[])
{
	// struct rte_mempool *mbuf_pool;
	unsigned nb_ports;
	uint16_t portid;
	struct cmdline *cl;
	// rte_log_set_global_level(RTE_LOG_DEBUG);

	uint64_t key[KEY_LEN/sizeof(uint64_t)/8] = {
		0x136b4dfc04ab4b34,
		0xd175e64e302d5283,
		0x84588c4f694ce1f6,
		0xad34a93028e13b5f,
	};

	// struct rte_hash *prover_keys;
	// struct prover_props **provers;

	/* Initializion the Environment Abstraction Layer (EAL). 8< */
	int ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
	/* >8 End of initialization the Environment Abstraction Layer (EAL). */

	argc -= ret;
	argv += ret;



	/* Check that there is an even number of ports to send/receive on. */
	nb_ports = rte_eth_dev_count_avail();
	if (nb_ports != 1)
		rte_exit(EXIT_FAILURE, "Error: only one port allowed\n");

	/* Creates a new mempool in memory to hold the mbufs. */

	/* Allocates mempool to hold the mbufs. 8< */
	mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS * nb_ports,
		MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
	/* >8 End of allocating mempool to hold mbuf. */

	int ring_size = rte_ring_get_memsize(16384);
	ring = rte_ring_create("RING", 16384, rte_socket_id(), RING_F_SP_ENQ);



	if (mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");
	printf("Created mbuf_pool\n");

	/* Initializing all ports. 8< */
	RTE_ETH_FOREACH_DEV(portid)
		if (port_init(portid) != 0)
			rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu16 "\n",
					portid);
	/* >8 End of initializing all ports. */

	uint16_t core_count = rte_lcore_count();

	// if (((core_count - 1) & (core_count - 2)) != 0)
	// 	rte_exit(EXIT_FAILURE, "Worker core count must be a power of 2. Worker core count: %hu\n", core_count - 1);
	if (core_count < 2)
		rte_exit(EXIT_FAILURE, "Must have at least two cores\n");
	
	printf("Core count: %hu\n", core_count);

	/* Call lcore_main on the main core only. Called on single lcore. 8< */
	// lcore_main();
	/* >8 End of called on single lcore. */

	struct lcore_args function_args = {
		.ctr = ctr,
		.key = key,
		.nonce=nonce,
		.app_hash={app_hash[0], app_hash[1], app_hash[2], app_hash[3]}
	};


	first_start_time.tv_nsec = 0;
	first_start_time.tv_sec = 0;
	final_stop_time.tv_nsec = 0;
	final_stop_time.tv_sec = 0;
	got_first_packet = false;
	for (int i = 0; i < 64; i++) {
		ver_ctrs[i] = NULL;
	}

	struct rte_hash_parameters hash_params = {
		.name="MBUF_KEYS",
		.entries=RX_RING_SIZE+1,
		.reserved=0,
		.key_len=sizeof(struct rte_mbuf *),
		.hash_func=rte_jhash,
		.hash_func_init_val=0,
		.socket_id=rte_lcore_id(),
		.extra_flag=0
	};

	mbuf_keys = rte_hash_create(&hash_params);

	if (mbuf_keys==NULL) {
		rte_exit(EXIT_FAILURE, "mbuf hash table not initialized\n");
	}

	for (int i = 0; i < RX_RING_SIZE + 1; i++) {
		start_times_mbuf[i].tv_nsec = 0;
		start_times_mbuf[i].tv_sec = 0;
	}

	rte_eal_mp_remote_launch(lcore_main, &function_args, SKIP_MAIN);

	bool running = false;
	while (!running) {
		running = true;
		int core;
		RTE_LCORE_FOREACH_WORKER(core) {
			if (rte_eal_get_lcore_state(core) != RUNNING) running = false;
		}
	}

	printf("Started all lcores\n");

	cl = cmdline_stdin_new(main_ctx, "ra-gen> ");
	if (cl == NULL)
		rte_panic("Cannot create cmdline instance\n");
	cmdline_interact(cl);
	cmdline_stdin_exit(cl);

	bool done = false;
	while (!done) {
		done = true;
		int core;
		RTE_LCORE_FOREACH_WORKER(core) {
			if (rte_eal_get_lcore_state(core) != WAIT) done = false;
		}
	}

	/* clean up the EAL */
	rte_eal_cleanup();

	return 0;
}
