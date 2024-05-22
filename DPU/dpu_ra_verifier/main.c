/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2015 Intel Corporation
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
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
#include "ra_ver.h"

#include <doca_argp.h>
#include <doca_error.h>
#include <doca_dev.h>
#include <doca_sha.h>
#include <doca_log.h>
#include <doca_dpdk.h>
#include <doca_ctx.h>

#include <utils.h>

// #define RX_RING_SIZE 8192
// #define TX_RING_SIZE 1024

#define NUM_MBUFS 32000
#define MBUF_CACHE_SIZE 250
// #define BURST_SIZE 32

DOCA_LOG_REGISTER(RA_SHA::MAIN);
struct doca_log_backend *sdk_log;
struct rte_mempool *mbuf_pool;
struct rte_ring *ring;
bool quit = 0;
// int8_t core_q_mapping[RTE_MAX_LCORE] = {-1};
uint64_t nonce[SWIFT_NONCE_LEN];
uint16_t ctr_val = 0;
uint16_t *ctr = &ctr_val;
const char *prover_table_name = "_PROV_TBL";
const char *starting_addr = "02:00:00:00:00:00";
struct rte_hash *prover_keys;
// volatile struct prover_props *provers[128];

// volatile struct timespec start_times_mbuf[RX_RING_SIZE + 1];
struct rte_hash *mbuf_keys;

// volatile struct timespec *start_times;
// volatile struct timespec *stop_times;

volatile uint64_t *start_times;
volatile uint64_t *stop_times;

uint32_t prover_quant;

volatile struct prover_props **provers;
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

static doca_error_t
data_callback(void *param, void *config)
{
	char *data = (char *)config;
	char *input_data = (char *)param;
	int len;

	len = strnlen(input_data, 1025);
	if (len == 1025) {
		DOCA_LOG_ERR("Invalid data length, should be less than %d", 1024);
		return DOCA_ERROR_INVALID_VALUE;
	}
	strcpy(data, input_data);
	return DOCA_SUCCESS;
}

/*
 * Register the command line parameters for the sample.
 *
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t
register_sha_params(void)
{
	doca_error_t result;
	struct doca_argp_param *data_param;

	result = doca_argp_param_create(&data_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create ARGP param: %s", doca_error_get_descr(result));
		return result;
	}
	doca_argp_param_set_short_name(data_param, "d");
	doca_argp_param_set_long_name(data_param, "data");
	doca_argp_param_set_description(data_param, "user data");
	doca_argp_param_set_callback(data_param, data_callback);
	doca_argp_param_set_type(data_param, DOCA_ARGP_TYPE_STRING);
	result = doca_argp_register_param(data_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to register program param: %s", doca_error_get_descr(result));
		return result;
	}
	return DOCA_SUCCESS;
}

doca_argp_dpdk_cb_t dpdk_callback(int argc, char **argv) {
	int ret = rte_eal_init(argc, argv);
	if (ret < 0) {
		printf("Error with EAL initialization\n");
	return DOCA_ERROR_INITIALIZATION;
	}
	/* >8 End of initialization the Environment Abstraction Layer (EAL). */

	argc -= ret;
	argv += ret;

	return DOCA_SUCCESS;
}

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


	// rte_eth_dev_get
	return 0;
}

static void lcore_main(struct lcore_args *function_args) {
	struct rte_mbuf *burst_rx[BURST_SIZE];
	struct rte_mbuf *burst_rx_filtered[BURST_SIZE];
	uint16_t core_id = rte_lcore_id();
	uint64_t total_processed = 0;
	uint16_t *ctr = function_args->ctr;
	uint64_t *nonce = function_args->nonce;
	uint64_t *key = function_args->key;
	uint64_t app_hash_local[KEY_LEN/sizeof(uint64_t)/8];
	for (uint64_t i = 0; i < KEY_LEN/sizeof(uint64_t)/8; i++) {
		app_hash_local[i] = function_args->app_hash[i];
	}
	uint64_t *sigs = (uint64_t *)malloc(BURST_SIZE * 4 * sizeof(uint64_t));

	uint64_t mask = 0;
	uint64_t *mask_ptr = &mask;
	// uint32_t *mask_ptr = &mask;
	int ret = -1;
	int *ret_ptr = &ret;

	uint32_t ver_ctr = 0;
	uint32_t *ver_ctr_ptr = &ver_ctr;
	// int *ret_ptr = &ret;

	// retval = rte_pktmbuf_alloc_bulk(mbuf_pool, burst_rx, BURST_SIZE);
	// if (retval != 0) {
	// 	printf("Core: %hu Not able to allocatte memory for recieve buffers\n", core_id);
	// 	return;
	// }

	// char data[1025];



	// strcpy(data, "11111111222222223333333344444444555555556666666677777777888888889999999900000000");

	// doca_error_t sha_result = sha_partial_create(data);
	// if (sha_result != DOCA_SUCCESS) {
	// 	DOCA_LOG_ERR("sha_partial_create() encountered an error: %s", doca_error_get_descr(sha_result));
	// }

	DOCA_LOG_INFO("Core %u: Initializing sha resources\n", core_id);
	struct sha_resources resources;
	
	struct program_core_objects *state = &resources.state;
	union doca_data *resource_data;// = {
	// 	.ptr = &resources,
	// 	.u64 = 0
	// };

	memset(&resources, 0, sizeof(resources));
	uint8_t *dst_buffers;
	uint8_t *src_buffers;
	uint8_t *final_src_buffers;

	src_buffers = (uint8_t *)malloc(BURST_SIZE * (SWIFT_HASH_LEN + RTE_ETHER_HDR_LEN + RTE_VLAN_HLEN + SWIFT_MSG_LEN) + BURST_SIZE * 64);
	final_src_buffers = &src_buffers[BURST_SIZE * (SWIFT_HASH_LEN + RTE_ETHER_HDR_LEN + RTE_VLAN_HLEN + SWIFT_MSG_LEN)];
	// dst_buffers = (uint8_t *)malloc(BURST_SIZE * 2 * 64);

	struct doca_buf **doca_dst_buffers;
	struct doca_sha_task_partial_hash **sha_partial_hash_task;
	struct doca_sha_task_hash **sha_hash_task;
	struct doca_task **partial_task;
	struct doca_task **hash_task;
	// union doca_data *resource_data;
	
	doca_error_t result;

	// void **original_src_buf = (void **)malloc(BURST_SIZE * sizeof(void *));

	sha_partial_hash_task = (struct doca_sha_task_partial_hash **)calloc(BURST_SIZE, sizeof(struct doca_sha_task_partial_hash *));
	sha_hash_task = (struct doca_sha_task_hash **)calloc(BURST_SIZE, sizeof(struct doca_sha_task_hash *));
	partial_task = (struct doca_task **)calloc(BURST_SIZE, sizeof(struct doca_task *));
	hash_task = (struct doca_task **)calloc(BURST_SIZE, sizeof(struct doca_task *));
	doca_dst_buffers = (struct doca_buf **)calloc(BURST_SIZE * 2, sizeof(struct doca_buf *));
	// resource_data = (union doca_data *)malloc(sizeof(union doca_data));

	resources.key = key;
	resources.src_doca_buf = (struct doca_buf **)calloc(BURST_SIZE * 2, sizeof(struct doca_buf *));
	resources.src_buffer = (void **)calloc(BURST_SIZE * 2, sizeof(void *));
	resources.final_doca_src_buf = (struct doca_buf **)calloc(BURST_SIZE, sizeof(struct doca_buf *));
	resources.final_src_buf = (void **)calloc(BURST_SIZE, sizeof(void *));
	resources.sha_hash_task = (struct doca_sha_task_hash **)malloc(BURST_SIZE * sizeof(struct doca_sha_task_hash *));
	resources.sha_partial_hash_task = (struct doca_sha_task_partial_hash **)malloc(BURST_SIZE * sizeof(struct doca_sha_task_partial_hash *));



	resources.dst_buffers = (struct doca_buf **)calloc(BURST_SIZE * 2, sizeof(struct doca_buf *));
	resources.result = (doca_error_t *)calloc(BURST_SIZE * 2, sizeof(doca_error_t));
	uint64_t ipad = 0x3636363636363636;
	uint64_t opad = 0x5c5c5c5c5c5c5c5c;
	resources.ikey = (uint64_t *)calloc(4, sizeof(uint64_t));
	resources.okey = (uint64_t *)calloc(4, sizeof(uint64_t));


	resources.completions = 0;
	// printf("Core %u: Passed resource malloc\n", core_id);

	for (uint8_t i = 0; i < 4; i++) {
		resources.ikey[i] = resources.key[i] ^ ipad;
		resources.okey[i] = resources.key[i] ^ opad;
	}

	resources.remaining_src_len = (size_t *)calloc(BURST_SIZE, sizeof(size_t));
	for (uint32_t i = 0; i < BURST_SIZE; i++) {
		resources.remaining_src_len[i] = (size_t)(SWIFT_HASH_LEN + RTE_ETHER_HDR_LEN + RTE_VLAN_HLEN + SWIFT_MSG_LEN);
	}

	resource_data = (union doca_data *)calloc(1, sizeof(union doca_data));
	// resource_data->ptr = resources;

	result = sha_init(state, &resources, resource_data, dst_buffers, src_buffers, final_src_buffers, doca_dst_buffers, BURST_SIZE, key, 
						sha_partial_hash_task, sha_hash_task, partial_task, hash_task);

	// for (uint32_t i = 0; i < BURST_SIZE; i++) printf("original src data %p, src_data %p\n", original_src_buf[i], resources.src_doca_buf[i]);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Core %u: Failed to initialize sha resources: %s", core_id, doca_error_get_descr(result));
		return;
	}

	int *hash_indices = calloc(BURST_SIZE, sizeof(int));
	resources.hash_indices = hash_indices;
	// char file_name[256];
	// sprintf(file_name, "../results/%u_prov/dpu_ra_test_%ucore_%uprover.csv", prover_quant, rte_lcore_count(), prover_quant);
	// printf("Core %u: sha_partial_hash_task: %p\n", core_id, sha_partial_hash_task);
	printf("Core: %hu Starting recieve loop.\n", core_id);
	while(!quit) {
		uint16_t nb_rx = 0;

		// nb_rx = rte_eth_rx_burst(0, core_q_mapping[core_id], burst_rx, BURST_SIZE);
		nb_rx = rte_ring_dequeue_bulk(ring, burst_rx, BURST_SIZE, NULL);

		if (nb_rx == 0) continue;
		//begin hashing
		// else {
		// 	// printf("Core: %u parsing %hu packets\n", core_id, nb_rx);
		// 	verify(burst_rx, ctr, nonce, nb_rx, key, mask_ptr, ret_ptr, ver_ctr_ptr);
		// 	// printf("Core: %u finished verify funtion\n", core_id);
		// 	if (ret < 0) {
		// 		printf("Core: %hu Verification function failed with err: %d\n", core_id, ret);
		// 		break;
		// 	}

			// for (long int j = 0; j < nb_rx; j++) {
			// 	if (!(mask && (1 << j))) {
			// 		printf("core: %u pkt not processed\n", core_id);
			// 		rte_pktmbuf_free(burst_rx[j]);
			// 	} else total_processed++;
			// }
		// }
		// total_processed++;
		// printf("Core %u: received %hu pkts\n", core_id, nb_rx);
		int swift_pkts = filter(burst_rx, burst_rx_filtered, ctr, nonce, nb_rx, sigs, mask_ptr, ret_ptr, hash_indices);
		// printf("core %u: %d pkts after filtering\n", core_id, swift_pkts);
		// for (long int j = 0; j < nb_rx; j++) {
		// 	if (!(mask && (1 << j))) {
		// 		printf("core: %u pkt not processed\n", core_id);
		// 		rte_pktmbuf_free(burst_rx[j]);
		// 	}
		// }

		// printf("Core %u: Mempool: %p, buf_inv: %p, mbuf: %p, doca_buf: %p\n", core_id, doca_mempool, state->buf_inv, burst_rx_filtered[0], resources.src_doca_buf[0]);
		// printf("Core %u: resources: %p\n", core_id, &resources);
		// printf("Core %u: src_buf %p, dst_buf %p, task %p, final_task: %p, final_src: %p, final_src_data: %p\n", core_id, resources.src_doca_buf[0], 
				// resources.dst_buffers[0], resources.sha_partial_hash_task[0], resources.sha_hash_task[0], resources.final_doca_src_buf[0], resources.final_src_buf[0]);

		result = sha_perform_bulk(&resources, doca_dst_buffers, burst_rx_filtered, swift_pkts, sha_partial_hash_task, hash_indices);
		// for (uint32_t i = 0; i < BURST_SIZE; i++) printf("original src data %p, src_data %p\n", original_src_buf[i], resources.src_doca_buf[i]);
		if (result != DOCA_SUCCESS) {
			DOCA_LOG_ERR("Core %u: Error with sha function: %s", core_id, doca_error_get_descr(result));
			return;
		}

		// printf("Core %u: finished with sha_bulk\n", core_id);

		total_processed += resources.completions;
		for (int i = 0; i < swift_pkts; i++) {
			bool match = true;
			struct doca_buf *buf = resources.dst_buffers[i+swift_pkts];
			// printf("Core %u: dst_buffer %p\n", core_id, buf);
			uint64_t *data;
			doca_buf_get_data(buf, &data);
			// rte_pktmbuf_dump(stdout, burst_rx_filtered[i], rte_pktmbuf_data_len(burst_rx_filtered[i]));
			for (int j = 0; j < 4; j++) {
				if (data[j] != sigs[i * 4 + j]) match = false;
				// printf("Core %u: doca_data %lx\n", core_id, data[j]);
				// printf("Core %u: sig_data %lx\n", core_id, sigs[i*4 + j]);
			}

			if (!match) {
				// int hash_index = rte_hash_lookup(prover_keys, )
				// if (clock_gettime(CLOCK_MONOTONIC, &stop_times[hash_indices[i]]) != 0) {
				// 	printf("Core %u: Couldn't get stop_time\n", core_id);
				// 	return;
				// }
				goto hash_reset;
			}

			// if (clock_gettime(CLOCK_MONOTONIC, &stop_times[hash_indices[i]]) != 0) {
			// 	printf("Core %u: Couldn't get stop_time\n", core_id);
			// 	return;
			// }
			ver_ctr++;
			// printf("Core %u: compared sig %d\n", core_id, i);
			// doca_sha_task_partial_hash_reset(sha_partial_hash_task[i]);
			// printf("Core %u: src buf: %p, final src buf: %p, partial_task %p, hash_task %p\n", core_id, resources.src_doca_buf[i], 
					// resources.final_doca_src_buf[i], resources.sha_partial_hash_task[i], resources.sha_hash_task[i]);
		hash_reset:
			resources.src_buffer[i] -= (SWIFT_HASH_LEN + RTE_ETHER_HDR_LEN + RTE_VLAN_HLEN + SWIFT_MSG_LEN);
			resources.remaining_src_len[i] = (size_t)(SWIFT_HASH_LEN + RTE_ETHER_HDR_LEN + RTE_VLAN_HLEN + SWIFT_MSG_LEN);
			// resources.sha_partial_hash_task[i] = sha_partial_hash_task[i];
			doca_buf_set_data(resources.src_doca_buf[i], resources.src_buffer[i], resources.remaining_src_len[i]);
			doca_buf_reset_data_len(resources.dst_buffers[i]);
			// doca_buf_reset_data_len(resources.dst_buffers[i+swift_pkts]);
			result = doca_sha_task_partial_hash_reset(resources.sha_partial_hash_task[i]);
			if (result != DOCA_SUCCESS) {
				DOCA_LOG_ERR("Core %u: Couldn't reset task: %s", core_id, doca_error_get_descr(result));
				return;
			}
			doca_sha_task_partial_hash_set_dst(resources.sha_partial_hash_task[i], resources.dst_buffers[i]);
			if (result != DOCA_SUCCESS) {
				DOCA_LOG_ERR("Core %u: Couldn't set dst buf: %s", core_id, doca_error_get_descr(result));
				return;
			}
			doca_sha_task_partial_hash_set_src(resources.sha_partial_hash_task[i], resources.src_doca_buf[i]);
			if (result != DOCA_SUCCESS) {
				DOCA_LOG_ERR("Core %u: Couldn't set src buf: %s", core_id, doca_error_get_descr(result));
				return;
			}

			// resources.completions = 0;
			// uint16_t refcount;
			// doca_buf_get_refcount(resources.dst_buffers[i], &refcount);
			// printf("Core %u, dst refcount %hu\n", core_id, refcount);
			// doca_sha_task_hash_set_dst(resources.sha_hash_task[i], resources.dst_buffers[i+swift_pkts]);
			// doca_sha_task_hash_set_src(resources.sha_hash_task[i], resources.final_doca_src_buf[i]);
			// doca_sha_task_hash_reset(resources.sha_hash_task[i]);
			// resources.sha_hash_task[i] = resources
			
		}
		// printf("Core %u: finished compare\n", core_id);
		rte_pktmbuf_free_bulk(burst_rx, nb_rx);
		for (int i = 0; i < BURST_SIZE * 2; i++) {
			resources.completions = 0;
			doca_buf_reset_data_len(resources.dst_buffers[i]);
		}

		// printf("Core %u: Starting time calc loop\n", core_id);
		// for (uint32_t i = 0; i < prover_quant; i++) {
		// 	if (!(start_times[i].tv_sec || start_times[i].tv_nsec)  || !(stop_times[i].tv_sec || stop_times[i].tv_nsec)) continue;

		// 	// printf("Core %u: got times for i = %u\n", core_id, i);

		// 	long long time_diff = calculate_elapsed_time_ns(start_times[i], stop_times[i]);
		// 	// printf("Core %u: Got time diff\n", core_id);

		// 	append_time_to_csv(file_name, time_diff);
		// 	start_times[i].tv_sec = 0;
		// 	start_times[i].tv_nsec = 0;
		// 	stop_times[i].tv_sec = 0;
		// 	stop_times[i].tv_nsec = 0;

		// }
	}

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
	char data[1025];
	int exit_status = EXIT_FAILURE;
	doca_error_t sha_result = doca_log_backend_create_standard();
	struct sha_resources *all_resources[8];

	rte_log_set_global_level(RTE_LOG_DEBUG);
	if (sha_result != DOCA_SUCCESS) {
		printf("Log failure\n");
		return;
	}
	/* Register a logger backend for internal SDK errors and warnings */
	sha_result = doca_log_backend_create_with_file_sdk(stderr, &sdk_log);
	if (sha_result != DOCA_SUCCESS) {
		printf("Log failure\n");
		return;
	}
	sha_result = doca_log_backend_set_sdk_level(sdk_log, DOCA_LOG_LEVEL_ERROR);
	if (sha_result != DOCA_SUCCESS) {
		printf("Log failure\n");
		return;
	}
	sha_result = doca_argp_init("doca_sha_partial_create", &data);
	if (sha_result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to init ARGP resources: %s", doca_error_get_descr(sha_result));
		goto sample_exit;
	}

	sha_result = register_sha_params();
	if (sha_result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to register ARGP params: %s", doca_error_get_descr(sha_result));
		goto argp_cleanup;
	}

	doca_argp_set_dpdk_program(dpdk_callback);

	sha_result = doca_argp_start(argc, argv);
	if (sha_result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to parse sample input: %s", doca_error_get_descr(sha_result));
		goto argp_cleanup;
	}
	DOCA_LOG_INFO("Starting the sample");
	uint64_t key[KEY_LEN/sizeof(uint64_t)/8] = {
		0x136b4dfc04ab4b34,
		0xd175e64e302d5283,
		0x84588c4f694ce1f6,
		0xad34a93028e13b5f,
	};

	// struct rte_hash *prover_keys;
	// struct prover_props **provers;

	/* Initializion the Environment Abstraction Layer (EAL). 8< */
	// int ret = rte_eal_init(argc, argv);
	// if (ret < 0)
	// 	rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
	// /* >8 End of initialization the Environment Abstraction Layer (EAL). */

	// argc -= ret;
	// argv += ret;

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

	// for (int i = 0; i < RX_RING_SIZE + 1; i++) {
	// 	start_times_mbuf[i].tv_nsec = 0;
	// 	start_times_mbuf[i].tv_sec = 0;
	// }

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

argp_cleanup:
	doca_argp_destroy();
sample_exit:
	if (exit_status == EXIT_SUCCESS)
		DOCA_LOG_INFO("Sample finished successfully");
	else
		DOCA_LOG_INFO("Sample finished with errors");
	return exit_status;

	return 0;
}
