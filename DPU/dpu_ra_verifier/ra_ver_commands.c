/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation.
 * Copyright (c) 2009, Olivier MATZ <zer0@droids-corp.org>
 * All rights reserved.
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include <rte_mempool.h>
#include <rte_ether.h>
#include <cmdline_rdline.h>
#include <cmdline_parse.h>
#include <cmdline_parse_ipaddr.h>
#include <cmdline_parse_etheraddr.h>
#include <cmdline_parse_num.h>
#include <cmdline_parse_string.h>
#include <cmdline.h>

#include <rte_string_fns.h>

#include <rte_mbuf.h>
#include <rte_random.h>
#include <rte_ethdev.h>
#include <rte_branch_prediction.h>
#include <rte_memcpy.h>
#include <rte_byteorder.h>
#include <rte_vxlan.h>
#include <rte_hash.h>
#include <math.h>
#include <time.h>
#include <rte_cycles.h>

#include <openssl/crypto.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/params.h>

#include "ra_ver.h"

struct cmd_help_result {
	cmdline_fixed_string_t help;
};

static void cmd_help_parsed(__rte_unused void *parsed_result,
			    struct cmdline *cl,
			    __rte_unused void *data)
{
	cmdline_printf(cl,
			   "This application can be used to send an attestation request and verify the results\n"
		       "- attest -- send attestation request"
			   "- init quant -- initiate the verifier for quant provers"
			   );
}

cmdline_parse_token_string_t cmd_help_help =
	TOKEN_STRING_INITIALIZER(struct cmd_help_result, help, "help");

cmdline_parse_inst_t cmd_help = {
	.f = cmd_help_parsed,  /* function to call */
	.data = NULL,      /* 2nd arg of func */
	.help_str = "show help",
	.tokens = {        /* token list, NULL terminated */
		(void *)&cmd_help_help,
		NULL,
	},
};

// struct cmd_send_result {
// 	cmdline_fixed_string_t action;
// 	struct rte_ether_addr dst;
// 	uint32_t quant;
// };

// cmdline_parse_token_string_t cmd_send_send =
// 	TOKEN_STRING_INITIALIZER(struct cmd_send_result, action, "send");
// cmdline_parse_token_etheraddr_t cmd_send_dst =
// 	TOKEN_ETHERADDR_INITIALIZER(struct cmd_send_result, dst);
// cmdline_parse_token_num_t cmd_send_quant =
// 	TOKEN_NUM_INITIALIZER(struct cmd_send_result, quant, RTE_UINT32);

// void cmd_send_parsed(void *parsed_result, struct cmdline *cl, __rte_unused void *data) {
// 	struct cmd_send_result *res = parsed_result;
// 	struct rte_mbuf *mbufs[res->quant];
// 	// struct rte_mbuf *mbufs_temp[BURST_SIZE];
// 	uint16_t port;

// 	for (uint32_t i = 0; i < res->quant; i++) {
//         mbufs[i] = rte_pktmbuf_alloc(mbuf_pool);
//         if (mbufs[i] == NULL) {
//             rte_exit(EXIT_FAILURE, "Failed to allocate mbuf\n");
//         }
//     }

// 	RTE_ETH_FOREACH_DEV(port) {
// 		create_l2_packet(mbufs, &res->dst, res->quant);
// 		uint16_t nb_tx = 0;
// 		uint16_t bursts = res->quant / BURST_SIZE;
// 		uint16_t excess = res->quant % BURST_SIZE;

// 		if (bursts > 0) {
// 			for (uint32_t i = 0; i < bursts; i++) {
// 				uint16_t buf = BURST_SIZE * i;
// 				for (uint32_t j = 0; j < BURST_SIZE; j++){
// 					rte_pktmbuf_dump(stdout, mbufs[j], rte_pktmbuf_pkt_len(mbufs[j]));
// 				}
// 				nb_tx += rte_eth_tx_burst(port, 0, &mbufs[buf], BURST_SIZE);
// 			}
// 			nb_tx += rte_eth_tx_burst(port, 0, &mbufs[res->quant - excess - 1], excess);
// 		}
// 		else {
// 			nb_tx += rte_eth_tx_burst(port, 0, mbufs, excess);
// 		}
// 		cmdline_printf(cl, "Total packets sent: %u\n", nb_tx);
// 	}

// 	for (uint32_t i = 0; i < res->quant; i++) {
//         rte_pktmbuf_free(mbufs[i]);
//     }
// }

// cmdline_parse_inst_t cmd_send = {
// 	.f = cmd_send_parsed,  /* function to call */
// 	.data = NULL,      /* 2nd arg of func */
// 	.help_str = "Send number of L2 (randomized payload and src address) packets to given destination (dst, number)",
// 	.tokens = {        /* token list, NULL terminated */
// 		(void *)&cmd_send_send,
// 		(void *)&cmd_send_dst,
// 		(void *)&cmd_send_quant,
// 		NULL
// 	}
// };

struct cmd_attest_result {
	cmdline_fixed_string_t attest;
	uint32_t sec;
};

cmdline_parse_token_string_t cmd_attest_attest =
	TOKEN_STRING_INITIALIZER(struct cmd_attest_result, attest, "attest");
cmdline_parse_token_num_t cmd_attest_sec = 
	TOKEN_NUM_INITIALIZER(struct cmd_attest_result, sec, RTE_UINT32);

void cmd_attest_parsed(void *parsed_result, struct cmdline *cl, __rte_unused void *data) {
	struct rte_mbuf *mbuf;
	struct rte_ether_addr src;
	struct rte_mbuf *burst_rx[BURST_SIZE];
	uint16_t core_id = rte_lcore_id();
	uint16_t port;

	struct cmd_attest_result *res = (struct cmd_attest_result *)parsed_result;
	uint32_t sec = res->sec;
	*ctr++;

	mbuf = rte_pktmbuf_alloc(mbuf_pool);
	if (mbuf == NULL) {
        rte_exit(EXIT_FAILURE, "Failed to allocate mbuf\n");
	}

	char file_name[256];
	sprintf(file_name, "../results/%u_prov/dpu_ra_test_%ucore_%uprover.csv", prover_quant, rte_lcore_count(), prover_quant);

	RTE_ETH_FOREACH_DEV(port) {
		for (int test_number = 0; test_number < 1; test_number++) {
			rte_eth_macaddr_get(port, &src);
			// uint64_t nonce[2];
			nonce[0] = 0x0123456789abcdef;
			nonce[1] = 0xfedcba9876543210;
			cmdline_printf(cl, "Nonce: %lx\n", nonce[0]);
			int retval = create_att_req(mbuf, &src, 1, 0, 0, *ctr, nonce);
			rte_pktmbuf_dump(stdout, mbuf, sizeof(struct rte_mbuf));
			if (retval != 0) {
				rte_exit(EXIT_FAILURE, "Failed to create att req. Error: %d\n", retval);
			}
			int nb_tx = rte_eth_tx_burst(port, 0, &mbuf, 1);
			cmdline_printf(cl, "Att_req sent: %d\n", nb_tx);

			
			const uint64_t start_cycles = rte_get_timer_cycles();
			const uint64_t hz = rte_get_timer_hz();
			const uint64_t duration_cycles = sec * hz; // 30 seconds

			int nb_rx_tot = 0;
			struct timespec start_time;

			printf("Main: Receiving packets\n");
			while (1) {
				// Get the current number of cycles
				uint64_t current_cycles = rte_get_timer_cycles();

				// Check if 30 seconds have passed
				if (current_cycles - start_cycles >= duration_cycles) {
					break; // Exit the loop after 30 seconds
				}

				int nb_rx = rte_eth_rx_burst(port, 0, burst_rx, BURST_SIZE);

				if (nb_rx == 0) goto sleep;

				nb_rx_tot += nb_rx;

				// if (clock_gettime(CLOCK_MONOTONIC, &start_time) != 0) {
				// 	printf("Core %u; Couldn't get clock time\n", core_id);
				// 	return;
				// }	
				
				// for (int i = 0; i < nb_rx; i++) {

				// 	int mbuf_index = rte_hash_add_key(mbuf_keys, burst_rx[i]);
				// 	if (mbuf_index < 0) {
				// 		printf("Main: failed to add key to hash table: %s\n", rte_strerror(mbuf_index));
				// 		// return;
				// 	}
				// 	start_times_mbuf[mbuf_index] = start_time;			
					
				// }

				int ring_enqueued = rte_ring_enqueue_bulk(ring, burst_rx, nb_rx, NULL);

				if (ring_enqueued == 0) {
					printf("Main: Error enqueuing packets to ring\n");
					break;
				}

				// printf("Core %u: Enqueued %d pkts\n", core_id, ring_enqueued);

				// Your loop code goes here
				// For example, processing packets or any other task

				// Optional: sleep for a short duration to prevent 100% CPU utilization
			sleep:
				// rte_delay_us_block(10); // Sleep for 10 microseconds
			}
			
			printf("Core %u: Starting time calc loop\n", core_id);
			for (uint32_t i = 0; i < prover_quant; i++) {
				// if (!(start_times[i].tv_sec || start_times[i].tv_nsec)  || !(stop_times[i].tv_sec || stop_times[i].tv_nsec)) {
				if (!start_times[i] || !stop_times[i]) {
					// printf("Core %u: prover %u, Start time, sec %ld, nsec %ld\t Stop time, sec %ld, nsec %ld\n", 
					// 	core_id, i, start_times[i].tv_sec, start_times[i].tv_nsec, stop_times[i].tv_sec, stop_times[i].tv_nsec);
					continue;
				}

				// printf("Core %u: got times for i = %u\n", core_id, i);

				// long long time_diff = calculate_elapsed_time_ns(start_times[i], stop_times[i]);
				// printf("Core %u: Got time diff\n", core_id);
				uint64_t cycles = stop_times[i] - start_times[i];

			    double tsc_hz = rte_get_tsc_hz(); // Cycles per second
    			double ns_per_cycle = 1e9 / tsc_hz; 
				double time_ns = cycles * ns_per_cycle;

				append_time_to_csv(file_name, time_ns);
				// start_times[i].tv_sec = 0;
				// start_times[i].tv_nsec = 0;
				// stop_times[i].tv_sec = 0;
				// stop_times[i].tv_nsec = 0;
				start_times[i] = 0;
				stop_times[i] = 0;

			}

			printf("Main: Total pkts offloaded to worker cores: %d\n", nb_rx_tot);
		}
	}
}

cmdline_parse_inst_t cmd_attest = {
	.f = cmd_attest_parsed,  /* function to call */
	.data = NULL,      /* 2nd arg of func */
	.help_str = "Broadcast an attestation request",
	.tokens = {        /* token list, NULL terminated */
		(void *)&cmd_attest_attest,
		(void *)&cmd_attest_sec,
		NULL
	}
};

struct cmd_quit_result {
	cmdline_fixed_string_t quit;
};

static void cmd_quit_parsed(__rte_unused void *parsed_result,
			    struct cmdline *cl,
			    __rte_unused void *data)
{
	quit = true;
	cmdline_quit(cl);
}

cmdline_parse_token_string_t cmd_quit_quit =
	TOKEN_STRING_INITIALIZER(struct cmd_quit_result, quit, "quit");

cmdline_parse_inst_t cmd_quit = {
	.f = cmd_quit_parsed,  /* function to call */
	.data = NULL,      /* 2nd arg of func */
	.help_str = "Exit program",
	.tokens = {        /* token list, NULL terminated */
		(void *)&cmd_quit_quit,
		NULL,
	},
};

struct cmd_init_result {
	cmdline_fixed_string_t init;
	uint32_t quant;
	
};

static void cmd_init_parsed( void *parsed_result,
			    struct cmdline *cl,
			    __rte_unused void *data)
{
	struct cmd_init_result *res = parsed_result;
	uint32_t quant = res->quant;

	prover_quant = quant;
	int retval;
	retval = hash_table_init(prover_table_name, quant, rte_socket_id());

	if (retval != 0) {
		printf("Hash table not created. Exiting...\n");
		quit = true;
		cmdline_quit(cl);
	}
	printf("Initiated prover hash table with %u entries\n", quant);

	retval = prover_props_init(prover_table_name, starting_addr, quant);
	if (retval != 0) {
		printf("Couldn't add provers to hash table. \n");
		quit = true;
		cmdline_quit(cl);
	}
	printf("Filled prover hash table\n");

}

cmdline_parse_token_string_t cmd_init_init =
	TOKEN_STRING_INITIALIZER(struct cmd_init_result, init, "init");
cmdline_parse_token_num_t cmd_init_quant = 
	TOKEN_NUM_INITIALIZER(struct cmd_init_result, quant, RTE_UINT32);

cmdline_parse_inst_t cmd_init = {
	.f = cmd_init_parsed,  /* function to call */
	.data = NULL,      /* 2nd arg of func */
	.help_str = "init quant: initiate verifier with quant number of provers.\n",
	.tokens = {        /* token list, NULL terminated */
		(void *)&cmd_init_init,
		(void *)&cmd_init_quant,
		NULL,
	},
};

cmdline_parse_ctx_t main_ctx[] = {
	&cmd_help,
	// &cmd_send,
	&cmd_attest,
	&cmd_quit,
	&cmd_init,
	NULL
};