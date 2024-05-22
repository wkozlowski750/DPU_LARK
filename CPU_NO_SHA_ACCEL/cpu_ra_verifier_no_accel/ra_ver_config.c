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
#include <rte_jhash.h>
#include <rte_errno.h>
#include <rte_malloc.h>
// #include <rte_cycles.h>
#include <math.h>
#include <time.h>

// #include <openssl/crypto.h>
// #include <openssl/core_names.h>
// #include <openssl/err.h>
// #include <openssl/evp.h>
// #include <openssl/hmac.h>
// #include <openssl/params.h>

#include "ra_ver.h"

int hash_table_init(const char *name, uint32_t entries, int socket_id) {
	struct rte_hash_parameters params = {
		.name=name,
		.entries=entries+1,
		.reserved=0,
		.key_len=RTE_ETHER_ADDR_LEN,
		.hash_func=rte_jhash,
		.hash_func_init_val=0,
		.socket_id=socket_id,
		.extra_flag=0
	};

	prover_keys = rte_hash_create(&params);

	if (prover_keys==NULL) {
		printf("Hash table creation error: %s\n", rte_strerror(rte_errno));
		return -1;
	}

	return 0;
}

int prover_props_init(const char *name, const char *starting_addr, uint32_t quant) {
	struct rte_ether_addr src;
	rte_ether_unformat_addr(starting_addr, &src);
	// struct rte_vlan_hdr vlan_hdr = {
	// 	.eth_proto = 0,
	// 	.vlan_tci = 1
	// };

	int retval;
	uint16_t last_bytes = src.addr_bytes[4];
    last_bytes = rte_be_to_cpu_16(last_bytes);

	provers = rte_malloc("prover_table", (quant+1) * sizeof(struct prover_props *), 0);
	if (provers == NULL) {
		printf("Failed to allocate memory for provers. \n");
		return -2;
	}

	start_times = rte_calloc("start_table", (quant+1), sizeof(struct timespec), 0);
	if (start_times == NULL) {
		printf("Failed to allocate memory for start_times. \n");
		return -2;
	}
	stop_times = rte_calloc("stop_table", (quant+1), sizeof(struct timespec), 0);
	if (stop_times == NULL) {
		printf("Failed to allocate memory for stop_times. \n");
		return -2;
	}
	// struct prover_props *provers_data[quant];
	// printf("Provers table addr %p\n", provers_data);
	// provers = provers_data;
	// printf("Provers table addr %p\n", provers);

	for (uint32_t i = 0; i < (quant); i++) {
		uint16_t be_last_bytes = rte_cpu_to_be_16(last_bytes);
		rte_memcpy(&src.addr_bytes[4], &be_last_bytes, sizeof(uint16_t));
		// printf("After memcpy\n");

		struct prover_props *prover = (struct prover_props *)rte_malloc("prover", sizeof(struct prover_props), 0);
		if (prover == NULL) {
			printf("Failed to allocate memory for prover.");
			return -3;
		}
		// printf("After prover malloc\n");

		// uint32_t *timer = (uint32_t *)malloc(sizeof(uint32_t));
		// retval = rte_timer_data_alloc(timer);
		// if (retval != 0) {
		// 	printf("Failes to allocate timer\n");
		// 	return -4;
		// }
		// rte_timer_init(*timer);

		for (int j = 0; j < 4; j++) {
			prover->vs[j] = app_hash[j];
		}
		// printf("Prover addr %p\n", prover);
		prover->valid = false;

		retval = rte_hash_add_key(prover_keys, src.addr_bytes);
		// printf("After addkey\n");
		if (retval < 0) {
			printf("Failed to add value to prover table. Key: %u Error: %d\n", i, retval);
			return -1;
		}

		char tmp[18];
		rte_ether_format_addr(tmp, 18, &src);
		// printf("SRC Address %s added to hash table, index %d\n", tmp, retval);

		provers[retval] = prover;
		// printf("Provers[retval]: %p\n", provers[retval]);

		// printf("Added prover pointer to provers tbl\n");
		last_bytes++;
	}

	return 0;
}