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

// #include <openssl/crypto.h>
// #include <openssl/core_names.h>
// #include <openssl/err.h>
// #include <openssl/evp.h>
// #include <openssl/hmac.h>
// #include <openssl/params.h>

#include <openssl/hmac.h>
#include <openssl/evp.h>

#include "ra_ver.h"

void append_data(append_func func, struct rte_mbuf *m, void *data, uint16_t quant) {
    func(m, data, quant);
}
void append_u64(struct rte_mbuf *m, void *data, uint16_t quant) {
	uint64_t *f_data = (uint64_t *) data;
	uint64_t *m_data = (uint64_t *)rte_pktmbuf_append(m, quant * sizeof(uint64_t));
    for (int i = 0; i < quant; i++) {
        m_data[i] = f_data[i];
    }
}

void append_u32(struct rte_mbuf *m, void *data, uint16_t quant) {
	uint32_t *f_data = (uint32_t *) data;
	uint32_t *m_data = (uint32_t *)rte_pktmbuf_append(m, quant * sizeof(uint32_t));
    for (int i = 0; i < quant; i++) {
        m_data[i] = f_data[i];
    }
}

void append_u16(struct rte_mbuf *m, void *data, uint16_t quant) {
	uint16_t *f_data = (uint16_t *) data;
	uint16_t *m_data = (uint16_t *)rte_pktmbuf_append(m, quant * sizeof(uint16_t));
    for (int i = 0; i < quant; i++) {
        m_data[i] = f_data[i];
    }
}

void append_char(struct rte_mbuf *m, void *data, uint16_t quant) {
	char *f_data = (char *) data;
	char *m_data = rte_pktmbuf_append(m, quant * sizeof(char));
    for (int i = 0; i < quant; i++) {
        m_data[i] = f_data[i];
    }
}

uint64_t htonll(uint64_t data) {
    uint32_t data1 = data >> 32;
    uint32_t data0 = data;

    data1 = htonl(data1);
    data0 = htonl(data0);

    uint64_t ndata1 = (uint64_t)data1;
    uint64_t ndata0 = (uint64_t)data0;
    return (ndata1 << 32) | ndata0;
}

void create_l2_packet(struct rte_mbuf **m, struct rte_ether_addr *dst_mac, uint32_t quant) {
	// struct rte_ether_hdr *eth;
	// rte_ether_addr_copy(dst_mac, &eth->dst_addr);

	time_t cur = time(NULL);
	uint64_t seed = (uint64_t)cur;
	rte_srand(seed);

	for (uint32_t i = 0; i < quant; i++) {

		struct rte_ether_hdr *eth;
		// struct rte_ether_addr *src;
		rte_pktmbuf_append(m[i], RTE_ETHER_HDR_LEN);

		eth = rte_pktmbuf_mtod(m[i], struct rte_ether_hdr *);
		eth->ether_type = htons(RTE_ETHER_TYPE_IPV4);

		rte_memcpy(&eth->dst_addr.addr_bytes, dst_mac->addr_bytes, RTE_ETHER_ADDR_LEN);
		rte_eth_random_addr(&eth->src_addr.addr_bytes[0]);
	}
}

int create_att_req(struct rte_mbuf *m, struct rte_ether_addr *src, uint16_t vid, uint16_t pcp, uint16_t cfi, uint16_t ctr, uint64_t *nonce) {
	struct rte_ether_hdr *eth_hdr;
	struct rte_vlan_hdr *vlan_hdr;
	const char *dst_mac = "ff:ff:ff:ff:ff:ff";

	//Append hdr storage to mbuf if mbuf is empty
	if (m->data_len == 0) {
		if (rte_pktmbuf_append(m, RTE_ETHER_HDR_LEN + RTE_VLAN_HLEN) == NULL) {
			printf("Failed to append hdr to mbuf\n");
			return -1;
		}
	}
	
	//Get pointer to beginning of packet data
	eth_hdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);

	//Set src mac
	if (rte_memcpy(&eth_hdr->src_addr.addr_bytes, &src->addr_bytes, RTE_ETHER_ADDR_LEN) == NULL) {
		printf("Failed to copy src address\n");
		return -2;
	}

	//Set dst mac to broadcast
	if (rte_ether_unformat_addr(dst_mac, &eth_hdr->dst_addr) < 0) {
		printf("Failed to parse MAC address\n");
        return -3;
	}

	//Set ethertype
	eth_hdr->ether_type = htons(RTE_ETHER_TYPE_VLAN);

	//Set payload data
	char *att = "attest";

	uint16_t ctr_reordered = htons(ctr);
	printf("reordered ctr\n");
	append_data(append_u16, m, (void *) &ctr_reordered, 1);
	printf("appended ctr\n");
	append_data(append_char, m, (void *) att, 6);
	printf("reordered attest\n");

	uint64_t nonce_reordered[2];
	nonce_reordered[0] = rte_cpu_to_be_64(nonce[0]);
	nonce_reordered[1] = rte_cpu_to_be_64(nonce[1]);
	printf("reordered nonce\n");
	append_data(append_u64, m, (void *) nonce_reordered, 2);
	printf("appended nonce ctr\n");

	const double payload_length = RTE_ETHER_MIN_LEN - RTE_ETHER_HDR_LEN - RTE_VLAN_HLEN - RTE_ETHER_CRC_LEN;

	pcp = pcp << 13;
	cfi = cfi << 12;
	vlan_hdr = rte_pktmbuf_mtod_offset(m, struct rte_vlan_hdr *, RTE_ETHER_HDR_LEN);
	vlan_hdr->vlan_tci = htons(pcp + cfi + vid);
	vlan_hdr->eth_proto = htons(6 * sizeof(uint32_t));

	uint16_t pad = payload_length - (6 * sizeof(uint32_t));
	for (int i = 0; i < pad; i++) {
		char pad = 0;
		append_data(append_char, m, (void *) &pad, 1);
	}
	printf("reordered padding\n");
	// uint32_t *payload = rte_pktmbuf_append(m, array_size * 4);
	// *payload = payload_array;
	return 0;
}

void verify(struct rte_mbuf **m, uint16_t *ctr, uint64_t *nonce, uint16_t quant, uint64_t *key, uint64_t *mask, int *ret, uint32_t *ver_ctr) {
	// struct rte_mbuf *mbuf;
	struct rte_ether_hdr *hdr;
	// struct rte_vlan_hdr *vlan_hdr;
	uint32_t core_id = rte_lcore_id();
	// struct verif_ret ret;
	
	uint16_t pkt_ctr;
	uint64_t *pkt_nonce = (uint64_t *)malloc(SWIFT_NONCE_LEN);
	uint64_t *pkt_state = (uint64_t *)malloc(SWIFT_HASH_LEN);
	uint64_t *pkt_sig = (uint64_t *)malloc(SWIFT_HASH_LEN);
	// struct prover_props *prover;
	const uint64_t keyword = 0x0123456789abcdef;
	volatile char *buf = (volatile char *)malloc(SWIFT_MSG_LEN + SWIFT_HASH_LEN);
	volatile char *rte_ret = NULL;

	int retval;
	uint64_t pkts_processed = 0;

	static const char *propq = NULL;
	// printf("Core: %u provers table addr %p\n", core_id, provers);
	struct timespec start_time;

	// if (clock_gettime(CLOCK_MONOTONIC, &start_time)) {
	// 	printf("Core %u: Coudln't get start time\n", core_id);
	// }

	for (uint16_t i = 0; i < quant; i++) {
		hdr = rte_pktmbuf_mtod(m[i], struct rte_ether_hdr *);
		// rte_pktmbuf_dump(stdout, m[i], rte_pktmbuf_data_len(m[i]));

		rte_ret = rte_pktmbuf_read(m[i], RTE_ETHER_HDR_LEN + RTE_VLAN_HLEN, SWIFT_MSG_LEN + SWIFT_HASH_LEN, buf);
		
		if (rte_ret==NULL){
			printf("Core: %u Couldn't read payload data.\n", core_id);
			// rte_pktmbuf_free(m[i]);
			pkts_processed |= 1 << i;
			continue;
		}

		for (int j = 0; j < SWIFT_MSG_LEN + SWIFT_HASH_LEN; j++) buf[j] = rte_ret[j];
		// printf("core: %u Got data to buf\n", core_id);
		// printf("buf: ");
		// for (uint16_t j = 0; j < 90; j++) {
		// 	printf("%02x ", (unsigned char)buf[j]);
		// 	if ((j + 3)%16==0) printf("\n");
		// }
		// printf("\n");

		uint64_t *lu_ptr = (uint64_t *)(&buf[SWIFT_CTR_LEN + SWIFT_NONCE_LEN]);
		// memcpy(&temp, &buf[SWIFT_CTR_LEN + SWIFT_NONCE_LEN], SWIFT_KEYWORD_LEN);
		uint64_t temp = 0;
		temp = rte_be_to_cpu_64(lu_ptr[0]);
		if (temp != keyword) {
			printf("Core: %u Keyword did not match. Keyword: %lx\n", core_id, temp);
			// rte_pktmbuf_free(m[i]);
			pkts_processed |= 1 << i;
			continue;
		}
		// printf("Core: %u keyword matched\n");

		char *tmp = (char *)malloc(18);
		rte_ether_format_addr(tmp, 18, &hdr->src_addr);
		// printf("Core: %u Searching for address in hash table. Lookup Addr %s. Pkt number: %hu\n", core_id, tmp, i);
		int hash_index = rte_hash_lookup(prover_keys, hdr->src_addr.addr_bytes);


		if (hash_index < 0) {
			printf("Core: %u Could not find address in hash table. Lookup Addr %s\n", core_id, tmp);
			*mask = pkts_processed;
			*ret = -1;
			return;
		}

		free(tmp);

		start_times[hash_index] = start_time;
		// printf("Core: %u Got key for hash table, addr %s, index %d\n", core_id, tmp, retval);

		// int mbuf_index = rte_hash_lookup(mbuf_keys, m[i]);
		// start_times[hash_index] = start_times_mbuf[mbuf_index];
		// if (mbuf_index < 0) {
		// 	printf("Core: %u Could not find start time in mbuf table\n", core_id);
		// 	*mask = pkts_processed;
		// 	*ret = -1;
		// 	return;
		// }
		// printf("Core %u: added start time, hash: %d\n", core_id, hash_index);
		// if (clock_gettime(CLOCK_MONOTONIC, &start_times[hash_index]) != 0) {
		// 	printf("Core %u; Couldn't get clock time\n", core_id);
		// 	return;
		// }

		struct prover_props *prover  = provers[hash_index];
		// struct prover_props *prover = (struct prover_props *)test;
		// printf("Core: %u Got prover data. Prover %p\n", core_id, prover);

		uint16_t *hu_ptr = (uint16_t *)buf;
		pkt_ctr = hu_ptr[0];
		pkt_ctr = rte_be_to_cpu_16(pkt_ctr);
		if (pkt_ctr != *ctr) {
			printf("Core: %u Ctr did not match. Pkt_ctr: %hu Ctr: %hu\n", core_id, pkt_ctr, *ctr);
			prover->valid = false;
			// rte_pktmbuf_free(m[i]);
			printf("Core %u: added stop time, ctr_failure\n", core_id);
			// if (clock_gettime(CLOCK_MONOTONIC, &stop_times[hash_index]) != 0) {
			// 	printf("Core %u: Couldn't get stop_time\n", core_id);
			// 	return;
			// }
			pkts_processed |= 1 << i;
			continue;
		}
		if (!got_first_packet) {
			got_first_packet = true;
			printf("-------------------------\n");
			printf("Got first start time\n");
			printf("-------------------------\n");
			clock_gettime(CLOCK_MONOTONIC, &first_start_time);
		}
		// printf("core %u: ctr matched\n", core_id);
		
		// uint64_t *lu_ptr = (uint64_t *)buf;
		memcpy(pkt_nonce, &buf[SWIFT_CTR_LEN], SWIFT_NONCE_LEN);
		bool match = true;
		for (long unsigned int j = 0; j < SWIFT_NONCE_LEN / sizeof(uint64_t); j++) {
			// memcpy(&pkt_nonce[j], &buf[SWIFT_CTR_LEN + sizeof(uint64_t) * j], sizeof(uint64_t));
			pkt_nonce[j] = rte_be_to_cpu_64(pkt_nonce[j]);

			if (pkt_nonce[j] != nonce[j]) {
				match = false;
			}
		}
		if (!match) {
			printf("Core: %u Nonce does not match. Nonce: %lx, pkt_none: %02lx\n", core_id, nonce[0], pkt_nonce[0]);
			prover->valid = false;
			// rte_pktmbuf_free(m[i]);
			// printf("Core %u: added stop time, nonce_failure\n", core_id);
			// if (clock_gettime(CLOCK_MONOTONIC, &stop_times[hash_index]) != 0) {
			// 	printf("Core %u: Couldn't get stop_time\n", core_id);
			// 	return;
			// }
			pkts_processed |= 1 << i;
			continue;
		}
		// printf("Core %u nonce matched\n", core_id);

		match = true;
		memcpy(pkt_state, &buf[SWIFT_CTR_LEN + SWIFT_NONCE_LEN + SWIFT_KEYWORD_LEN], SWIFT_HASH_LEN);
		// printf("Core: %u after pkt_state memcpy\n", core_id);
		for (long unsigned int j = 0; j < SWIFT_HASH_LEN / sizeof(uint64_t); j++) {
			pkt_state[j] = rte_be_to_cpu_64(pkt_state[j]);
			// printf("Core: %u reordered pkt_state\n", core_id);
			// printf("Core: %u prover %p\n", core_id, prover);
			// printf("Core: %u valid %d\n", core_id, prover->valid);
			// printf("Core: %u app_hash_addr %p\n", core_id, prover->vs);
			if ((prover->vs)[j] != pkt_state[j]) {
				match = false;
			}	
			// printf("Core: %u after state compare\n", core_id);
		}
		if (!match) {
			printf("core: %u State does not match. State: %lx%lx%lx%lx pkt_state: %lx%lx%lx%lx\n", core_id, prover->vs[0], prover->vs[1], prover->vs[2], prover->vs[3], pkt_state[0], pkt_state[1], pkt_state[2], pkt_state[3]);
			prover->valid = false;
			// rte_pktmbuf_free(m[i]);
			printf("Core %u: added stop time, state_failure\n", core_id);
			// if (clock_gettime(CLOCK_MONOTONIC, &stop_times[hash_index]) != 0) {
			// 	printf("Core %u: Couldn't get stop_time\n", core_id);
			// 	return;
			// }
			pkts_processed |= 1 << i;
			continue;
		}
		// printf("Core: %u pkt_state matched\n", core_id);

		//Implement authentication check
		// match = false;
		// goto skip;

		unsigned char *msg = rte_pktmbuf_mtod(m[i], unsigned char *);
		// char tmp_2[18];
		// rte_ether_format_addr(tmp_2, 18, &hdr->src_addr);
        // printf("Core: %u msg for addr %s: ",core_id, tmp_2);
        // for (int j = 0; j < rte_pktmbuf_data_len(m[i]) - SWIFT_HASH_LEN; j++) {
        //     printf("%02x", msg[j]);
        // }
        // printf("\n");
		int mac_ret = EXIT_FAILURE;
        // OSSL_LIB_CTX *lib_context = NULL;
        // EVP_MAC *mac = NULL;
        // EVP_MAC_CTX *mctx = NULL;
        // EVP_MD_CTX *digest_context = NULL;
        // unsigned char *out = NULL;
        // size_t out_len = 0;
        // OSSL_PARAM params[4], *p = params;
        // char digest_name[] = "SHA256";

        // lib_context = OSSL_LIB_CTX_new();
        // if (lib_context == NULL) {
        //     fprintf(stderr, "OSSL_LIB_CTX_new() returned NULL\n");
        //     goto end;
        // }

        // /* Fetch the HMAC implementation */
        // mac = EVP_MAC_fetch(lib_context, "HMAC", propq);
        // if (mac == NULL) {
        //     fprintf(stderr, "EVP_MAC_fetch() returned NULL\n");
        //     goto end;
        // }

        // /* Create a context for the HMAC operation */
        // mctx = EVP_MAC_CTX_new(mac);
        // if (mctx == NULL) {
        //     fprintf(stderr, "EVP_MAC_CTX_new() returned NULL\n");
        //     goto end;
        // }

        // /* The underlying digest to be used */
        // *p++ = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, digest_name,
        //                                         sizeof(digest_name));
        // *p = OSSL_PARAM_construct_end();

        // /* Initialise the HMAC operation */
        // if (!EVP_MAC_init(mctx, (unsigned char *)key, 4 * sizeof(uint64_t), params)) {
        //     fprintf(stderr, "EVP_MAC_init() failed\n");
        //     goto end;
        // }

        // /* Make one or more calls to process the data to be authenticated */
        // // printf("----------------Pre-hash[%hu]---------------------\n", i);
        // // rte_pktmbuf_dump(stdout, mbufs[i], rte_pktmbuf_data_len(mbufs[i]));
		// // printf("----------------------------------------------\n");
        
        // if (!EVP_MAC_update(mctx, msg, rte_pktmbuf_data_len(m[i]) - SWIFT_HASH_LEN)) {
        //     fprintf(stderr, "EVP_MAC_update() failed\n");
        //     goto end;
        // }

        // /* Make a call to the final with a NULL buffer to get the length of the MAC */
        // if (!EVP_MAC_final(mctx, NULL, &out_len, 0)) {
        //     fprintf(stderr, "EVP_MAC_final() failed\n");
        //     goto end;
        // }
        // out = OPENSSL_malloc(out_len);
        // if (out == NULL) {
        //     fprintf(stderr, "malloc failed\n");
        //     goto end;
        // }
        // /* Make one call to the final to get the MAC */
        // if (!EVP_MAC_final(mctx, out, &out_len, out_len)) {
        //     fprintf(stderr, "EVP_MAC_final() failed\n");
        //     goto end;
        // }

        // printf("Generated MAC:\n");
        // BIO_dump_indent_fp(stdout, out, out_len, 2);
        // putchar('\n');

		unsigned char *mac_out;
    	unsigned int result_len = -1;
		HMAC_CTX *ctx = HMAC_CTX_new();
		if (!ctx) {
			fprintf(stderr, "Failed to create HMAC context\n");
			goto end;
		}

		if (!HMAC_Init_ex(ctx, (const void *)key, KEY_LEN/8, EVP_sha256(), NULL)) {
			fprintf(stderr, "HMAC Init failed\n");
			HMAC_CTX_free(ctx);
			goto end;
    	}

		if (!HMAC_Update(ctx, (const unsigned char*)msg, rte_pktmbuf_data_len(m[i]) - SWIFT_HASH_LEN)) {
			fprintf(stderr, "HMAC Update failed\n");
			// HMAC_CTX_free(ctx);
			goto end;
    	}

		mac_out = (unsigned char*)malloc(EVP_MAX_MD_SIZE);
    	if (!mac_out) {
			fprintf(stderr, "Failed to allocate memory for result\n");
			// HMAC_CTX_free(ctx);
			goto end;
    	}

		if (!HMAC_Final(ctx, mac_out, &result_len)) {
			fprintf(stderr, "HMAC Final failed\n");
			// free(result);
			// HMAC_CTX_free(ctx);
        	goto end;
    	}

        mac_ret = EXIT_SUCCESS;
    end:
        if (mac_ret != EXIT_SUCCESS) {
            ERR_print_errors_fp(stderr);
			free(mac_out);
    		HMAC_CTX_free(ctx);
			*mask = pkts_processed;
			*ret = -2;
            return;
        }
        /* OpenSSL free functions will ignore NULL arguments */

		match = true;
		memcpy(pkt_sig, &buf[SWIFT_CTR_LEN + SWIFT_NONCE_LEN + SWIFT_KEYWORD_LEN + SWIFT_HASH_LEN], SWIFT_HASH_LEN);
		uint64_t *out_long = (uint64_t *)mac_out;
		for (uint64_t j = 0; j < SWIFT_HASH_LEN / sizeof(uint64_t); j++) {
			// pkt_sig[j] = rte_be_to_cpu_64(pkt_sig[j]);
			if (out_long[j] != pkt_sig[j]) {
				match = false;
			}	
		}

	// skip:
		if (!match) {
			printf("core: %u Sig does not match. Calculated: %lx%lx%lx%lx pkt_sig: %lx%lx%lx%lx\n", core_id, out_long[0], out_long[1], out_long[2], out_long[3], pkt_sig[0], pkt_sig[1], pkt_sig[2], pkt_sig[3]);
			prover->valid = false;
			// rte_pktmbuf_free(m[i]);
			printf("Core %u: added stop time, sig_failure\n", core_id);
			// if (clock_gettime(CLOCK_MONOTONIC, &stop_times[hash_index]) != 0) {
			// 	printf("Core %u: Couldn't get stop_time\n", core_id);
			// 	return;
			// }
			pkts_processed |= 1 << i;
			continue;
		}
		// printf("Core: %u msg authenticated\n", core_id);

        // OPENSSL_free(out);
		// // printf("Core: %u out freed\n", core_id);
        // EVP_MD_CTX_free(digest_context);
		// // printf("Core: %u dgst_ctx freed\n", core_id);
        // EVP_MAC_CTX_free(mctx);
		// // printf("Core: %u mctx freed\n", core_id);
        // EVP_MAC_free(mac);
		free(mac_out);
    	HMAC_CTX_free(ctx);
		// printf("Core: %u mac freed\n", core_id);
		prover->valid = true;
		// printf("Core: %u valid set\n", core_id);
		// rte_pktmbuf_free(m[i]);
		// printf("Core: %u pkt_mbuf freed\n", core_id);
		pkts_processed |= 1 << i;
		// printf("Core: %u after pkts_processed\n", core_id);
		*ver_ctr += 1;

		// printf("Core %u: added stop time, hash: %d\n", core_id, hash_index);
		// if (clock_gettime(CLOCK_MONOTONIC, &stop_times[hash_index]) != 0) {
		// 	printf("Core %u: Couldn't get stop_time\n", core_id);
		// 	return;
		// }

		// struct timespec stop_time = {5, 500000};
		// stop_times[hash_index] = stop_time;
		// printf("Core: %u pkts processed: %u\n", core_id, pkts_processed);
	}
	free(buf);
	free(pkt_state);
	free(pkt_nonce);
	free(pkt_sig);
	// printf("Core: %u mask pointer: %p\n", core_id, mask);
	*mask = pkts_processed;
	// printf("Core: %u mask set\n", core_id);
	*ret = 0;
	// printf("Core: %u ret set\n", core_id);

	return;
}