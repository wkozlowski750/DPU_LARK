/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 */

#ifndef _RA_VER_H_
#define _RA_VER_H_
#pragma once

#include <rte_lcore.h>
#include "ra_ver_config.h"
#include "ra_ver_commands.h"
#include "ra_sha.h"

#define BURST_SIZE 32

#define SWIFT_NONCE_LEN 128/8
#define SWIFT_CTR_LEN 2
#define SWIFT_KEYWORD_LEN 8
#define SWIFT_HASH_LEN 256/8
#define SWIFT_MSG_LEN SWIFT_NONCE_LEN + SWIFT_CTR_LEN + SWIFT_KEYWORD_LEN + SWIFT_HASH_LEN
#define SWIFT_FRAME_LEN RTE_ETHER_HDR_LEN + RTE_VLAN_HLEN + SWIFT_MSG_LEN + SWIFT_HASH_LEN

extern struct rte_mempool *mbuf_pool;
extern struct rte_ring *ring;
extern int8_t core_q_mapping[RTE_MAX_LCORE];
extern uint64_t nonce[SWIFT_NONCE_LEN];
extern uint16_t *ctr;
extern uint32_t prover_quant;
extern struct sha_resources *all_resources[8];


typedef struct lcore_args {
    uint16_t *ctr;
    uint64_t *key;
    uint64_t *nonce;
    uint64_t app_hash[KEY_LEN/sizeof(uint64_t)/8];
    struct sha_resources **all_resources;
} lcore_args;

typedef struct verif_ret {
    uint32_t mask;
    int ret;
} verif_ret;

void create_l2_packet(struct rte_mbuf **m, struct rte_ether_addr *dst_mac, uint32_t quant);
int create_att_req(struct rte_mbuf *m, struct rte_ether_addr *src, uint16_t vid, uint16_t pcp, uint16_t cfi, uint16_t ctr, uint64_t *nonce);
void verify(struct rte_mbuf **m, uint16_t *ctr, uint64_t *nonce, uint16_t quant, uint64_t *key, uint64_t *mask, int *ret, uint32_t *ver_ctr);
int filter(struct rte_mbuf **m, struct rte_mbuf **m_dup, uint16_t *ctr, uint64_t *nonce, uint16_t quant, uint64_t *sigs, uint64_t *mask, int *ret, int *hash_indices);

typedef void (*append_func)(struct rte_mbuf *, void *, uint16_t);
void append_char(struct rte_mbuf *m, void *data, uint16_t quant);
void append_u16(struct rte_mbuf *m, void *data, uint16_t quant);
void append_u32(struct rte_mbuf *m, void *data, uint16_t quant);
void append_u64(struct rte_mbuf *m, void *data, uint16_t quant);
void append_data(append_func func, struct rte_mbuf *m, void *data, uint16_t quant);
uint64_t htonll(uint64_t data);
long long calculate_elapsed_time_ns(struct timespec start, struct timespec end);

void append_time_to_csv(const char* filename, double time_ns);

#endif /* _RA_VER_COMMANDS_H_ */