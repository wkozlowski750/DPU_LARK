/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 */

#ifndef _RA_VER_CONFIG_H_
#define _RA_VER_CONFIG_H_
#pragma once

#define KEY_LEN 256
#define RX_RING_SIZE 16384
#define TX_RING_SIZE 1024

extern uint64_t key[KEY_LEN/sizeof(uint64_t)/8];
extern uint64_t app_hash[KEY_LEN/sizeof(uint64_t)/8];
extern struct rte_hash *prover_keys;
// extern volatile struct prover_props *provers[128];
extern volatile struct prover_props **provers;
extern const char *prover_table_name;
extern const char *starting_addr;

// extern volatile struct timespec start_times_mbuf[RX_RING_SIZE + 1];
// extern volatile uint64_t start_times_mbuf[RX_RING_SIZE + 1];
extern struct rte_hash *mbuf_keys;

// extern volatile struct timespec *start_times;
// extern volatile struct timespec *stop_times;
extern volatile uint64_t *start_times;
extern volatile uint64_t *stop_times;

typedef struct prover_props {
    uint64_t vs[KEY_LEN/sizeof(uint64_t)/8];
    bool valid;
    struct timespec start_time;
    struct timespec stop_time;
} prover_props;

int hash_table_init(const char *name, uint32_t entries, int socket_id);

int prover_props_init(const char *name, const char *starting_addr, uint32_t quant);

#endif /* _RA_VER_COMMANDS_H_ */
