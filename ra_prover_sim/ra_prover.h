#ifndef _RA_PROVER_H_
#define _RA_PROVER_H_

#define BURST_SIZE 8
#define NUM_MBUFS 32000
#define MBUF_CACHE_SIZE 250
#define KEY_LEN 256

extern struct rte_mempool *mbuf_pool;
extern uint64_t key[KEY_LEN/sizeof(uint64_t)/8];
// extern uint64_t app_hash[KEY_LEN/sizeof(uint64_t)/8];

extern int8_t core_q_mapping[RTE_MAX_LCORE];
// extern struct rte_mbuf **mbufs[];

typedef struct mp_function_args {
    struct rte_mbuf *template;
    struct rte_mbuf **mbufs;
    uint16_t quant;
    uint64_t *key;
    uint8_t relative_core_id;
} mp_function_args;

int msg_template(struct rte_mbuf *mbuf, struct rte_ether_addr *dst, char *starting_adr, struct rte_vlan_hdr *vlan, rte_be16_t ethertype, uint16_t ctr, uint64_t *nonce, uint64_t *app_hash);
int hash_and_create(struct rte_mbuf *template, struct rte_mbuf **mbufs, uint16_t quant, uint64_t *key, uint8_t relative_core_id);

typedef void (*append_func)(struct rte_mbuf *, void *, uint16_t);
void append_char(struct rte_mbuf *m, void *data, uint16_t quant);
void append_u16(struct rte_mbuf *m, void *data, uint16_t quant);
void append_u32(struct rte_mbuf *m, void *data, uint16_t quant);
void append_u64(struct rte_mbuf *m, void *data, uint16_t quant);
void append_data(append_func func, struct rte_mbuf *m, void *data, uint16_t quant);
long long calculate_elapsed_time_ns(struct timespec start, struct timespec end);


#endif
