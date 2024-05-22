#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include <rte_mempool.h>
#include <rte_ether.h>
#include <rte_mbuf.h>
#include <rte_memcpy.h>
#include <rte_byteorder.h>
#include <rte_string_fns.h>

#include <openssl/crypto.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/params.h>

#include "ra_prover.h"

int msg_template(struct rte_mbuf *mbuf, struct rte_ether_addr *dst, char *starting_adr, struct rte_vlan_hdr *vlan, rte_be16_t ethertype, uint16_t ctr, uint64_t *nonce, uint64_t *app_hash) {
    struct rte_ether_hdr *hdr;
    uint16_t pkt_len = RTE_ETHER_HDR_LEN;

    //allocate mbuf to store template packet

    //add vlan info if necessary
    if ((vlan->eth_proto != 0) || (vlan->vlan_tci != 0)) {
        // printf("Got into vlan statement.\n");
        pkt_len += RTE_VLAN_HLEN;
        hdr = (struct rte_ether_hdr *)rte_pktmbuf_append(mbuf, pkt_len);
        // printf("Appended vlan data.\n");
        if (hdr == NULL) {
            printf("Failed to append data to template.\n");
            return -2;
        }
        struct rte_vlan_hdr *vlan_hdr = rte_pktmbuf_mtod_offset(mbuf, struct rte_vlan_hdr *, RTE_ETHER_HDR_LEN);
        vlan_hdr->eth_proto = vlan->eth_proto;
        // printf("Assigned eth_proto.\n");
        vlan_hdr->vlan_tci = vlan->vlan_tci;
        // printf("Assigned TCI.\n");
        hdr->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_VLAN);
        //printf("Assigned ether_type.\n");
    }

    //copy verifier destination address
    hdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
    void *ret = rte_memcpy(hdr->dst_addr.addr_bytes, dst->addr_bytes, RTE_ETHER_ADDR_LEN);
    //printf("Copied dst addr.\n");
    if (ret == NULL) {
        printf("Failed to copy dst addr to template packet.\n");
        return -3;
    }

    int retval = rte_ether_unformat_addr(starting_adr, &hdr->src_addr);
    //printf("Copied src address.\n");
    if (retval < 0) {
        printf("Src address not copied.\n");
        return retval;
    }
    if ((vlan->eth_proto == 0) && (vlan->vlan_tci == 0)) hdr->ether_type = ethertype;
    
    //copy data to packet
    uint16_t ctr_n = rte_cpu_to_be_16(ctr);
    append_u16(mbuf, &ctr_n, 1);
    //printf("Appended ctr.\n");


    uint64_t nonce_reordered[2];
    nonce_reordered[0] = rte_cpu_to_be_64(nonce[0]);
    nonce_reordered[1] = rte_cpu_to_be_64(nonce[1]);
    //printf("Reordered Nonce.\n");

    append_u64(mbuf, nonce_reordered, 2);
    //printf("Appended nonce.\n");

    uint64_t keyword = 0x0123456789abcdef;
    keyword = rte_cpu_to_be_64(keyword);
    append_u64(mbuf, &keyword, 1);

    uint64_t hash_reordered[4];
    for (int i = 0; i < 4; i++) {
        hash_reordered[i] = rte_cpu_to_be_64(app_hash[i]);
    }
    append_u64(mbuf, hash_reordered, 4);
    
    return 0;
}

int hash_and_create(struct rte_mbuf *template, struct rte_mbuf **mbufs, uint16_t quant, uint64_t *key, uint8_t relative_core_id) {
    struct rte_ether_hdr *hdr;
    // void *res = NULL;
    const unsigned int core_id = rte_lcore_id();

    hdr = rte_pktmbuf_mtod(template, struct rte_ether_hdr *);
    
    uint16_t last_bytes = hdr->src_addr.addr_bytes[4];
    last_bytes = rte_be_to_cpu_16(last_bytes);
    last_bytes += relative_core_id * quant;
    // printf("Core: %u LAst Bytes: %hu\n", core_id, last_bytes);
    uint32_t tot_false = 0;
    uint32_t false_ctr = 0;
    uint32_t false_nonce = 0;
    uint32_t false_hash = 0;
    uint32_t false_sig = 0;
    static const char *propq = NULL;
    //update src address
    // printf("Core: %u\tStarting template copy for loop.\n", core_id);
    for (uint16_t i = 0; i < quant; i++) {
        
        bool ctr_fake = false;
        bool nonce_fake = false;
        bool hash_fake = false;
        bool sig_fake = false;
        // if (rand() % 100 == 0) {
        if (0) {
            tot_false++;
            // If selected, randomly choose one of four values
            int choice = rand() % 4;
                switch (choice) {
                    case 0:
                        ctr_fake = true;
                        false_ctr++;
                        break;
                    case 1:
                        nonce_fake = true;
                        false_nonce++;
                        break;
                    case 2:
                        hash_fake = true;
                        false_hash++;
                        break;
                    case 3:
                        sig_fake = true;
                        false_sig++;
                        break;
                    default:
                        // This case should never be hit due to the modulo operation
                        printf("Unexpected selection\n");
                }
        }
        // mbufs[i] = rte_pktmbuf_copy(template, mbuf_pool, 0, rte_pktmbuf_data_len(template));
        // if (mbufs[i] == NULL) {
        //     printf("Failed to copy template for mbuf[%hu]\n", i);
        //     return -1;
        // }
        // printf("Core_id: %hu\tCopied template packet %hu.\n", core_id, i);
        uint16_t be_last_bytes = rte_cpu_to_be_16(last_bytes);
        hdr = rte_pktmbuf_mtod(mbufs[i], struct rte_ether_hdr *);
        rte_memcpy(&hdr->src_addr.addr_bytes[4], &be_last_bytes, sizeof(uint16_t));

        if (ctr_fake){
            uint16_t data = 11;
            void *ptr = rte_pktmbuf_mtod_offset(mbufs[i], void *, RTE_ETHER_HDR_LEN + RTE_VLAN_HLEN);
            rte_memcpy(ptr, &data, sizeof(uint16_t));
        } else if(nonce_fake) {
            uint64_t data = 11;
            void *ptr = rte_pktmbuf_mtod_offset(mbufs[i], void *, RTE_ETHER_HDR_LEN + RTE_VLAN_HLEN + sizeof(uint16_t));
            rte_memcpy(ptr, &data, sizeof(uint16_t));
        } else if (hash_fake) {
            uint64_t data = 11;
            void *ptr = rte_pktmbuf_mtod_offset(mbufs[i], void *, RTE_ETHER_HDR_LEN + RTE_VLAN_HLEN + sizeof(uint16_t) + 3 * sizeof(uint64_t));
            rte_memcpy(ptr, &data, sizeof(uint16_t));
        }

        //HMAC
        unsigned char *msg = rte_pktmbuf_mtod(mbufs[i], unsigned char *);
        // char tmp[18];
		// rte_ether_format_addr(tmp, 18, &hdr->src_addr);
        // printf("Core: %u msg for addr %s: ",core_id, tmp);
        // for (int j = 0; j < rte_pktmbuf_data_len(mbufs[i]); j++) {
        //     printf("%02x", msg[j]);
        // }
        // printf("\n");

        int mac_ret = EXIT_FAILURE;
        OSSL_LIB_CTX *lib_context = NULL;
        EVP_MAC *mac = NULL;
        EVP_MAC_CTX *mctx = NULL;
        EVP_MD_CTX *digest_context = NULL;
        unsigned char *out = NULL;
        size_t out_len = 0;
        OSSL_PARAM params[4], *p = params;
        char digest_name[] = "SHA256";

        lib_context = OSSL_LIB_CTX_new();
        if (lib_context == NULL) {
            fprintf(stderr, "OSSL_LIB_CTX_new() returned NULL\n");
            goto end;
        }

        /* Fetch the HMAC implementation */
        mac = EVP_MAC_fetch(lib_context, "HMAC", propq);
        if (mac == NULL) {
            fprintf(stderr, "EVP_MAC_fetch() returned NULL\n");
            goto end;
        }

        /* Create a context for the HMAC operation */
        mctx = EVP_MAC_CTX_new(mac);
        if (mctx == NULL) {
            fprintf(stderr, "EVP_MAC_CTX_new() returned NULL\n");
            goto end;
        }

        /* The underlying digest to be used */
        *p++ = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, digest_name,
                                                sizeof(digest_name));
        *p = OSSL_PARAM_construct_end();

        /* Initialise the HMAC operation */
        if (!EVP_MAC_init(mctx, key, 4 * sizeof(uint64_t), params)) {
            fprintf(stderr, "EVP_MAC_init() failed\n");
            goto end;
        }

        /* Make one or more calls to process the data to be authenticated */
        // printf("----------------Pre-hash[%hu]---------------------\n", i);
        // rte_pktmbuf_dump(stdout, mbufs[i], rte_pktmbuf_data_len(mbufs[i]));
		// printf("----------------------------------------------\n");
        
        if (!EVP_MAC_update(mctx, msg, rte_pktmbuf_data_len(mbufs[i]))) {
            fprintf(stderr, "EVP_MAC_update() failed\n");
            goto end;
        }

        /* Make a call to the final with a NULL buffer to get the length of the MAC */
        if (!EVP_MAC_final(mctx, NULL, &out_len, 0)) {
            fprintf(stderr, "EVP_MAC_final() failed\n");
            goto end;
        }
        out = OPENSSL_malloc(out_len);
        if (out == NULL) {
            fprintf(stderr, "malloc failed\n");
            goto end;
        }
        /* Make one call to the final to get the MAC */
        if (!EVP_MAC_final(mctx, out, &out_len, out_len)) {
            fprintf(stderr, "EVP_MAC_final() failed\n");
            goto end;
        }

        // printf("Generated MAC:\n");
        // BIO_dump_indent_fp(stdout, out, out_len, 2);
        // putchar('\n');

        mac_ret = EXIT_SUCCESS;
    end:
        if (mac_ret != EXIT_SUCCESS) {
            ERR_print_errors_fp(stderr);
            return -1;
        }
        /* OpenSSL free functions will ignore NULL arguments */

        append_char(mbufs[i], out, (uint16_t)out_len);

        if (sig_fake) {
            uint64_t data = 11;
            void *ptr = rte_pktmbuf_mtod_offset(mbufs[i], void *, RTE_ETHER_HDR_LEN + RTE_VLAN_HLEN + sizeof(uint16_t) + 7 * sizeof(uint64_t));
            rte_memcpy(ptr, &data, sizeof(uint64_t));
        }

        if (rte_pktmbuf_data_len(mbufs[i]) < RTE_ETHER_MIN_LEN) {
            char pad = 0;
            append_char(mbufs[i], &pad, RTE_ETHER_MIN_LEN - rte_pktmbuf_data_len(mbufs[i]));
        }

        OPENSSL_free(out);
        EVP_MD_CTX_free(digest_context);
        EVP_MAC_CTX_free(mctx);
        EVP_MAC_free(mac);

        last_bytes++;
        // printf("----------------Resp[%hu]---------------------\n", i);
	    // rte_pktmbuf_dump(stdout, mbufs[i], rte_pktmbuf_data_len(mbufs[i]));
		// printf("----------------------------------------------\n");
    }

    printf("Core: %u Total false pkts: %u False ctr: %u False nonce: %u False hash: %u False sig: %u\n", core_id, tot_false, false_ctr, false_nonce, false_hash, false_sig);
    return 0;
}

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

long long calculate_elapsed_time_ns(struct timespec start, struct timespec end) {
    long long diff = (end.tv_sec - start.tv_sec) * 1000000000LL + (end.tv_nsec - start.tv_nsec);
    printf("%lld\n", diff); // Write the time in nanoseconds
    return diff;
}
