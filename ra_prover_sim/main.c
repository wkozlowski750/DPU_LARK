/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2015 Intel Corporation
 */

#include <stdint.h>
#include <stdlib.h>
#include <inttypes.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
//#include <rte_hash.h>

#include <cmdline_rdline.h>
#include <cmdline_parse.h>
#include <cmdline_socket.h>
#include <cmdline.h>
#include "ra_prover.h"

#include <math.h>
#define _POSIX_C_SOURCE 199309L
#include <time.h>
#include <unistd.h>

#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024

static const char *_MBUF_POOL = "MBUF_POOL";
struct rte_mempool *mbuf_pool;
int8_t core_q_mapping[RTE_MAX_LCORE] = {-1};
/* basicfwd.c: Basic DPDK skeleton forwarding example. */

/*
 * Initializes a given port using global settings and with the RX buffers
 * coming from the mbuf_pool passed as a parameter.
 */

/* Main functional part of port initialization. 8< */
static inline int
port_init(uint16_t port, struct rte_mempool *mbuf_pool)
{
	struct rte_eth_conf port_conf;
	const uint16_t rx_rings = 1, tx_rings = 2;
	uint16_t nb_rxd = RX_RING_SIZE;
	uint16_t nb_txd = TX_RING_SIZE;
	int retval;
	uint16_t q;
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

	/* Configure the Ethernet device. */
	retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
	if (retval != 0)
		return retval;

	retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
	if (retval != 0)
		return retval;

	/* Allocate and set up 1 RX queue per Ethernet port. */
	for (q = 0; q < rx_rings; q++) {
		retval = rte_eth_rx_queue_setup(port, q, nb_rxd,
				rte_eth_dev_socket_id(port), NULL, mbuf_pool);
		if (retval < 0)
			return retval;
	}

	txconf = dev_info.default_txconf;
	txconf.offloads = port_conf.txmode.offloads;

	/* Allocate and set up 1 TX queue per core. */
	uint16_t core_id;
	q = 0;
	RTE_LCORE_FOREACH(core_id) {
		retval = rte_eth_tx_queue_setup(port, q, nb_txd,
				rte_eth_dev_socket_id(port), &txconf);
		if (retval < 0)
			return retval;
		
		core_q_mapping[core_id] = q;
		q++;
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

	// retval = rte_eth_dev_set_vlan_ether_type(port, RTE_ETH_VLAN_TYPE_OUTER, 0xFFFF);
	/* Enable RX in promiscuous mode for the Ethernet device. */
	retval = rte_eth_promiscuous_enable(port);
	// /* End of setting RX port in promiscuous mode. */
	if (retval != 0)
		return retval;

	return 0;
}
/* >8 End of main functional part of port initialization. */

/* >8 End Basic forwarding application lcore. */
void printHex(const char *str) {
    printf("Hex representation of \"%s\": ", str);
    while (*str) {
        printf("%02X ", (unsigned char)*str);
        str++;
    }
    printf("\n");
}

static void lcore_send(struct mp_function_args *args) {
	struct rte_mbuf *template = args->template;
	struct rte_mbuf **mbufs = args->mbufs;
	uint16_t quant = args->quant;
	uint64_t *key = args->key;
	uint8_t relative_core_id = args->relative_core_id;
	
	unsigned int core_id = rte_lcore_id();
	int retval = -1;

	printf("Sending from core %u\n", core_id);
	// printf("Core: %hu template: %p, mbufs: %p, quant: %hu, key: %p, rel_core_id: %hhu\n", core_id, template, mbufs, quant, key, relative_core_id);
	// uint16_t index = relative_core_id * quant;
	struct rte_mempool *lmbuf_pool;
	if (rte_eal_process_type() == RTE_PROC_SECONDARY) {
		lmbuf_pool = rte_mempool_lookup(_MBUF_POOL);
		if (lmbuf_pool == NULL) {
			printf("Core: %u\tCouldn't get mbuf_pool\n", core_id);
			return;
		}
	} else {
		printf("Core: %hu\tGot mbuf pool\n",core_id);
		lmbuf_pool = mbuf_pool;
	}

	struct rte_mbuf **tx_mbufs = mbufs;

	printf("Core: %u\t quant: %hu\n", core_id, quant);
	for (uint16_t i = 0; i < quant; i++) {
		mbufs[i] = rte_pktmbuf_copy(template, lmbuf_pool, 0, rte_pktmbuf_data_len(template));
		if (mbufs[i] == NULL) {
			printf("Core: %hu\tFailed to copy template for mbuf[%hu]\n", core_id, i);
			return;
		}
		// printf("Core_id: %hu\tCopied template packet %hu.\n", core_id, i);
	}
	//Create packets
	retval = -1;
	// printf("Core: %u\tStarting hash.\n", core_id);
	retval = hash_and_create(template, tx_mbufs, quant, key, relative_core_id);
	if (retval != 0) {
		printf("Failed to create packets. Core id: %d, Error: %d\n", core_id, retval);
		// rte_pktmbuf_free_bulk(tx_mbufs, quant);
		return;
	} else printf("Core: %d\tHashed packets.\n", core_id);

	uint16_t nb_tx = 0;
	//Send pkts
	struct timespec start_time;
	struct timespec stop_time;
	// if (clock_gettime(CLOCK_MONOTONIC, &start_time) != 0) {
	// 	printf("Core %u: Couldn't get start time\n", core_id);
	// 	return;
	// }

	for (int i = 0; i < quant; i += BURST_SIZE) {
		nb_tx += rte_eth_tx_burst(0, core_q_mapping[core_id], &tx_mbufs[i], BURST_SIZE);
		// nb_tx += rte_eth_tx_burst(0, 0, &tx_mbufs[i], BURST_SIZE);
		usleep(300);
		// printf("Core: %u\tSent packets from %d\t Packets sent: %hu\n", core_id, i, nb_tx);
	}

	// if (clock_gettime(CLOCK_MONOTONIC, &stop_time) != 0) {
	// 	printf("Core %u: Couldn't get stop time\n", core_id);
	// 	return;
	// }

	// calculate_elapsed_time_ns(start_time, stop_time);
	rte_pktmbuf_free_bulk(tx_mbufs, quant);
	printf("Core id: %u\tPackets sent: %d\n", core_id, nb_tx);
	printf("Core: %u\tExited send loop\n", core_id);
	//free packets
	// rte_pktmbuf_free_bulk(tx_mbufs, quant);

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

	uint64_t key[KEY_LEN/sizeof(uint64_t)/8] = {
		0x136b4dfc04ab4b34,
		0xd175e64e302d5283,
		0x84588c4f694ce1f6,
		0xad34a93028e13b5f,
	};

	uint64_t app_hash[KEY_LEN/sizeof(uint64_t)/8] = {
		0x8a8f60ecb09b7e64,
		0xc6d5214a8043865e,
		0x608507db8c3f61f9,
		0x95eae6d078875901,
	};

	/* Initializion the Environment Abstraction Layer (EAL). 8< */
	int ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
	/* >8 End of initialization the Environment Abstraction Layer (EAL). */

	argc -= ret;
	argv += ret;

	if (argc != 2) {
		rte_exit(EXIT_FAILURE, "Need the number of packets to send. Must be multiple of 32.\n");
	}

	uint16_t tot_packets = atoi(argv[1]);

	if (tot_packets % 32 != 0) {
		rte_exit(EXIT_FAILURE, "Packet count must be divisible by 32.\n");
	}

	uint16_t core_id;

	uint16_t core_count = rte_lcore_count();
	if ((core_count & (core_count - 1)) != 0) {
		rte_exit(EXIT_FAILURE, "Core count must be a power of 2. Current count: %hu\n", core_count);
	}

	/* Check that there is an even number of ports to send/receive on. */
	nb_ports = rte_eth_dev_count_avail();
	if (nb_ports != 1)
		rte_exit(EXIT_FAILURE, "Error: only one port allowed\n");

	/* Creates a new mempool in memory to hold the mbufs. */

	/* Allocates mempool to hold the mbufs. 8< */
	mbuf_pool = rte_pktmbuf_pool_create(_MBUF_POOL, NUM_MBUFS * nb_ports,
		MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
	/* >8 End of allocating mempool to hold mbuf. */

	if (mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

	/* Initializing all ports. 8< */
	RTE_ETH_FOREACH_DEV(portid)
		if (port_init(portid, mbuf_pool) != 0)
			rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu16 "\n",
					portid);
	/* >8 End of initializing all ports. */

	printf("Starting while loop.\n");
	while(true) {
		struct rte_mbuf *rec_mbuf[BURST_SIZE];
		uint32_t nb_rx = 0;
		int retval;

		nb_rx = rte_eth_rx_burst(0, 0, rec_mbuf, BURST_SIZE);

		if (nb_rx == 0) {
			//printf("No packets recieved.\n");
			continue;
		}
		else if (nb_rx > 1) {
			printf("Received too many packets. Count: %u ... Exiting ...\n", nb_rx);
			for (int i = 0; i < BURST_SIZE; i++) {
				rte_pktmbuf_dump(stdout, rec_mbuf[i], rte_pktmbuf_pkt_len(rec_mbuf[i]));
			}
			break;
		}

		else {
			//extract info from attestation req
			printf("Recieved one packet\n");
			struct rte_ether_hdr *ver_hdr;

			uint16_t ctr;
			uint64_t nonce[2];
			volatile char buf[7];
			buf[6] = '\0';

			struct rte_vlan_hdr *vlan;
			struct rte_vlan_hdr vlan_copy = {0, 0};

			volatile char *ret = NULL;

			//get pointer to ethernet header
			ver_hdr = rte_pktmbuf_mtod(rec_mbuf[0], struct rte_ether_hdr *);
			

			// printf("Ethertype: %hx\n", ver_hdr->ether_type);
			//strip vlan info if necessary
			if (ver_hdr->ether_type == 0x0081) {
				printf("Got into vlan removal.\n");
				vlan = rte_pktmbuf_mtod_offset(rec_mbuf[0], struct rte_vlan_hdr *, RTE_ETHER_HDR_LEN);
				printf("Stripping vlan header. VID: %hx\n", vlan->vlan_tci);
				vlan_copy.eth_proto = vlan->eth_proto;
				vlan_copy.vlan_tci = vlan->vlan_tci;
				retval = rte_vlan_strip(rec_mbuf[0]);
				if (retval != 0) {
					printf("Failed to strip vlan hdr.\n");
					break;
				}
			}
			printf("----------------Recieved Request---------------------\n");
			rte_pktmbuf_dump(stdout, rec_mbuf[0], rte_pktmbuf_data_len(rec_mbuf[0]));
			printf("-----------------------------------------------------\n");

			//get counter and nonce
			const char keyword[7] = "attest";
			ret = rte_pktmbuf_read(rec_mbuf[0], RTE_ETHER_HDR_LEN + sizeof(uint16_t), 6, buf);
			if (ret == NULL) {
				printf("Could not get keyword.\n");
				break;
			}
			for (int j = 0; j < 6; j++) buf[j] = ret[j];
			if (strcmp(buf, keyword) != 0) {
				char tmp_buf[6];
				// printf("Breaking at string print.\n");
				printf("Keyword did not match. String content: %s\n", buf);
				continue;
			}
			uint16_t *char_ret = NULL;
			char_ret = rte_pktmbuf_read(rec_mbuf[0], RTE_ETHER_HDR_LEN, sizeof(uint16_t), &ctr);
			if (ret == NULL) {
				printf("Could not get ctr\n");
				break;
			}
			ctr = *char_ret;
			ctr = rte_be_to_cpu_16(ctr);
			printf("Counter value: %d\n", ctr);
			uint64_t *nonce_ret = NULL;
			nonce_ret = rte_pktmbuf_read(rec_mbuf[0], RTE_ETHER_HDR_LEN + sizeof(uint64_t), 2 * sizeof(uint64_t), nonce);
			if (nonce_ret == NULL) {
				printf("Couldn't get nonce\n");
				break;
			}
			for (int j = 0; j < 2; j++) nonce[j] = nonce_ret[j];
			nonce[0] = rte_be_to_cpu_64(nonce[0]);
			nonce[1] = rte_be_to_cpu_64(nonce[1]);
			printf("Nonce value: %#lx%lx\n", nonce[0], nonce[1]);

			//construct template packet
			char *starting_addr = "02:00:00:00:00:00";
			struct rte_mbuf *template;
			template = rte_pktmbuf_alloc(mbuf_pool);
    		if (template == NULL) {
        		printf("Failed to allocate memory for template packet.\n");
        		break;
    		}
			// printf("Creating template. ver_src_addr: %hhx:%hhx:%hhx:%hhx:%hhx:%hhx\n", ver_hdr->src_addr.addr_bytes[0], ver_hdr->src_addr.addr_bytes[1], ver_hdr->src_addr.addr_bytes[2], ver_hdr->src_addr.addr_bytes[3], ver_hdr->src_addr.addr_bytes[4], ver_hdr->src_addr.addr_bytes[5]);
			retval = -1;
			ver_hdr = rte_pktmbuf_mtod(rec_mbuf[0], struct rte_ether_hdr *);
			retval = msg_template(template, &ver_hdr->src_addr, starting_addr, &vlan_copy, ver_hdr->ether_type, ctr, nonce, app_hash);
			if (retval != 0) {
				printf("Msg template creation failed with error: %d\n", retval);
				break;
			}
			printf("Created Template.\n");

			printf("Main: ----------------Template Packet---------------------\n");
			rte_pktmbuf_dump(stdout, template, rte_pktmbuf_data_len(template));
			printf("Main: ----------------------------------------------------\n");

			//setup for calling function on each lcore
			printf("Core_count: %hu\n", core_count);
			// uint16_t tot_packets = 128;
			uint16_t packets_per_core = tot_packets / core_count;

			uint8_t core_ctr = 0;

			//allocate memory for function args pointers and mbuf arrays
			struct mp_function_args *function_args[core_count];
			struct rte_mbuf **mbufs[core_count];
			for (uint8_t i = 0; i < core_count; i++) {
				function_args[i] = (struct mp_function_args *)malloc(sizeof(struct mp_function_args));
				if (function_args[i] == NULL) {
					rte_panic("Failed to allocate memory for function args %hhu. Exiting...\n", i);
				} 

				mbufs[i] = (struct rte_mbuf **)malloc(sizeof(struct rte_mbuf *) * packets_per_core);
				if (mbufs[i] == NULL) {
					rte_panic("Failed to allocate memory for mbufs %hhu. Exiting...\n", i);
				} 
			} printf("Main: Allocated memory for fucntion args and mbufs.\n");
			// printf("Main: mbufs[0]: %p\tmbufs[1] %p\n",mbufs[0], mbufs[1]);

			// printf("Main: packets_per_core: %hu\n", packets_per_core);
			RTE_LCORE_FOREACH_WORKER(core_id) {
				// printf("RTE_FOREACH\n");
				function_args[core_ctr]->template = template;
				// function_args.template = template;
				// printf("Main: function_args[%hu]->template: %p\n", core_ctr, function_args[core_ctr]->template);
				// printf("Main: function_args[%hu]->template: %p\n", core_ctr, function_args.template);
				// printf("After function->template\n");
				function_args[core_ctr]->mbufs = mbufs[core_ctr];
				// printf("Main: function_args[%hu]->mbufs: %p\n", core_ctr, function_args[core_ctr]->mbufs[core_ctr]);
				// function_args.mbufs = mbufs[core_ctr];
				// printf("Main: function_args[%hu]->mbufs: %p\n", core_ctr, function_args.mbufs[core_ctr]);
				// printf("After function->mbufs\n");
				function_args[core_ctr]->quant = packets_per_core;
				// printf("Main: function_args[%hu]->quant: %hu\n", core_ctr, function_args[core_ctr]->quant);
				// function_args.quant = packets_per_core;
				// printf("Main: function_args[%hu]->quant: %hu\n", core_ctr, function_args.quant);
				function_args[core_ctr]->key = key;
				// printf("Main: function_args[%hu]->key: %p\n", core_ctr, function_args[core_ctr]->key);
				// function_args.key = key;
				// printf("Main: function_args[%hu]->key: %p\n", core_ctr, function_args.key);
				// printf("After function->key\n");
				function_args[core_ctr]->relative_core_id = core_ctr;
				// function_args.relative_core_id = core_ctr;
				// printf("Core_id: %hu\tRel_core_id: %hu\n", core_id, core_ctr);
				retval = rte_eal_remote_launch(lcore_send, function_args[core_ctr], core_id);
				if (retval != 0) {
					printf("Main: Failed to launch mp function on listed lcores.\n");
					break;
				} //else printf("Launched on core %hhu\n", core_id);
				core_ctr++;
			}

			// printf("Core_id: %hu\tRel_core_id: %hu\n", rte_lcore_id(), core_ctr);
			function_args[core_ctr]->key = key;
			function_args[core_ctr]->mbufs = mbufs[core_ctr];
			function_args[core_ctr]->quant = packets_per_core;
			function_args[core_ctr]->relative_core_id = core_ctr;
			function_args[core_ctr]->template = template;

			lcore_send(function_args[core_ctr]);
			while (rte_eal_get_lcore_state(1) == RUNNING) {}
			printf("Main: All cores finished sending\n");
			//free function arguments

			for (uint8_t i = 0; i < core_count; i++) {
				free(mbufs[i]);
				free(function_args[i]);
			}

			//free mbufs
			rte_pktmbuf_free(template);
			// rte_pktmbuf_free_bulk(mbufs, tot_packets);
			
			/*End multi-processing*/
		}
	}

	/* clean up the EAL */
	rte_eal_cleanup();

	return 0;
}
