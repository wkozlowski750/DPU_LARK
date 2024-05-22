/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 */

#ifndef _RA_SHA_H_
#define _RA_SHA_H_
#pragma once

#include <doca_error.h>
#include <doca_types.h>
#include <doca_buf.h>
#include <doca_buf.h>
#include <doca_sha.h>
#include <doca_ctx.h>
#include <doca_pe.h>
#include <doca_mmap.h>
#include <doca_buf_inventory.h>

#include "common.h"

// doca_error_t
// sha_partial_create(char *src_buffer);

// doca_error_t
// sha_create_core_objects(struct sha_core_objects *state, uint32_t max_bufs);
struct sha_resources {
	struct program_core_objects state;	/* Core objects that manage our "state" */
	struct doca_sha *sha_ctx;		/* DOCA SHA context */
	struct doca_buf **src_doca_buf;		/* Source buffer as a DOCA Buffer */
	void **src_buffer;			/* Source buffer as a C pointer */
	struct doca_buf **final_doca_src_buf;
	void **final_src_buf;
	size_t *remaining_src_len;		/* Remaining bytes in source buffer */
	uint32_t partial_block_size;		/* SHA block size */
	doca_error_t *result;			/* Current DOCA Error result */
	bool run_main_loop;			/* Should we keep on running the main loop? */
    uint64_t *key;
    uint64_t *ikey;
    uint64_t *okey;
	struct doca_buf **dst_buffers;
	uint32_t completions;
	struct doca_sha_task_hash **sha_hash_task;
	struct doca_sha_task_partial_hash **sha_partial_hash_task;
	int *hash_indices;
	uint32_t overall_completions;
};

typedef struct sha_core_objects {
	struct doca_dev *dev;			/* doca device */
	struct doca_mmap *src_mmap;		/* doca mmap for source buffer */
	struct doca_mmap *dst_mmap;		/* doca mmap for destination buffer */
	struct doca_buf_inventory *buf_inv;	/* doca buffer inventory */
	struct doca_ctx **ctx;			/* doca context */
	struct doca_pe *pe;			/* doca progress engine */
} sha_core_objects;

doca_error_t
sha_init(struct program_core_objects *state, struct sha_resources *resources, union doca_data *resource_data, uint8_t *dst_buffers, uint8_t *src_buffers, uint8_t *final_src_buf,
		struct doca_buf **doca_dst_buffers, uint32_t quant, uint64_t *key, struct doca_sha_task_partial_hash **sha_partial_hash_task, 
		struct doca_sha_task_hash **sha_hash_task, struct doca_task **task, struct doca_task **hash_task);

// static doca_error_t
// prepare_and_submit_partial_sha_hash_task_bulk(struct sha_resources *resources,
// 					 struct doca_sha_task_partial_hash *sha_partial_hash_task, uint32_t quant);

doca_error_t
sha_perform_bulk(struct sha_resources *resources, struct doca_buf **doca_dst_buffers, struct rte_mbuf **mbufs, uint32_t quant, 
				struct doca_sha_task_partial_hash **sha_partial_hash_task, int *hash_indices);

/* DOCA core objects used by the samples / applications */




#endif /* _RA_SHA_H_ */