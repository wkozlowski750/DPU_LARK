/*
 * Copyright (c) 2022 NVIDIA CORPORATION & AFFILIATES, ALL RIGHTS RESERVED.
 *
 * This software product is a proprietary product of NVIDIA CORPORATION &
 * AFFILIATES (the "Company") and all right, title, and interest in and to the
 * software product, including all associated intellectual property rights, are
 * and shall remain exclusively with the Company.
 *
 * This software product is governed by the End User License Agreement
 * provided with the software product.
 *
 */

#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include <doca_buf.h>
#include <doca_buf_inventory.h>
#include <doca_ctx.h>
#include <doca_sha.h>
#include <doca_pe.h>
#include <doca_error.h>
#include <doca_log.h>
#include <doca_sha.h>
#include <doca_error.h>

#include <cmdline_rdline.h>
#include <cmdline_parse.h>
#include <cmdline_parse_ipaddr.h>
#include <cmdline_parse_etheraddr.h>
#include <cmdline_parse_num.h>
#include <cmdline_parse_string.h>
#include <cmdline.h>

#include <rte_ether.h>
#include <math.h>
#include <doca_dpdk.h>
#include <rte_cycles.h>
#include <time.h>

#include "common.h"
#include "ra_ver.h"

DOCA_LOG_REGISTER(RA_SHA);

#define SLEEP_IN_NANOS			(10 * 1000)			/* Sample the task every 10 microseconds  */
#define PARTIAL_SHA_LEN			(64)				/* Buffer length of first partial SHA rask */
#define LOG_NUM_PARTIAL_SHA_TASKS	(0)				/* Log of SHA tasks number */
#define SHA_SAMPLE_ALGORITHM		(DOCA_SHA_ALGORITHM_SHA256)	/* doca_sha_algorithm for the sample */

// struct sha_resources {
// 	struct sha_core_objects state;	/* Core objects that manage our "state" */
// 	struct doca_sha *sha_ctx;		/* DOCA SHA context */
// 	struct doca_buf *src_doca_buf;		/* Source buffer as a DOCA Buffer */
// 	void *src_buffer;			/* Source buffer as a C pointer */
// 	size_t remaining_src_len;		/* Remaining bytes in source buffer */
// 	uint32_t partial_block_size;		/* SHA block size */
// 	doca_error_t result;			/* Current DOCA Error result */
// 	bool run_main_loop;			/* Should we keep on running the main loop? */
// };

/*
 * Free callback - free doca_buf allocated pointer
 *
 * @addr [in]: Memory range pointer
 * @len [in]: Memory range length
 * @opaque [in]: An opaque pointer passed to iterator
 */
void
free_cb(void *addr, size_t len, void *opaque)
{
	(void)len;
	(void)opaque;

	free(addr);
}

/*
 * Clean all the sample resources
 *
 * @resources [in]: sha_resources struct
 * @return: DOCA_SUCCESS if the device supports SHA hash task and DOCA_ERROR otherwise.
 */
static doca_error_t
sha_cleanup(struct sha_resources *resources)
{
	struct program_core_objects *state = &resources->state;
	doca_error_t result = DOCA_SUCCESS, tmp_result;

	if (state->pe != NULL && state->ctx != NULL) {
		tmp_result = doca_ctx_stop(state->ctx);
		if (tmp_result != DOCA_SUCCESS) {
			DOCA_ERROR_PROPAGATE(result, tmp_result);
			DOCA_LOG_ERR("Failed to destroy DOCA SHA: %s", doca_error_get_descr(tmp_result));
		}

		state->ctx = NULL;
	}

	if (resources->sha_ctx != NULL) {
		tmp_result = doca_sha_destroy(resources->sha_ctx);
		if (tmp_result != DOCA_SUCCESS) {
			DOCA_ERROR_PROPAGATE(result, tmp_result);
			DOCA_LOG_ERR("Failed to destroy DOCA SHA: %s", doca_error_get_descr(tmp_result));
		}
	}

	tmp_result = destroy_core_objects(state);
	if (tmp_result != DOCA_SUCCESS) {
		DOCA_ERROR_PROPAGATE(result, tmp_result);
		DOCA_LOG_ERR("Failed to destroy DOCA SHA: %s", doca_error_get_descr(tmp_result));
	}

	return result;
}

/*
 * Prepare next block in partial task and then submit the task
 *
 * @resources [in]: sha_resources struct
 * @sha_partial_hash_task [in]: the allocated partial SHA task
 * @return: DOCA_SUCCESS if the device supports SHA hash task and DOCA_ERROR otherwise.
 */
// static doca_error_t
// prepare_and_submit_partial_sha_hash_task(struct sha_resources *resources,
// 					 struct doca_sha_task_partial_hash *sha_partial_hash_task)
// {
// 	struct doca_task *task;
// 	size_t src_len;
// 	doca_error_t result;

// 	if (resources->remaining_src_len > resources->partial_block_size)
// 		src_len = resources->partial_block_size;
// 	else
// 		src_len = resources->remaining_src_len;

// 	/* Set data address and length in the doca_buf */
// 	result = doca_buf_set_data(resources->src_doca_buf, resources->src_buffer, src_len);
// 	if (result != DOCA_SUCCESS) {
// 		DOCA_LOG_ERR("Failed to set data for source buffer: %s", doca_error_get_descr(result));
// 		return result;
// 	}

// 	result = doca_sha_task_partial_hash_set_src(sha_partial_hash_task, resources->src_doca_buf);
// 	if (result != DOCA_SUCCESS) {
// 		DOCA_LOG_ERR("Failed to set source buffer for SHA partial hash task: %s", doca_error_get_descr(result));
// 		return result;
// 	}

// 	/* If we got to final task then mark it as such */
// 	if (src_len == resources->remaining_src_len) {
// 		result = doca_sha_task_partial_hash_set_is_final_buffer(sha_partial_hash_task);
// 		if (result != DOCA_SUCCESS) {
// 			DOCA_LOG_ERR("Failed to set final buffer for SHA partial hash task: %s",
// 				     doca_error_get_descr(result));
// 			return result;
// 		}
// 	}

// 	/* Move the src buffer to the next block and decrease the remaining source length */
// 	resources->src_buffer += src_len;
// 	resources->remaining_src_len -= src_len;

// 	task = doca_sha_task_partial_hash_as_task(sha_partial_hash_task);

// 	/* Submit SHA partial hash task */
// 	result = doca_task_submit(task);
// 	if (result != DOCA_SUCCESS) {
// 		DOCA_LOG_ERR("Failed to submit SHA partial hash task: %s", doca_error_get_descr(result));
// 		return result;
// 	}

// 	return DOCA_SUCCESS;
// }

static doca_error_t
prepare_and_submit_partial_sha_hash_task_bulk(struct sha_resources *resources,
					 struct doca_sha_task_partial_hash *sha_partial_hash_task, uint64_t id)
{
	struct doca_task *task;
	size_t src_len;
	doca_error_t result;

	uint32_t core_id = rte_lcore_id();
	// printf("Core %u: starting task with id %u\n", core_id, id);
	// printf("Before print\n");
	// printf("Core %u: task: %p, id: %u, src_buf: %p\n", core_id, sha_partial_hash_task, id, resources->src_doca_buf[id]);
	
	if (resources->remaining_src_len[id] > resources->partial_block_size)
		src_len = resources->partial_block_size;
	else
		src_len = resources->remaining_src_len[id];

	// void *data;
	// doca_buf_get_data(resources->dst_buffers[id], &data);
	// size_t buf_len;
	// doca_buf_get_data_len(resources->src_doca_buf[id], &buf_len);
	// printf("Before print\n");
	// printf("Core %u: src_buf %p, src_buf_void %p, dst_buf %p, dst_buf_data %p, task %p, src_len %zu, buf_src_len %zu\n", core_id, resources->src_doca_buf[id], resources->src_buffer[id], resources->dst_buffers[id], data, sha_partial_hash_task, src_len, buf_len);
	// printf("Core %u: src_buf %p, src_buf_void %p, task %p, src_len %zu, buf_src_len %zu\n", core_id, resources->src_doca_buf[id], resources->src_buffer[id], sha_partial_hash_task, src_len, buf_len);
	/* Set data address and length in the doca_buf */
	result = doca_buf_set_data(resources->src_doca_buf[id], resources->src_buffer[id], src_len);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to set data for source buffer: %s", doca_error_get_descr(result));
		return result;
	}

	// unsigned char *char_buf = (unsigned char *)resources->src_buffer[id];
	// printf("Core %u buf: ", core_id);
	// for (uint16_t j = 0; j < src_len; j++) {
	// 	printf("%02x ", char_buf[j]);
	// 	if ((j + 3)%16==0) printf("\n");
	// }
	// printf("\n");
	// printf("Core %u: set doca buf src len and addr\n", core_id);

	// result = doca_sha_task_partial_hash_set_dst(sha_partial_hash_task, resources->dst_buffers[id]);
	// if (result != DOCA_SUCCESS) {
	// 	DOCA_LOG_ERR("Failed to set dst buffer for SHA partial hash task: %s", doca_error_get_descr(result));
	// 	return result;
	// }

	result = doca_sha_task_partial_hash_set_src(sha_partial_hash_task, resources->src_doca_buf[id]);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to set source buffer for SHA partial hash task: %s", doca_error_get_descr(result));
		return result;
	}
	// printf("src_buf %p\n", resources->src_doca_buf[id]);

	// printf("Core %u: changed src buf for task\n", core_id);

	/* If we got to final task then mark it as such */
	if (src_len == resources->remaining_src_len[id]) {
		// printf("Core %u: Set Final buffer\n", core_id);
		result = doca_sha_task_partial_hash_set_is_final_buffer(sha_partial_hash_task);
		if (result != DOCA_SUCCESS) {
			DOCA_LOG_ERR("Failed to set final buffer for SHA partial hash task: %s",
				     doca_error_get_descr(result));
			return result;
		}
	}

	/* Move the src buffer to the next block and decrease the remaining source length */
	resources->src_buffer[id] += src_len;
	resources->remaining_src_len[id] -= src_len;

	task = doca_sha_task_partial_hash_as_task(sha_partial_hash_task);

	// printf("src_buf %p\n", resources->src_doca_buf[id]);

	/* Submit SHA partial hash task */
	result = doca_task_submit(task);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to submit SHA partial hash task: %s", doca_error_get_descr(result));
		return result;
	}
	// printf("Core %u: submitted partial task\n\n", core_id);

	return DOCA_SUCCESS;
}

/*
 * SHA partial hash task completed callback
 *
 * @sha_partial_hash_task [in]: Completed task
 * @task_user_data [in]: doca_data from the task
 * @ctx_user_data [in]: doca_data from the context
 */
// static void
// sha_partial_hash_completed_callback(struct doca_sha_task_partial_hash *sha_partial_hash_task, union doca_data task_user_data,
// 				    union doca_data ctx_user_data)
// {
// 	struct sha_resources *resources = (struct sha_resources *)ctx_user_data.ptr;
// 	bool last_task_finished = resources->remaining_src_len == 0;

// 	uint64_t id = task_user_data.u64;

// 	/* Assign success to the result */
// 	resources->result[id] = DOCA_SUCCESS;
// 	DOCA_LOG_INFO("SHA hash task has completed successfully");

// 	/* If not last task prepare the next one */
// 	if (!last_task_finished)
// 		resources->result = prepare_and_submit_partial_sha_hash_task_bulk(resources, sha_partial_hash_task, id);

// 	/* Free task and stop context once all tasks are completed or entered error */
// 	if (last_task_finished || resources->result != DOCA_SUCCESS) {
// 		doca_task_free(doca_sha_task_partial_hash_as_task(sha_partial_hash_task));
// 		// (void)doca_ctx_stop(resources->state.ctx);
// 	}
// }

doca_error_t
prepare_and_submit_sha_hash_task_bulk(struct sha_resources *resources, struct doca_sha_task_hash *sha_hash_task, uint32_t id) {
	struct doca_task *task;
	size_t src_len;
	doca_error_t result;
	uint32_t core_id = rte_lcore_id();
	// void *data;
	// doca_buf_get_data(resources->dst_buffers[id], &data);

	// result = doca_buf_set_data(resources->dst_buffers[id], data, KEY_LEN/8 + resources->partial_block_size);
	// if (result != DOCA_SUCCESS) {
	// 	DOCA_LOG_ERR("Core %u: could not set data for final src buf: %s", core_id, doca_error_get_descr(result));
	// 	return result;
	// }

	// printf("src_buf %p\n", resources->src_doca_buf[id]);
	
	// void *data;
	// doca_buf_get_data(resources->dst_buffers[id], &data);
	// printf("Core %u: task: %p, id: %u, src_buf: %p, src_buf_data: %p\n", core_id, sha_hash_task, id, resources->final_doca_src_buf[id], resources->final_src_buf[id]);
	// void *data2;
	// doca_buf_get_data(resources->final_doca_src_buf[id], &data2);
	// memcpy(resources->final_src_buf[id] + (uint8_t)32, data, (size_t)(32));

	// printf("src_buf %p\n", resources->src_doca_buf[id]);
	// doca_buf_set_data(resources->src_doca_buf[id], );

	result = doca_sha_task_hash_set_src(sha_hash_task, resources->src_doca_buf[id]);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Core %u: could not set src buf: %s", core_id, doca_error_get_descr(result));
		return result;
	}

	// printf("src_buf %p\n", resources->src_doca_buf[id]);

	task = doca_sha_task_hash_as_task(sha_hash_task);

	// printf("src_buf %p\n", resources->src_doca_buf[id]);

	result = doca_task_submit(task);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Core %u: Failed to submit SHA hash task: %s", core_id, doca_error_get_descr(result));
		return result;
	}

	// printf("src_buf %p\n", resources->src_doca_buf[id]);
	
	return result;
}

static void
sha_partial_hash_completed_callback(struct doca_sha_task_partial_hash *sha_partial_hash_task, union doca_data task_user_data,
				    union doca_data ctx_user_data)
{
	
	// printf("Sha resources: %p, task: %p, user_ptr: %p\n", ctx_user_data.ptr, sha_partial_hash_task, task_user_data.ptr);
	struct sha_resources *resources = (struct sha_resources *)ctx_user_data.ptr;
	// printf("After resource assignment\n");
	uint64_t id = task_user_data.u64;
	// printf("ID: %lu\n", id);
	bool last_task_finished = resources->remaining_src_len[id] == 0;
	// uint16_t refcount;
	// doca_buf_get_refcount(resources->dst_buffers[id], &refcount);
	// printf("Partial task completion. ID: %lu, Task: %p\n", id, sha_partial_hash_task);

	// uint16_t refcount;
	// doca_buf_get_refcount(resources->dst_buffers[id], &refcount);
	// uint32_t list_len;
	// doca_buf_get_list_len(resources->dst_buffers[id], &list_len);
	// size_t dst_data_len;
	// doca_buf_get_data_len(resources->dst_buffers[id], &dst_data_len);
	// void *head;
	// doca_buf_get_head(resources->dst_buffers[id], &head);
	// size_t dst_len;
	// doca_buf_get_len(resources->dst_buffers[id], &dst_len);

	// printf("--------------------------SUC DST INFO--------------------------\n");
	// printf("refcount: %hu\n", refcount);
	// printf("list_len: %u\n", list_len);
	// printf("data_len: %zu\n", dst_data_len);
	// printf("head: %p", head);
	// printf("bud_len: %zu\n", dst_len);
	// printf("----------------------------------------------------------------\n");

	// uint16_t src_refcount;
	// doca_buf_get_refcount(resources->src_doca_buf[id], &src_refcount);
	// uint32_t src_list_len;
	// doca_buf_get_list_len(resources->src_doca_buf[id], &src_list_len);
	// size_t src_data_len;
	// doca_buf_get_data_len(resources->src_doca_buf[id], &src_data_len);
	// void *src_head;
	// doca_buf_get_head(resources->src_doca_buf[id], &src_head);
	// size_t src_len;
	// doca_buf_get_len(resources->src_doca_buf[id], &src_len);
	// printf("--------------------------SUC SRC INFO--------------------------\n");
	// printf("refcount: %hu\n", src_refcount);
	// printf("list_len: %u\n", src_list_len);
	// printf("data_len: %zu\n", src_data_len);
	// printf("head: %p", src_head);
	// printf("bud_len: %zu\n", src_len);
	// printf("----------------------------------------------------------------\n");

	// struct doca_buf *dst = doca_sha_task_partial_hash_get_dst(sha_partial_hash_task);
	// struct doca_buf *src = doca_sha_task_partial_hash_get_src(sha_partial_hash_task);
	// void *data;
	// doca_buf_get_data(dst, &data);
	// void *data2;
	// doca_buf_get_data(src, &data2);
	// void *data3;
	// doca_buf_get_data(resources->dst_buffers[id], &data3);
	// printf("actual_src: %p, desired_src: %p, actl_src_data: %p, des_src_data: %p, act_dst: %p, des_dst: %p, actl_dst_data: %p, des_dst_data: %p, resources: %p, src_buffers: %p, src_buf_ptr %p\n",
	// 				src, resources->src_doca_buf[id], data2, resources->src_buffer[id], dst, resources->dst_buffers[id], data, data3, resources, resources->src_doca_buf, &resources->src_doca_buf[id]);

	/* Assign success to the result */
	resources->result[id] = DOCA_SUCCESS;
	DOCA_LOG_INFO("SHA partial hash task with id %lu has completed successfully", id);	

	/* If not last task prepare the next one */
	if (!last_task_finished) {
		// printf("Submitting partial hash task fro callback.\n");
		resources->result[id] = prepare_and_submit_partial_sha_hash_task_bulk(resources, sha_partial_hash_task, id);
	}
	/* Free task and stop context once all tasks are completed or entered error */
	// if (resources->result[id] != DOCA_SUCCESS) {
	// 	// doca_task_free(doca_sha_task_partial_hash_as_task(sha_partial_hash_task));
	// 	// (void)doca_ctx_stop(resources->state.ctx);
	// } 

	else if (last_task_finished) {
		// struct doca_buf *dst = doca_sha_task_partial_hash_get_dst(sha_partial_hash_task);
		// struct doca_buf *src = doca_sha_task_partial_hash_get_src(sha_partial_hash_task);
		// void *data;
		// doca_buf_get_data(dst, &data);
		// void *data2;
		// doca_buf_get_data(src, &data2);
		// printf("Submitted final hash task. src %p, src_data %p, dst %p, data %p\n",src, data2, dst, data);
		// printf("Submitting final hash task %lu, src_buf %p\n", id, resources->src_doca_buf[id]);
		resources->result[id] = prepare_and_submit_sha_hash_task_bulk(resources, resources->sha_hash_task[id], id);
		// doca_task_free(doca_sha_task_partial_hash_as_task(sha_partial_hash_task));
	}
}



/*
 * SHA partial hash task error callback
 *
 * @sha_partial_hash_task [in]: Failed task
 * @task_user_data [in]: doca_data from the task
 * @ctx_user_data [in]: doca_data from the context
 */
static void
sha_partial_hash_error_callback(struct doca_sha_task_partial_hash *sha_partial_hash_task, union doca_data task_user_data,
				union doca_data ctx_user_data)
{

	printf("Partial task failure.\n");
	

	// printf("Core %u: src_buf %p, src_buf_void %p, dst_buf %p, task %p, src_len %d\n", core_id, resources->src_doca_buf[id], resources->src_buffer[id], resources->dst_buffers[id], sha_partial_hash_task, src_len);
	struct sha_resources *resources = (struct sha_resources *)ctx_user_data.ptr;
	
	// printf("got resources\n");
	struct doca_task *task = doca_sha_task_partial_hash_as_task(sha_partial_hash_task);
	// printf("cast task\n");

	uint64_t id = task_user_data.u64;
	void *data;
	doca_buf_get_data(resources->src_doca_buf[id], &data);
	void *data2;
	size_t buf_len;
	doca_buf_get_data(resources->dst_buffers[id], &data2);
	doca_buf_get_data_len(resources->src_doca_buf[id], &buf_len);
	printf("Sha resources: %p, task: %p, src_buf %p, src_buf_data %p, dst_buf %p, dst_buf_data %p, src_len %zu\n", ctx_user_data.ptr, sha_partial_hash_task, resources->src_doca_buf[id], data, resources->dst_buffers[id], data2, buf_len);

	
	// printf("got user data\n");

	struct doca_buf *doca_dst_ptr = doca_sha_task_partial_hash_get_dst(sha_partial_hash_task);
	printf("task dst ptr %p\n", doca_dst_ptr);
	struct doca_buf *doca_src_ptr = doca_sha_task_partial_hash_get_src(sha_partial_hash_task);
	printf("task src ptr %p\n", doca_src_ptr);
	uint8_t is_final = doca_sha_task_partial_hash_get_is_final(sha_partial_hash_task);
	printf("task is final %hhu\n", is_final);
	uint8_t has_result = doca_sha_task_partial_hash_get_has_result(sha_partial_hash_task);
	printf("task has_result %hhu\n", has_result);
	uint16_t refcount;
	doca_buf_get_refcount(resources->dst_buffers[id], &refcount);
	uint32_t list_len;
	doca_buf_get_list_len(resources->dst_buffers[id], &list_len);
	size_t dst_data_len;
	doca_buf_get_data_len(resources->dst_buffers[id], &dst_data_len);
	void *head;
	doca_buf_get_head(resources->dst_buffers[id], &head);
	size_t dst_len;
	doca_buf_get_len(resources->dst_buffers[id], &dst_len);

	printf("--------------------------ERR DST INFO--------------------------\n");
	printf("refcount: %hu\n", refcount);
	printf("list_len: %u\n", list_len);
	printf("data_len: %zu\n", dst_data_len);
	printf("head: %p", head);
	printf("bud_len: %zu\n", dst_len);
	printf("----------------------------------------------------------------\n");

	uint16_t src_refcount;
	doca_buf_get_refcount(resources->src_doca_buf[id], &src_refcount);
	uint32_t src_list_len;
	doca_buf_get_list_len(resources->src_doca_buf[id], &src_list_len);
	size_t src_data_len;
	doca_buf_get_data_len(resources->src_doca_buf[id], &src_data_len);
	void *src_head;
	doca_buf_get_head(resources->src_doca_buf[id], &src_head);
	size_t src_len;
	doca_buf_get_len(resources->src_doca_buf[id], &src_len);
	printf("--------------------------ERR SRC INFO--------------------------\n");
	printf("refcount: %hu\n", src_refcount);
	printf("list_len: %u\n", src_list_len);
	printf("data_len: %zu\n", src_data_len);
	printf("head: %p", src_head);
	printf("bud_len: %zu\n", src_len);
	printf("----------------------------------------------------------------\n");

	// printf("Partial task failure. Task: %u\n", id);
	/* Get the result of the task */
	resources->result[id] = doca_task_get_status(task);
	DOCA_LOG_ERR("SHA parial hash task failed: %s", doca_error_get_descr(resources->result[id]));

	/* Free task */
	// doca_task_free(task);
	/* Stop context once error encountered */
	// (void)doca_ctx_stop(resources->state.ctx);
}

static void
sha_hash_completed_callback(struct doca_sha_task_hash *sha_hash_task, union doca_data task_user_data,
				    union doca_data ctx_user_data) {

	struct sha_resources *resources = (struct sha_resources *)ctx_user_data.ptr;
	doca_error_t result;

	uint64_t id = task_user_data.u64;
	// clock_gettime(CLOCK_MONOTONIC, &stop_times[resources->hash_indices[id]]);
	stop_times[resources->hash_indices[id]] = rte_rdtsc();
	uint32_t core_id = rte_lcore_id();

	// printf("Hash task completion. Task: %u", id);
	/* Assign success to the result */
	resources->result[id] = DOCA_SUCCESS;
	// DOCA_LOG_INFO("Core %u: SHA hash task with id %lu has completed successfully\n", core_id, id);

	// void *dst = (void *)resources->dst_buffers[id];
	// dst += 32;

	// result = doca_buf_set_data(resources->dst_buffers[id], dst, KEY_LEN/8 + resources->partial_block_size);
	// if (result != DOCA_SUCCESS) {
	// 	DOCA_LOG_ERR("Core %u: could not reset data for final src buf: %s", core_id, doca_error_get_descr(result));
	// }
	resources->completions++;
	void *data;
	struct doca_buf *dst = doca_sha_task_hash_get_dst(sha_hash_task);
	doca_buf_get_data(dst, &data);
	// printf("Task: %u added to completions. buf %p, data %p, src_buf %p\n", id, dst, data, resources->src_doca_buf[id]);

	// if (resources->result[id] != DOCA_SUCCESS) {
	// 	// doca_task_free(doca_sha_task_partial_hash_as_task(sha_partial_hash_task));
	// 	// (void)doca_ctx_stop(resources->state.ctx);
	// }
	// doca_buf_dec_refcount(resources->src_doca_buf[id], NULL);
}

static void
sha_hash_error_callback(struct doca_sha_task_hash *sha_hash_task, union doca_data task_user_data,
				    union doca_data ctx_user_data) {


	printf("Sha resources: %p, task: %p\n", ctx_user_data, sha_hash_task);					
	struct sha_resources *resources = (struct sha_resources *)ctx_user_data.ptr;
	struct doca_task *task = doca_sha_task_hash_as_task(sha_hash_task);

	uint64_t id = task_user_data.u64;
	uint32_t core_id = rte_lcore_id();

	struct doca_buf *doca_dst_ptr = doca_sha_task_partial_hash_get_dst(sha_hash_task);
	printf("task dst ptr %p\n", doca_dst_ptr);
	struct doca_buf *doca_src_ptr = doca_sha_task_partial_hash_get_src(sha_hash_task);
	printf("task src ptr %p\n", doca_src_ptr);

	uint16_t refcount;
	doca_buf_get_refcount(doca_dst_ptr, &refcount);
	uint32_t list_len;
	doca_buf_get_list_len(doca_dst_ptr, &list_len);
	size_t dst_data_len;
	doca_buf_get_data_len(doca_dst_ptr, &dst_data_len);
	void *head;
	doca_buf_get_head(doca_dst_ptr, &head);
	size_t dst_len;
	doca_buf_get_len(doca_dst_ptr, &dst_len);

	printf("--------------------------ERR DST INFO--------------------------\n");
	printf("refcount: %hu\n", refcount);
	printf("list_len: %u\n", list_len);
	printf("data_len: %zu\n", dst_data_len);
	printf("head: %p", head);
	printf("bud_len: %zu\n", dst_len);
	printf("----------------------------------------------------------------\n");



	uint16_t src_refcount;
	doca_buf_get_refcount(doca_src_ptr, &src_refcount);
	uint32_t src_list_len;
	doca_buf_get_list_len(doca_src_ptr, &src_list_len);
	size_t src_data_len;
	doca_buf_get_data_len(doca_src_ptr, &src_data_len);
	void *src_head;
	doca_buf_get_head(doca_src_ptr, &src_head);
	size_t src_len;
	doca_buf_get_len(doca_src_ptr, &src_len);
	printf("--------------------------ERR SRC INFO--------------------------\n");
	printf("refcount: %hu\n", src_refcount);
	printf("list_len: %u\n", src_list_len);
	printf("data_len: %zu\n", src_data_len);
	printf("head: %p", src_head);
	printf("bud_len: %zu\n", src_len);
	printf("----------------------------------------------------------------\n");

	printf("Hash task failure. Task: %u", id);
	/* Get the result of the task */
	resources->result[id] = doca_task_get_status(task);
	DOCA_LOG_ERR("Core %u: SHA hash task failed: %s",core_id, doca_error_get_descr(resources->result[id]));

	/* Free task */
	// doca_task_free(task);
	/* Stop context once error encountered */
	// (void)doca_ctx_stop(resources->state.ctx);
}

/*
 * Check if given device is capable of executing a SHA partial hash task.
 *
 * @devinfo [in]: The DOCA device information
 * @return: DOCA_SUCCESS if the device supports SHA hash task and DOCA_ERROR otherwise.
 */
static doca_error_t
sha_partial_hash_is_supported(struct doca_devinfo *devinfo)
{
	return doca_sha_cap_task_partial_hash_get_supported(devinfo, SHA_SAMPLE_ALGORITHM);
}

/*
 * Perform a series of SHA partial hash tasks, which includes allocating the task, submitting it with different slices of
 * the source buffer and waiting for its completions
 *
 * @resources [in]: sha_resources struct
 * @dst_doca_buf [out]: Destination buffer
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise.
 */
// static doca_error_t
// perform_partial_sha_hash_task(struct sha_resources *resources, struct doca_buf **dst_doca_buf)
// {
// 	struct program_core_objects *state = &resources->state;
// 	struct doca_sha_task_partial_hash *sha_partial_hash_task = NULL;
// 	struct doca_task *task = NULL;
// 	union doca_data task_user_data = {0};
// 	struct timespec ts = {
// 		.tv_sec = 0,
// 		.tv_nsec = SLEEP_IN_NANOS,
// 	};
// 	doca_error_t result;

// 	/* Construct DOCA buffer for the source SHA buffer */
// 	result = doca_buf_inventory_buf_get_by_data(state->buf_inv, state->src_mmap, resources->src_buffer,
// 						    resources->remaining_src_len, &resources->src_doca_buf);
// 	if (result != DOCA_SUCCESS) {
// 		DOCA_LOG_ERR("Unable to acquire DOCA buffer representing source buffer: %s", doca_error_get_descr(result));
// 		return result;
// 	}

// 	/* Allocate and construct SHA partial hash task. We will reuse this task for submitting all partial hash task */
// 	result = doca_sha_task_partial_hash_alloc_init(resources->sha_ctx, SHA_SAMPLE_ALGORITHM,
// 						       resources->src_doca_buf, *dst_doca_buf, task_user_data,
// 						       &sha_partial_hash_task);
// 	if (result != DOCA_SUCCESS) {
// 		DOCA_LOG_ERR("Failed to allocate SHA partial hash task: %s", doca_error_get_descr(result));
// 		doca_buf_dec_refcount(resources->src_doca_buf, NULL);
// 		return result;
// 	}

// 	task = doca_sha_task_partial_hash_as_task(sha_partial_hash_task);
// 	if (task == NULL) {
// 		DOCA_LOG_ERR("Failed to get SHA partial hash task as DOCA task: %s", doca_error_get_descr(result));
// 		doca_buf_dec_refcount(resources->src_doca_buf, NULL);
// 		return result;
// 	}

// 	result = prepare_and_submit_partial_sha_hash_task(resources, sha_partial_hash_task);
// 	if (result != DOCA_SUCCESS) {
// 		doca_task_free(task);
// 		doca_buf_dec_refcount(resources->src_doca_buf, NULL);
// 		return result;
// 	}

// 	resources->run_main_loop = true;

// 	/* Wait for the task to be completed context to be stopped */
// 	while (resources->run_main_loop) {
// 		if (doca_pe_progress(state->pe) == 0)
// 			nanosleep(&ts, &ts);
// 	}

// 	doca_buf_dec_refcount(resources->src_doca_buf, NULL);

// 	/* Propagate result of task according to the result we update in the callbacks */
// 	DOCA_ERROR_PROPAGATE(result, resources->result);

// 	return result;
// }

doca_error_t
sha_perform_bulk(struct sha_resources *resources, struct doca_buf **doca_dst_buffers, struct rte_mbuf **mbufs, uint32_t quant, 
				struct doca_sha_task_partial_hash **sha_partial_hash_task, int *hash_indices) {
	struct program_core_objects *state = &resources->state;
	// struct doca_sha_task_partial_hash **sha_partial_hash_task = (struct doca_sha_task_partial_hash **)calloc(quant, sizeof(struct doca_sha_task_partial_hash *));
	// struct doca_sha_task_hash **sha_hash_task = (struct doca_sha_hash_task **)calloc(quant, sizeof(struct doca_sha_hash_task *));
	// struct doca_task **task = (struct doca_task **)calloc(quant, sizeof(struct doca_task *));
	// struct doca_task **hash_task = (struct doca_task **)calloc(quant, sizeof(struct doca_task *));
	// union doca_data task_user_data = {0};
	struct timespec ts = {
		.tv_sec = 0,
		.tv_nsec = SLEEP_IN_NANOS,
	};
	doca_error_t result;
	uint32_t core_id = rte_lcore_id();

	for (uint32_t i = 0; i < quant; i++) {
		// struct doca_buf *buf = resources->src_doca_buf[i];
		// printf("src_buf %p\n", buf);
		struct rte_mbuf *rte_buf = mbufs[i];
		void *mbuf_ptr = rte_pktmbuf_mtod(rte_buf, void *);
		// rte_pktmbuf_dump(stdout, rte_buf, rte_pktmbuf_data_len(rte_buf));
		// printf("Core %u: Before mbuf to buf conversion\n", core_id);
		// printf("Core %u: buf_inv: %p, mbuf: %p, doca_buf: %p\n", core_id, state->buf_inv, rte_buf, resources->src_doca_buf[i]);

		// result = doca_dpdk_mempool_mbuf_to_buf(doca_mempool, state->buf_inv, rte_buf, &resources->src_doca_buf[i]);
		// if (result != DOCA_SUCCESS) {
		// 	DOCA_LOG_ERR("Core: %u Failed to copy dpdk mbufs to doca buf: %s", core_id, doca_error_get_descr(result));
		// 	return result;
		// }

		// printf("Core %u: converted mbuf to doca_buf\n", core_id);

		// void *head;
		void *data;

		// doca_buf_get_head(buf, &head);
		doca_buf_get_data(resources->src_doca_buf[i], &data);

		// printf("got data %p\n", data);

		// void *data_mod = data + 32;
		// unsigned char *char_buf = (unsigned char *)data;
		// printf("Core %u buf: ", core_id);
		// for (uint16_t j = 0; j < 90; j++) {
		// 	printf("%02x ", char_buf[j]);
		// 	if ((j + 3)%16==0) printf("\n");
		// }
		// printf("\n");

		// printf("Core %u: Head: %p, data: %p\n", core_id, head, data);

		// resources->src_buffer[i] = data;

		// printf("Core %u: Head: %p, data: %p\n", core_id, head, data);
		// if (data-head >= 32) {
		// 	DOCA_LOG_DBG("Core: %u Was able to prepend data\n", core_id);
		// 	doca_buf_set_data(buf, data - 32, resources->remaining_src_len[i]);
		// 	void *app_data = data - 32;
		// 	memcpy(app_data, resources->ikey, 4 * sizeof(uint64_t));
		// 	resources->src_buffer[i] = app_data;
		// } else {
		// void *app_data = data + 32;
		// memmove(app_data, data, RTE_ETHER_HDR_LEN + RTE_VLAN_HLEN + SWIFT_MSG_LEN);
		// printf("Core %u: ikey: %lx%lx%lx%lx\n", core_id, resources->ikey[0], resources->ikey[1], resources->ikey[2], resources->ikey[3]);
		// memcpy(data, resources->ikey, 4 * sizeof(uint64_t));
		memcpy(data + (uint8_t)32, mbuf_ptr, (size_t)(RTE_ETHER_HDR_LEN + RTE_VLAN_HLEN + SWIFT_HASH_LEN));
		// printf("performed memcyp\n");
		// doca_buf_set_data(buf, data, resources->remaining_src_len[i]);
		// printf("Core %u: Appended key to buf\n", core_id);
		// resources->src_buffer[i] = data;
		// }
		// printf("Core %u: Appended key to buf\n", core_id);

		// unsigned char *char_buf = (unsigned char *)data;
		// printf("Core %u buf: ", core_id);
		// for (uint16_t j = 0; j < 122; j++) {
		// 	printf("%02x ", char_buf[j]);
		// 	if ((j + 3)%16==0) printf("\n");
		// }
		// printf("\n");

		// task_user_data.u64 = i;
		// task_user_data.ptr = sha_hash_task;
		// result = doca_sha_task_partial_hash_alloc_init(resources->sha_ctx, SHA_SAMPLE_ALGORITHM, buf, doca_dst_buffers[i], task_user_data, &sha_partial_hash_task[i]);
		// if (result != DOCA_SUCCESS) {
		// 	DOCA_LOG_ERR("Core: %u Failed to allocate and initialize partial hash task: %s", core_id, doca_error_get_descr(result));
		// 	doca_buf_dec_refcount(buf, NULL);
		// 	return result;
		// }

		// result = doca_sha_task_hash_alloc_init(resources->sha_ctx, SHA_SAMPLE_ALGORITHM, doca_dst_buffers[i], doca_dst_buffers[quant + i], task_user_data, sha_hash_task[i]);
		// if (result != DOCA_SUCCESS) {
		// 	DOCA_LOG_ERR("Core: %u Failed to allocate and initialize hash task: %s", core_id, doca_error_get_descr(result));
		// 	doca_buf_dec_refcount(buf, NULL);
		// 	return result;
		// }

		// task[i] = doca_sha_task_partial_hash_as_task(sha_partial_hash_task[i]);
		// if (task == NULL) {
		// 	DOCA_LOG_ERR("Failed to get SHA partial hash task as DOCA task\n");
		// 	doca_buf_dec_refcount(buf, NULL);
		// 	return result;
		// }

		// hash_task[i] = doca_sha_task_hash_as_task(sha_hash_task[i]);
		// if (task == NULL) {
		// 	DOCA_LOG_ERR("Failed to get SHA hash task as DOCA task\n");
		// 	doca_buf_dec_refcount(buf, NULL);
		// 	return result;
		// }

		// printf("Core %u: partial task: %p\n", core_id, resources->sha_partial_hash_task[i]);
		// clock_gettime(CLOCK_MONOTONIC, &start_times[hash_indices[i]]);
		start_times[resources->hash_indices[i]] = rte_rdtsc();
		result = prepare_and_submit_partial_sha_hash_task_bulk(resources, resources->sha_partial_hash_task[i], i);
		if (result != DOCA_SUCCESS) {
			for (uint32_t i = 0; i < quant; i++) {
				// doca_task_free(task[i]);
				doca_buf_dec_refcount(resources->src_doca_buf[i], NULL);
				return result;
			}
		}
		// printf("Core %u: submission result: %s\n", core_id, doca_error_get_descr(result));
		// doca_pe_progress(state->pe);
	}



	// printf("Waiting for hashes to finish\n");
	resources->run_main_loop = true;

	/* Wait for the task to be completed context to be stopped */
	while (resources->run_main_loop) {
		if (doca_pe_progress(state->pe) == 0)
			// nanosleep(&ts, &ts);
			continue;
		if (resources->completions == quant) {
			resources->run_main_loop = false;
			// resources->completions = 0;
		}
	}

	// printf("Hashes complete\n");
	// for (uint32_t i = 0; i < quant; i++) {
	// 	rte_pktmbuf_free	
	// }
	// free(task);
	// free(sha_partial_hash_task);

	/* Propagate result of task according to the result we update in the callbacks */
	DOCA_ERROR_PROPAGATE(result, resources->result[0]);

	return result;

}
/**
 * Callback triggered whenever SHA context state changes
 *
 * @user_data [in]: User data associated with the SHA context. Will hold struct sha_resources *
 * @ctx [in]: The SHA context that had a state change
 * @prev_state [in]: Previous context state
 * @next_state [in]: Next context state (context is already in this state when the callback is called)
 */
static void
sha_state_changed_callback(const union doca_data user_data, struct doca_ctx *ctx, enum doca_ctx_states prev_state,
			   enum doca_ctx_states next_state)
{
	(void)ctx;
	(void)prev_state;

	struct sha_resources *resources = (struct sha_resources *)user_data.ptr;

	switch (next_state) {
	case DOCA_CTX_STATE_IDLE:
		DOCA_LOG_INFO("SHA context has been stopped");
		/* We can stop the main loop */
		resources->run_main_loop = false;
		break;
	case DOCA_CTX_STATE_STARTING:
		/**
		 * The context is in starting state, this is unexpected for SHA.
		 */
		DOCA_LOG_ERR("SHA context entered into starting state. Unexpected transition");
		break;
	case DOCA_CTX_STATE_RUNNING:
		DOCA_LOG_INFO("SHA context is running");
		break;
	case DOCA_CTX_STATE_STOPPING:
		/**
		 * The context is in stopping due to failure encountered in one of the tasks, nothing to do at this stage.
		 * doca_pe_progress() will cause all tasks to be flushed, and finally transition state to idle
		 */
		DOCA_LOG_ERR("SHA context entered into stopping state. All inflight tasks will be flushed");
		// rte_exit(-1, "EXIT\n");
		break;
	default:
		break;
	}
}


doca_error_t
sha_init(struct program_core_objects *state, struct sha_resources *resources, union doca_data *resource_data, uint8_t *dst_buffers, uint8_t *src_buffers, uint8_t *final_src_buf,
		struct doca_buf **doca_dst_buffers, uint32_t quant, uint64_t *key, struct doca_sha_task_partial_hash **sha_partial_hash_task, 
		struct doca_sha_task_hash **sha_hash_task, struct doca_task **task, struct doca_task **hash_task) {
	doca_error_t result;
	uint32_t min_dst_sha_buffer_size;
	uint32_t max_bufs;
	uint32_t core_id = rte_lcore_id();


	// resources->key = key;
	// resources->src_doca_buf = (struct doca_buf **)malloc(quant * sizeof(struct doca_buf *));
	// resources->src_buffer = (void **)malloc(quant * sizeof(void *));



	// resources->dst_buffers = (struct doca_buf **)malloc(quant * 2 * sizeof(struct doca_buf *));
	// resources->result = (doca_error_t *)malloc(quant * 2 * sizeof(doca_error_t));
	// uint64_t ipad = 0x3636363636363636;
	// uint64_t opad = 0x5c5c5c5c5c5c5c5c;
	// resources->ikey = (uint64_t *)malloc(4 * sizeof(uint64_t));
	// resources->okey = (uint64_t *)malloc(4 * sizeof(uint64_t));

	// resources->completions = 0;
	// // printf("Core %u: Passed resource malloc\n", core_id);

	// for (uint8_t i = 0; i < 4; i++) {
	// 	resources->ikey[i] = resources->key[i] ^ ipad;
	// 	resources->okey[i] = resources->key[i] ^ opad;
	// }

	// sha_partial_hash_task = (struct doca_sha_task_partial_hash **)malloc(quant * sizeof(struct doca_sha_task_partial_hash *));
	// printf("Core %u: patial_hash_task: %p\n", core_id, sha_partial_hash_task);
	// sha_hash_task = (struct doca_sha_task_hash **)malloc(quant * sizeof(struct doca_sha_task_hash *));
	// task = (struct doca_task **)malloc(quant * sizeof(struct doca_task *));
	// hash_task = (struct doca_task **)malloc(quant * sizeof(struct doca_task *));
	// doca_dst_buffers = (struct doca_buf **)malloc(quant * 2 * sizeof(struct doca_buf *));
	union doca_data task_user_data = {0};

	// printf("Core %u: Passed hash task malloc\n", core_id);

	result = open_doca_device_with_capabilities(&sha_partial_hash_is_supported, &state->dev);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to open DOCA device for SHA partial hash task: %s", doca_error_get_descr(result));
		return result;
	}

	result = doca_sha_cap_get_min_dst_buffer_size(doca_dev_as_devinfo(state->dev), SHA_SAMPLE_ALGORITHM, &min_dst_sha_buffer_size);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to get minimum destination buffer size for DOCA SHA: %s", doca_error_get_descr(result));
		sha_cleanup(resources);
		return result;
	}

	dst_buffers = (uint8_t *)malloc(BURST_SIZE * 2 * min_dst_sha_buffer_size);

	result = doca_sha_cap_get_partial_hash_block_size(doca_dev_as_devinfo(state->dev), SHA_SAMPLE_ALGORITHM,
							  &resources->partial_block_size);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to get the partial hash block size for DOCA SHA: %s", doca_error_get_descr(result));
		sha_cleanup(resources);
		return result;
	}

	// resources->remaining_src_len = (size_t *)malloc(quant * sizeof(size_t));
	// for (uint32_t i = 0; i < quant; i++) {
	// 	resources->remaining_src_len[i] = SWIFT_HASH_LEN + RTE_ETHER_HDR_LEN + RTE_VLAN_HLEN + SWIFT_MSG_LEN;
	// }

	// if (resources->remaining_src_len <= resources->partial_block_size) {
	// 	DOCA_LOG_ERR("User data length %lu should be bigger than one partial hash block size %u",
	// 		     resources->remaining_src_len, resources->partial_block_size);
	// 	sha_cleanup(resources);
	// 	return DOCA_ERROR_INVALID_VALUE;
	// }

	max_bufs = 4 * quant;

	result = doca_sha_create(state->dev, &resources->sha_ctx);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to create sha engine: %s", doca_error_get_descr(result));
		sha_cleanup(resources);
		return result;
	}

	state->ctx = doca_sha_as_ctx(resources->sha_ctx);

	result = create_core_objects(state, max_bufs);
	if (result != DOCA_SUCCESS) {
		sha_cleanup(resources);
		return result;
	}

	result = doca_pe_connect_ctx(state->pe, state->ctx);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to connect progress engine to context: %s", doca_error_get_descr(result));
		sha_cleanup(resources);
		return result;
	}

	result = doca_sha_task_partial_hash_set_conf(resources->sha_ctx, sha_partial_hash_completed_callback,
						     sha_partial_hash_error_callback, (uint8_t)ceil(log2((double)(quant))));
	if (result != DOCA_SUCCESS) {
		sha_cleanup(resources);
		return result;
	}

	result = doca_sha_task_hash_set_conf(resources->sha_ctx, sha_hash_completed_callback, 
							sha_hash_error_callback, (uint8_t)ceil(log2((double)(quant))));
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Core: %u could not configure task pool for normal hash\n", core_id);
		sha_cleanup(resources);
		return result;
	}								

	result = doca_ctx_set_state_changed_cb(state->ctx, sha_state_changed_callback);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to set SHA state change callback: %s", doca_error_get_descr(result));
		sha_cleanup(resources);
		return result;
	}

	// src_buffers = (uint8_t *)calloc(quant, 1600);
	if (src_buffers == NULL) {
		DOCA_LOG_ERR("Failed to allocate memory for src buffers\n");
		sha_cleanup(resources);
		return DOCA_ERROR_NO_MEMORY;
	}

	// printf("Core %u: Allocatinf mem for src mmap\n", core_id);
	result = doca_mmap_set_memrange(state->src_mmap, src_buffers, quant * (SWIFT_HASH_LEN + RTE_ETHER_HDR_LEN + RTE_VLAN_HLEN + SWIFT_MSG_LEN) + quant * 64);
	if (result != DOCA_SUCCESS) {
		free(src_buffers);
		sha_cleanup(resources);
		return result;
	}

	result = doca_mmap_set_free_cb(state->src_mmap, &free_cb, NULL);
	if (result != DOCA_SUCCESS) {
		free(src_buffers);
		sha_cleanup(resources);
		return result;
	}

	result = doca_mmap_start(state->src_mmap);
	if (result != DOCA_SUCCESS) {
		free(dst_buffers);
		sha_cleanup(resources);
		return result;
	}

	void *addr;
	size_t len;
	doca_mmap_get_memrange(state->src_mmap, &addr, &len);
	printf("src_mmap: %p, size %zu\n", addr, len);

	// doca_mmap_get_memrange()
	// printf("Core %u: getting doca bufs for src buffers\n", core_id);
	for (uint32_t i = 0; i < quant; i++) {
		result = doca_buf_inventory_buf_get_by_addr(state->buf_inv, state->src_mmap, &src_buffers[i * (SWIFT_HASH_LEN + RTE_ETHER_HDR_LEN + RTE_VLAN_HLEN + SWIFT_MSG_LEN)], (SWIFT_HASH_LEN + RTE_ETHER_HDR_LEN + RTE_VLAN_HLEN + SWIFT_MSG_LEN), &resources->src_doca_buf[i]);
		if (result != DOCA_SUCCESS) {
			DOCA_LOG_ERR("Unable to acquire DOCA buffer representing src buffer: %s", doca_error_get_descr(result));
			sha_cleanup(resources);
			return result;
		}
		void *data;
		doca_buf_get_data(resources->src_doca_buf[i], &data);
		doca_buf_set_data(resources->src_doca_buf[i], data, resources->remaining_src_len[i]);
		resources->src_buffer[i] = data;
		// original_src_buf[i] = resources->src_doca_buf[i];
		memcpy(data, resources->ikey, 4 * sizeof(uint64_t));

		// printf("Core %u: allocated src bufs %u, addr %p, data %p\n", core_id, i, resources->src_doca_buf[i], data);

		result = doca_buf_inventory_buf_get_by_addr(state->buf_inv, state->src_mmap, &src_buffers[(quant * (SWIFT_HASH_LEN + RTE_ETHER_HDR_LEN + RTE_VLAN_HLEN + SWIFT_MSG_LEN)) + i * resources->partial_block_size], resources->partial_block_size, &resources->final_doca_src_buf[i]);
		if (result != DOCA_SUCCESS) {
			DOCA_LOG_ERR("Unable to acquire DOCA buffer representing final_src buffer: %s", doca_error_get_descr(result));
			sha_cleanup(resources);
			return result;
		}

		void *data2;
		doca_buf_get_data(resources->final_doca_src_buf[i], &data2);
		doca_buf_set_data(resources->final_doca_src_buf[i], data2, resources->remaining_src_len[i]);
		// printf("Core %u: allocated final src bufs %u, addr %p,data %p\n", core_id, i, resources->final_doca_src_buf[i], data2);
	}
	// printf("Core %u: Allocatinf bufs for dst bufs\n", core_id);
	// dst_buffers = calloc(quant, 2 * min_dst_sha_buffer_size + KEY_LEN/8);
	if (dst_buffers == NULL) {
		DOCA_LOG_ERR("Failed to allocate memory for dst buffers\n");
		sha_cleanup(resources);
		return DOCA_ERROR_NO_MEMORY;
	}
	// printf("Core %u: Passed dest buffers\n", core_id);
	// printf("Core %u: Allocatinf mem for dst mmap\n", core_id);
	result = doca_mmap_set_memrange(state->dst_mmap, dst_buffers, quant * 2 * min_dst_sha_buffer_size);
	if (result != DOCA_SUCCESS) {
		free(dst_buffers);
		sha_cleanup(resources);
		return result;
	}

	result = doca_mmap_set_free_cb(state->dst_mmap, &free_cb, NULL);
	if (result != DOCA_SUCCESS) {
		free(dst_buffers);
		sha_cleanup(resources);
		return result;
	}

	result = doca_mmap_start(state->dst_mmap);
	if (result != DOCA_SUCCESS) {
		free(dst_buffers);
		sha_cleanup(resources);
		return result;
	}

	void *dst_addr;
	size_t dst_len;
	doca_mmap_get_memrange(state->dst_mmap, &dst_addr, &dst_len);
	printf("dst_mmap: %p, size %zu", dst_addr, dst_len);

	printf("Core %u: Started mmap\n", core_id);
	/* Construct response DOCA buffer for all partial tasks */
	for(uint32_t i = 0; i < quant * 2; i++) {
		uint32_t index;
		size_t dst_buf_len;
		// if (i < quant) {
		// 	index = i * (min_dst_sha_buffer_size + KEY_LEN/8);
		// 	dst_buf_len = min_dst_sha_buffer_size + KEY_LEN/8;
		// } else {
		// 	index = quant * (min_dst_sha_buffer_size + KEY_LEN/8) + (i-quant) * min_dst_sha_buffer_size;
		// 	dst_buf_len = min_dst_sha_buffer_size;
		// }

		index = i * min_dst_sha_buffer_size;
		dst_buf_len = min_dst_sha_buffer_size;

		// printf("Core %u: Index: %u buf_len: %u\n", core_id, index, dst_buf_len);
		result = doca_buf_inventory_buf_get_by_addr(state->buf_inv, state->dst_mmap, &dst_buffers[index], min_dst_sha_buffer_size,
								&resources->dst_buffers[i]);
		if (result != DOCA_SUCCESS) {
			DOCA_LOG_ERR("Unable to acquire DOCA buffer representing destination buffer: %s", doca_error_get_descr(result));
			sha_cleanup(resources);
			return result;
		}
		doca_buf_reset_data_len(resources->dst_buffers[i]);
		
		// printf("Core %u: Got buffer %u\n", core_id, i);
		// resources->dst_buffers[i] = doca_dst_buffers[i];
		// printf("Core %u: assigned to resource buffer\n", core_id);
		// doca_dst_buffers[i] = resources->dst_buffers[i];
		// printf("Core %u: id %u, dst buf %p, buf_copy %p\n", core_id, i, resources->dst_buffers[i], doca_dst_buffers[i]);
	}

	printf("Core %u: Constructed doca buffers\n", core_id);

	for(uint32_t i = 0; i < quant; i++) {
		void *data;
		doca_buf_get_data(resources->final_doca_src_buf[i], &data);
		memcpy(data, resources->okey, 4 * sizeof(uint64_t));
		doca_buf_set_data(resources->final_doca_src_buf[i], data, resources->partial_block_size);
		resources->final_src_buf[i] = data;
	}

	// printf("Core %u: Put okey in dst buffers\n", core_id);

	// resource_data = (union doca_data *)malloc(sizeof(union doca_data));
	resource_data->ptr = resources;
	doca_ctx_set_user_data(state->ctx, *resource_data);

	result = doca_ctx_start(state->ctx);
	if (result != DOCA_SUCCESS) {
		for (uint32_t i = 0; i < quant * 2; i++) {
			doca_buf_dec_refcount(doca_dst_buffers[i], NULL);
		}
		sha_cleanup(resources);
		return result;
	}



	for (uint64_t i = 0; i < quant; i++) {
		task_user_data.u64 = i;

		result = doca_sha_task_hash_alloc_init(resources->sha_ctx, SHA_SAMPLE_ALGORITHM, resources->final_doca_src_buf[i], resources->dst_buffers[quant + i], task_user_data, &(resources->sha_hash_task[i]));
		if (result != DOCA_SUCCESS) {
			DOCA_LOG_ERR("Core: %u Failed to allocate and initialize hash task: %s", core_id, doca_error_get_descr(result));
			// doca_buf_dec_refcount(buf, NULL);
			return result;
		}

		result = doca_sha_task_partial_hash_alloc_init(resources->sha_ctx, SHA_SAMPLE_ALGORITHM, resources->src_doca_buf[i], resources->dst_buffers[i], task_user_data, &(resources->sha_partial_hash_task[i]));
		if (result != DOCA_SUCCESS) {
			DOCA_LOG_ERR("Core: %u Failed to allocate and initialize partial hash task: %s", core_id, doca_error_get_descr(result));
			// doca_buf_dec_refcount(NULL, NULL);
			return result;
		}

		sha_hash_task[i] = resources->sha_hash_task[i];
		sha_partial_hash_task[i] = resources->sha_partial_hash_task[i];
		// result = doca_sha_task_hash_alloc_init(resources->sha_ctx, SHA_SAMPLE_ALGORITHM, resources->final_doca_src_buf[i], resources->dst_buffers[quant + i], task_user_data, &(sha_hash_task[i]));
		// if (result != DOCA_SUCCESS) {
		// 	DOCA_LOG_ERR("Core: %u Failed to allocate and initialize hash task: %s", core_id, doca_error_get_descr(result));
		// 	// doca_buf_dec_refcount(buf, NULL);
		// 	return result;
		// }

		// task[i] = doca_sha_task_partial_hash_as_task(sha_partial_hash_task[i]);
		// if (task == NULL) {
		// 	DOCA_LOG_ERR("Failed to get SHA partial hash task as DOCA task\n");
		// 	// doca_buf_dec_refcount(buf, NULL);
		// 	return result;
		// }

		// hash_task[i] = doca_sha_task_hash_as_task(sha_hash_task[i]);
		// if (task == NULL) {
		// 	DOCA_LOG_ERR("Failed to get SHA hash task as DOCA task\n");
		// 	// doca_buf_dec_refcount(buf, NULL);
		// 	return result;
		// }
	}

	// printf("Core %u: Allocated all tasks\n", core_id);

	// result = doca_dpdk_mempool_create(mbuf_pool, doca_mempool);
	// if (result != DOCA_SUCCESS) {
	// 	DOCA_LOG_ERR("Core %u: Could not create doca_mempool: %s", core_id, doca_error_get_descr(result));
	// 	return result;
	// }
	// result = doca_dpdk_mempool_dev_add(*doca_mempool, state->dev);
	// if (result != DOCA_SUCCESS) {
	// 	DOCA_LOG_ERR("Core %u: Could not add dev to doca_Mempool: %s", core_id, doca_error_get_descr(result));
	// 	return result;
	// }

	// result = doca_dpdk_mempool_start(*doca_mempool);
	// if (result != DOCA_SUCCESS) {
	// 	DOCA_LOG_ERR("Core %u: Could not start doca_Mempool: %s", core_id, doca_error_get_descr(result));
	// 	return result;
	// }

	// printf("Core %u: Started dpdk_mempool\n", core_id);
	return result;
}

