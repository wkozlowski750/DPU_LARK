/*
 * Copyright (c) 2022-2023 NVIDIA CORPORATION & AFFILIATES, ALL RIGHTS RESERVED.
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

#include <stdlib.h>
#include <string.h>

#include <doca_argp.h>
#include <doca_error.h>
#include <doca_dev.h>
#include <doca_sha.h>
#include <doca_log.h>

#include <utils.h>

DOCA_LOG_REGISTER(SHA_CREATE::MAIN);

#define MAX_USER_DATA_LEN 1024			/* max user data length */
#define MAX_DATA_LEN (MAX_USER_DATA_LEN + 1)	/* max data length */
#define MIN_USER_DATA_LEN 1			/* min user data length */

/* Sample's Logic */
doca_error_t sha_create(char *src_buffer, int bytes);

int bytes;
// char *data;

struct argp_config {
	void *data;
	void *bytes;
};

/*
 * ARGP Callback - Handle user data parameter
 *
 * @param [in]: Input parameter
 * @config [in/out]: Program configuration context
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t 
data_callback(void *param, void *config)
{
	struct argp_config *arg_config = (struct argp_config *)config;
	char *data = (char *)arg_config->data;
	char *input_data = (char *)param;
	int len;

	len = strnlen(input_data, MAX_DATA_LEN);
	if (len == MAX_DATA_LEN || len < MIN_USER_DATA_LEN) {
		DOCA_LOG_ERR("Invalid data length, should be between %d and %d", MIN_USER_DATA_LEN, MAX_USER_DATA_LEN);
		return DOCA_ERROR_INVALID_VALUE;
	}
	strcpy(data, input_data);
	return DOCA_SUCCESS;
}

static doca_error_t
bytes_callback(void *param, void *config) {
	struct argp_config *arg_config = (struct argp_config *)config;
	int *bytes = arg_config->bytes;
	int *input_bytes = (int *)param;

	*bytes = *input_bytes;
	return DOCA_SUCCESS;
}

/*
 * Register the command line parameters for the sample.
 *
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t
register_sha_params(void)
{
	doca_error_t result;
	struct doca_argp_param *data_param;
	struct doca_argp_param *bytes_param;

	result = doca_argp_param_create(&data_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create ARGP param: %s", doca_error_get_descr(result));
		return result;
	}
	doca_argp_param_set_short_name(data_param, "d");
	doca_argp_param_set_long_name(data_param, "data");
	doca_argp_param_set_description(data_param, "user data");
	doca_argp_param_set_callback(data_param, data_callback);
	doca_argp_param_set_type(data_param, DOCA_ARGP_TYPE_STRING);
	result = doca_argp_register_param(data_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to register program param: %s", doca_error_get_descr(result));
		return result;
	}

	result = doca_argp_param_create(&bytes_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create ARGP param: %s", doca_error_get_descr(result));
		return result;
	}
	doca_argp_param_set_short_name(bytes_param, "b");
	doca_argp_param_set_long_name(bytes_param, "bytes");
	doca_argp_param_set_description(bytes_param, "number of bytes");
	doca_argp_param_set_callback(bytes_param, bytes_callback);
	doca_argp_param_set_type(bytes_param, DOCA_ARGP_TYPE_INT);
	result = doca_argp_register_param(bytes_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to register program param: %s", doca_error_get_descr(result));
		return result;
	}
	return DOCA_SUCCESS;
}

/*
 * Sample main function
 *
 * @argc [in]: command line arguments size
 * @argv [in]: array of command line arguments
 * @return: EXIT_SUCCESS on success and EXIT_FAILURE otherwise
 */

// doca_argp_dpdk_cb_t dpdk_callback(int argc, char **argv) {

// 	if (argc < 2) {
// 		printf("Need bytes avlue\n");
// 		return DOCA_ERROR_INITIALIZATION;
// 	}

// 	bytes = atoi(argv[1]);

// 	return DOCA_SUCCESS;
// }

int
main(int argc, char **argv)
{
	doca_error_t result;
	struct doca_log_backend *sdk_log;
	int exit_status = EXIT_FAILURE;
	char data[MAX_DATA_LEN];
	char *my_data;

	// strcpy(data, "1234567890abcdef");

	struct argp_config config;
	config.bytes = &bytes;
	config.data = data;

	/* Register a logger backend */
	result = doca_log_backend_create_standard();
	if (result != DOCA_SUCCESS)
		goto sample_exit;

	/* Register a logger backend for internal SDK errors and warnings */
	result = doca_log_backend_create_with_file_sdk(stderr, &sdk_log);
	if (result != DOCA_SUCCESS)
		goto sample_exit;
	result = doca_log_backend_set_sdk_level(sdk_log, DOCA_LOG_LEVEL_WARNING);
	if (result != DOCA_SUCCESS)
		goto sample_exit;

	DOCA_LOG_INFO("Starting the sample");

	

	result = doca_argp_init("doca_sha_create", &config);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to init ARGP resources: %s", doca_error_get_descr(result));
		goto sample_exit;
	}

	// doca_argp_set_dpdk_program(dpdk_callback);
	// result = doca_argp_init("doca_sha_create", &data);
	// if (result != DOCA_SUCCESS) {
	// 	DOCA_LOG_ERR("Failed to init ARGP resources: %s", doca_error_get_descr(result));
	// 	goto sample_exit;
	// }

	result = register_sha_params();
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to register ARGP params: %s", doca_error_get_descr(result));
		goto argp_cleanup;
	}

	result = doca_argp_start(argc, argv);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to parse sample input: %s", doca_error_get_descr(result));
		goto argp_cleanup;
	}

	// data = (char *)malloc(bytes * sizeof(char));
	my_data = (char *)malloc((bytes + 1) * sizeof(char));
	my_data[bytes] = '\0';
	memset(my_data, 'A', bytes);


	result = sha_create(my_data, bytes);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("sha_create() encountered an error: %s", doca_error_get_descr(result));
		goto argp_cleanup;
	}

	exit_status = EXIT_SUCCESS;

argp_cleanup:
	doca_argp_destroy();
sample_exit:
	if (exit_status == EXIT_SUCCESS)
		DOCA_LOG_INFO("Sample finished successfully");
	else
		DOCA_LOG_INFO("Sample finished with errors");
	return exit_status;
}
