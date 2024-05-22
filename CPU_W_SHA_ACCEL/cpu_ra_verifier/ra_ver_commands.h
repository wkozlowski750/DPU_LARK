/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 */

#ifndef _RA_VER_COMMANDS_H_
#define _RA_VER_COMMANDS_H_
#pragma once

extern cmdline_parse_ctx_t main_ctx[];
extern bool quit;

void append_time_to_csv(const char* filename, long long time_ns);

long long calculate_elapsed_time_ns(struct timespec start, struct timespec end);

#endif /* _RA_VER_COMMANDS_H_ */
