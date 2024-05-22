# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2017 Intel Corporation

# meson file, for building this example as part of a main DPDK build.
#
# To build this example as a standalone application with an already-installed
# DPDK instance, use 'make'

# includes += include_directories('/usr/local/include')
# allow_experimental_apis = true
# sources = files(
#         'main.c',
#         'ra_ver_commands.c',
#         'ra_ver.c',
#         'ra_ver_config.c',
# )

project('CPU_VERIFIER', 'C', 'CPP',
	# Get version number from file.
	# version: run_command(find_program('cat'),
	# 	files('/opt/mellanox/doca/applications/VERSION'), check: true).stdout().strip(),
	# license: 'Proprietary',
	default_options: ['buildtype=debug'],
	meson_version: '>= 0.61.2'
)

SAMPLE_NAME = 'ra_verifier'

cc = meson.get_compiler('c')
# Comment this line to restore warnings of experimental DOCA features
# add_project_arguments('-D DOCA_ALLOW_EXPERIMENTAL_API', language: ['c', 'cpp'])

sample_dependencies = []
# Required for all DOCA programs
# sample_dependencies += dependency('doca')
sample_dependencies += dependency('libdpdk')
sample_dependencies += dependency('openssl')
sample_dependencies += cc.find_library('m')

sample_srcs = [
        'main.c',
        'ra_ver_commands.c',
        'ra_ver.c',
        'ra_ver_config.c'
]

sample_inc_dirs  = []
# Common DOCA logic (samples)
# sample_inc_dirs += include_directories('/opt/mellanox/doca/samples')
# Common DOCA logic
# sample_inc_dirs += include_directories('/opt/mellanox/doca')
# Common DOCA logic (applications)
# sample_inc_dirs += include_directories('/opt/mellanox/doca/applications/common/src')

executable('cpu_' + SAMPLE_NAME, sample_srcs,
	c_args : ['-Wno-missing-braces'],
	dependencies : sample_dependencies,
	include_directories: sample_inc_dirs,
	install: false)