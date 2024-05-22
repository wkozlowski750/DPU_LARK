# project('dpdk_ra_verif', 'c',
#         version : '0.1',
#         default_options : ['warning_level=3'])

# src_files = ['main.c', 'ra_ver_commands.c', 'ra_ver_config.c', 'ra_ver.c', 'ra_sha.c', '/opt/mellanox/doca/samples/common.c', '/opt/mellanox/doca/applications/common/src/utils.c']

# # Dependencies
# deps = []
# deps += dependency('libdpdk', fallback: ['libdpdk', 'dpdk_dep'])
# deps += dependency('doca')
# deps += dependency('openssl')

# # Add directory for library search

# # doca_lib = '/opt/mellanox/doca/lib/aarch64-linux-gnu'
# dpdk_lib = '/opt/mellanox/dpdk/lib/aarch64-linux-gnu'
# # sha_lib = '/opt/mellanox/doca/infrastructure/doca_sha_offload_engine'

# # Add directory for header search
# include_dirs = []
# # include_dirs += include_directories('/opt/mellanox/doca/include')
# include_dirs += include_directories('/opt/mellanox/doca')
# # include_dirs += include_directories('/opt/mellanox/dpdk/include/dpdk')
# # include_dirs += include_directories('/opt/mellanox/dpdk/include/aarch64-linux-gnu/dpdk')
# include_dirs += include_directories('/opt/mellanox/doca/samples')
# include_dirs += include_directories('/opt/mellanox/doca/applications/common/src')

# add_project_arguments('-D DOCA_ALLOW_EXPERIMENTAL_API', language: ['c', 'cpp'])

# executable('dpdk_ra_verif', src_files,
#            dependencies : deps,
#            include_directories : include_dirs,
#            link_args : ['-L' + dpdk_lib],
#            install : false)


#
# Copyright (c) 2022 NVIDIA CORPORATION & AFFILIATES, ALL RIGHTS RESERVED.
#
# This software product is a proprietary product of NVIDIA CORPORATION &
# AFFILIATES (the "Company") and all right, title, and interest in and to the
# software product, including all associated intellectual property rights, are
# and shall remain exclusively with the Company.
#
# This software product is governed by the End User License Agreement
# provided with the software product.
#

project('DOCA_SAMPLE', 'C', 'CPP',
	# Get version number from file.
	version: run_command(find_program('cat'),
		files('/opt/mellanox/doca/applications/VERSION'), check: true).stdout().strip(),
	license: 'Proprietary',
	default_options: ['buildtype=debug'],
	meson_version: '>= 0.61.2'
)

SAMPLE_NAME = 'ra_verifier'

cc = meson.get_compiler('c')
# Comment this line to restore warnings of experimental DOCA features
add_project_arguments('-D DOCA_ALLOW_EXPERIMENTAL_API', language: ['c', 'cpp'])

sample_dependencies = []
# Required for all DOCA programs
sample_dependencies += dependency('doca')
sample_dependencies += dependency('libdpdk')
sample_dependencies += dependency('openssl')
sample_dependencies += cc.find_library('m')

sample_srcs = [
	# The sample itself
	'main.c',
	# Main function for the sample's executable
	'ra_sha.c',
	# Common code for all DOCA samples
        'ra_ver_commands.c',
        'ra_ver_config.c',
        'ra_ver.c',
	'/opt/mellanox/doca/samples/common.c',
	# Common code for all DOCA applications
	'/opt/mellanox/doca/applications/common/src/utils.c'
]

sample_inc_dirs  = []
# Common DOCA logic (samples)
sample_inc_dirs += include_directories('/opt/mellanox/doca/samples')
# Common DOCA logic
sample_inc_dirs += include_directories('/opt/mellanox/doca')
# Common DOCA logic (applications)
sample_inc_dirs += include_directories('/opt/mellanox/doca/applications/common/src')

executable('doca_' + SAMPLE_NAME, sample_srcs,
	c_args : ['-Wno-missing-braces', '-lm'],
	dependencies : sample_dependencies,
	include_directories: sample_inc_dirs,
	install: false)
