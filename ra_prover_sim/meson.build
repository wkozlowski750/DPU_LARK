project('dpdk_ra_verif', 'c',
        version : '0.1',
        default_options : ['warning_level=3'])

src_files = ['main.c', 'ra_prover.c']

# Dependencies
deps = []
deps += dependency('libdpdk', fallback: ['libdpdk', 'dpdk_dep'])
deps += dependency('doca', fallback: ['doca', 'doca_dep'])
deps += dependency('openssl')

# Add directory for library search

doca_lib = '/opt/mellanox/doca/lib/aarch64-linux-gnu'
dpdk_lib = '/opt/mellanox/dpdk/lib/aarch64-linux-gnu'

# Add directory for header search
include_dirs = []
include_dirs += include_directories('/opt/mellanox/doca/include')
include_dirs += include_directories('/opt/mellanox/dpdk/include/dpdk')
include_dirs += include_directories('/opt/mellanox/dpdk/include/aarch64-linux-gnu/dpdk')

executable('dpdk_ra_verif', src_files,
           dependencies : deps,
           include_directories : include_dirs,
           link_args : ['-L' + doca_lib, '-L' + dpdk_lib],
           install : true)
