# Qemu "p-series" powerpc64 

qppc_os = linux-gnu

qppc_cross_ldflags = \
    -Wl,--dynamic-linker=/lib64/ld64.so.1

qppc_arch = powerpc

qppc_root_packages = vppinfra vlib vlib-api vnet svm \
	vpp vpp-api-test

vnet_configure_args_qppc = \
	--without-libssl

vpp_configure_args_qppc = \
	--without-libssl

vlib_configure_args_qppc = --with-pre-data=128

qppc_march=powerpc64

# native tool chain additions for this platform
qppc_native_tools = vppapigen

qppc_uses_dpdk = no

qppc_debug_TAG_CFLAGS = -m64 -g -O0 -DCLIB_DEBUG -DCLIB_LOG2_CACHE_LINE_BYTES=6 -maltivec
qppc_debug_TAG_LDFLAGS = -m64 -g -O0 -DCLIB_DEBUG -DCLIB_LOG2_CACHE_LINE_BYTES=6 -maltivec

qppc_TAG_CFLAGS = -m64 -g -O2 -DCLIB_LOG2_CACHE_LINE_BYTES=6 -maltivec
qppc_TAG_LDFLAGS = -m64 -g -O2 -DCLIB_LOG2_CACHE_LINE_BYTES=6 -maltivec


