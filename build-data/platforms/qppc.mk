# Qemu "p-series" powerpc64 

qppc_arch = powerpc64

qppc_root_packages = vppinfra openssl vlib-no-dpdk vlib-api-no-dpdk vnet-no-dpdk svm \
	vpp-no-dpdk vpp-api-test-no-dpdk

vpp_configure_args_qppc = 
vnet-no-dpdk_configure_args_qppc = # nothing
vlib-no-dpdk_configure_args_qppc = --with-pre-data=128

qppc_march=powerpc64

# native tool chain additions for this platform
qppc_native_tools = vppapigen vppversion

qppc_debug_TAG_CFLAGS = -g -O0 -DCLIB_DEBUG -DCLIB_LOG2_CACHE_LINE_BYTES=6 -maltivec
qppc_debug_TAG_LDFLAGS = -g -O0 -DCLIB_DEBUG -DCLIB_LOG2_CACHE_LINE_BYTES=6 -maltivec

qppc_TAG_CFLAGS = -g -O2 -DCLIB_LOG2_CACHE_LINE_BYTES=6 -maltivec
qppc_TAG_LDFLAGS = -g -O2 -DCLIB_LOG2_CACHE_LINE_BYTES=6 -maltivec


