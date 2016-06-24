# Override OS so we can use the sdk toolchain instead of building one
thunder_os = thunderx-linux-gnu

# Override CROSS_LDFLAGS so we can use 
# /lib/aarch64-linux-gnu/ld-linux-aarch64.so.1 instead of building glibc
thunder_cross_ldflags = \
    -Wl,--dynamic-linker=/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1	\
    -Wl,-rpath -Wl,$(lots_of_slashes_to_pad_names)$(TOOL_INSTALL_LIB_DIR)

thunder_arch = aarch64
# suppress -march=foo, the cross compiler doesn't understand it
thunder_march = " "

thunder_root_packages = vppinfra vlib-cavium-dpdk vnet-cavium-dpdk cavium-dpdk \
	vpp-cavium-dpdk vpp-api-test-cavium-dpdk

vnet-cavium-dpdk_configure_args_thunder = \
	--with-dpdk --without-ipsec --without-ipv6sr

vpp-cavium-dpdk_configure_args_thunder = \
	--with-dpdk --without-ipsec --without-ipv6sr

cavium-dpdk_configure_args_thunder = --with-headroom=256

vlib-cavium-dpdk_configure_args_thunder = --with-pre-data=128

# native tool chain additions for this platform
thunder_native_tools = vppapigen 

thunder_debug_TAG_CFLAGS = -g -O0 -DCLIB_DEBUG 
thunder_debug_TAG_LDFLAGS = -g -O0 -DCLIB_DEBUG

thunder_TAG_CFLAGS = -g -O2
thunder_TAG_LDFLAGS = -g -O2


