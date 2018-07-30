
include_directories (
  /usr/include/dpdk
)
##############################################################################
# svm shared library
##############################################################################
add_vpp_plugin(dpdk_plugin
  buffer.c
  main.c
  thread.c
  api/dpdk_api.c
  api/dpdk_test.c
  device/cli.c
  device/common.c
  device/device.c
  device/flow.c
  device/format.c
  device/init.c
  device/node.c
  hqos/hqos.c
  ipsec/cli.c
  ipsec/crypto_node.c
  ipsec/esp_decrypt.c
  ipsec/esp_encrypt.c
  ipsec/ipsec.c
  api/dpdk.api
)

set(DPDK_LINK_FLAGS "-Wl,--whole-archive,-l:libdpdk.a,--no-whole-archive")
set(DPDK_LINK_FLAGS "${DPDK_LINK_FLAGS} -Wl,--exclude-libs,libIPSec_MB.a,-l:libIPSec_MB.a")
set(DPDK_LINK_FLAGS "${DPDK_LINK_FLAGS} -Wl,-lnuma")

message(STATUS "DPDK_LINK_FLAGS: ${DPDK_LINK_FLAGS}")

set_target_properties(dpdk_plugin PROPERTIES LINK_FLAGS "${DPDK_LINK_FLAGS}")

