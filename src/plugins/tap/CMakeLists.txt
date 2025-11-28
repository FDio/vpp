# SPDX-License-Identifier: Apache-2.0

add_compile_options(-Wmissing-prototypes)
add_compile_options(-Wmissing-declarations)

add_vpp_plugin(tap
  SOURCES
    plugin.c
    cli.c
    tap.c
    tap_pre_input.c
    format.c
    tx_node.c
    rx_node.c
    tapv2_api.c

  MULTIARCH_SOURCES
    rx_node.c
    tx_node.c

  INSTALL_HEADERS
    tap.h

  API_FILES
    tapv2.api

  SUPPORTED_OS_LIST Linux
)
