

set (PRE_DATA_SIZE 128)

configure_file (
    ${CMAKE_SOURCE_DIR}/vlib/config.h.in
    ${CMAKE_BINARY_DIR}/vlib/config.h
)


set(VLIB_SRCS
  buffer.c
  buffer_serialize.c
  cli.c
  counter.c
  error.c
  format.c
  i2c.c
  init.c
  linux/pci.c
  linux/physmem.c
  linux/vfio.c
  log.c
  main.c
  mc.c
  node.c
  node_cli.c
  node_format.c
  pci/pci.c
  threads.c
  threads_cli.c
  trace.c
  unix/cj.c
  unix/cli.c
  unix/input.c
  unix/main.c
  unix/mc_socket.c
  unix/plugin.c
  unix/util.c
)

add_library(vlib SHARED ${VLIB_SRCS})
target_link_libraries(vlib vppinfra svm)
install(TARGETS vlib DESTINATION lib)

