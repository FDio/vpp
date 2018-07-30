
set(VLIBMEMORY_SRCS
  memory_api.c
  memory_shared.c
  memory_client.c
  vlib_api.c
  vlib_api_cli.c
  socket_api.c
  socket_client.c
  ../vlibapi/api_shared.c
  ../vlibapi/node_serialize.c
)

set (VLIBMEMORY_API_FILES
  memclnt.api
)

set(VLIBMEMORY_API_HDRS)
foreach (file ${VLIBMEMORY_API_FILES})
  vpp_api_generate_h (${file})
  list (APPEND VLIBMEMORY_API_HDRS ${CMAKE_CURRENT_BINARY_DIR}/${file}.h)
endforeach()

add_library (vlibmemory SHARED
  ${VLIBMEMORY_SRCS}
  ${VLIBMEMORY_API_HDRS}
)

target_link_libraries (vlibmemory vppinfra)
install (TARGETS vlibmemory DESTINATION lib)
