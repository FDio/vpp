
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

# api_files (${VLIBMEMORY_API_FILES})

set (file memclnt.api)
add_custom_command (OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/${file}.h
  COMMAND ${CMAKE_SOURCE_DIR}/tools/vppapigen/vppapigen
  ARGS --includedir ${CMAKE_SOURCE_DIR} --input ${CMAKE_CURRENT_SOURCE_DIR}/${file} --output ${CMAKE_CURRENT_BINARY_DIR}/${file}.h
  DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/${file}
  COMMENT "Compiling ${output_name} from ${file}"
)

add_library (vlibmemory SHARED
  ${VLIBMEMORY_SRCS}
  ${VLIBMEMORY_API_FILES}
)

target_link_libraries (vlibmemory vppinfra)
target_sources (vlibmemory PUBLIC ${CMAKE_CURRENT_BINARY_DIR}/memclnt.api.h)
install (TARGETS vlibmemory DESTINATION lib)

