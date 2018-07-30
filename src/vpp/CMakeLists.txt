
set (VNET_API_FILES
  api/vpe.api
  stats/stats.api
  oam/oam.api
)

set(API_HDRS)
foreach (file ${VNET_API_FILES})
  set (output_name ${CMAKE_CURRENT_BINARY_DIR}/${file}.h)
  get_filename_component(output_dir ${output_name} DIRECTORY)
  add_custom_command (OUTPUT ${output_name}
    COMMAND mkdir -p ${output_dir}
    COMMAND ${CMAKE_SOURCE_DIR}/tools/vppapigen/vppapigen
    ARGS --includedir ${CMAKE_SOURCE_DIR} --input ${CMAKE_CURRENT_SOURCE_DIR}/${file} --output ${output_name}
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/${file}
    COMMENT "Compiling ${output_name} from ${file}"
  )
  list (APPEND API_HDRS ${output_name})
endforeach()

add_executable (vpp
  vnet/main.c
  api/api_main.c
  api/api_format.c
  api/json_format.c
  api/custom_dump.c
  ../vat/plugin.c
)
target_link_libraries (vpp vlib vppinfra vlibmemory vnet Threads::Threads dl)
target_sources (vpp PUBLIC ${API_HDRS})

