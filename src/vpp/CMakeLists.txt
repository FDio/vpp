
set (VPP_SRCS
  vnet/main.c
  api/api_main.c
  api/api_format.c
  api/json_format.c
  api/custom_dump.c
  ../vat/plugin.c
)

set (VPP_API_FILES
  api/vpe.api
  stats/stats.api
  oam/oam.api
)

set(VPP_API_HDRS)
foreach (file ${VPP_API_FILES})
  vpp_api_generate_h (${file})
  list (APPEND VPP_API_HDRS ${CMAKE_CURRENT_BINARY_DIR}/${file}.h)
endforeach()

add_executable (vpp
  ${VPP_SRCS}
  ${VPP_API_HDRS}
)

target_link_libraries (vpp vlib vppinfra vlibmemory vnet Threads::Threads dl)

