
##############################################################################
# Generate vpp/app/version.h
##############################################################################
add_custom_command(
  OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/vpp/app/version.h
  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
  COMMAND mkdir
  ARGS -p ${CMAKE_CURRENT_BINARY_DIR}/app
  COMMAND vpp/app/version.h.sh
  ARGS ${CMAKE_CURRENT_BINARY_DIR}/app/version.h
  COMMENT "Generating VPP version.h"
)

##############################################################################
# vpp binary
##############################################################################
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
  vnet/main.c
  app/vpe_cli.c
  app/version.c
  oam/oam.c
  oam/oam_api.c
  stats/stats.c
  stats/stat_segment.c
  api/api.c
  api/api_main.c
  api/api_format.c
  api/json_format.c
  api/custom_dump.c
  api/plugin.c
  ${VPP_API_HDRS}
  ${CMAKE_CURRENT_BINARY_DIR}/vpp/app/version.h
)
target_link_libraries(vpp svm vlib vppinfra vlibmemory vnet Threads::Threads dl)
install(TARGETS vpp DESTINATION bin)

##############################################################################
# vppctl binary
##############################################################################
add_executable(vppctl app/vppctl.c)
target_link_libraries(vppctl vppinfra)
install(TARGETS vppctl DESTINATION bin)

##############################################################################
# vpp_get_metrics binary
##############################################################################
add_executable (vpp_get_metrics api/vpp_get_metrics.c ${VPP_API_HDRS})
target_link_libraries (vpp_get_metrics vppinfra svm svmdb)
install(TARGETS vpp_get_metrics DESTINATION bin)

##############################################################################
# stats binaries
##############################################################################
add_executable(summary_stats_client api/summary_stats_client.c)
add_executable(stat_client app/stat_client.c)
target_link_libraries(summary_stats_client vppinfra svm vlibmemoryclient)
target_link_libraries(stat_client vppinfra svm vlibmemoryclient)

##############################################################################
# install
##############################################################################

