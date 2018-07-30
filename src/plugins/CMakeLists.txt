
include_directories (
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_BINARY_DIR}
)

macro(add_vpp_plugin plugin_name)
  set(api_headers)
  foreach(f ${ARGN})
     if(${f} MATCHES ".*\.api$")
       message(STATUS "${f} is API file")
       vpp_api_generate_h (${f})
       list(APPEND api_headers ${f}.h)
     endif()
  endforeach()
  add_library(${plugin_name} SHARED ${ARGN} ${api_headers})
  add_dependencies(${plugin_name} vpp_version_h)
  set_target_properties(${plugin_name} PROPERTIES PREFIX "")
  install(TARGETS ${plugin_name} DESTINATION lib/vpp_plugins)
endmacro()

##############################################################################
# find and add all plugin subdirs
############################################################################
FILE(GLOB files RELATIVE
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}/*/CMakeLists.txt
)
foreach (f ${files})
  get_filename_component(dir ${f} DIRECTORY)
  add_subdirectory(${dir})
endforeach()
