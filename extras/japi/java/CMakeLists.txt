# Copyright (c) 2018 Cisco and/or its affiliates.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

include (UseJava)

find_path(VNET_INCLUDE_DIR NAMES vnet/api_errno.h)
find_library(VPPINFRA_DIR NAMES vppinfra REQUIRED)
find_library(VLIBMEMORYCLIENT_DIR NAMES vlibmemoryclient REQUIRED)
find_library(SVM_DIR NAMES svm REQUIRED)

include_directories(${VNET_INCLUDE_DIR}
                    ${VNET_INCLUDE_DIR}/vpp_plugins
                    ${Java_INCLUDE_DIRS}
                    ${CMAKE_CURRENT_SOURCE_DIR}
                    ${CMAKE_BINARY_DIR/../vpp/plugins})
add_compile_options(-Wall)
############# Common package ##################
add_library(jvpp_common SHARED jvpp-common/jvpp_common.c)
set_target_properties(jvpp_common PROPERTIES SOVERSION ${JAPI_LIB_VERSION})
target_link_libraries(jvpp_common ${VPPINFRA_DIR})
install(TARGETS jvpp_common DESTINATION lib COMPONENT libjvpp_common)
install(FILES jvpp-common/jvpp_common.h DESTINATION include/japi/)

set(JVPP_LIBS jvpp_common ${VPPINFRA_DIR} ${VLIBMEMORYCLIENT_DIR} ${SVM_DIR}
  Threads::Threads m rt)

############# Registry package ##################
set(PACKAGE_DIR_JVPP_REGISTRY io/fd/vpp/jvpp)
unset(files)
FILE(GLOB files RELATIVE
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}/jvpp-registry/${PACKAGE_DIR_JVPP_REGISTRY}/*.java
  ${CMAKE_CURRENT_SOURCE_DIR}/jvpp-registry/${PACKAGE_DIR_JVPP_REGISTRY}/*/*.java
)

add_custom_target (jvpp-registry-classes)
add_custom_command (TARGET jvpp-registry-classes
  PRE_BUILD
  COMMAND mkdir -p ${CMAKE_CURRENT_BINARY_DIR}/jvpp-registry
  COMMAND ${Java_JAVAC_EXECUTABLE}
  ARGS -d ${CMAKE_CURRENT_BINARY_DIR}/jvpp-registry -h jvpp-registry ${files}
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)

add_library(jvpp_registry SHARED jvpp-registry/jvpp_registry.c)
target_link_libraries(jvpp_registry ${JVPP_LIBS})
include_directories(jvpp-registry)
add_dependencies(jvpp_registry jvpp_common jvpp-registry-classes)
add_jar(jvpp-registry ${files} VERSION ${JAPI_LIB_VERSION})
install_jar(jvpp-registry DESTINATION share/java/)

############## Functions #########################
function(japigen name)
  if(NOT VPP_JAVA_APIGEN)
    set(VPP_JAVA_APIGEN ${CMAKE_CURRENT_SOURCE_DIR}/jvpp/gen/jvpp_gen.py)
  endif()
  add_custom_target(japigen-${name} DEPENDS jvpp-registry)
  add_custom_command(TARGET japigen-${name}
    POST_BUILD
    COMMAND mkdir -p jvpp-${name}/target
    COMMAND mkdir -p ${CMAKE_CURRENT_BINARY_DIR}/jvpp-${name}
    COMMAND ${VPP_JAVA_APIGEN}
      ARGS --plugin_name ${name} --root_dir jvpp-${name} -i ${ARGN}
    COMMAND find jvpp-${name} -name \*.java > jvpp-${name}/jvpp-${name}.files
    COMMAND ${Java_JAVAC_EXECUTABLE}
      ARGS -cp ${CMAKE_CURRENT_BINARY_DIR}/jvpp-registry-${JAPI_LIB_VERSION}.jar -d
      ${CMAKE_CURRENT_SOURCE_DIR}/jvpp-${name}/target -h jvpp-${name}
      @jvpp-${name}/jvpp-${name}.files
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    COMMENT "JAVA_API_GEN ${name}"
  )
endfunction()

function(jargen name)
  add_custom_command(TARGET jvpp_${name}
    POST_BUILD
    COMMAND cp ${CMAKE_BINARY_DIR}/lib/libjvpp_${name}.so jvpp-${name}/target
    COMMAND ${Java_JAR_EXECUTABLE} ARGS cf
      ${CMAKE_CURRENT_BINARY_DIR}/jvpp-${name}-${JAPI_LIB_VERSION}.jar
      -C jvpp-${name}/target . #@jvpp-${name}/jvpp-${name}.files
    COMMAND rm ARGS -rf jvpp-${name}/target jvpp-${name}/jvpp-${name}.files
      jvpp-${name}/jvpp_${name}_gen.h jvpp-${name}/io_fd_vpp_jvpp_*.h
      jvpp-registry/io_fd_vpp_jvpp_*.h
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    COMMENT "JAR_GEN ${name}"
  )
  install(
    FILES ${CMAKE_CURRENT_BINARY_DIR}/jvpp-${name}-${JAPI_LIB_VERSION}.jar
    DESTINATION share/java
  )
endfunction()

function(java_api_binding name src_file)
  japigen (${name} ${ARGN})
  add_library(jvpp_${name} SHARED jvpp-${name}/jvpp_${src_file}.c)
  target_link_libraries(jvpp_${name} ${JVPP_LIBS})
  include_directories(jvpp-${name})
  add_dependencies(jvpp_${name} jvpp_common jvpp_registry japigen-${name})
  jargen (${name})
endfunction()

############ Core Package #######################
unset (files)
unset (JSON_API_PATH)
set (JSON_API_PATH ${CMAKE_BINARY_DIR}/../vpp)

FILE(GLOB_RECURSE files RELATIVE
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${JSON_API_PATH}/vnet/*.api.json
  ${JSON_API_PATH}/vpp/*.api.json
)

java_api_binding (core core ${files})

############ Plugin Packages #######################
unset (ACL_JSON_FILE)
unset (NAT_JSON_FILE)
unset (NSH_JSON_FILE)
unset (GTPU_JSON_FILE)
unset (PPPOE_JSON_FILE)
unset (IOAM_TRACE_JSON_FILE)
unset (IOAM_POT_JSON_FILE)
unset (IOAM_EXPORT_JSON_FILE)

set (plugin_path ${CMAKE_BINARY_DIR}/../vpp/plugins)

find_file(ACL_JSON_FILE NAMES acl.api.json HINTS ${plugin_path} PATH_SUFFIXES acl)
find_file(NAT_JSON_FILE NAMES nat.api.json HINTS ${plugin_path} PATH_SUFFIXES nat)
find_file(NSH_JSON_FILE NAMES nsh.api.json HINTS ${plugin_path} PATH_SUFFIXES nsh)
find_file(GTPU_JSON_FILE NAMES gtpu.api.json HINTS ${plugin_path} PATH_SUFFIXES gtpu)
find_file(PPPOE_JSON_FILE NAMES pppoe.api.json HINTS ${plugin_path} PATH_SUFFIXES pppoe)
find_file(IOAM_TRACE_JSON_FILE NAMES trace.api.json HINTS ${plugin_path} PATH_SUFFIXES ioam/lib-trace)
find_file(IOAM_POT_JSON_FILE NAMES pot.api.json HINTS ${plugin_path} PATH_SUFFIXES ioam/lib-pot)
find_file(IOAM_EXPORT_JSON_FILE NAMES ioam_export.api.json HINTS ${plugin_path} PATH_SUFFIXES ioam/export)

if(ACL_JSON_FILE)
  java_api_binding (acl acl ${ACL_JSON_FILE})
endif()

if(NAT_JSON_FILE)
  java_api_binding (nat nat ${NAT_JSON_FILE})
endif()

if(NSH_JSON_FILE)
  java_api_binding (nsh nsh ${NSH_JSON_FILE})
endif()

if(GTPU_JSON_FILE)
  java_api_binding (gtpu gtpu ${GTPU_JSON_FILE})
endif()

if(PPPOE_JSON_FILE)
  java_api_binding (pppoe pppoe ${PPPOE_JSON_FILE})
endif()

if(IOAM_TRACE_JSON_FILE)
  java_api_binding (ioamtrace ioam_trace ${IOAM_TRACE_JSON_FILE})
endif()

if(IOAM_POT_JSON_FILE)
  java_api_binding (ioampot ioam_pot ${IOAM_POT_JSON_FILE})
endif()

if(IOAM_EXPORT_JSON_FILE)
  java_api_binding (ioamexport ioam_export ${IOAM_EXPORT_JSON_FILE})
endif()
