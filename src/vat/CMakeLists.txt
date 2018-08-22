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

##############################################################################
# vat plugin shared library
##############################################################################
add_library(vatplugin SHARED plugin_api.c)
target_link_libraries(vatplugin vppinfra)
add_dependencies (vatplugin vppinfra)
install(TARGETS vatplugin DESTINATION lib)

##############################################################################
# vpp_api_test
##############################################################################
add_executable (vpp_api_test
  api_format.c
  main.c
  plugin.c
  json_format.c
  vat.h
  json_format.h
)
target_link_libraries (vpp_api_test vlibmemoryclient svm vatplugin vppinfra
                       Threads::Threads rt m dl crypto)
set_target_properties(vpp_api_test PROPERTIES ENABLE_EXPORTS 1)
install(TARGETS vpp_api_test DESTINATION bin)

##############################################################################
#  vpp_json_test
##############################################################################
add_executable (vpp_json_test
  json_format.h
  json_format.c
  json_test.c)
target_link_libraries(vpp_json_test vppinfra m)
set_target_properties(vpp_json_test PROPERTIES ENABLE_EXPORTS 1)
install(TARGETS vpp_json_test DESTINATION bin)

##############################################################################
# vat headers
##############################################################################
vpp_add_header_files(vat
  vat.h
  json_format.h
)

##############################################################################
# restart
##############################################################################
add_executable (vpp_restart restart.c)
target_link_libraries (vpp_restart svmdb svm vppinfra pthread rt)
install(TARGETS vpp_restart DESTINATION bin )

