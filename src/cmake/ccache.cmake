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
# ccache
##############################################################################
option(VPP_USE_CCACHE "Use ccache compiler cache." ON)
if(VPP_USE_CCACHE)
  find_program(CCACHE_FOUND ccache)
  message(STATUS "Looking for ccache")
  if(CCACHE_FOUND)
    message(STATUS "Looking for ccache - found")
    set_property(GLOBAL PROPERTY RULE_LAUNCH_COMPILE ccache)
    set_property(GLOBAL PROPERTY RULE_LAUNCH_LINK ccache)
  else(CCACHE_FOUND)
    message(STATUS "Looking for ccache - not found")
  endif(CCACHE_FOUND)
endif(VPP_USE_CCACHE)
