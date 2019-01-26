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
# Highlight WARNING and ERROR messages
##############################################################################
function(message)
  list(GET ARGV 0 type)
  if("$ENV{TERM}" STREQUAL "xterm-256color")
    string(ASCII 27 esc)
    set(red "${esc}[1;31m")
    set(yellow "${esc}[1;33m")
    set(reset "${esc}[m")
  endif()
  if(type STREQUAL FATAL_ERROR OR type STREQUAL SEND_ERROR)
    list(REMOVE_AT ARGV 0)
    _message(${type} "${red}${ARGV}${reset}")
  elseif(type STREQUAL WARNING)
    list(REMOVE_AT ARGV 0)
    _message(STATUS "${yellow}${ARGV}${reset}")
  elseif(type STREQUAL STATUS)
    list(REMOVE_AT ARGV 0)
    _message(STATUS "${ARGV}")
  else()
    _message(${ARGV})
  endif()
endfunction()

##############################################################################
# aligned config output
##############################################################################
function(pr desc val)
  if("$ENV{TERM}" STREQUAL "xterm-256color")
    string(ASCII 27 esc)
    set(reset "${esc}[m")
    set(cyan "${esc}[36m")
  endif()
  string(LENGTH ${desc} len)
  while (len LESS 20)
    set (desc "${desc} ")
    string(LENGTH ${desc} len)
  endwhile()
  _message("${cyan}${desc}${reset}: ${val}")
endfunction()

##############################################################################
# string append
##############################################################################

macro(string_append var str)
  if (NOT ${var})
    set(${var} "${str}")
  else()
    set(${var} "${${var}} ${str}")
  endif()
endmacro()

