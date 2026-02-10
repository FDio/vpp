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
function(pr desc)
  string(REPLACE ";" " " val "${ARGN}")
  if("$ENV{TERM}" STREQUAL "xterm-256color")
    string(ASCII 27 esc)
    set(reset "${esc}[m")
    set(cyan "${esc}[36m")
    set(gray "${esc}[90m")
  endif()
  string(LENGTH "${desc}" len)
  while (len LESS 20)
    set (desc "${desc} ")
    string(LENGTH "${desc}" len)
  endwhile()
  set(prefix_plain "${desc}: ")
  string(LENGTH "${prefix_plain}" prefix_len)
  math(EXPR max_total_len "99")
  math(EXPR max_val_len "${max_total_len} - ${prefix_len}")
  if(max_val_len LESS 1)
    set(max_val_len 1)
  endif()

  string(REGEX REPLACE "[ \t]+" ";" words "${val}")
  list(FILTER words EXCLUDE REGEX "^$")

  if(words)
    set(lines "")
    set(cur "")
    foreach(word IN LISTS words)
      if(cur STREQUAL "")
	set(cur "${word}")
      else()
	string(LENGTH "${cur}" cur_len)
	string(LENGTH "${word}" word_len)
	math(EXPR new_len "${cur_len} + 1 + ${word_len}")
	if(new_len GREATER max_val_len)
	  list(APPEND lines "${cur}")
	  set(cur "${word}")
	else()
	  set(cur "${cur} ${word}")
	endif()
      endif()
    endforeach()
    if(NOT cur STREQUAL "")
      list(APPEND lines "${cur}")
    endif()

    list(GET lines 0 line0)
    _message("${cyan}${desc}${reset}: ${line0}")

    if(lines)
      set(indent "")
      set(i 0)
      while(i LESS prefix_len)
	set(indent "${indent} ")
	math(EXPR i "${i} + 1")
      endwhile()
      list(REMOVE_AT lines 0)
      foreach(line IN LISTS lines)
	_message("${indent}${line}")
      endforeach()
    endif()
  else()
    if(val STREQUAL "")
      set(val "${gray}none${reset}")
    endif()
    _message("${cyan}${desc}${reset}: ${val}")
  endif()
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

##############################################################################
# validate consumed list sentinel
##############################################################################
macro(vpp_check_consumed_list list_var message)
  if(DEFINED ${list_var})
    set(_vpp_list ${${list_var}})
    if(_vpp_list MATCHES "-NOTFOUND$")
      return()
    endif()
    list(REMOVE_ITEM _vpp_list "__EOL__")
    if(_vpp_list)
      message(FATAL_ERROR "${message}: ${_vpp_list}")
    endif()
  endif()
endmacro()
