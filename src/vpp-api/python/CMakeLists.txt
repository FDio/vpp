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

find_package(Python3 REQUIRED COMPONENTS Interpreter)
set(PYTHONINTERP_FOUND ${Python3_Interpreter_FOUND})
set(PYTHON_EXECUTABLE ${Python3_EXECUTABLE})

install(
  CODE "
  execute_process(
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    COMMAND ${PYTHON_EXECUTABLE} -m pip
      install .
	--disable-pip-version-check
	--root=\$ENV{DESTDIR}/
	--prefix=${CMAKE_INSTALL_PREFIX}
	--no-deps
    RESULT_VARIABLE _pip_result
  )
  if(NOT _pip_result EQUAL 0)
    message(FATAL_ERROR \"pip install failed with code: \${_pip_result}\")
  endif()
  "
  COMPONENT vpp-api-python
)
