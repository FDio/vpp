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

if (CMAKE_VERSION VERSION_LESS 3.12)
  find_package(PythonInterp 2.7)
else()
  find_package(Python3 COMPONENTS Interpreter)
endif()

if(PYTHONINTERP_FOUND)
  install(
    CODE "
    execute_process(
      WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
      COMMAND ${PYTHON_EXECUTABLE} ./setup.py
	install
	  --root /
	  --prefix=${CMAKE_INSTALL_PREFIX}
	  --single-version-externally-managed
	  bdist_wheel
	  --dist-dir=${CMAKE_INSTALL_PREFIX}
      OUTPUT_QUIET
    )"
    COMPONENT vpp-api-python
  )
endif()
