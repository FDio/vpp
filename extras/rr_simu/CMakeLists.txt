# Copyright (c) 2023 Cisco and/or its affiliates.
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

cmake_minimum_required(VERSION 3.10)

project(rr_simulation)

set(CMAKE_CXX_STANDARD 17)

add_executable(rr_simulation main.cpp event_handler.cpp event.cpp frame_generator.cpp packet.cpp parser.cpp scheduler.cpp grapher.cpp)

target_include_directories(rr_simulation PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})