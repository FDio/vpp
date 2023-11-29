/* Copyright (c) 2023 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License. */

#pragma once
#include "packet.hpp"
#include <unordered_map>
#include <string>
#include <map>
#include <cmath>
#include <chrono>
#include <memory>
#include <queue>
#include <algorithm>
#include "parser.hpp"
#include <thread>
#include <random>

class FrameGenerator
{

public:
  FrameGenerator () = default;
  void init (std::unordered_map<std::string, std::string> &configParam);
  void generate_frame (std::chrono::time_point<std::chrono::steady_clock,
					       std::chrono::nanoseconds> &time,
		       frame &curr_frame);
  double get_size_esperance ();

private:
  unsigned long max_frame_size;
  unsigned long max_num_queue;
  unsigned long long id_count = 0;
  std::map<int, float> class_repartition_map;
  std::map<int, float> size_repartition_map;
  std::vector<float> class_repartition_vec;
  std::vector<float> size_repartition_vec;

  void
  generate_packet (std::chrono::time_point<std::chrono::steady_clock,
					   std::chrono::nanoseconds> &time,
		   frame &curr_frame);
  std::vector<float>
  generate_distribution_vector (std::map<int, float> repartition_map,
				unsigned int max_size);

  std::discrete_distribution<> class_d;
  std::discrete_distribution<> size_d;
};