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
#include <map>
#include "parser.hpp"
#include <unordered_map>
#include <string>
#include <memory>
#include <iostream>
#include <fstream>

class Grapher
{

public:
  Grapher () = default;
  void init (std::unordered_map<std::string, std::string> &configParam);
  void add_packet_true (std::shared_ptr<Packet> &pkt);
  void add_packet_simpl (std::shared_ptr<Packet> &pkt);
  void save_data (std::chrono::time_point<std::chrono::steady_clock,
					  std::chrono::nanoseconds>
		    time,
		  std::chrono::time_point<std::chrono::steady_clock,
					  std::chrono::nanoseconds>
		    ini_time);
  void write_to_file (std::string file_name,
		      std::map<unsigned int, double> &map, bool first_call,
		      long time);

private:
  std::map<int, float> class_repartition_map;
  std::map<unsigned int, double> bandwidth_per_class_true = {};
  std::map<unsigned int, double> bandwidth_per_class_simpl = {};
  std::map<unsigned int, double> jitter_per_class_true = {};
  std::map<unsigned int, double> jitter_per_class_simpl = {};
  std::map<unsigned int, double> latency_per_class_true = {};
  std::map<unsigned int, double> latency_per_class_simpl = {};
  std::map<unsigned int, int> num_per_class_true = {};
  std::map<unsigned int, int> num_per_class_simpl = {};
  unsigned long max_num_queue;
};