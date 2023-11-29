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
#include <string>
#include <unordered_map>
#include <queue>
#include "grapher.hpp"
#include <memory>
#include <algorithm>
#include "packet.hpp"
#include "utility"
#include <cmath>

class Scheduler
{

public:
  Scheduler () = default;
  void init (std::unordered_map<std::string, std::string> &configParam);
  void enqueue (frame &curr_frame);
  std::shared_ptr<Packet> select_packet ();
  void
  forward_packet (std::chrono::time_point<std::chrono::steady_clock,
					  std::chrono::nanoseconds> &time);
  bool is_active ();
  void change_active ();

  void enqueue_simpl (frame &curr_frame);
  std::shared_ptr<Packet> select_packet_simpl ();
  void forward_packet_simpl (
    std::chrono::time_point<std::chrono::steady_clock,
			    std::chrono::nanoseconds> &time);
  bool is_active_simpl ();
  void change_active_simpl ();

private:
  unsigned long max_num_queue;
  unsigned long max_nic_size;
  std::unordered_map<unsigned int, std::queue<std::shared_ptr<Packet> > >
    pkt_map = {};
  std::shared_ptr<Packet> next_pkt, next_pkt_simpl;
  unsigned long num_pkt = 0, num_pkt_simpl = 0;
  bool active = false, active_simpl = false;
  std::queue<std::shared_ptr<Packet> > pkt_queue_simpl = {};
  std::queue<frame> frame_queue = {};
};