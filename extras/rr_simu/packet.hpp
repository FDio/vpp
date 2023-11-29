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
#include <ctime>
#include <vector>
#include <memory>
#include <chrono>

class Packet
{

public:
  Packet (unsigned long long pkt_id, unsigned int pkt_class,
	  unsigned int pkt_size,
	  std::chrono::time_point<std::chrono::steady_clock,
				  std::chrono::nanoseconds> &pkt_timestamp);
  int get_pkt_id ();
  int get_pkt_class ();
  int get_pkt_size ();
  std::chrono::time_point<std::chrono::steady_clock, std::chrono::nanoseconds>
  get_pkt_in_timestamp ();
  std::chrono::time_point<std::chrono::steady_clock, std::chrono::nanoseconds>
  get_pkt_out_timestamp ();
  void
  set_pkt_out_timestamp (std::chrono::time_point<std::chrono::steady_clock,
						 std::chrono::nanoseconds>
			   timestamp);

  static bool comparePtrClass (std::shared_ptr<Packet> pkt1,
			       std::shared_ptr<Packet> pkt2);

private:
  unsigned long long pkt_id;
  unsigned int pkt_class;
  unsigned int pkt_size;
  std::chrono::time_point<std::chrono::steady_clock, std::chrono::nanoseconds>
    pkt_in_timestamp;
  std::chrono::time_point<std::chrono::steady_clock, std::chrono::nanoseconds>
    pkt_out_timestamp;
};

typedef std::vector<std::shared_ptr<Packet> > frame;