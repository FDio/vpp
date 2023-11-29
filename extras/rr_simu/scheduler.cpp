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

#include "scheduler.hpp"
#include <iostream>

// initialize the scheduler, notably by creating the entries in the packet map
void
Scheduler::init (std::unordered_map<std::string, std::string> &configParam)
{
  this->max_num_queue = stol (configParam.at ("queue_class_number"));
  this->max_nic_size = stol (configParam.at ("max_nic_size"));

  for (long i = 0; i < max_num_queue; i++)
    pkt_map.insert ({ i, {} });
}

void
Scheduler::enqueue (frame &curr_frame)
{
  for (auto pkt_ptr : curr_frame)
    {
      pkt_map.at (pkt_ptr->get_pkt_class ()).push (pkt_ptr);
      num_pkt++;
    }
}

// select the next packet as the first one in the next non-empty class queue
std::shared_ptr<Packet>
Scheduler::select_packet ()
{
  static int to_looked_up_class = 0;
  while (pkt_map.at (to_looked_up_class).empty ())
    {
      to_looked_up_class++;
      if (to_looked_up_class >= max_num_queue)
	to_looked_up_class = 0;
    }
  next_pkt = pkt_map.at (to_looked_up_class).front ();
  pkt_map.at (to_looked_up_class).pop ();
  to_looked_up_class++;
  if (to_looked_up_class >= max_num_queue)
    to_looked_up_class = 0;
  return next_pkt;
}

void
Scheduler::forward_packet (
  std::chrono::time_point<std::chrono::steady_clock, std::chrono::nanoseconds>
    &time)
{
  next_pkt->set_pkt_out_timestamp (time);
  num_pkt--;
  if (!num_pkt)
    active = false;
}

bool
Scheduler::is_active ()
{
  return active;
}

void
Scheduler::change_active ()
{
  active = !active;
}

void
Scheduler::enqueue_simpl (frame &curr_frame)
{
  std::unordered_map<unsigned int, std::queue<std::shared_ptr<Packet> > >
    pkt_map_simpl;
  std::vector<int> class_vec = {};
  int num_pkt_simpl = 0;
  for (auto pkt_ptr : curr_frame)
    {
      pkt_map_simpl[pkt_ptr->get_pkt_class ()].push (pkt_ptr);
      num_pkt_simpl++;
      if (std::find (class_vec.begin (), class_vec.end (),
		     pkt_ptr->get_pkt_class ()) == class_vec.end ())
	class_vec.push_back (pkt_ptr->get_pkt_class ());
    }

  while (num_pkt_simpl > 0 && pkt_queue_simpl.size () < max_nic_size)
    {
      for (int i : class_vec)
	{
	  if (!pkt_map_simpl.at (i).empty ())
	    {
	      pkt_queue_simpl.push (pkt_map_simpl.at (i).front ());
	      pkt_map_simpl.at (i).pop ();
	      num_pkt_simpl--;
	    }
	}
    }
}

std::shared_ptr<Packet>
Scheduler::select_packet_simpl ()
{
  next_pkt_simpl = pkt_queue_simpl.front ();
  pkt_queue_simpl.pop ();
  return next_pkt_simpl;
}

void
Scheduler::forward_packet_simpl (
  std::chrono::time_point<std::chrono::steady_clock, std::chrono::nanoseconds>
    &time)
{
  next_pkt_simpl->set_pkt_out_timestamp (time);

  if (pkt_queue_simpl.empty ())
    active_simpl = false;
}

bool
Scheduler::is_active_simpl ()
{
  return active_simpl;
}

void
Scheduler::change_active_simpl ()
{
  active_simpl = !active_simpl;
}
