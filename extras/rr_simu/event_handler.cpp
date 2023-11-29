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

#include "event_handler.hpp"
#include <iostream>

EventHandler::EventHandler (
  std::unordered_map<std::string, std::string> &configParam)
{
  this->configParam = configParam;

  unsigned long duration = stol (configParam.at ("duration"));
  unsigned long input_rate = stol (configParam.at ("input_byte_rate"));
  this->max_frame_size = stol (configParam.at ("frame_size"));
  this->output_rate = stol (configParam.at ("output_byte_rate"));

  frame_generator.init (configParam);
  sched.init (configParam);
  grapher.init (configParam);

  ini_time = std::chrono::time_point_cast<std::chrono::nanoseconds> (
    std::chrono::steady_clock::now ());
  curr_time = ini_time;
  long num_frame =
    std::ceil ((float) input_rate / frame_generator.get_size_esperance () /
	       max_frame_size);

  for (long i = 1; i <= duration * num_frame; i++)
    priority_queue.emplace (
      FRAME_ARRIVING,
      curr_time + std::chrono::nanoseconds (1000000000 / num_frame * i));
  for (long j = 1; j <= duration * 100 * 1.2; j++)
    priority_queue.emplace (
      SAVE_DATA, curr_time + std::chrono::nanoseconds (10000000 * j));
}

void
EventHandler::run ()
{

  while (!priority_queue.empty ())
    {
      start = std::chrono::high_resolution_clock::now ();
      curr_time = priority_queue.top ().get_timestamp ();

      switch (priority_queue.top ().get_type ())
	{

	case FRAME_ARRIVING:
	  frame_generator.generate_frame (curr_time, curr_frame);
	  sched.enqueue (curr_frame);
	  sched.enqueue_simpl (curr_frame);
	  if (!sched.is_active ())
	    {
	      priority_queue.emplace (TRANS_START_TRUE, curr_time);
	      sched.change_active ();
	    }
	  if (!sched.is_active_simpl ())
	    {
	      priority_queue.emplace (TRANS_START_FRAME, curr_time);
	      sched.change_active_simpl ();
	    }
	  break;

	case TRANS_START_TRUE:
	  next_packet = sched.select_packet ();
	  priority_queue.emplace (
	    TRANS_END_TRUE, curr_time + std::chrono::nanoseconds (
					  (long) next_packet->get_pkt_size () *
					  1000000000 / output_rate));
	  break;

	case TRANS_START_SIMPL:
	  next_packet_simpl = sched.select_packet_simpl ();
	  priority_queue.emplace (
	    TRANS_END_FRAME,
	    curr_time + std::chrono::nanoseconds (
			  (long) next_packet_simpl->get_pkt_size () *
			  1000000000 / output_rate));
	  break;

	case TRANS_END_TRUE:
	  sched.forward_packet (curr_time);
	  grapher.add_packet_true (next_packet);
	  if (sched.is_active ())
	    priority_queue.emplace (TRANS_START_TRUE, curr_time);
	  break;

	case TRANS_END_SIMPL:
	  sched.forward_packet_simpl (curr_time);
	  grapher.add_packet_simpl (next_packet_simpl);
	  if (sched.is_active_simpl ())
	    priority_queue.emplace (TRANS_START_FRAME, curr_time);
	  break;

	case SAVE_DATA:
	  grapher.save_data (curr_time, ini_time);
	  break;
	}
      priority_queue.pop ();
    }
}