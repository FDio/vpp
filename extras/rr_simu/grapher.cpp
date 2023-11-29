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

#include "grapher.hpp"

void
Grapher::init (std::unordered_map<std::string, std::string> &configParam)
{
  this->max_num_queue = stol (configParam.at ("queue_class_number"));
  this->class_repartition_map =
    Parser::parsePairArray (configParam.at ("class_repartition"));

  for (auto i_pair : class_repartition_map)
    {
      bandwidth_per_class_true.insert ({ i_pair.first, 0 });
      bandwidth_per_class_simpl.insert ({ i_pair.first, 0 });
      latency_per_class_true.insert ({ i_pair.first, 0 });
      latency_per_class_simpl.insert ({ i_pair.first, 0 });
    }
  bandwidth_per_class_true.insert ({ max_num_queue, 0 });
  bandwidth_per_class_simpl.insert ({ max_num_queue, 0 });
  latency_per_class_true.insert ({ max_num_queue, 0 });
  latency_per_class_simpl.insert ({ max_num_queue, 0 });
}

void
Grapher::add_packet_true (std::shared_ptr<Packet> &pkt)
{
  int pkt_class = pkt->get_pkt_class ();
  if (bandwidth_per_class_true.find (pkt_class) ==
      bandwidth_per_class_true.end ())
    pkt_class = max_num_queue;

  bandwidth_per_class_true.at (pkt_class) += pkt->get_pkt_size ();

  static std::map<
    int, std::pair<long, std::chrono::time_point<std::chrono::steady_clock,
						 std::chrono::nanoseconds> > >
    jitter_per_class_temp;
  if (jitter_per_class_temp[pkt->get_pkt_class ()].second !=
      pkt->get_pkt_in_timestamp ())
    jitter_per_class_temp[pkt->get_pkt_class ()].first +=
      std::chrono::duration_cast<std::chrono::nanoseconds> (
	pkt->get_pkt_out_timestamp () -
	jitter_per_class_temp[pkt->get_pkt_class ()].second)
	.count ();
  jitter_per_class_temp[pkt->get_pkt_class ()].second =
    pkt->get_pkt_out_timestamp ();

  latency_per_class_true.at (pkt_class) +=
    std::chrono::duration_cast<std::chrono::nanoseconds> (
      pkt->get_pkt_out_timestamp () - pkt->get_pkt_in_timestamp ())
      .count ();

  num_per_class_true[pkt->get_pkt_class ()]++;
}

void
Grapher::add_packet_simpl (std::shared_ptr<Packet> &pkt)
{
  int pkt_class = pkt->get_pkt_class ();
  if (num_per_class_true.find (pkt_class) == num_per_class_true.end ())
    pkt_class = max_num_queue;

  bandwidth_per_class_simpl.at (pkt_class) += pkt->get_pkt_size ();

  static std::map<
    int, std::pair<long, std::chrono::time_point<std::chrono::steady_clock,
						 std::chrono::nanoseconds> > >
    jitter_per_class_temp;
  if (jitter_per_class_temp[pkt->get_pkt_class ()].second !=
      pkt->get_pkt_in_timestamp ())
    jitter_per_class_temp[pkt->get_pkt_class ()].first +=
      std::chrono::duration_cast<std::chrono::nanoseconds> (
	pkt->get_pkt_out_timestamp () -
	jitter_per_class_temp[pkt->get_pkt_class ()].second)
	.count ();
  jitter_per_class_temp[pkt->get_pkt_class ()].second =
    pkt->get_pkt_out_timestamp ();

  latency_per_class_simpl.at (pkt_class) +=
    std::chrono::duration_cast<std::chrono::nanoseconds> (
      pkt->get_pkt_out_timestamp () - pkt->get_pkt_in_timestamp ())
      .count ();

  num_per_class_simpl.at (pkt_class)++;
}

void
Grapher::save_data (
  std::chrono::time_point<std::chrono::steady_clock, std::chrono::nanoseconds>
    curr_time,
  std::chrono::time_point<std::chrono::steady_clock, std::chrono::nanoseconds>
    ini_time)
{

  int time = std::chrono::duration_cast<std::chrono::milliseconds> (curr_time -
								    ini_time)
	       .count ();

  for (auto i_pair : num_per_class_true)
    {
      if (num_per_class_true.at (i_pair.first))
	{
	  jitter_per_class_true.at (i_pair.first) /=
	    num_per_class_true.at (i_pair.first);
	  latency_per_class_true.at (i_pair.first) /=
	    num_per_class_true.at (i_pair.first);
	}
    }

  for (auto i_pair : num_per_class_simpl)
    {
      if (num_per_class_simpl.at (i_pair.first))
	{
	  jitter_per_class_simpl.at (i_pair.first) /=
	    num_per_class_simpl.at (i_pair.first);
	  latency_per_class_simpl.at (i_pair.first) /=
	    num_per_class_simpl.at (i_pair.first);
	}
    }

  static bool first_call = true;
  write_to_file ("../results_bw_true.csv", bandwidth_per_class_true,
		 first_call, time);
  write_to_file ("../results_bw_simpl.csv", bandwidth_per_class_simpl,
		 first_call, time);
  write_to_file ("../results_ltc_true.csv", latency_per_class_true, first_call,
		 time);
  write_to_file ("../results_ltc_simpl.csv", latency_per_class_simpl,
		 first_call, time);
  write_to_file ("../results_jt_true.csv", jitter_per_class_true, first_call,
		 time);
  write_to_file ("../results_jt_simpl.csv", jitter_per_class_simpl, first_call,
		 time);

  for (auto i_pair : num_per_class_true)
    {
      num_per_class_simpl.at (i_pair.first) = 0;
      num_per_class_true.at (i_pair.first) = 0;
    }

  if (first_call)
    first_call = !first_call;
}

void
Grapher::write_to_file (std::string file_name,
			std::map<unsigned int, double> &map, bool first_call,
			long time)
{
  std::ofstream file;
  if (first_call)
    {
      file.open (file_name);
      file << "t";
      for (auto i_pair : num_per_class_true)
	file << "," << i_pair.first;
      first_call = false;
    }
  else
    file.open (file_name, std::ios_base::app);

  file << "\n" << time;

  for (auto data_pair : map)
    {
      file << "," << data_pair.second * 10;
      data_pair.second = 0;
    }

  for (auto i_pair : num_per_class_true)
    map.at (i_pair.first) = 0;
}