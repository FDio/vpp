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

#include <string>
#include <chrono>

enum event_type
{
  FRAME_ARRIVING = 0,
  TRANS_START_TRUE = 1,
  TRANS_START_SIMPL = 2,
  TRANS_END_TRUE = 3,
  TRANS_END_SIMPL = 4,
  SAVE_DATA = 5
};

class Event
{

public:
  Event (event_type type, std::chrono::time_point<std::chrono::steady_clock,
						  std::chrono::nanoseconds>
			    timestamp);
  static bool compare_event (Event event1, Event event2);
  const event_type get_type () const;
  const std::chrono::time_point<std::chrono::steady_clock,
				std::chrono::nanoseconds>
  get_timestamp () const;

  friend bool operator> (const Event &e1, const Event &e2);

private:
  event_type type;
  std::chrono::time_point<std::chrono::steady_clock, std::chrono::nanoseconds>
    timestamp;
};