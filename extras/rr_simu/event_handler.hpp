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

#include "event.hpp"
#include "scheduler.hpp"
#include "frame_generator.hpp"
#include <string>
#include "grapher.hpp"
#include <unordered_map>
#include <queue>
#include "parser.hpp"
#include <chrono>

class EventHandler {

    public:
        EventHandler(std::unordered_map<std::string, std::string> &configParam);
        void run();

    private:
        std::unordered_map<std::string, std::string> configParam;

        std::chrono::time_point<std::chrono::steady_clock,std::chrono::nanoseconds> curr_time;
        std::chrono::time_point<std::chrono::steady_clock,std::chrono::nanoseconds> ini_time;

        unsigned long max_frame_size;
        unsigned long output_rate;

        std::priority_queue<Event, std::vector<Event>, std::greater<Event>> priority_queue;
        frame curr_frame = {};
        std::shared_ptr<Packet> next_packet, next_packet_simpl;

        FrameGenerator frame_generator;
        Scheduler sched;
        Grapher grapher;

        std::chrono::system_clock::time_point start;
};