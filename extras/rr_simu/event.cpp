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

Event::Event(event_type type, std::chrono::time_point<std::chrono::steady_clock, std::chrono::nanoseconds> timestamp) {
    this->type = type;
    this->timestamp = timestamp;
}

const event_type Event::get_type() const {
    return type;
}

const std::chrono::time_point<std::chrono::steady_clock, std::chrono::nanoseconds> Event::get_timestamp() const {
    return timestamp;
}

bool operator > (const Event& e1, const Event& e2) {
    return e1.timestamp > e2.timestamp;
}
