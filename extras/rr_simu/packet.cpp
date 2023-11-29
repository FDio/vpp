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

#include "packet.hpp"

Packet::Packet(unsigned long long pkt_id, unsigned int pkt_class, unsigned int pkt_size, std::chrono::time_point<std::chrono::steady_clock,std::chrono::nanoseconds> &timestamp) {
    this->pkt_id = pkt_id;
    this->pkt_class = pkt_class;
    this->pkt_size = pkt_size;
    this->pkt_in_timestamp = timestamp;
}

int Packet::get_pkt_id() {
    return pkt_id;
}

int Packet::get_pkt_class() {
    return pkt_class;
}

int Packet::get_pkt_size() {
    return pkt_size;
}

std::chrono::time_point<std::chrono::steady_clock,std::chrono::nanoseconds> Packet::get_pkt_in_timestamp() {
    return pkt_in_timestamp;
}

std::chrono::time_point<std::chrono::steady_clock,std::chrono::nanoseconds> Packet::get_pkt_out_timestamp() {
    return pkt_out_timestamp;
}

void Packet::set_pkt_out_timestamp(std::chrono::time_point<std::chrono::steady_clock,std::chrono::nanoseconds> timestamp) {
    this->pkt_out_timestamp = timestamp;
}

bool Packet::comparePtrClass(std::shared_ptr<Packet> pkt1, std::shared_ptr<Packet> pkt2) {
    return pkt1->get_pkt_class() < pkt2->get_pkt_class();
}
