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

#include "frame_generator.hpp"
#include <iostream>

void FrameGenerator::init(std::unordered_map<std::string, std::string> &configParam) {
    this->max_frame_size = stol(configParam.at("frame_size"));
    this->max_num_queue = stol(configParam.at("queue_class_number"));

    this->class_repartition_map = Parser::parsePairArray(configParam.at("class_repartition"));
    this->size_repartition_map = Parser::parsePairArray(configParam.at("size_repartition"));

    class_repartition_vec = generate_distribution_vector(class_repartition_map, max_num_queue);
    size_repartition_vec = generate_distribution_vector(size_repartition_map, 1501);

    for (int i = 0; i < 64; i++)
        size_repartition_vec.at(i) = 0;

    class_d = std::discrete_distribution<>(class_repartition_vec.begin(), class_repartition_vec.end());
    size_d = std::discrete_distribution<>(size_repartition_vec.begin(), size_repartition_vec.end());
}

void FrameGenerator::generate_frame(std::chrono::time_point<std::chrono::steady_clock,std::chrono::nanoseconds> &time, frame &curr_fram) {
    curr_fram.clear();
    static unsigned long num_pkt = 0;

    while (curr_fram.size() < max_frame_size) {
        generate_packet(time, curr_fram);
        num_pkt++;
    }
}

void FrameGenerator::generate_packet(std::chrono::time_point<std::chrono::steady_clock,std::chrono::nanoseconds> &time, frame &curr_frame) {

    static std::random_device rd;
    static std::mt19937 gen(rd());

    unsigned int pkt_class = class_d(gen);
    unsigned int size = size_d(gen);

    curr_frame.push_back(std::make_shared<Packet>(id_count++, pkt_class, size, time));
}

std::vector<float> FrameGenerator::generate_distribution_vector(std::map<int, float> repartition_map, unsigned int max_size) {

    std::vector<float> repartition_vec;

    if ((repartition_map).size() == max_size) {
        for (auto class_pair : repartition_map){
            repartition_vec.push_back(class_pair.second);
        }
    }
    else {
        float total_sum = 0;
        std::vector<int> element_defined = {};
        for (auto pair : repartition_map){
            total_sum += pair.second;
            element_defined.push_back(pair.first);
        }
        for (int i = 0; i < max_size; i++) {
            auto it = std::find(element_defined.begin(), element_defined.end(), i);
            if (it != std::end(element_defined)) {
                if (total_sum < 100) {
                    repartition_vec.push_back(repartition_map.at(*it));
                }
                else {
                    repartition_vec.push_back(repartition_map.at(*it)*100.0/total_sum);
                }
            }
            else {
                if (total_sum < 100) {
                    repartition_vec.push_back((100 - total_sum)/(max_size - element_defined.size()));
                }
                else {
                    repartition_vec.push_back(0);
                }
            }
        }
    }
    return repartition_vec;
}

double FrameGenerator::get_size_esperance() {
    double sum = 0;
    int i = 0;
    for (auto n : size_d.probabilities()) {
        sum += i*n;
        i++;
    }
    return sum;
}