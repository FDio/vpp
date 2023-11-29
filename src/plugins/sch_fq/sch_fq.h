/*
 * Copyright (c) 2021 Cisco and/or its affiliates.
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
 * limitations under the License.
 */

#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
#include <vnet/ip/ip4.h>
#include "ring_buffer.h"

#define MAX_CLASS 256

typedef struct {
    clib_bitmap_t *class_bitmap;
    ring_buffer_t queue_map[MAX_CLASS];
    unsigned long long num_round;
    int num_bit_excess;
} sch_fq_buffer_t;

typedef struct {
    int queue_i;
    int pos;
    unsigned long long start_time;
    unsigned long long finish_time;
} trace_en_t;

typedef struct {
    int queue_i;
    int pos;
    int rem_pkt;
    unsigned long long num_round;
} trace_de_t;

extern sch_fq_buffer_t *fq_buffer;