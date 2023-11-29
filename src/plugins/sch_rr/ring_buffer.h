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
#include <stdbool.h>

#define QUEUE_SIZE 1000

typedef struct {
    u32 buffer[QUEUE_SIZE];
    int begin;
    int end;
    int size;
    int count;
    bool is_init;
} ring_buffer;

void init_ring_buffer(ring_buffer *buf);
void ring_buffer_push(ring_buffer *buf, u32 data);
u32 ring_buffer_pop(ring_buffer *buf);