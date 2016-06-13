/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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
#ifndef __included_dpdk_threads_h__
#define __included_dpdk_threads_h__

#include <vnet/vnet.h>

typedef void (*dpdk_worker_thread_callback_t) (vlib_main_t *vm);

void dpdk_worker_thread (vlib_worker_thread_t * w,
                         dpdk_worker_thread_callback_t callback);

int dpdk_frame_queue_dequeue (vlib_main_t *vm);

#endif /* __included_dpdk_threads_h__ */
