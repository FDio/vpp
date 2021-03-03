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

#ifndef included_vnet_interface_tx_queue_h
#define included_vnet_interface_tx_queue_h

#define log_debug(fmt, ...) vlib_log_debug (if_txq_log.class, fmt, __VA_ARGS__)
#define log_err(fmt, ...)   vlib_log_err (if_txq_log.class, fmt, __VA_ARGS__)

typedef struct
{
  u32 n_threads;
  uword first_worker_thread_index;
  uword last_worker_thread_index;
  uword next_worker_thread_index;
} vnet_interface_txq_thread_t;

#endif /* included_vnet_interface_tx_queue_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
