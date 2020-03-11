/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
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

#ifndef included_unat_inlines_h
#define included_unat_inlines_h

static inline void
unat_key_from_packet (u32 fib_index, ip4_header_t *ip, u16 sport, u16 dport, unat_key_t *key)
{
  key->sa = ip->src_address;
  key->da = ip->dst_address;
  key->proto = ip->protocol;
  key->fib_index = fib_index;
  key->sp = sport;
  key->dp = dport;
}

static inline void
unat_counter_lock (unat_main_t * um)
{
  if (um->counter_lock)
    clib_spinlock_lock (&um->counter_lock);
}

static inline void
unat_counter_unlock (unat_main_t * um)
{
  if (um->counter_lock)
    clib_spinlock_unlock (&um->counter_lock);
}

#endif
