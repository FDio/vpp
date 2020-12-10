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

#ifndef __included_nat44_ei_inlines_h__
#define __included_nat44_ei_inlines_h__

#include <nat/nat44-ei/nat44_ei_ha.h>

static_always_inline u8
nat44_ei_maximum_sessions_exceeded (snat_main_t *sm, u32 thread_index)
{
  if (pool_elts (sm->per_thread_data[thread_index].sessions) >=
      sm->max_translations_per_thread)
    return 1;
  return 0;
}

always_inline void
nat44_ei_session_update_counters (snat_session_t *s, f64 now, uword bytes,
				  u32 thread_index)
{
  s->last_heard = now;
  s->total_pkts++;
  s->total_bytes += bytes;
  nat_ha_sref (&s->out2in.addr, s->out2in.port, &s->ext_host_addr,
	       s->ext_host_port, s->nat_proto, s->out2in.fib_index,
	       s->total_pkts, s->total_bytes, thread_index,
	       &s->ha_last_refreshed, now);
}

#endif /* __included_nat44_ei_inlines_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
