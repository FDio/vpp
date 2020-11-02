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
/**
 * @brief The NAT44 inline functions
 */

#ifndef included_nat44_inlines_h__
#define included_nat44_inlines_h__

#include <vnet/fib/ip4_fib.h>
#include <nat/nat.h>

static_always_inline u8
nat44_maximum_sessions_exceeded (snat_main_t * sm, u32 thread_index)
{
  if (pool_elts (sm->per_thread_data[thread_index].sessions) >=
      sm->max_translations_per_thread)
    return 1;
  return 0;
}

static_always_inline u8
nat44_ed_maximum_sessions_exceeded (snat_main_t * sm,
				    u32 fib_index, u32 thread_index)
{
  u32 translations;
  translations = pool_elts (sm->per_thread_data[thread_index].sessions);
  if (vec_len (sm->max_translations_per_fib) <= fib_index)
    fib_index = 0;
  return translations >= sm->max_translations_per_fib[fib_index];
}

#endif /* included_nat44_inlines_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
