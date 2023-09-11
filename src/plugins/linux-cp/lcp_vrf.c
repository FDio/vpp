/* Hey Emacs use -*- mode: C -*- */
/*
 * Copyright 2021 Cisco and/or its affiliates.
 *
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

#include <linux-cp/lcp_vrf.h>

#include <plugins/linux-cp/lcp_vrf.h>

uword *lcp_router_table_db[FIB_PROTOCOL_MAX];
lcp_router_table_t *lcp_router_table_pool;

lcp_router_table_t *
lcp_router_table_find (uint32_t id, fib_protocol_t fproto)
{
  uword *p;

  p = hash_get (lcp_router_table_db[fproto], id);

  if (p)
    return pool_elt_at_index (lcp_router_table_pool, p[0]);

  return (NULL);
}
