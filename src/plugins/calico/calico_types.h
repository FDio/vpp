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

#ifndef __CALICO_TYPES_H__
#define __CALICO_TYPES_H__

#include <vnet/fib/fib_node.h>
#include <vnet/fib/fib_source.h>
#include <vnet/ip/ip_types.h>

/* only in the default table for v4 and v6 */
#define CALICO_FIB_TABLE 0

#define CALICO_SESSION_MAX_AGE 10
#define CALICO_DEFAULT_SCANNER_TIMEOUT (1.0)

#define CALICO_DEFAULT_SESSION_BUCKETS     1024
#define CALICO_DEFAULT_SESSION_MEMORY     (1 << 20)

typedef struct calico_endpoint_t_
{
  ip_address_t ce_ip;
  u16 ce_port;
} calico_endpoint_t;

typedef struct calico_main_
{
  /* Memory size of the session bihash */
  uword session_hash_memory;
  /* Number of buckets of the  session bihash */
  u32 session_hash_buckets;

  /* delay in seconds between two scans of session/clients tables */
  f64 scanner_timeout;
} calico_main_t;

extern u8 *format_calico_endpoint (u8 * s, va_list * args);
extern f64 *calico_timestamps;

always_inline u32
calico_timestamp_new (f64 ts)
{
  f64 *timeout;
  pool_get (calico_timestamps, timeout);
  *timeout = ts;
  return timeout - calico_timestamps;
}

always_inline void
calico_timestamp_update (u32 index, f64 ts)
{
  f64 *timeout = pool_elt_at_index (calico_timestamps, index);
  *timeout = ts;
}

always_inline f64
calico_timestamp_get (u32 index)
{
  f64 *timeout = pool_elt_at_index (calico_timestamps, index);
  return *timeout;
}

always_inline void
calico_timestamp_free (u32 index)
{
  f64 *timeout = pool_elt_at_index (calico_timestamps, index);
  pool_put (calico_timestamps, timeout);
}


extern fib_source_t calico_fib_source;
extern calico_main_t calico_main;

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

#endif
