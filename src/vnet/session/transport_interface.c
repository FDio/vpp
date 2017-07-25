/*
 * Copyright (c) 2017 Cisco and/or its affiliates.
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

#include <vnet/session/transport_interface.h>
#include <vnet/session/session.h>

/**
 * Per-type vector of transport protocol virtual function tables
 */
transport_proto_vft_t *tp_vfts;

u32
transport_endpoint_lookup (transport_endpoint_table_t * ht,
			   ip46_address_t * ip, u16 port)
{
  clib_bihash_kv_24_8_t kv;
  int rv;

  kv.key[0] = ip->as_u64[0];
  kv.key[1] = ip->as_u64[1];
  kv.key[2] = port;

  rv = clib_bihash_search_inline_24_8 (ht, &kv);
  if (rv == 0)
    return kv.value;

  return TRANSPORT_ENDPOINT_INVALID_INDEX;
}

void
transport_endpoint_table_add (transport_endpoint_table_t * ht,
			      transport_endpoint_t * te, u32 value)
{
  clib_bihash_kv_24_8_t kv;

  kv.key[0] = te->ip.as_u64[0];
  kv.key[1] = te->ip.as_u64[1];
  kv.key[2] = te->port;
  kv.value = value;

  clib_bihash_add_del_24_8 (ht, &kv, 1);
}

void
transport_endpoint_table_del (transport_endpoint_table_t * ht,
			      transport_endpoint_t * te)
{
  clib_bihash_kv_24_8_t kv;

  kv.key[0] = te->ip.as_u64[0];
  kv.key[1] = te->ip.as_u64[1];
  kv.key[2] = te->port;

  clib_bihash_add_del_24_8 (ht, &kv, 0);
}

/**
 * Register transport virtual function table.
 *
 * @param type - session type (not protocol type)
 * @param vft - virtual function table
 */
void
session_register_transport (transport_proto_t transport_proto, u8 is_ip4,
			    const transport_proto_vft_t * vft)
{
  u8 session_type;
  session_type = session_type_from_proto_and_ip (transport_proto, is_ip4);

  vec_validate (tp_vfts, session_type);
  tp_vfts[session_type] = *vft;

  /* If an offset function is provided, then peek instead of dequeue */
  session_manager_set_transport_rx_fn (session_type,
				       vft->tx_fifo_offset != 0);
}

/**
 * Get transport virtual function table
 *
 * @param type - session type (not protocol type)
 */
transport_proto_vft_t *
session_get_transport_vft (u8 session_type)
{
  if (session_type >= vec_len (tp_vfts))
    return 0;
  return &tp_vfts[session_type];
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
