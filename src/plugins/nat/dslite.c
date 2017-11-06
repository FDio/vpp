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
#include <nat/dslite.h>
#include <nat/dslite_dpo.h>
#include <vnet/fib/fib_table.h>

dslite_main_t dslite_main;

void
dslite_init (vlib_main_t * vm)
{
  dslite_main_t *dm = &dslite_main;
  vlib_thread_registration_t *tr;
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  uword *p;
  dslite_per_thread_data_t *td;
  u32 translation_buckets = 1024;
  u32 translation_memory_size = 128 << 20;
  u32 b4_buckets = 128;
  u32 b4_memory_size = 64 << 20;

  dm->first_worker_index = 0;
  dm->num_workers = 0;

  p = hash_get_mem (tm->thread_registrations_by_name, "workers");
  if (p)
    {
      tr = (vlib_thread_registration_t *) p[0];
      if (tr)
	{
	  dm->num_workers = tr->count;
	  dm->first_worker_index = tr->first_index;
	}
    }

  if (dm->num_workers)
    dm->port_per_thread = (0xffff - 1024) / dm->num_workers;
  else
    dm->port_per_thread = 0xffff - 1024;

  vec_validate (dm->per_thread_data, tm->n_vlib_mains - 1);

  /* *INDENT-OFF* */
  vec_foreach (td, dm->per_thread_data)
    {
      clib_bihash_init_24_8 (&td->in2out, "in2out", translation_buckets,
                             translation_memory_size);

      clib_bihash_init_8_8 (&td->out2in, "out2in", translation_buckets,
                            translation_memory_size);

      clib_bihash_init_16_8 (&td->b4_hash, "b4s", b4_buckets, b4_memory_size);
    }
  /* *INDENT-ON* */

  dslite_dpo_module_init ();
}

int
dslite_set_aftr_ip6_addr (dslite_main_t * dm, ip6_address_t * addr)
{
  dpo_id_t dpo_v6 = DPO_INVALID;

  dslite_dpo_create (DPO_PROTO_IP6, 0, &dpo_v6);
  fib_prefix_t pfx = {
    .fp_proto = FIB_PROTOCOL_IP6,
    .fp_len = 128,
    .fp_addr.ip6.as_u64[0] = addr->as_u64[0],
    .fp_addr.ip6.as_u64[1] = addr->as_u64[1],
  };
  fib_table_entry_special_dpo_add (0, &pfx, FIB_SOURCE_PLUGIN_HI,
				   FIB_ENTRY_FLAG_EXCLUSIVE, &dpo_v6);
  dpo_reset (&dpo_v6);

  dm->aftr_ip6_addr.as_u64[0] = addr->as_u64[0];
  dm->aftr_ip6_addr.as_u64[1] = addr->as_u64[1];
  return 0;
}

int
dslite_add_del_pool_addr (dslite_main_t * dm, ip4_address_t * addr, u8 is_add)
{
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  snat_address_t *a = 0;
  int i = 0;
  dpo_id_t dpo_v4 = DPO_INVALID;
  fib_prefix_t pfx = {
    .fp_proto = FIB_PROTOCOL_IP4,
    .fp_len = 32,
    .fp_addr.ip4.as_u32 = addr->as_u32,
  };

  for (i = 0; i < vec_len (dm->addr_pool); i++)
    {
      if (dm->addr_pool[i].addr.as_u32 == addr->as_u32)
	{
	  a = dm->addr_pool + i;
	  break;
	}
    }
  if (is_add)
    {
      if (a)
	return VNET_API_ERROR_VALUE_EXIST;
      vec_add2 (dm->addr_pool, a, 1);
      a->addr = *addr;
#define _(N, i, n, s) \
      clib_bitmap_alloc (a->busy_##n##_port_bitmap, 65535); \
      a->busy_##n##_ports = 0; \
      vec_validate_init_empty (a->busy_##n##_ports_per_thread, tm->n_vlib_mains - 1, 0);
      foreach_snat_protocol
#undef _
	dslite_dpo_create (DPO_PROTO_IP4, 0, &dpo_v4);
      fib_table_entry_special_dpo_add (0, &pfx, FIB_SOURCE_PLUGIN_HI,
				       FIB_ENTRY_FLAG_EXCLUSIVE, &dpo_v4);
      dpo_reset (&dpo_v4);
    }
  else
    {
      if (!a)
	return VNET_API_ERROR_NO_SUCH_ENTRY;
#define _(N, id, n, s) \
      clib_bitmap_free (a->busy_##n##_port_bitmap); \
      vec_free (a->busy_##n##_ports_per_thread);
      foreach_snat_protocol
#undef _
	fib_table_entry_special_remove (0, &pfx, FIB_SOURCE_PLUGIN_HI);
      vec_del1 (dm->addr_pool, i);
    }
  return 0;
}

u8 *
format_dslite_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  dslite_trace_t *t = va_arg (*args, dslite_trace_t *);

  s =
    format (s, "next index %d, session %d", t->next_index, t->session_index);

  return s;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
