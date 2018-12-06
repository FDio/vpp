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
#include <nat/lwb4.h>
#include <nat/lwb4_dpo.h>
#include <vnet/fib/fib_table.h>

lwb4_main_t lwb4_main;

void
lwb4_init (vlib_main_t * vm)
{
  lwb4_main_t *dm = &lwb4_main;
  vlib_thread_registration_t *tr;
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  uword *p;
  lwb4_per_thread_data_t *td;
  u32 translation_buckets = 1024;
  u32 translation_memory_size = 128 << 20;

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

  vec_validate (dm->per_thread_data, tm->n_vlib_mains - 1);

  /* *INDENT-OFF* */
  vec_foreach (td, dm->per_thread_data)
    {
      clib_bihash_init_8_8 (&td->in2out, "in2out", translation_buckets,
                             translation_memory_size);

      clib_bihash_init_8_8 (&td->out2in, "out2in", translation_buckets,
                            translation_memory_size);
    }
  /* *INDENT-ON* */

  lwb4_dpo_module_init ();
}

int
lwb4_port_in_psid (lwb4_main_t * dm, u16 port)
{
  u16 psid_mask = (1 << dm->psid_length) - 1;
  if (((port >> dm->psid_shift) & psid_mask) == dm->psid)
    return 1;
  return 0;
}

int
lwb4_set_aftr_ip6_addr (lwb4_main_t * dm, ip6_address_t * addr)
{
  dpo_id_t dpo = DPO_INVALID;

  lwb4_dpo_create (DPO_PROTO_IP4, 0, &dpo);
  fib_prefix_t pfx = {
    .fp_proto = FIB_PROTOCOL_IP4,
    .fp_len = 0,
    .fp_addr.ip4.as_u32 = 0,
  };
  fib_table_entry_special_dpo_add (0, &pfx, FIB_SOURCE_PLUGIN_HI,
				   FIB_ENTRY_FLAG_EXCLUSIVE, &dpo);

  dpo_reset (&dpo);

  dm->aftr_ip6_addr.as_u64[0] = addr->as_u64[0];
  dm->aftr_ip6_addr.as_u64[1] = addr->as_u64[1];
  return 0;
}

int
lwb4_set_b4_params (lwb4_main_t * dm, ip6_address_t * ip6_addr,
		    ip4_address_t * ip4_addr, u8 psid_length, u8 psid_shift,
		    u16 psid)
{
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  dpo_id_t dpo = DPO_INVALID;
  snat_address_t *a = &dm->snat_addr;

  lwb4_dpo_create (DPO_PROTO_IP6, 0, &dpo);
  fib_prefix_t pfx = {
    .fp_proto = FIB_PROTOCOL_IP6,
    .fp_len = 128,
    .fp_addr.ip6.as_u64[0] = ip6_addr->as_u64[0],
    .fp_addr.ip6.as_u64[1] = ip6_addr->as_u64[1],
  };
  fib_table_entry_special_dpo_add (0, &pfx, FIB_SOURCE_PLUGIN_HI,
				   FIB_ENTRY_FLAG_EXCLUSIVE, &dpo);

  dpo_reset (&dpo);

  dm->b4_ip6_addr.as_u64[0] = ip6_addr->as_u64[0];
  dm->b4_ip6_addr.as_u64[1] = ip6_addr->as_u64[1];
  dm->b4_ip4_addr.as_u32 = ip4_addr->as_u32;

  dm->psid = psid;
  dm->psid_length = psid_length;
  dm->psid_shift = psid_shift;

  /* Allocate ports according to lw46/MAP-E mapping */
  nat_set_alloc_addr_and_port_mape (psid, 16 - psid_length - psid_shift,
				    psid_length);

  /* Initialize busy ports, none are busy */
  dm->snat_addr.addr.as_u32 = ip4_addr->as_u32;
  a->fib_index = 0;
#define _(N, i, n, s) \
  clib_bitmap_alloc (a->busy_##n##_port_bitmap, 65535); \
  a->busy_##n##_ports = 0; \
  vec_validate_init_empty (a->busy_##n##_ports_per_thread, tm->n_vlib_mains - 1, 0);
  foreach_snat_protocol
#undef _
    dm->addr_pool = 0;
  vec_add1 (dm->addr_pool, dm->snat_addr);

  return 0;
}

u8 *
format_lwb4_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  lwb4_trace_t *t = va_arg (*args, lwb4_trace_t *);

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
