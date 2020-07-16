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
#include <vnet/plugin/plugin.h>
#include <nat/dslite/dslite.h>
#include <nat/dslite/dslite_dpo.h>
#include <vnet/fib/fib_table.h>
#include <vpp/app/version.h>

dslite_main_t dslite_main;
fib_source_t nat_fib_src_hi;

clib_error_t *dslite_api_hookup (vlib_main_t * vm);

void
add_del_dslite_pool_addr_cb (ip4_address_t addr, u8 is_add, void *opaque);

static clib_error_t *
dslite_init (vlib_main_t * vm)
{
  dslite_main_t *dm = &dslite_main;
  vlib_thread_registration_t *tr;
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  uword *p;
  vlib_node_t *node;
  dslite_per_thread_data_t *td;
  u32 translation_buckets = 1024;
  u32 translation_memory_size = 128 << 20;
  u32 b4_buckets = 128;
  u32 b4_memory_size = 64 << 20;

  node = vlib_get_node_by_name (vm, (u8 *) "dslite-in2out");
  dm->dslite_in2out_node_index = node->index;

  node = vlib_get_node_by_name (vm, (u8 *) "dslite-in2out-slowpath");
  dm->dslite_in2out_slowpath_node_index = node->index;

  node = vlib_get_node_by_name (vm, (u8 *) "dslite-out2in");
  dm->dslite_out2in_node_index = node->index;

  dm->first_worker_index = 0;
  dm->num_workers = 0;

  // init nat address pool
  dm->pool.add_del_pool_addr_cb = add_del_dslite_pool_addr_cb;
  dm->pool.alloc_addr_and_port_cb = nat_alloc_ip4_addr_and_port_cb_default;

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

  dm->is_ce = 0;

  /* Init counters */
  dm->total_b4s.name = "total-b4s";
  dm->total_b4s.stat_segment_name = "/dslite/total-b4s";
  vlib_validate_simple_counter (&dm->total_b4s, 0);
  vlib_zero_simple_counter (&dm->total_b4s, 0);
  dm->total_sessions.name = "total-sessions";
  dm->total_sessions.stat_segment_name = "/dslite/total-sessions";
  vlib_validate_simple_counter (&dm->total_sessions, 0);
  vlib_zero_simple_counter (&dm->total_sessions, 0);

  dslite_dpo_module_init ();

  nat_fib_src_hi = fib_source_allocate ("dslite-hi",
					FIB_SOURCE_PRIORITY_HI,
					FIB_SOURCE_BH_SIMPLE);

  return dslite_api_hookup (vm);
}

void
dslite_set_ce (dslite_main_t * dm, u8 set)
{
  dm->is_ce = (set != 0);
}

static clib_error_t *
dslite_config (vlib_main_t * vm, unformat_input_t * input)
{
  dslite_main_t *dm = &dslite_main;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "ce"))
	dslite_set_ce (dm, 1);
    }
  return 0;
}

VLIB_CONFIG_FUNCTION (dslite_config, "dslite");

int
dslite_set_aftr_ip6_addr (dslite_main_t * dm, ip6_address_t * addr)
{
  dpo_id_t dpo = DPO_INVALID;

  if (dm->is_ce)
    {
      dslite_ce_dpo_create (DPO_PROTO_IP4, 0, &dpo);
      fib_prefix_t pfx = {
	.fp_proto = FIB_PROTOCOL_IP4,
	.fp_len = 0,
	.fp_addr.ip4.as_u32 = 0,
      };
      fib_table_entry_special_dpo_add (0, &pfx, nat_fib_src_hi,
				       FIB_ENTRY_FLAG_EXCLUSIVE, &dpo);
    }
  else
    {
      dslite_dpo_create (DPO_PROTO_IP6, 0, &dpo);
      fib_prefix_t pfx = {
	.fp_proto = FIB_PROTOCOL_IP6,
	.fp_len = 128,
	.fp_addr.ip6.as_u64[0] = addr->as_u64[0],
	.fp_addr.ip6.as_u64[1] = addr->as_u64[1],
      };
      fib_table_entry_special_dpo_add (0, &pfx, nat_fib_src_hi,
				       FIB_ENTRY_FLAG_EXCLUSIVE, &dpo);
    }

  dpo_reset (&dpo);

  dm->aftr_ip6_addr.as_u64[0] = addr->as_u64[0];
  dm->aftr_ip6_addr.as_u64[1] = addr->as_u64[1];
  return 0;
}

int
dslite_set_aftr_ip4_addr (dslite_main_t * dm, ip4_address_t * addr)
{
  dm->aftr_ip4_addr.as_u32 = addr->as_u32;
  return 0;
}

int
dslite_set_b4_ip6_addr (dslite_main_t * dm, ip6_address_t * addr)
{
  if (dm->is_ce)
    {
      dpo_id_t dpo = DPO_INVALID;

      dslite_ce_dpo_create (DPO_PROTO_IP6, 0, &dpo);
      fib_prefix_t pfx = {
	.fp_proto = FIB_PROTOCOL_IP6,
	.fp_len = 128,
	.fp_addr.ip6.as_u64[0] = addr->as_u64[0],
	.fp_addr.ip6.as_u64[1] = addr->as_u64[1],
      };
      fib_table_entry_special_dpo_add (0, &pfx, nat_fib_src_hi,
				       FIB_ENTRY_FLAG_EXCLUSIVE, &dpo);

      dpo_reset (&dpo);

      dm->b4_ip6_addr.as_u64[0] = addr->as_u64[0];
      dm->b4_ip6_addr.as_u64[1] = addr->as_u64[1];
    }
  else
    {
      return VNET_API_ERROR_FEATURE_DISABLED;
    }

  return 0;
}

int
dslite_set_b4_ip4_addr (dslite_main_t * dm, ip4_address_t * addr)
{
  if (dm->is_ce)
    {
      dm->b4_ip4_addr.as_u32 = addr->as_u32;
    }
  else
    {
      return VNET_API_ERROR_FEATURE_DISABLED;
    }

  return 0;
}

void
add_del_dslite_pool_addr_cb (ip4_address_t addr, u8 is_add, void *opaque)
{
  dpo_id_t dpo_v4 = DPO_INVALID;
  fib_prefix_t pfx = {
    .fp_proto = FIB_PROTOCOL_IP4,
    .fp_len = 32,
    .fp_addr.ip4.as_u32 = addr.as_u32,
  };

  if (is_add)
    {
      dslite_dpo_create (DPO_PROTO_IP4, 0, &dpo_v4);
      fib_table_entry_special_dpo_add (0, &pfx, nat_fib_src_hi,
				       FIB_ENTRY_FLAG_EXCLUSIVE, &dpo_v4);
      dpo_reset (&dpo_v4);
    }
  else
    {
      fib_table_entry_special_remove (0, &pfx, nat_fib_src_hi);
    }
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

u8 *
format_dslite_ce_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  dslite_ce_trace_t *t = va_arg (*args, dslite_ce_trace_t *);

  s = format (s, "next index %d", t->next_index);

  return s;
}

VLIB_INIT_FUNCTION (dslite_init);

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () =
{
  .version = VPP_BUILD_VER,
  .description = "Dual-Stack Lite",
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
