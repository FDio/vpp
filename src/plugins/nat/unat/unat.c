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

#include <stdbool.h>
#include <vlib/vlib.h>
#include <vnet/feature/feature.h>
#include <vppinfra/clib_error.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/reass/ip4_sv_reass.h>
#include "pool.h"
#include "unat.h"
#include <vnet/ip/format.h>
#include <arpa/inet.h>
#include <vnet/ip/ip4.h>
#include "cdb.h"
#include <math.h>
#include <vnet/fib/fib_table.h>

extern vlib_node_registration_t unat_fp_i2o_node;
extern vlib_node_registration_t unat_fp_o2i_node;
extern vlib_node_registration_t unat_sp_i2o_node;
extern vlib_node_registration_t unat_sp_o2i_node;

static bool
unat_validate_configuration (void)
{
  unat_main_t *um = &unat_main;
  u32 in2out = 0, out2in = 0;

  /* Validate pool */
  if (vec_len(um->pool_per_thread) == 0 || um->pool_per_thread[0] == ~0) {
    return false;
  }

  if (vec_len(um->sessions_per_worker) == 0) {
    return false;
  }

  /* Validate inside and outside interfaces */
  unat_interface_t *interface;
  pool_foreach(interface, um->interfaces,
	       ({
		 if (interface->in2out) in2out++;
		 if (!interface->in2out) out2in++;
	       }));
  if (in2out == 0 || out2in == 0) return false;

  return true;
}

void
unat_reset_tables (void)
{
  unat_main_t *um = &unat_main;
  int i;
  vlib_main_t *vm = vlib_get_main();

  /* New */
  clib_bihash_16_8_t flowhash = { 0 };
  unat_session_t **sessions_per_worker = 0;
  dlist_elt_t **lru_pool = 0;
  u32 *lru_head_index = 0;

  vec_validate (sessions_per_worker, um->no_threads);
  vec_validate (lru_pool, um->no_threads);
  vec_validate (lru_head_index, um->no_threads);

  /* Old */
  clib_bihash_16_8_t old_flowhash;
  unat_session_t **old_sessions_per_worker;
  dlist_elt_t **old_lru_pool;

  /* Create new tables */
  clib_bihash_init_16_8 (&flowhash, "flow hash", um->max_sessions, um->max_sessions * 250);

  /* per-worker */
  for (i = 0; i < um->no_threads + 1; i++) {
    pool_init_fixed(sessions_per_worker[i], um->max_sessions);
    pool_init_fixed (lru_pool[i], um->max_sessions);

    dlist_elt_t *head;
    pool_get (lru_pool[i], head);
    lru_head_index[i] = head - lru_pool[i];
    clib_dlist_init (lru_pool[i], lru_head_index[i]);
  }

  /* Swap with old */
  vlib_worker_thread_barrier_sync(vm);

  old_flowhash = um->flowhash;

  old_sessions_per_worker = um->sessions_per_worker;
  old_lru_pool = um->lru_pool;

  um->flowhash = flowhash;

  um->sessions_per_worker = sessions_per_worker;
  um->lru_pool = lru_pool;
  um->lru_head_index = lru_head_index;

  vlib_worker_thread_barrier_release(vm);

  /* Free old */
  if (old_sessions_per_worker) {
    clib_bihash_free_16_8(&old_flowhash);

    for (i = 0; i < um->no_threads + 1; i++) {
      pool_free(old_sessions_per_worker[i]);
      pool_free (old_lru_pool[i]);
    }
    vec_free(old_sessions_per_worker);
    vec_free(old_lru_pool);
  }
}

/*
 * Will not enable NAT until all required configuration is in place.
 * XXX: If this funtion fails, it will leave the configuration in undefined state.
 */
clib_error_t *
unat_enable (vlib_main_t *vm)
{
  unat_main_t *um = &unat_main;

  if (um->enabled) return 0;
  if (!unat_validate_configuration()) return 0;

  /*
   * Register fast path handover
   */
  um->handoff_i2o_node = "unat-handoff";
  um->handoff_o2i_node = "unat-handoff-o2i";

  um->fast_path_i2o_node_index = vlib_frame_queue_main_init (unat_fp_i2o_node.index, 64);
  um->fast_path_o2i_node_index = vlib_frame_queue_main_init (unat_fp_o2i_node.index, 64);

  clib_spinlock_init(&um->counter_lock);
  clib_spinlock_lock (&um->counter_lock); /* should be no need */

  vec_validate (um->counters, UNAT_N_COUNTER - 1);
#define _(E,n,p)                                                        \
  um->counters[UNAT_COUNTER_##E].name = #n;				\
  um->counters[UNAT_COUNTER_##E].stat_segment_name = "/" #p "/" #n;	\
  vlib_validate_simple_counter (&um->counters[UNAT_COUNTER_##E], 0);	\
  vlib_zero_simple_counter (&um->counters[UNAT_COUNTER_##E], 0);
  foreach_unat_counter_name
#undef _
    clib_spinlock_unlock (&um->counter_lock);

  unat_interface_t *interface;
  pool_foreach(interface, um->interfaces,
	       ({
		 /* Enable NAT packet processing on outside interface */
		 if (interface->in2out == false) {
		   if (vnet_feature_enable_disable ("ip4-unicast", um->handoff_o2i_node,
						    interface->sw_if_index, 1, 0, 0) != 0)
		     return clib_error_return(0, "VNET feature enable failed on %u", interface->sw_if_index);
		   if (vnet_feature_enable_disable ("ip4-output", um->handoff_i2o_node,
						    interface->sw_if_index, 1, 0, 0) != 0)
		     return clib_error_return(0, "VNET feature enable failed on %u", interface->sw_if_index);
		 }

		 ip4_sv_reass_enable_disable_with_refcnt (interface->sw_if_index, 1);
	       }));

  um->enabled = true;

  return 0;
}

void
unat_register_interface (u32 sw_if_index, u32 node_index, bool in2out)
{
  unat_main_t *um = &unat_main;
  unat_interface_t *interface;

  pool_get (um->interfaces, interface);
  interface->sw_if_index = sw_if_index;
  vec_validate_init_empty(um->interface_by_sw_if_index, sw_if_index, ~0);
  um->interface_by_sw_if_index[sw_if_index] = interface - um->interfaces;
  interface->in2out = in2out;
}

void
unat_ip4_add_del_interface_address_cb (ip4_main_t * im,
                                       uword opaque,
                                       u32 sw_if_index,
                                       ip4_address_t * address,
                                       u32 address_length,
                                       u32 if_address_index, u32 is_delete)
{
  unat_main_t *um = &unat_main;
  if (um->pool_sw_if_index != sw_if_index) {
    return;
  }

  /*
   * Delete pools belonging to that part of the configuration
   * Delete session table
   * Re-create sub-pools
   */

  /* Check if this is an address we are interested in */
  //cbb_lookup("/unat/pool/interface/sw_if_index");
  
  cdb_notify_path(um->cdb, "/unat/pool/interface");
}

u8 *
format_unat_state (u8 *s, va_list * args)
{
  enum unat_session_state state = va_arg (*args, enum unat_session_state);

  switch (state) {
  case UNAT_STATE_TCP_SYN_SEEN:
    s = format (s, "syn seen");
    break;
  case UNAT_STATE_TCP_ESTABLISHED:
    s = format (s, "tcp established");
    break;
  case UNAT_STATE_TCP_FIN_WAIT:
    s = format (s, "tcp fin wait");
    break;
  case UNAT_STATE_TCP_CLOSE_WAIT:
    s = format (s, "tcp close wait");
    break;
  case UNAT_STATE_TCP_CLOSED:
    s = format (s, "tcp closed");
    break;
  case UNAT_STATE_TCP_LAST_ACK:
    s = format (s, "tcp last ack");
    break;
  case UNAT_STATE_UNKNOWN:
  default:
    s = format (s, "unknown");
  }
  return s;
}

u8 *
format_unat_fp_session (u8 * s, va_list * args)
{
  unat_fp_session_t *ses = va_arg (*args, unat_fp_session_t *);

  if (ses->instructions & (UNAT_INSTR_DESTINATION_ADDRESS|UNAT_INSTR_DESTINATION_PORT)) {
    s = format (s,
		"%U%%%u:%u -> %U:%u (%U:%u) state: %U",
		format_ip4_address, &ses->k.sa,	ses->fib_index, ntohs(ses->k.sp),
		format_ip4_address, &ses->k.da, ntohs(ses->k.dp),
		format_ip4_address, &ses->post_da, ntohs(ses->post_dp),
		format_unat_state, ses->state);
  } else if (ses->instructions & (UNAT_INSTR_SOURCE_ADDRESS|UNAT_INSTR_SOURCE_PORT)) {
    s = format (s,
		"%U%%%u:%u (%U:%u) -> %U:%u state: %U",
		format_ip4_address, &ses->k.sa, ses->fib_index, ntohs(ses->k.sp),
		format_ip4_address, &ses->post_sa, ntohs(ses->post_sp),
		format_ip4_address, &ses->k.da, ntohs(ses->k.dp),
		format_unat_state, ses->state);
  } else
    s = format (s, "UNKNOWN INSTRUCTIONS %u", ses->instructions);
  s = format (s, "\n");
  return s;
}

u8 *
format_unat_session (u8 * s, va_list * args)
{
  vlib_main_t *vm = vlib_get_main ();
  f64 now = vlib_time_now (vm);
  u32 poolidx = va_arg (*args, u32);
  unat_session_t *ses = va_arg (*args, unat_session_t *);

  s = format(s, "[%-8u] i2o: %U", poolidx, format_unat_fp_session, &ses->in2out);
  s = format(s, "          o2i: %U", format_unat_fp_session, &ses->out2in);
  s = format(s, "          last heard: %.2f", now - ses->last_heard);
  s = format (s, "\n");
  return s;
}


static void
unat_cfg_pool_prefix (void *data, int is_add, u32 index)
{
  unat_cfg_pool_t *cfg = data;
  unat_main_t *um = &unat_main;
  u8 psid_length = (int)(log2(um->no_threads + 1) + 0.5);
  u32 poolindex;
  int i;

  /* Delete existing pools */
  u32 *pi;
  vec_foreach (pi, um->pool_per_thread) {
    if (*pi != ~0)
      pool_del_addr_pool(*pi);
  }

  /* Create per-thread pools */
  for (i = 0; i < um->no_threads + 1; i++) {
    poolindex = pool_add_addr_pool (&cfg->prefix, cfg->prefixlen, psid_length, i, cfg->vrf_id, i);
    um->pool_per_thread[i] = poolindex;
  }
}

static void
unat_cfg_pool_interface (void *data, int is_add, u32 index)
{
  unat_cfg_pool_interface_t *cfg = data;
  unat_main_t *um = &unat_main;
  u8 psid_length = (int)(log2(um->no_threads + 1) + 0.5);
  u32 poolindex;
  int i;
  ip4_address_t *a;
  ip4_main_t *i4m = &ip4_main;

  if (um->pool_is_interface_address == false) { // Not yet configured
    /* Set up the interface address add/del callback */
    ip4_add_del_interface_address_callback_t cb4 =
      {
       .function = unat_ip4_add_del_interface_address_cb,
       .function_opaque = 0
      };
    ip4_main_t *im = &ip4_main;
    vec_add1 (im->add_del_interface_address_callbacks, cb4);
    um->pool_is_interface_address = true;
  }
  um->pool_sw_if_index = cfg->sw_if_index;
  a = ip4_interface_first_address(i4m, cfg->sw_if_index, 0);
  if (!a) return; /* Create pools as part of callback */

  u32 vrf_id = fib_table_get_index_for_sw_if_index (FIB_PROTOCOL_IP4, cfg->sw_if_index);

  /* Delete existing pools */
  u32 *pi;
  vec_foreach (pi, um->pool_per_thread) {
    if (*pi != ~0)
      pool_del_addr_pool(*pi);
  }

  /* Create new pools */
  for (i = 0; i < um->no_threads + 1; i++) {
    poolindex = pool_add_addr_pool (a, 32, psid_length, i, vrf_id, i);
    um->pool_per_thread[i] = poolindex;
  }
}

void
unat_cfg_pool (void *data, int mode, u32 index)
{
  /* Pool configuration has changed */
  unat_reset_tables();
  unat_enable(vlib_get_main());
}


void
unat_cfg_interface (void *data, int mode, u32 index)
{
  unat_cfg_interface_t *cfg = data, *c = &cfg[index];

  unat_register_interface(c->sw_if_index,
			  c->in2out ? unat_sp_i2o_node.index : unat_sp_o2i_node.index,
			  c->in2out);
  unat_enable(vlib_get_main());
}

void
unat_cfg_params (void *data, int mode, u32 index)
{
  unat_cfg_params_t *cfg = data;
  unat_main_t *um = &unat_main;

  /* Only change if set / different from default */
  /* If max-sessions is changed, reset all tables */
  um->max_sessions = cfg->max_sessions;
  um->default_timeout = cfg->default_timeout;
  um->icmp_timeout = cfg->icmp_timeout;
  um->udp_timeout = cfg->udp_timeout;
  um->tcp_transitory_timeout = cfg->tcp_transitory_timeout;
  um->tcp_established_timeout = cfg->tcp_established_timeout;

}

clib_error_t *
unat_init (vlib_main_t * vm)
{
  unat_main_t *um = &unat_main;

  memset (um, 0, sizeof(*um));

  um->max_sessions = 1 << 20;	/* Default 1M sessions */
  um->default_timeout = 200;
  um->icmp_timeout = 10;
  um->udp_timeout = 200;
  um->tcp_transitory_timeout = 10;
  um->tcp_established_timeout = 30;
  um->no_threads = vlib_num_workers();
  vec_validate_init_empty(um->pool_per_thread, um->no_threads, ~0);

  /* Configuration database */
  um->cdb = cdb_init("configuration store");
  cdb_subscribe(um->cdb, "/unat/pool/interface", unat_cfg_pool_interface);
  cdb_subscribe(um->cdb, "/unat/pool/prefix", unat_cfg_pool_prefix);
  cdb_subscribe(um->cdb, "/unat/pool", unat_cfg_pool);
  cdb_subscribe(um->cdb, "/unat/interfaces", unat_cfg_interface);
  cdb_subscribe(um->cdb, "/unat/parameters", unat_cfg_params);
  return 0;
}

VLIB_INIT_FUNCTION (unat_init);
