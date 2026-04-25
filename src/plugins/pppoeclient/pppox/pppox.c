/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2017 RaydoNetworks.
 * Copyright (c) 2026 Hi-Jiajun.
 */
#include <stdint.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <inttypes.h>

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/dpo/interface_tx_dpo.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>

#include <pppoeclient/pppox/pppd/pppd.h>
#include <pppoeclient/pppox/pppd/fsm.h>
#include <pppoeclient/pppox/pppd/lcp.h>
#include <pppoeclient/pppox/pppd/ipcp.h>
#include <pppoeclient/pppox/pppd/ipv6cp.h>
#include <pppoeclient/pppox/pppd/upap.h>
#include <pppoeclient/pppox/pppd/chap-new.h>
#include <pppoeclient/pppox/pppd/magic.h>

#define PPP_PROTOCOL_IP4      0x0021
#define PPP_PROTOCOL_IP6      0x0057
#define PPP_PROTOCOL_IPX      0x002B
#define PPP_PROTOCOL_VJ_COMP  0x002D
#define PPP_PROTOCOL_VJ_UCOMP 0x002F
extern void pppd_calltimeout (void);

#include <pppoeclient/pppox/pppox.h>

#include <vppinfra/hash.h>
#include <vppinfra/bihash_template.c>

#define PPPOX_PPPOECLIENT_DISCONNECT_PPP_DEAD  4
#define PPPOX_PPPOECLIENT_DISCONNECT_AUTH_FAIL 5

__clib_export pppox_main_t pppox_main;

static_always_inline u8
pppox_unit_is_valid (u32 unit)
{
  return unit != ~0 && unit < NUM_PPP;
}

/* Sticky per-unit flag set by the imported pppd auth.c on CHAP / PAP
 * rejection; consumed (and cleared) by the pppox cleanup / restart paths so
 * the pppoeclient side can distinguish authentication denial from a generic
 * PPP teardown and lengthen its rediscovery backoff accordingly. */
static u8 pppox_auth_failed_flag[NUM_PPP];

__clib_export void
pppox_note_auth_failure (int unit)
{
  if (unit < 0 || !pppox_unit_is_valid ((u32) unit))
    return;
  pppox_auth_failed_flag[unit] = 1;
}

static u8
pppox_consume_auth_failed_flag (int unit)
{
  u8 was_set;

  if (unit < 0 || !pppox_unit_is_valid ((u32) unit))
    return 0;
  was_set = pppox_auth_failed_flag[unit];
  pppox_auth_failed_flag[unit] = 0;
  return was_set;
}

static char *
pppox_dup_c_string_vec (u8 *src)
{
  char *dst = 0;
  u32 len;

  if (src == 0)
    return 0;

  len = vec_len (src);
  vec_validate (dst, len);
  clib_memcpy (dst, src, len);
  dst[len] = 0;
  return dst;
}

void pppox_handle_allocated_address (pppox_virtual_interface_t *t, u8 is_add);
static void pppox_handle_allocated_ipv6_address (pppox_virtual_interface_t *t, u8 is_add);

static pppox_virtual_interface_t *
pppox_get_virtual_interface_by_unit (pppox_main_t *pom, u32 unit)
{
  if (!pppox_unit_is_valid (unit) || unit >= vec_len (pom->virtual_interfaces) ||
      pool_is_free_index (pom->virtual_interfaces, unit))
    return 0;

  return pool_elt_at_index (pom->virtual_interfaces, unit);
}

static pppox_virtual_interface_t *
pppox_get_virtual_interface_by_sw_if_index (pppox_main_t *pom, u32 sw_if_index, u32 *unit)
{
  pppox_virtual_interface_t *t;
  u32 pool_index;

  if (unit)
    *unit = ~0;

  if (sw_if_index >= vec_len (pom->virtual_interface_index_by_sw_if_index))
    return 0;

  pool_index = pom->virtual_interface_index_by_sw_if_index[sw_if_index];
  t = pppox_get_virtual_interface_by_unit (pom, pool_index);
  if (t && unit)
    *unit = pool_index;

  return t;
}

/* This function is adapted to oss pppd main.c:get_input.
 * refer to pppoeclient_session_input to see what packets can
 * be delivered here, if new protocol enabled, should modify
 * there too. */
int
consume_pppox_ctrl_pkt (u32 bi, vlib_buffer_t *b)
{
  pppox_main_t *pom = &pppox_main;
  u32 sw_if_index = vnet_buffer (b)->sw_if_index[VLIB_RX];
  pppox_virtual_interface_t *t = 0;
  u8 *p = 0;
  int i = 0;
  u16 protocol = 0;
  struct protent *protp;
  int len = pppox_buffer (b)->len;
  u32 unit;

  /* If instance is deleted, simple return. */
  t = pppox_get_virtual_interface_by_sw_if_index (pom, sw_if_index, &unit);
  if (t == 0 || !pppox_unit_is_valid (unit))
    return 1;

  clib_spinlock_lock_if_init (&pom->ctrl_lock);

  p = vlib_buffer_get_current (b);

  if (len < 2)
    {
      clib_spinlock_unlock_if_init (&pom->ctrl_lock);
      return 1;
    }

  GETSHORT (protocol, p);
  /* Our pppox frame will only have a 16B protocol field. */
  len -= 2;

  if (protocol != PPP_LCP && lcp_fsm[unit].state != OPENED)
    {
      clib_spinlock_unlock_if_init (&pom->ctrl_lock);
      return 1;
    }

  if (phase[unit] <= PHASE_AUTHENTICATE &&
      !(protocol == PPP_LCP || protocol == PPP_PAP || protocol == PPP_CHAP))
    {
      clib_spinlock_unlock_if_init (&pom->ctrl_lock);
      return 1;
    }

  for (i = 0; (protp = protocols[i]) != NULL; ++i)
    {
      if (protp->protocol == protocol && protp->enabled_flag)
	{
	  (*protp->input) (unit, p, len);
	  clib_spinlock_unlock_if_init (&pom->ctrl_lock);
	  return 0;
	}
      if (protocol == (protp->protocol & ~0x8000) && protp->enabled_flag &&
	  protp->datainput != NULL)
	{
	  (*protp->datainput) (unit, p, len);
	  clib_spinlock_unlock_if_init (&pom->ctrl_lock);
	  return 0;
	}
    }

  lcp_sprotrej (unit, p - PPP_HDRLEN, len + PPP_HDRLEN);
  clib_spinlock_unlock_if_init (&pom->ctrl_lock);

  return 1;
}

/*
 * restart_dead_client - restart dead pppoe client to reconnect.
 */
static void
pppox_restart_dead_client (void)
{
  pppox_main_t *pom = &pppox_main;
  pppox_virtual_interface_t *vif;
  static void (*pppoeclient_restart_session_with_reason_func) (u32 client_index,
							       u8 disconnect_reason) = 0;
  static void (*pppoeclient_restart_session_func) (u32 client_index) = 0;

  if (pppoeclient_restart_session_with_reason_func == 0 && pppoeclient_restart_session_func == 0)
    {
      pppoeclient_restart_session_with_reason_func =
	vlib_get_plugin_symbol ("pppoeclient_plugin.so", "pppoeclient_restart_session_with_reason");
      if (pppoeclient_restart_session_with_reason_func == 0)
	pppoeclient_restart_session_func =
	  vlib_get_plugin_symbol ("pppoeclient_plugin.so", "pppoeclient_restart_session");
    }
  if (pppoeclient_restart_session_with_reason_func == 0 && pppoeclient_restart_session_func == 0)
    return;
  if (pom->is_shutting_down)
    return;

  pool_foreach (vif, pom->virtual_interfaces)
    {
      u32 unit = vif - pom->virtual_interfaces;

      if (!pppox_unit_is_valid (unit))
	continue;

      if (phase[unit] == PHASE_DEAD && vif->pppoe_session_allocated && !vif->delete_pending)
	{
	  u8 reason = pppox_consume_auth_failed_flag ((int) unit) ?
			PPPOX_PPPOECLIENT_DISCONNECT_AUTH_FAIL :
			PPPOX_PPPOECLIENT_DISCONNECT_PPP_DEAD;
	  if (pppoeclient_restart_session_with_reason_func)
	    (*pppoeclient_restart_session_with_reason_func) (vif->pppoeclient_index, reason);
	  else
	    (*pppoeclient_restart_session_func) (vif->pppoeclient_index);
	}
    }
}

static void
pppox_cleanup_virtual_interface (u32 unit)
{
  if (!pppox_unit_is_valid (unit))
    return;

  /* pap client. */
  if (upap[unit].us_user)
    {
      vec_free (upap[unit].us_user);
      upap[unit].us_user = NULL;
      upap[unit].us_userlen = 0;
    }
  if (upap[unit].us_passwd)
    {
      clib_memset (upap[unit].us_passwd, 0, vec_len (upap[unit].us_passwd));
      vec_free (upap[unit].us_passwd);
      upap[unit].us_passwd = NULL;
      upap[unit].us_passwdlen = 0;
    }

  /* chap client. */
  if (chap_client[unit].us_user)
    {
      vec_free (chap_client[unit].us_user);
      chap_client[unit].us_user = NULL;
      chap_client[unit].us_userlen = 0;
    }
  if (chap_client[unit].us_passwd)
    {
      clib_memset (chap_client[unit].us_passwd, 0, vec_len (chap_client[unit].us_passwd));
      vec_free (chap_client[unit].us_passwd);
      chap_client[unit].us_passwd = NULL;
      chap_client[unit].us_passwdlen = 0;
    }
}

static void
pppox_clear_allocated_runtime_state (pppox_virtual_interface_t *t)
{
  if (t->our_addr || t->his_addr)
    {
      pppox_handle_allocated_address (t, 0 /* is_del */);
      t->our_addr = 0;
      t->his_addr = 0;
    }

  if (!ip6_address_is_zero (&t->our_ipv6) || !ip6_address_is_zero (&t->his_ipv6))
    {
      pppox_handle_allocated_ipv6_address (t, 0 /* is_del */);
      ip6_address_set_zero (&t->our_ipv6);
      ip6_address_set_zero (&t->his_ipv6);
    }
}

static uword
pppox_process (vlib_main_t *vm, vlib_node_runtime_t *rt, vlib_frame_t *f)
{
  pppox_main_t *pom = &pppox_main;
  uword event_type;
  uword *event_data = 0;

  while (1)
    {
      /*
       * Drive the imported pppd timers with a simple one-second tick.
       * The shim currently operates on whole-second granularity, so a
       * finer wait calculation is not required here.
       */
      vlib_process_wait_for_event_or_clock (vm, 1); /* 1 second. */

      event_type = vlib_process_get_events (vm, &event_data);

      switch (event_type)
	{
	case ~0:
	  clib_spinlock_lock_if_init (&pom->ctrl_lock);
	  pppd_calltimeout ();
	  clib_spinlock_unlock_if_init (&pom->ctrl_lock);
	  /* We need restart dead client due to various reason. */
	  pppox_restart_dead_client ();
	  break;
	}

      vec_reset_length (event_data);
    }

  /* NOTREACHED */
  return 0;
}

VLIB_REGISTER_NODE (pppox_process_node, static) = {
  .function = pppox_process,
  .type = VLIB_NODE_TYPE_PROCESS,
  .name = "pppox-process",
  .process_log2_n_stack_bytes = 16,
};

static u8 *
format_pppox_name (u8 *s, va_list *args)
{
  u32 dev_instance = va_arg (*args, u32);
  pppox_main_t *pom = &pppox_main;
  pppox_virtual_interface_t *t;

  if (!pool_is_free_index (pom->virtual_interfaces, dev_instance))
    {
      t = pool_elt_at_index (pom->virtual_interfaces, dev_instance);
      if (vec_len (t->custom_name))
	return format (s, "%v", t->custom_name);
    }
  return format (s, "pppox%d", dev_instance);
}

static uword
dummy_interface_tx (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  /* PPPOX interfaces never transmit via the generic device path. */
  u32 *from = vlib_frame_vector_args (frame);
  vlib_buffer_free (vm, from, frame->n_vectors);
  return frame->n_vectors;
}

static clib_error_t *
pppox_interface_admin_up_down (vnet_main_t *vnm, u32 hw_if_index, u32 flags)
{
  u32 hw_flags = (flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP) ? VNET_HW_INTERFACE_FLAG_LINK_UP : 0;
  vnet_hw_interface_set_flags (vnm, hw_if_index, hw_flags);

  return /* no error */ 0;
}

static u8 *
pppox_build_rewrite (vnet_main_t *vnm, u32 sw_if_index, vnet_link_t link_type,
		     const void *dst_address)
{
  /* only need append a 16B protocol filed. */
  int len = 2;
  u8 *rw = 0;

  vec_validate (rw, len - 1);

  switch (link_type)
    {
    case VNET_LINK_IP4:
      *((u16 *) rw) = clib_host_to_net_u16 (PPP_PROTOCOL_IP4);
      break;
    case VNET_LINK_IP6:
      *((u16 *) rw) = clib_host_to_net_u16 (PPP_PROTOCOL_IP6);
      break;
    default:
      vec_free (rw);
      return NULL;
    }

  return rw;
}
VNET_DEVICE_CLASS (pppox_device_class, static) = {
  .name = "PPPOX",
  .format_device_name = format_pppox_name,
  .tx_function = dummy_interface_tx,
  .admin_up_down_function = pppox_interface_admin_up_down,
};
VNET_HW_INTERFACE_CLASS (pppox_hw_class, static) = {
  .name = "PPPOX",
  .build_rewrite = pppox_build_rewrite,
  /* Do not need leverage adj, use default update adj with
   * our own rewrite to insert the ppp protocol field. */
  /*.update_adjacency = pppox_update_adj,*/
  .flags = VNET_HW_INTERFACE_CLASS_FLAG_P2P,
};

u32 __clib_export
pppox_allocate_interface (u32 pppoeclient_index)
{
  pppox_main_t *pom = &pppox_main;
  u32 hw_if_index = ~0;
  u32 sw_if_index = ~0;
  vnet_hw_interface_t *hi;
  vnet_sw_interface_t *si;
  vnet_main_t *vnm = pom->vnet_main;
  pppox_virtual_interface_t *t = 0;
  u32 unit;

  pool_get_aligned (pom->virtual_interfaces, t, CLIB_CACHE_LINE_BYTES);
  clib_memset (t, 0, sizeof (*t));

  unit = t - pom->virtual_interfaces;
  if (!pppox_unit_is_valid (unit))
    {
      pool_put (pom->virtual_interfaces, t);
      clib_warning ("pppox: unit %u exceeds NUM_PPP (%d) limit", unit, NUM_PPP);
      return ~0;
    }

  t->pppoeclient_index = pppoeclient_index;

  if (vec_len (pom->free_pppox_hw_if_indices) > 0)
    {
      vnet_interface_main_t *im = &vnm->interface_main;
      hw_if_index = pom->free_pppox_hw_if_indices[vec_len (pom->free_pppox_hw_if_indices) - 1];
      vec_pop (pom->free_pppox_hw_if_indices);

      hi = vnet_get_hw_interface (vnm, hw_if_index);
      hi->dev_instance = unit;
      hi->hw_instance = unit;

      /* clear old stats of freed X before reuse */
      sw_if_index = hi->sw_if_index;
      vnet_interface_counter_lock (im);
      vlib_zero_combined_counter (&im->combined_sw_if_counters[VNET_INTERFACE_COUNTER_TX],
				  sw_if_index);
      vlib_zero_combined_counter (&im->combined_sw_if_counters[VNET_INTERFACE_COUNTER_RX],
				  sw_if_index);
      vlib_zero_simple_counter (&im->sw_if_counters[VNET_INTERFACE_COUNTER_DROP], sw_if_index);
      vnet_interface_counter_unlock (im);
    }
  else
    {
      hw_if_index =
	vnet_register_interface (vnm, pppox_device_class.index, unit, pppox_hw_class.index, unit);
      hi = vnet_get_hw_interface (vnm, hw_if_index);
      hi->output_node_index = pppox_output_node.index;
    }

  t->hw_if_index = hw_if_index;
  t->sw_if_index = sw_if_index = hi->sw_if_index;

  vec_validate_init_empty (pom->virtual_interface_index_by_sw_if_index, sw_if_index, ~0);
  pom->virtual_interface_index_by_sw_if_index[sw_if_index] = unit;

  si = vnet_get_sw_interface (vnm, sw_if_index);
  si->flags &= ~VNET_SW_INTERFACE_FLAG_HIDDEN;
  vnet_sw_interface_set_flags (vnm, sw_if_index, VNET_SW_INTERFACE_FLAG_ADMIN_UP);

  /* pap client. */
  upap[unit].us_user = NULL;
  upap[unit].us_userlen = 0;
  upap[unit].us_passwd = NULL;
  upap[unit].us_passwdlen = 0;

  /* chap client. */
  chap_client[unit].us_user = NULL;
  chap_client[unit].us_userlen = 0;
  chap_client[unit].us_passwd = NULL;
  chap_client[unit].us_passwdlen = 0;

  return hw_if_index;
}

void
pppox_handle_allocated_address (pppox_virtual_interface_t *t, u8 is_add)
{
  pppox_main_t *pom = &pppox_main;
  ip4_address_t our_adr_ipv4;
  fib_prefix_t pfx;
  u32 fib_index;

  /* Configure ip4 address. */
  our_adr_ipv4.as_u32 = t->our_addr;
  ip4_add_del_interface_address (pom->vlib_main, t->sw_if_index, (void *) &our_adr_ipv4, 32,
				 !is_add /*is_del*/);

  /* Configure reverse route. */
  pfx.fp_addr.ip4.as_u32 = t->his_addr;
  pfx.fp_len = 32; /* always 32 */
  pfx.fp_proto = FIB_PROTOCOL_IP4;
  fib_index = fib_table_get_index_for_sw_if_index (FIB_PROTOCOL_IP4, t->sw_if_index);
  if (is_add)
    {
      fib_table_entry_path_add (fib_index, &pfx, FIB_SOURCE_API, FIB_ENTRY_FLAG_NONE,
				fib_proto_to_dpo (pfx.fp_proto), &pfx.fp_addr, t->sw_if_index, ~0,
				1, NULL, FIB_ROUTE_PATH_FLAG_NONE);
    }
  else
    {
      fib_table_entry_path_remove (fib_index, &pfx, FIB_SOURCE_API, fib_proto_to_dpo (pfx.fp_proto),
				   &pfx.fp_addr, t->sw_if_index, ~0, 1, FIB_ROUTE_PATH_FLAG_NONE);
    }
}

#define PPPOX_IPV6CP_PREFIX_LEN 64

static_always_inline void
pppox_make_ipv6_link_local_address (ip6_address_t *addr, const u8 *ifaceid)
{
  clib_memset (addr, 0, sizeof (*addr));
  addr->as_u64[0] = clib_host_to_net_u64 (0xFE80000000000000ULL);
  clib_memcpy (&addr->as_u8[8], ifaceid, 8);
}

static void
pppox_handle_allocated_ipv6_address (pppox_virtual_interface_t *t, u8 is_add)
{
  pppox_main_t *pom = &pppox_main;
  fib_prefix_t peer_pfx = {
    .fp_len = 128,
    .fp_proto = FIB_PROTOCOL_IP6,
  };
  fib_prefix_t default_pfx = {
    .fp_len = 0,
    .fp_proto = FIB_PROTOCOL_IP6,
  };
  ip46_address_t nh = {
    .ip6 = t->his_ipv6,
  };
  u32 fib_index;

  if (!ip6_address_is_zero (&t->our_ipv6))
    ip6_add_del_interface_address (pom->vlib_main, t->sw_if_index, &t->our_ipv6,
				   PPPOX_IPV6CP_PREFIX_LEN, !is_add /* is_del */);

  if (ip6_address_is_zero (&t->his_ipv6))
    return;

  fib_index = fib_table_get_index_for_sw_if_index (FIB_PROTOCOL_IP6, t->sw_if_index);
  peer_pfx.fp_addr.ip6 = t->his_ipv6;

  if (is_add)
    {
      fib_table_entry_path_add (fib_index, &peer_pfx, FIB_SOURCE_API, FIB_ENTRY_FLAG_NONE,
				DPO_PROTO_IP6, &nh, t->sw_if_index, ~0, 1, NULL,
				FIB_ROUTE_PATH_FLAG_NONE);

      if (t->add_default_route6)
	fib_table_entry_path_add (fib_index, &default_pfx, FIB_SOURCE_API, FIB_ENTRY_FLAG_NONE,
				  DPO_PROTO_IP6, &nh, t->sw_if_index, ~0, 1, NULL,
				  FIB_ROUTE_PATH_FLAG_NONE);
    }
  else
    {
      if (t->add_default_route6)
	fib_table_entry_path_remove (fib_index, &default_pfx, FIB_SOURCE_API, DPO_PROTO_IP6, &nh,
				     t->sw_if_index, ~0, 1, FIB_ROUTE_PATH_FLAG_NONE);

      fib_table_entry_path_remove (fib_index, &peer_pfx, FIB_SOURCE_API, DPO_PROTO_IP6, &nh,
				   t->sw_if_index, ~0, 1, FIB_ROUTE_PATH_FLAG_NONE);
    }
}

void __clib_export
pppox_free_interface (u32 hw_if_index)
{
  pppox_main_t *pom = &pppox_main;
  vnet_main_t *vnm = pom->vnet_main;
  vnet_hw_interface_t *hi;
  pppox_virtual_interface_t *t = 0;
  u32 unit = ~0;

  hi = vnet_get_hw_interface (vnm, hw_if_index);

  t = pppox_get_virtual_interface_by_sw_if_index (pom, hi->sw_if_index, &unit);
  if (t == 0)
    return;

  if (!pppox_unit_is_valid (unit))
    return;

  t->delete_pending = 1;

  /* turn down underlying lcp. */
  clib_spinlock_lock_if_init (&pom->ctrl_lock);
  lcp_close (unit, "User request");
  clib_spinlock_unlock_if_init (&pom->ctrl_lock);

  /* Make explicit delete robust even if PPP cleanup callbacks arrive after
   * the interface mapping has been torn down. */
  pppox_clear_allocated_runtime_state (t);
  t->pppoe_session_allocated = 0;

  vnet_sw_interface_set_flags (vnm, hi->sw_if_index, 0 /* down */);
  {
    vnet_sw_interface_t *si = vnet_get_sw_interface (vnm, hi->sw_if_index);
    si->flags |= VNET_SW_INTERFACE_FLAG_HIDDEN;
  }

  vec_add1 (pom->free_pppox_hw_if_indices, hw_if_index);
  pom->virtual_interface_index_by_sw_if_index[hi->sw_if_index] = ~0;
  if (vec_len (t->custom_name))
    {
      /* Revert hw->name to the default "pppoxN" so the recycled hw_if_index
       * doesn't carry a stale custom name into the next allocation. */
      u8 *default_name = format (0, "pppox%u%c", unit, 0);
      clib_error_t *err = vnet_rename_interface (vnm, hw_if_index, (char *) default_name);
      vec_free (default_name);
      if (err)
	clib_error_free (err);
    }
  vec_free (t->custom_name);
  pppox_cleanup_virtual_interface (unit);
  pool_put (pom->virtual_interfaces, t);
}

/* Assign an operator-supplied interface name to the PPPoX virtual
 * interface owning sw_if_index. Passing NULL or an empty vector reverts
 * to the default "pppoxN" formatting. Intended to be called immediately
 * after pppox_allocate_interface, before the name is surfaced anywhere.
 *
 * vnet_register_interface caches the default "pppoxN" in hw->name at
 * allocate time, so we must rename the hw interface too -- format_device_name
 * is only consulted once. */
__clib_export void
pppox_set_interface_name (u32 sw_if_index, const u8 *name)
{
  pppox_main_t *pom = &pppox_main;
  pppox_virtual_interface_t *t;
  u32 unit = ~0;

  t = pppox_get_virtual_interface_by_sw_if_index (pom, sw_if_index, &unit);
  if (t == 0 || !pppox_unit_is_valid (unit))
    return;

  vec_free (t->custom_name);
  if (name && vec_len (name))
    {
      t->custom_name = vec_dup ((u8 *) name);
      /* Null-terminate a scratch buffer for vnet_rename_interface (char *). */
      u8 *c_name = 0;
      vec_add (c_name, name, vec_len (name));
      vec_add1 (c_name, 0);
      clib_error_t *err = vnet_rename_interface (pom->vnet_main, t->hw_if_index, (char *) c_name);
      vec_free (c_name);
      if (err)
	{
	  clib_warning ("pppox: rename to %v failed: %U", t->custom_name, format_clib_error, err);
	  clib_error_free (err);
	}
    }
}

__clib_export void
pppox_lower_up (u32 sw_if_index)
{
  pppox_main_t *pom = &pppox_main;
  pppox_virtual_interface_t *t = 0;
  u32 unit = ~0;

  t = pppox_get_virtual_interface_by_sw_if_index (pom, sw_if_index, &unit);
  if (t && pppox_unit_is_valid (unit))
    {
      struct protent *protp;

      clib_spinlock_lock_if_init (&pom->ctrl_lock);
      t->pppoe_session_allocated = 1;
      t->delete_pending = 0;

      new_phase (unit, PHASE_INITIALIZE);
      for (int i = 0; (protp = protocols[i]) != NULL; ++i)
	{
	  if (protp->init != NULL)
	    (*protp->init) (unit);
	}
      init_auth_context (unit);
      ipcp_wantoptions[unit].default_route = t->add_default_route4;
      ipcp_set_use_peer_dns (unit, t->use_peer_dns);

      /* Apply operator-configured MRU to LCP wantoptions.
       * lcp_init() sets wo->mru = DEFMRU (1500); override here if the
       * operator specified a smaller value via `set pppoe client … mru`. */
      if (t->configured_mru > 0)
	{
	  lcp_wantoptions[unit].mru = t->configured_mru;
	  lcp_wantoptions[unit].neg_mru = 1;
	}

      lcp_open (unit);
      start_link (unit);
      clib_spinlock_unlock_if_init (&pom->ctrl_lock);
    }
}

__clib_export void
pppox_lower_down (u32 sw_if_index)
{
  pppox_main_t *pom = &pppox_main;
  pppox_virtual_interface_t *t = 0;
  u32 unit = ~0;

  t = pppox_get_virtual_interface_by_sw_if_index (pom, sw_if_index, &unit);
  if (t && pppox_unit_is_valid (unit))
    {
      t->pppoe_session_allocated = 0;
      clib_spinlock_lock_if_init (&pom->ctrl_lock);
      lcp_lowerdown (unit);
      clib_spinlock_unlock_if_init (&pom->ctrl_lock);
    }
}

__clib_export int
pppox_set_auth (u32 sw_if_index, u8 *username, u8 *password)
{
  pppox_main_t *pom = &pppox_main;
  pppox_virtual_interface_t *t = 0;
  int unit;

  if (sw_if_index >= vec_len (pom->virtual_interface_index_by_sw_if_index))
    return VNET_API_ERROR_INVALID_INTERFACE;

  unit = pom->virtual_interface_index_by_sw_if_index[sw_if_index];
  if (!pppox_unit_is_valid ((u32) unit) || pool_is_free_index (pom->virtual_interfaces, unit))
    return VNET_API_ERROR_INVALID_INTERFACE;

  t = pool_elt_at_index (pom->virtual_interfaces, unit);

  clib_spinlock_lock_if_init (&pom->ctrl_lock);

  /* PAP client credentials -- zero old password before freeing */
  vec_free (upap[unit].us_user);
  upap[unit].us_user = pppox_dup_c_string_vec (username);
  upap[unit].us_userlen = upap[unit].us_user ? vec_len (upap[unit].us_user) - 1 : 0;
  if (upap[unit].us_passwd)
    clib_memset (upap[unit].us_passwd, 0, vec_len (upap[unit].us_passwd));
  vec_free (upap[unit].us_passwd);
  upap[unit].us_passwd = pppox_dup_c_string_vec (password);
  upap[unit].us_passwdlen = upap[unit].us_passwd ? vec_len (upap[unit].us_passwd) - 1 : 0;

  /* CHAP client credentials -- zero old password before freeing */
  vec_free (chap_client[unit].us_user);
  chap_client[unit].us_user = pppox_dup_c_string_vec (username);
  chap_client[unit].us_userlen =
    chap_client[unit].us_user ? vec_len (chap_client[unit].us_user) - 1 : 0;
  if (chap_client[unit].us_passwd)
    clib_memset (chap_client[unit].us_passwd, 0, vec_len (chap_client[unit].us_passwd));
  vec_free (chap_client[unit].us_passwd);
  chap_client[unit].us_passwd = pppox_dup_c_string_vec (password);
  chap_client[unit].us_passwdlen =
    chap_client[unit].us_passwd ? vec_len (chap_client[unit].us_passwd) - 1 : 0;

  /* After auth is configured, notify pppoeclient to open session.
   * NB: This immediately starts LCP negotiation, so any per-session
   * options (add-default-route, use-peer-dns, MTU, etc.) MUST be
   * configured on the pppoeclient side BEFORE calling pppox set auth.
   * The pppoeclient_set_options API or `set pppoe client` CLI can be
   * used to pre-configure these options. */
  static void (*pppoeclient_set_auth_func) (u32 client_index, u8 * username, u8 * password) = 0;
  static void (*pppoeclient_open_session_func) (u32 client_index) = 0;
  if (pppoeclient_set_auth_func == 0)
    {
      pppoeclient_set_auth_func =
	vlib_get_plugin_symbol ("pppoeclient_plugin.so", "pppoeclient_set_auth");
    }
  if (pppoeclient_open_session_func == 0)
    {
      pppoeclient_open_session_func =
	vlib_get_plugin_symbol ("pppoeclient_plugin.so", "pppoeclient_open_session");
    }
  if (pppoeclient_set_auth_func)
    (*pppoeclient_set_auth_func) (t->pppoeclient_index, username, password);
  if (pppoeclient_open_session_func)
    (*pppoeclient_open_session_func) (t->pppoeclient_index);

  clib_spinlock_unlock_if_init (&pom->ctrl_lock);
  return 0;
}

__clib_export int
pppox_set_add_default_route4 (u32 sw_if_index, u8 enabled)
{
  pppox_main_t *pom = &pppox_main;
  pppox_virtual_interface_t *t;
  u32 unit;

  t = pppox_get_virtual_interface_by_sw_if_index (pom, sw_if_index, &unit);
  if (t == 0)
    return VNET_API_ERROR_INVALID_INTERFACE;

  clib_spinlock_lock_if_init (&pom->ctrl_lock);
  t->add_default_route4 = !!enabled;
  ipcp_wantoptions[unit].default_route = t->add_default_route4;
  clib_spinlock_unlock_if_init (&pom->ctrl_lock);

  return 0;
}

__clib_export int
pppox_set_add_default_route6 (u32 sw_if_index, u8 enabled)
{
  pppox_main_t *pom = &pppox_main;
  pppox_virtual_interface_t *t;
  u32 unit;

  t = pppox_get_virtual_interface_by_sw_if_index (pom, sw_if_index, &unit);
  if (t == 0)
    return VNET_API_ERROR_INVALID_INTERFACE;

  clib_spinlock_lock_if_init (&pom->ctrl_lock);
  t->add_default_route6 = !!enabled;
  clib_spinlock_unlock_if_init (&pom->ctrl_lock);

  return 0;
}

/* Convenience: set both IPv4 and IPv6 default route flags at once. */
__clib_export int
pppox_set_add_default_route (u32 sw_if_index, u8 enabled)
{
  int rv;
  rv = pppox_set_add_default_route4 (sw_if_index, enabled);
  if (rv)
    return rv;
  return pppox_set_add_default_route6 (sw_if_index, enabled);
}

__clib_export int
pppox_set_use_peer_dns (u32 sw_if_index, u8 enabled)
{
  pppox_main_t *pom = &pppox_main;
  pppox_virtual_interface_t *t;
  u32 unit;

  t = pppox_get_virtual_interface_by_sw_if_index (pom, sw_if_index, &unit);
  if (t == 0)
    return VNET_API_ERROR_INVALID_INTERFACE;

  clib_spinlock_lock_if_init (&pom->ctrl_lock);
  t->use_peer_dns = !!enabled;
  ipcp_set_use_peer_dns (unit, t->use_peer_dns);
  clib_spinlock_unlock_if_init (&pom->ctrl_lock);

  return 0;
}

__clib_export int
pppox_set_configured_mru (u32 sw_if_index, u16 mru)
{
  pppox_main_t *pom = &pppox_main;
  pppox_virtual_interface_t *t;
  u32 unit;

  t = pppox_get_virtual_interface_by_sw_if_index (pom, sw_if_index, &unit);
  if (t == 0)
    return VNET_API_ERROR_INVALID_INTERFACE;

  clib_spinlock_lock_if_init (&pom->ctrl_lock);
  t->configured_mru = mru;
  clib_spinlock_unlock_if_init (&pom->ctrl_lock);

  return 0;
}

u8 __clib_export
pppox_get_ppp_debug_runtime (u32 sw_if_index, pppox_ppp_debug_runtime_t *rt)
{
  pppox_main_t *pom = &pppox_main;
  pppox_virtual_interface_t *t;
  u32 unit;

  if (rt == 0)
    return 0;

  clib_memset (rt, 0, sizeof (*rt));

  t = pppox_get_virtual_interface_by_sw_if_index (pom, sw_if_index, &unit);
  if (t == 0 || !pppox_unit_is_valid (unit))
    return 0;

  clib_spinlock_lock_if_init (&pom->ctrl_lock);
  rt->present = 1;
  rt->phase = phase[unit];
  rt->lcp_state = lcp_fsm[unit].state;
  rt->ipcp_state = ipcp_fsm[unit].state;
  rt->ipv6cp_state = ipv6cp_fsm[unit].state;
  rt->lcp_timeout = lcp_fsm[unit].timeouttime;
  rt->ipcp_timeout = ipcp_fsm[unit].timeouttime;
  rt->ipv6cp_timeout = ipv6cp_fsm[unit].timeouttime;
  rt->req_dns1 = ipcp_wantoptions[unit].req_dns1;
  rt->req_dns2 = ipcp_wantoptions[unit].req_dns2;
  rt->default_route4 = ipcp_wantoptions[unit].default_route;
  rt->negotiated_dns1 = ipcp_gotoptions[unit].dnsaddr[0];
  rt->negotiated_dns2 = ipcp_gotoptions[unit].dnsaddr[1];
  if (lcp_fsm[unit].state == OPENED)
    {
      lcp_options *go = &lcp_gotoptions[unit];
      lcp_options *ho = &lcp_hisoptions[unit];
      lcp_options *wo = &lcp_wantoptions[unit];
      rt->negotiated_mtu = ho->neg_mru ? ho->mru : PPP_MRU;
      rt->negotiated_mru = go->neg_mru ? clib_max (wo->mru, go->mru) : PPP_MRU;
    }
  clib_spinlock_unlock_if_init (&pom->ctrl_lock);

  return 1;
}

clib_error_t *
pppox_init (vlib_main_t *vm)
{
  pppox_main_t *pom = &pppox_main;

  pom->vnet_main = vnet_get_main ();
  pom->vlib_main = vm;
  pom->is_shutting_down = 0;
  clib_spinlock_init (&pom->ctrl_lock);
  magic_init ();

  return 0;
}

VLIB_INIT_FUNCTION (pppox_init);
/* Plugin registration moved to pppoeclient.c; pppox is now compiled into
 * pppoeclient_plugin.so as of the pppox/pppoeclient merge. */
/* pppd-->vpp interaction. */

/********************************************************************
 *
 * output - Output PPP packet.
 *
 * Uses pppoeclient_output_ctrl_pkt() to build the complete PPPoE session
 * frame and send it directly to the physical interface, bypassing the
 * pppox-output -> pppoeclient-session-output vector-node path.  The old
 * path drops packets when called from the main-thread process-node context.
 */
void
output (int unit, u8 *p, int len)
{
  pppox_main_t *pom = &pppox_main;
  pppox_virtual_interface_t *t = 0;

  static void (*output_ctrl_pkt_fn) (u32, u8 *, int) = 0;

  if (unit < 0)
    return;

  t = pppox_get_virtual_interface_by_unit (pom, (u32) unit);
  if (t == 0)
    return;

  if (PREDICT_FALSE (output_ctrl_pkt_fn == 0))
    PPPOECLIENT_LAZY_PLUGIN_SYMBOL (output_ctrl_pkt_fn, "pppoeclient_plugin.so",
				    "pppoeclient_output_ctrl_pkt");

  if (PREDICT_FALSE (output_ctrl_pkt_fn == 0))
    {
      clib_warning ("pppoeclient_output_ctrl_pkt not found");
      return;
    }

  /* PPPoE removes the PPP address/control bytes (0xff03) before Ethernet
   * encapsulation; skip them and pass just PPP protocol + payload.
   * A well-formed pppd frame always carries the 2-byte address/control
   * header, but refuse to underflow len if a caller ever hands us less
   * than that. */
  if (PREDICT_FALSE (len < 2))
    return;
  p += 2;
  len -= 2;

  (*output_ctrl_pkt_fn) (t->sw_if_index, p, len);
}

typedef struct
{
  int unit;
  int is_add;
  u32 our_adr;
  u32 his_adr;
  u32 net_mask;
} ifaddr_arg_t;

static void *
ifaddr_callback (void *arg)
{
  pppox_main_t *pom = &pppox_main;
  pppox_virtual_interface_t *t;
  ifaddr_arg_t *a = arg;

  if (a->unit < 0)
    return 0;

  t = pppox_get_virtual_interface_by_unit (pom, a->unit);
  if (t == 0)
    return 0;

  if (a->is_add)
    {
      t->our_addr = a->our_adr;
      t->his_addr = a->his_adr;
      pppox_handle_allocated_address (t, 1);
    }
  else
    {
      pppox_handle_allocated_address (t, 0);
      t->our_addr = t->his_addr = 0;
    }

  return 0;
}

typedef struct
{
  int unit;
  int is_add;
  ip6_address_t our_ipv6;
  ip6_address_t his_ipv6;
} if6addr_arg_t;

static void *
if6addr_callback (void *arg)
{
  pppox_main_t *pom = &pppox_main;
  pppox_virtual_interface_t *t;
  if6addr_arg_t *a = arg;
  static void (*pppoeclient_set_ipv6_state_func) (u32, const ip6_address_t *, const ip6_address_t *,
						  u8) = 0;
  ip6_address_t zero_addr = { 0 };

  if (a->unit < 0)
    return 0;

  t = pppox_get_virtual_interface_by_unit (pom, a->unit);
  if (t == 0)
    return 0;

  if (a->is_add)
    {
      t->our_ipv6 = a->our_ipv6;
      t->his_ipv6 = a->his_ipv6;
      pppox_handle_allocated_ipv6_address (t, 1);
    }
  else
    {
      pppox_handle_allocated_ipv6_address (t, 0);
      ip6_address_set_zero (&t->our_ipv6);
      ip6_address_set_zero (&t->his_ipv6);
    }

  PPPOECLIENT_LAZY_PLUGIN_SYMBOL (pppoeclient_set_ipv6_state_func, "pppoeclient_plugin.so",
				  "pppoeclient_set_ipv6_state");

  if (pppoeclient_set_ipv6_state_func)
    {
      if (a->is_add)
	(*pppoeclient_set_ipv6_state_func) (t->sw_if_index, &a->our_ipv6, &a->his_ipv6,
					    PPPOX_IPV6CP_PREFIX_LEN);
      else
	(*pppoeclient_set_ipv6_state_func) (t->sw_if_index, &zero_addr, &zero_addr, 0);
    }

  return 0;
}

typedef struct
{
  int unit;
  u32 dns1;
  u32 dns2;
} dns_arg_t;

static void *
dns_callback (void *arg)
{
  pppox_main_t *pom = &pppox_main;
  pppox_virtual_interface_t *t;
  dns_arg_t *a = arg;
  static void (*pppoeclient_set_peer_dns_func) (u32, u32, u32) = 0;

  if (a->unit < 0)
    return 0;

  t = pppox_get_virtual_interface_by_unit (pom, a->unit);
  if (t == 0)
    return 0;

  PPPOECLIENT_LAZY_PLUGIN_SYMBOL (pppoeclient_set_peer_dns_func, "pppoeclient_plugin.so",
				  "pppoeclient_set_peer_dns");

  if (pppoeclient_set_peer_dns_func)
    (*pppoeclient_set_peer_dns_func) (t->sw_if_index, a->dns1, a->dns2);

  return 0;
}

int
sifdns (int unit, u32 dns1, u32 dns2)
{
  dns_arg_t a = {
    .unit = unit,
    .dns1 = dns1,
    .dns2 = dns2,
  };

  if (unit < 0)
    return 0;

  vlib_rpc_call_main_thread (dns_callback, (u8 *) &a, sizeof (a));
  return 1;
}

int
cifdns (int unit)
{
  return sifdns (unit, 0, 0);
}

typedef struct
{
  int unit;
  u32 mtu;
} mtu_arg_t;

static void *
mtu_callback (void *arg)
{
  pppox_main_t *pom = &pppox_main;
  pppox_virtual_interface_t *t;
  mtu_arg_t *a = arg;

  if (a->unit < 0 || a->mtu == 0)
    return 0;

  t = pppox_get_virtual_interface_by_unit (pom, a->unit);
  if (t == 0)
    return 0;

  vnet_sw_interface_set_mtu (pom->vnet_main, t->sw_if_index, a->mtu);
  return 0;
}

__clib_export void
pppox_set_interface_mtu (int unit, int mtu)
{
  mtu_arg_t a = {
    .unit = unit,
    .mtu = mtu,
  };

  if (unit < 0 || mtu <= 0)
    return;

  vlib_rpc_call_main_thread (mtu_callback, (u8 *) &a, sizeof (a));
}

typedef struct
{
  int unit;
  int is_add;
  u32 gateway;
} default_route_arg_t;

static void *
default_route_callback (void *arg)
{
  pppox_main_t *pom = &pppox_main;
  pppox_virtual_interface_t *t;
  default_route_arg_t *a = arg;
  fib_prefix_t all_0s = {
    .fp_len = 0,
    .fp_proto = FIB_PROTOCOL_IP4,
  };
  ip46_address_t nh = {
    .ip4.as_u32 = a->gateway,
  };
  u32 fib_index;

  if (a->unit < 0 || a->gateway == 0)
    return 0;

  t = pppox_get_virtual_interface_by_unit (pom, a->unit);
  if (t == 0)
    return 0;

  fib_index = fib_table_get_index_for_sw_if_index (FIB_PROTOCOL_IP4, t->sw_if_index);
  if (a->is_add)
    fib_table_entry_path_add (fib_index, &all_0s, FIB_SOURCE_API, FIB_ENTRY_FLAG_NONE,
			      DPO_PROTO_IP4, &nh, t->sw_if_index, ~0, 1, NULL,
			      FIB_ROUTE_PATH_FLAG_NONE);
  else
    fib_table_entry_path_remove (fib_index, &all_0s, FIB_SOURCE_API, DPO_PROTO_IP4, &nh,
				 t->sw_if_index, ~0, 1, FIB_ROUTE_PATH_FLAG_NONE);

  return 0;
}

/********************************************************************
 *
 * sifdefaultroute - assign a default route through the peer address.
 */
int
sifdefaultroute (int unit, u_int32_t ouraddr, u_int32_t gateway)
{
  default_route_arg_t a = {
    .unit = unit,
    .is_add = 1,
    .gateway = gateway,
  };

  (void) ouraddr;

  if (unit < 0 || gateway == 0)
    return 0;

  vlib_rpc_call_main_thread (default_route_callback, (u8 *) &a, sizeof (a));
  return 1;
}

/********************************************************************
 *
 * cifdefaultroute - remove the default route through the peer address.
 */
int
cifdefaultroute (int unit, u_int32_t ouraddr, u_int32_t gateway)
{
  default_route_arg_t a = {
    .unit = unit,
    .is_add = 0,
    .gateway = gateway,
  };

  (void) ouraddr;

  if (unit < 0 || gateway == 0)
    return 0;

  vlib_rpc_call_main_thread (default_route_callback, (u8 *) &a, sizeof (a));
  return 1;
}

/********************************************************************
 *
 * sifaddr - Config the interface IP addresses and netmask.
 */
int
sifaddr (int unit, u32 our_adr, u32 his_adr, u32 net_mask)
{
  ifaddr_arg_t a;

  clib_memset (&a, 0, sizeof (a));
  a.unit = unit;
  /* NB: oss-pppd pass network endian u32 here, and vpp fib
   * parameter require u32 too, so not conversion here. */
  a.our_adr = our_adr;
  a.his_adr = his_adr;
  /* oss-pppd passed net_mask is not used, always treat as host address. */
  a.net_mask = 32;
  a.is_add = 1;

  /* Add route in main thread, otherwise it will crash when
   * fib code do barrier check because we will then waiting for
   * our barrier finished... */
  vlib_rpc_call_main_thread (ifaddr_callback, (u8 *) &a, sizeof (a));

  return 1;
}

/********************************************************************
 *
 * cifaddr - Clear the interface IP addresses, and delete routes
 * through the interface if possible.
 */

int
cifaddr (int unit, u32 our_adr, u32 his_adr)
{
  ifaddr_arg_t a;

  clib_memset (&a, 0, sizeof (a));
  a.unit = unit;
  /* NB: oss-pppd pass network endian u32 here, and vpp fib
   * parameter require u32 too, so not conversion here.
   * NB: just record them here, we will use the address
   * we recorded on virtual interface to delete. */
  a.our_adr = our_adr;
  a.his_adr = his_adr;
  a.net_mask = 32;
  a.is_add = 0;

  /* Add route in main thread, otherwise it will crash when
   * fib code do barrier check because we will then waiting for
   * our barrier finished... */
  vlib_rpc_call_main_thread (ifaddr_callback, (u8 *) &a, sizeof (a));

  return 1;
}

int
sif6up (int unit)
{
  return (unit >= 0);
}

int
sif6down (int unit)
{
  return (unit >= 0);
}

int
sif6addr (int unit, const u8 *ourid, const u8 *hisid)
{
  if6addr_arg_t a;

  if (unit < 0 || ourid == 0 || hisid == 0)
    return 0;

  clib_memset (&a, 0, sizeof (a));
  a.unit = unit;
  a.is_add = 1;
  pppox_make_ipv6_link_local_address (&a.our_ipv6, ourid);
  pppox_make_ipv6_link_local_address (&a.his_ipv6, hisid);

  vlib_rpc_call_main_thread (if6addr_callback, (u8 *) &a, sizeof (a));

  return 1;
}

int
cif6addr (int unit, const u8 *ourid, const u8 *hisid)
{
  if6addr_arg_t a;

  if (unit < 0 || ourid == 0 || hisid == 0)
    return 0;

  clib_memset (&a, 0, sizeof (a));
  a.unit = unit;
  a.is_add = 0;
  pppox_make_ipv6_link_local_address (&a.our_ipv6, ourid);
  pppox_make_ipv6_link_local_address (&a.his_ipv6, hisid);

  vlib_rpc_call_main_thread (if6addr_callback, (u8 *) &a, sizeof (a));

  return 1;
}

typedef struct
{
  int unit;
} cleanup_arg_t;

static void *
cleanup_callback (void *arg)
{
  pppox_main_t *pom = &pppox_main;
  cleanup_arg_t *a = arg;
  static void (*pppoeclient_restart_session_with_reason_func) (u32 client_index,
							       u8 disconnect_reason) = 0;
  static void (*pppoeclient_restart_session_func) (u32 client_index) = 0;
  u32 client_index = ~0;
  u8 delete_pending = 0;

  if (a->unit < 0 || !pppox_unit_is_valid ((u32) a->unit))
    return 0;

  if (a->unit < vec_len (pom->virtual_interfaces) &&
      !pool_is_free_index (pom->virtual_interfaces, a->unit))
    {
      pppox_virtual_interface_t *t = pool_elt_at_index (pom->virtual_interfaces, a->unit);
      client_index = t->pppoeclient_index;
      delete_pending = t->delete_pending;
      t->pppoe_session_allocated = 0;
    }

  if (client_index == ~0)
    return 0;
  if (pom->is_shutting_down)
    return 0;

  /* Admin delete already performs a synchronous stop/teardown from the
   * pppoeclient side before freeing the PPPoX interface. The cleanup
   * callback should only trigger automatic reconnect for unexpected PPP
   * death, and must stay quiet while an explicit delete is in progress. */
  if (!delete_pending)
    {
      if (pppoeclient_restart_session_with_reason_func == 0 &&
	  pppoeclient_restart_session_func == 0)
	{
	  pppoeclient_restart_session_with_reason_func = vlib_get_plugin_symbol (
	    "pppoeclient_plugin.so", "pppoeclient_restart_session_with_reason");
	  if (pppoeclient_restart_session_with_reason_func == 0)
	    pppoeclient_restart_session_func =
	      vlib_get_plugin_symbol ("pppoeclient_plugin.so", "pppoeclient_restart_session");
	}
      if (pppoeclient_restart_session_with_reason_func)
	{
	  u8 reason = pppox_consume_auth_failed_flag (a->unit) ?
			PPPOX_PPPOECLIENT_DISCONNECT_AUTH_FAIL :
			PPPOX_PPPOECLIENT_DISCONNECT_PPP_DEAD;
	  (*pppoeclient_restart_session_with_reason_func) (client_index, reason);
	}
      else if (pppoeclient_restart_session_func)
	(*pppoeclient_restart_session_func) (client_index);
    }

  return 0;
}

int
channel_cleanup (int unit)
{
  cleanup_arg_t a;

  clib_memset (&a, 0, sizeof (a));
  a.unit = unit;

  /* Might be called in worker thread, so use rpc. */
  vlib_rpc_call_main_thread (cleanup_callback, (u8 *) &a, sizeof (a));

  return 1;
}

/*
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
