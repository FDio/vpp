/*
 * Copyright (c) 2017 RaydoNetworks.
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

#include <pppox/pppd/pppd.h>
#include <pppox/pppd/fsm.h>
#include <pppox/pppd/lcp.h>
#include <pppox/pppd/ipcp.h>
#include <pppox/pppd/upap.h>
#include <pppox/pppd/chap-new.h>

#define PPP_PROTOCOL_IP4      0x0021
#define PPP_PROTOCOL_IP6      0x0057
#define PPP_PROTOCOL_IPX      0x002B
#define PPP_PROTOCOL_VJ_COMP  0x002D
#define PPP_PROTOCOL_VJ_UCOMP 0x002F

#define GETSHORT(s, p)                                                                             \
  (s) = ((u16) ((p)[0] << 8) | (p)[1]);                                                            \
  (p) += 2

extern void pppd_calltimeout (void);

#include <pppox/pppox.h>

#include <vppinfra/hash.h>
#include <vppinfra/bihash_template.c>

__clib_export pppox_main_t pppox_main;

static pppox_virtual_interface_t *
pppox_get_virtual_interface_by_unit (pppox_main_t *pom, u32 unit)
{
  if (unit == ~0 || unit >= vec_len (pom->virtual_interfaces) ||
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

// This function is adapted to oss pppd main.c:get_input.
// refer to pppoeclient_session_input to see what packets can
// be delivered here, if new protocol enabled, should modify
// there too.
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
  int len = vnet_buffer (b)->pppox.len;
  // Use virtual interface context index as pppd unit number.
  u32 unit = ~0;

  // If instance is deleted, simple return.
  t = pppox_get_virtual_interface_by_sw_if_index (pom, sw_if_index, &unit);
  if (t == 0)
    return 1;

  p = vlib_buffer_get_current (b);

  GETSHORT (protocol, p);
  // Our pppox frame will only have a 16B protocol field.
  len -= 2;

  clib_warning ("PPPOX_CTRL protocol=0x%04x unit=%u phase=%d lcp_state=%d", protocol, unit,
		phase[unit], lcp_fsm[unit].state);

  if (protocol != PPP_LCP && lcp_fsm[unit].state != OPENED)
    {
      clib_warning ("PPPOX_CTRL reject proto=0x%04x phase=%d lcp=%d", protocol, phase[unit],
		    lcp_fsm[unit].state);
      return 1;
    }

  if (phase[unit] <= PHASE_AUTHENTICATE &&
      !(protocol == PPP_LCP || protocol == PPP_PAP || protocol == PPP_CHAP))
    {
      clib_warning ("PPPOX_CTRL reject proto=0x%04x phase=%d lcp=%d", protocol, phase[unit],
		    lcp_fsm[unit].state);
      return 1;
    }

  for (i = 0; (protp = protocols[i]) != NULL; ++i)
    {
      if (protp->protocol == protocol && protp->enabled_flag)
	{
	  clib_warning ("PPPOX_CTRL dispatch proto=0x%04x", protocol);
	  (*protp->input) (unit, p, len);
	  clib_warning ("PPPOX_CTRL dispatch proto=0x%04x", protocol);
	  return 0;
	}
      if (protocol == (protp->protocol & ~0x8000) && protp->enabled_flag &&
	  protp->datainput != NULL)
	{
	  clib_warning ("PPPOX_CTRL dispatch proto=0x%04x", protocol);
	  (*protp->datainput) (unit, p, len);
	  clib_warning ("PPPOX_CTRL dispatch proto=0x%04x", protocol);
	  return 0;
	}
    }

  clib_warning ("PPPOX_CTRL reject proto=0x%04x phase=%d lcp=%d", protocol, phase[unit],
		lcp_fsm[unit].state);
  lcp_sprotrej (unit, p - PPP_HDRLEN, len + PPP_HDRLEN);

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
  static void (*pppoe_client_close_session_func) (u32 client_index) = 0;

  if (pppoe_client_close_session_func == 0)
    {
      pppoe_client_close_session_func =
	vlib_get_plugin_symbol ("pppoeclient_plugin.so", "pppoe_client_close_session");
    }
  if (pppoe_client_close_session_func == 0)
    return;

  pool_foreach (vif, pom->virtual_interfaces)
    {
      u32 unit = vif - pom->virtual_interfaces;

      if (phase[unit] == PHASE_DEAD && vif->pppoe_session_allocated)
	(*pppoe_client_close_session_func) (vif->pppoe_client_index);
    }
}

static uword
pppox_process (vlib_main_t *vm, vlib_node_runtime_t *rt, vlib_frame_t *f)
{
  uword event_type;
  uword *event_data = 0;

  while (1)
    {
      // 1 second loop serve as a tick to drive oss-pppd timers.
      // XXX: actually we can call timeleft(sys-vpp.c) to
      // figure out what timeout we need here, but current
      // pppd timer mininum is 1s, so it's enough to do
      // this in a tick manner.
      vlib_process_wait_for_event_or_clock (vm, 1); // 1 second.

      event_type = vlib_process_get_events (vm, &event_data);

      switch (event_type)
	{
	case ~0:
	  pppd_calltimeout ();
	  // We need restart dead client due to various reason.
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
  return format (s, "pppox%d", dev_instance);
}

static uword
dummy_interface_tx (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  clib_warning ("you shouldn't be here, leaking buffers...");
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
  // only need append a 16B protocol filed.
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
      break;
    }

  return rw;
}
VNET_DEVICE_CLASS (pppox_device_class, static) = {
  .name = "PPPPOX",
  .format_device_name = format_pppox_name,
  .tx_function = dummy_interface_tx,
  .admin_up_down_function = pppox_interface_admin_up_down,
};
VNET_HW_INTERFACE_CLASS (pppox_hw_class, static) = {
  .name = "PPPOX",
  .build_rewrite = pppox_build_rewrite,
  // Do not need leverage adj, use default update adj with
  // our own rewrite to insert the ppp protocol field.
  //.update_adjacency = pppox_update_adj,
  .flags = VNET_HW_INTERFACE_CLASS_FLAG_P2P,
};

u32 __clib_export
pppox_allocate_interface (u32 pppoe_client_index)
{
  pppox_main_t *pom = &pppox_main;
  u32 hw_if_index = ~0;
  u32 sw_if_index = ~0;
  vnet_hw_interface_t *hi;
  vnet_sw_interface_t *si;
  vnet_main_t *vnm = pom->vnet_main;
  pppox_virtual_interface_t *t = 0;
  int unit;

  pool_get_aligned (pom->virtual_interfaces, t, CLIB_CACHE_LINE_BYTES);
  memset (t, 0, sizeof (*t));

  t->pppoe_client_index = pppoe_client_index;

  if (vec_len (pom->free_pppox_hw_if_indices) > 0)
    {
      vnet_interface_main_t *im = &vnm->interface_main;
      hw_if_index = pom->free_pppox_hw_if_indices[vec_len (pom->free_pppox_hw_if_indices) - 1];
      vec_pop (pom->free_pppox_hw_if_indices);

      hi = vnet_get_hw_interface (vnm, hw_if_index);
      hi->dev_instance = t - pom->virtual_interfaces;
      hi->hw_instance = hi->dev_instance;

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
	vnet_register_interface (vnm, pppox_device_class.index, t - pom->virtual_interfaces,
				 pppox_hw_class.index, t - pom->virtual_interfaces);
      hi = vnet_get_hw_interface (vnm, hw_if_index);
      hi->output_node_index = pppox_output_node.index;
    }

  t->hw_if_index = hw_if_index;
  t->sw_if_index = sw_if_index = hi->sw_if_index;

  vec_validate_init_empty (pom->virtual_interface_index_by_sw_if_index, sw_if_index, ~0);
  pom->virtual_interface_index_by_sw_if_index[sw_if_index] = t - pom->virtual_interfaces;

  si = vnet_get_sw_interface (vnm, sw_if_index);
  si->flags &= ~VNET_SW_INTERFACE_FLAG_HIDDEN;
  vnet_sw_interface_set_flags (vnm, sw_if_index, VNET_SW_INTERFACE_FLAG_ADMIN_UP);

  unit = t - pom->virtual_interfaces;
  // pap client.
  upap[unit].us_user = NULL;
  upap[unit].us_userlen = 0;
  upap[unit].us_passwd = NULL;
  upap[unit].us_passwdlen = 0;

  // chap client.
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

  // Configure ip4 address.
  our_adr_ipv4.as_u32 = t->our_addr;
  ip4_add_del_interface_address (pom->vlib_main, t->sw_if_index, (void *) &our_adr_ipv4, 32,
				 !is_add /*is_del*/);

  // Configure reverse route.
  pfx.fp_addr.ip4.as_u32 = t->his_addr;
  pfx.fp_len = 32; // always 32
  pfx.fp_proto = FIB_PROTOCOL_IP4;
  if (is_add)
    {
      fib_table_entry_path_add (0, &pfx, FIB_SOURCE_API, FIB_ENTRY_FLAG_NONE,
				fib_proto_to_dpo (pfx.fp_proto), &pfx.fp_addr, t->sw_if_index, ~0,
				1, NULL, FIB_ROUTE_PATH_FLAG_NONE);
    }
  else
    {
      fib_table_entry_path_remove (0, &pfx, FIB_SOURCE_API, fib_proto_to_dpo (pfx.fp_proto),
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

    // clean allocated address.
    // lcp_close will trigger the ip freeed if we have allocated one.
#if 0
  if (t->our_addr) {
    pppox_handle_allocated_address (t, 0);
   }
#endif

  // turn down underlying lcp.
  lcp_close (unit, "User request");

  vnet_sw_interface_set_flags (vnm, hi->sw_if_index, 0 /* down */);
  vnet_sw_interface_t *si = vnet_get_sw_interface (vnm, hi->sw_if_index);
  si->flags |= VNET_SW_INTERFACE_FLAG_HIDDEN;

  vec_add1 (pom->free_pppox_hw_if_indices, hw_if_index);

  pom->virtual_interface_index_by_sw_if_index[hi->sw_if_index] = ~0;

  pool_put (pom->virtual_interfaces, t);

  // pap client.
  if (upap[unit].us_user)
    {
      vec_free (upap[unit].us_user);
      upap[unit].us_user = NULL;
      upap[unit].us_userlen = 0;
    }
  if (upap[unit].us_passwd)
    {
      vec_free (upap[unit].us_passwd);
      upap[unit].us_passwd = NULL;
      upap[unit].us_passwdlen = 0;
    }

  // chap client.
  if (chap_client[unit].us_user)
    {
      vec_free (chap_client[unit].us_user);
      chap_client[unit].us_user = NULL;
      chap_client[unit].us_userlen = 0;
    }
  if (chap_client[unit].us_passwd)
    {
      vec_free (chap_client[unit].us_passwd);
      chap_client[unit].us_passwd = NULL;
      chap_client[unit].us_passwdlen = 0;
    }
}

__clib_export void
pppox_lower_up (u32 sw_if_index)
{
  pppox_main_t *pom = &pppox_main;
  pppox_virtual_interface_t *t = 0;
  u32 unit = ~0;

  t = pppox_get_virtual_interface_by_sw_if_index (pom, sw_if_index, &unit);
  if (t)
    {
      struct protent *protp;

      t->pppoe_session_allocated = 1;

      new_phase (unit, PHASE_INITIALIZE);
      for (int i = 0; (protp = protocols[i]) != NULL; ++i)
	{
	  if (protp->init != NULL)
	    (*protp->init) (unit);
	}
      init_auth_context (unit);
      ipcp_wantoptions[unit].default_route = t->add_default_route4;
      ipcp_set_use_peer_dns (unit, t->use_peer_dns);

      lcp_open (unit);
      start_link (unit);
    }
}

__clib_export void
pppox_lower_down (u32 sw_if_index)
{
  pppox_main_t *pom = &pppox_main;
  pppox_virtual_interface_t *t = 0;
  u32 unit = ~0;

  t = pppox_get_virtual_interface_by_sw_if_index (pom, sw_if_index, &unit);
  if (t)
    {
      t->pppoe_session_allocated = 0;
      lcp_lowerdown (unit);
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
  if (unit == ~0 || pool_is_free_index (pom->virtual_interfaces, unit))
    return VNET_API_ERROR_INVALID_INTERFACE;

  t = pool_elt_at_index (pom->virtual_interfaces, unit);

  // pap client.
  if (upap[unit].us_user)
    {
      vec_free (upap[unit].us_user);
    }
  upap[unit].us_user = (char *) vec_dup (username);
  upap[unit].us_userlen = strlen (upap[unit].us_user);
  if (upap[unit].us_passwd)
    {
      vec_free (upap[unit].us_passwd);
    }
  upap[unit].us_passwd = (char *) vec_dup (password);
  upap[unit].us_passwdlen = strlen (upap[unit].us_passwd);

  // chap client.
  if (chap_client[unit].us_user)
    {
      vec_free (chap_client[unit].us_user);
    }
  chap_client[unit].us_user = (char *) vec_dup (username);
  chap_client[unit].us_userlen = strlen (chap_client[unit].us_user);
  if (chap_client[unit].us_passwd)
    {
      vec_free (chap_client[unit].us_passwd);
    }
  chap_client[unit].us_passwd = (char *) vec_dup (password);
  chap_client[unit].us_passwdlen = strlen (chap_client[unit].us_passwd);

  // after auth configured, notify pppoe to open session to start.
  static void (*pppoe_client_open_session_func) (u32 client_index) = 0;
  if (pppoe_client_open_session_func == 0)
    {
      pppoe_client_open_session_func =
	vlib_get_plugin_symbol ("pppoeclient_plugin.so", "pppoe_client_open_session");
    }
  if (pppoe_client_open_session_func)
    (*pppoe_client_open_session_func) (t->pppoe_client_index);

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

  t->add_default_route4 = !!enabled;
  ipcp_wantoptions[unit].default_route = t->add_default_route4;

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

  t->add_default_route6 = !!enabled;

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

  t->use_peer_dns = !!enabled;
  ipcp_set_use_peer_dns (unit, t->use_peer_dns);

  return 0;
}

clib_error_t *
pppox_init (vlib_main_t *vm)
{
  pppox_main_t *pom = &pppox_main;

  pom->vnet_main = vnet_get_main ();
  pom->vlib_main = vm;

  return 0;
}

VLIB_INIT_FUNCTION (pppox_init);
VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "PPPoX",
};
// pppd-->vpp interaction.

/********************************************************************
 *
 * output - Output PPP packet through pppox virtual interface node.
 */
void
output (int unit, u8 *p, int len)
{
  pppox_main_t *pom = &pppox_main;
  vlib_main_t *vm = pom->vlib_main;
  vnet_main_t *vnm = pom->vnet_main;
  vlib_buffer_t *b;
  u32 bi;
  u32 *to_next;
  vlib_frame_t *f;
  pppox_virtual_interface_t *t = 0;
  vnet_hw_interface_t *hw;

  if (unit < 0)
    return;

  t = pppox_get_virtual_interface_by_unit (pom, (u32) unit);
  if (t == 0)
    {
      // PPPoE client might be deleted, simple return.
      return;
    }
  hw = vnet_get_hw_interface (vnm, t->hw_if_index);
  // TODO: should we should use packet template to prevent allocate buffer????
  if (vlib_buffer_alloc (vm, &bi, 1) != 1)
    {
      clib_warning ("buffer allocation failure");
      return;
    }
  b = vlib_get_buffer (vm, bi);

  ASSERT (b->current_data == 0);

  f = vlib_get_frame_to_node (vm, hw->output_node_index);
  // XXX: if later we suppport other X of PPPoX, we should check
  // remove ppp framing address and control field for PPPoE encap.
  p += 2;
  len -= 2;

  clib_memcpy (vlib_buffer_get_current (b), p, len);
  b->current_length = len;
  // Set tx if index to pppox virtual if index.
  vnet_buffer (b)->sw_if_index[VLIB_TX] = t->sw_if_index;

  /* Enqueue the packet right now */
  to_next = vlib_frame_vector_args (f);
  to_next[0] = bi;
  f->n_vectors = 1;

  vlib_put_frame_to_node (vm, hw->output_node_index, f);
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
  static void (*pppoe_client_set_ipv6_state_func) (u32, const ip6_address_t *,
						   const ip6_address_t *, u8) = 0;
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

  if (pppoe_client_set_ipv6_state_func == 0)
    {
      pppoe_client_set_ipv6_state_func =
	vlib_get_plugin_symbol ("pppoeclient_plugin.so", "pppoe_client_set_ipv6_state");
    }

  if (pppoe_client_set_ipv6_state_func)
    {
      if (a->is_add)
	(*pppoe_client_set_ipv6_state_func) (t->sw_if_index, &a->our_ipv6, &a->his_ipv6,
					     PPPOX_IPV6CP_PREFIX_LEN);
      else
	(*pppoe_client_set_ipv6_state_func) (t->sw_if_index, &zero_addr, &zero_addr, 0);
    }

  return 0;
}

void vl_api_rpc_call_main_thread (void *fp, u8 *data, u32 data_length);

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
  static void (*pppoe_client_set_peer_dns_func) (u32, u32, u32) = 0;

  if (a->unit < 0)
    return 0;

  t = pppox_get_virtual_interface_by_unit (pom, a->unit);
  if (t == 0)
    return 0;

  if (pppoe_client_set_peer_dns_func == 0)
    {
      pppoe_client_set_peer_dns_func =
	vlib_get_plugin_symbol ("pppoeclient_plugin.so", "pppoe_client_set_peer_dns");
    }

  if (pppoe_client_set_peer_dns_func)
    (*pppoe_client_set_peer_dns_func) (t->sw_if_index, a->dns1, a->dns2);

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

  vl_api_rpc_call_main_thread (dns_callback, (u8 *) &a, sizeof (a));
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

  vl_api_rpc_call_main_thread (mtu_callback, (u8 *) &a, sizeof (a));
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

  vl_api_rpc_call_main_thread (default_route_callback, (u8 *) &a, sizeof (a));
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

  vl_api_rpc_call_main_thread (default_route_callback, (u8 *) &a, sizeof (a));
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

  memset (&a, 0, sizeof (a));
  a.unit = unit;
  // NB: oss-pppd pass network endian u32 here, and vpp fib
  // parameter require u32 too, so not conversion here.
  a.our_adr = our_adr;
  a.his_adr = his_adr;
  // oss-pppd passed net_mask is not used, always treat as host address.
  // net_mask = net_mask; // removed self-assign
  a.net_mask = 32;
  a.is_add = 1;

  // Add route in main thread, otherwise it will crash when
  // fib code do barrier check because we will then waiting for
  // our barrier finished...
  vl_api_rpc_call_main_thread (ifaddr_callback, (u8 *) &a, sizeof (a));

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

  memset (&a, 0, sizeof (a));
  a.unit = unit;
  // NB: oss-pppd pass network endian u32 here, and vpp fib
  // parameter require u32 too, so not conversion here.
  // NB: just record them here, we will use the address
  // we recorded on virtual interface to delete.
  a.our_adr = our_adr;
  a.his_adr = his_adr;
  a.net_mask = 32;
  a.is_add = 0;

  // Add route in main thread, otherwise it will crash when
  // fib code do barrier check because we will then waiting for
  // our barrier finished...
  vl_api_rpc_call_main_thread (ifaddr_callback, (u8 *) &a, sizeof (a));

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

  vl_api_rpc_call_main_thread (if6addr_callback, (u8 *) &a, sizeof (a));

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

  vl_api_rpc_call_main_thread (if6addr_callback, (u8 *) &a, sizeof (a));

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
  pppox_virtual_interface_t *t;
  cleanup_arg_t *a = arg;

  if (a->unit < 0)
    return 0;

  t = pppox_get_virtual_interface_by_unit (pom, a->unit);
  if (t == 0)
    return 0;
  // notify pppoe to close session.
  static void (*pppoe_client_close_session_func) (u32 client_index) = 0;
  if (pppoe_client_close_session_func == 0)
    {
      pppoe_client_close_session_func =
	vlib_get_plugin_symbol ("pppoeclient_plugin.so", "pppoe_client_close_session");
    }
  if (pppoe_client_close_session_func)
    (*pppoe_client_close_session_func) (t->pppoe_client_index);

  return 0;
}

int
channel_cleanup (int unit)
{
  ifaddr_arg_t a;

  memset (&a, 0, sizeof (a));
  a.unit = unit;

  // Might be called in worker thread, so use rpc.
  vl_api_rpc_call_main_thread (cleanup_callback, (u8 *) &a, sizeof (a));

  return 1;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
