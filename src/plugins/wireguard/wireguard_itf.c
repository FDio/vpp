
#include <vnet/adj/adj_midchain.h>
#include <vnet/udp/udp.h>

#include <wireguard/wireguard_messages.h>
#include <wireguard/wireguard_itf.h>
#include <wireguard/wireguard.h>


/* bitmap of Allocated WG_ITF instances */
static uword *wg_itf_instances;

/* pool of interfaces */
static wg_itf_t *wg_itf_pool;

static u32 *wg_itf_index_by_sw_if_index;

static u8 *
format_wg_itf_name (u8 * s, va_list * args)
{
  u32 dev_instance = va_arg (*args, u32);
  return format (s, "wg%d", dev_instance);
}

wg_itf_t *
wg_itf_find_by_sw_if_index (u32 sw_if_index)
{
  if (vec_len (wg_itf_index_by_sw_if_index) <= sw_if_index)
    return NULL;
  u32 ti = wg_itf_index_by_sw_if_index[sw_if_index];
  if (ti == ~0)
    return NULL;
  return pool_elt_at_index (wg_itf_pool, ti);
}

//static noise_remote_t *
//wg_remote_get (u32 sw_if_index, uint8_t public_key[NOISE_PUBLIC_KEY_LEN])
//{
//  wg_itf_t *wg_itf;
//  wg_itf = wg_itf_find_by_sw_if_index(sw_if_index);
//  if (!wg_itf)
//      return NULL;

//  wg_peer_t *peer = NULL;
//  wg_peer_t *peer_iter;
//  /* *INDENT-OFF* */
//  pool_foreach (peer_iter, wg_itf->peers,
//  ({
//    if (!memcmp (peer_iter->remote.r_public, public_key, NOISE_PUBLIC_KEY_LEN))
//    {
//      peer = peer_iter;
//      break;
//    }
//  }));
//  /* *INDENT-ON* */
//  return peer ? &peer->remote : NULL;
//}

//static uint32_t
//wg_index_set (u32 sw_if_index, noise_remote_t * remote)
//{
//  wg_itf_t *wg_itf;
//  u32 rnd_seed;

//  wg_itf = wg_itf_find_by_sw_if_index(sw_if_index);
//  if (!wg_itf)
//    return ~0;

//  rnd_seed = (u32) (vlib_time_now (vlib_get_main()) * 1e6);
//  return wg_index_table_add (&wg_itf->index_table, remote->r_peer_idx, rnd_seed);
//}

//static void
//wg_index_drop (u32 sw_if_index, uint32_t key)
//{
//  wg_itf_t *wg_itf;

//  wg_itf = wg_itf_find_by_sw_if_index(sw_if_index);
//  if (!wg_itf)
//    return;

//  wg_index_table_del (&wg_itf->index_table, key);
//}

static clib_error_t *
wg_itf_admin_up_down (vnet_main_t * vnm, u32 hw_if_index, u32 flags)
{
  vnet_hw_interface_t *hi;
  wg_itf_t *itf;
  u32 hw_flags;

  hi = vnet_get_hw_interface (vnm, hw_if_index);
  hw_flags = (flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP ?
	      VNET_HW_INTERFACE_FLAG_LINK_UP : 0);
  vnet_hw_interface_set_flags (vnm, hw_if_index, hw_flags);

  itf = wg_itf_find_by_sw_if_index (hi->sw_if_index);

//  if (itf)
//    wg_tun_protect_walk_itf (itf->ii_sw_if_index,
//                                wg_tun_protect_walk_state_change, itf);

  return (NULL);
}

static int
wg_itf_tunnel_desc (u32 sw_if_index,
		    ip46_address_t * src, ip46_address_t * dst, u8 * is_l2)
{
  ip46_address_reset (src);
  ip46_address_reset (dst);
  *is_l2 = 0;

  return (0);
}

static u8 *
wg_itf_build_rewrite (void)
{
  u8 *rewrite = NULL;

  vec_validate (rewrite, 0);
  vec_reset_length (rewrite);

  return (rewrite);
}

static u8 *
wg_itf_build_rewrite_i (vnet_main_t * vnm,
			u32 sw_if_index,
			vnet_link_t link_type, const void *dst_address)
{
  return (wg_itf_build_rewrite ());
}


void
wg_itf_update_adj (vnet_main_t * vnm, u32 sw_if_index, adj_index_t ai)
{
  adj_nbr_midchain_update_rewrite
    (ai, NULL, NULL, ADJ_FLAG_MIDCHAIN_IP_STACK, wg_itf_build_rewrite ());
}


/* *INDENT-OFF* */
VNET_DEVICE_CLASS (wg_itf_device_class) = {
  .name = "Wireguard Tunnel",
  .format_device_name = format_wg_itf_name,
  .admin_up_down_function = wg_itf_admin_up_down,
  .ip_tun_desc = wg_itf_tunnel_desc,
};

VNET_HW_INTERFACE_CLASS(wg_hw_interface_class) = {
  .name = "Wireguard",
  .build_rewrite = wg_itf_build_rewrite_i,
  .update_adjacency = wg_itf_update_adj,
  .flags = VNET_HW_INTERFACE_CLASS_FLAG_P2P,
};
/* *INDENT-ON* */

/*
 * Maintain a bitmap of allocated wg_itf instance numbers.
 */
#define WG_ITF_MAX_INSTANCE		(16 * 1024)

static u32
wg_itf_instance_alloc (u32 want)
{
  /*
   * Check for dynamically allocated instance number.
   */
  if (~0 == want)
    {
      u32 bit;

      bit = clib_bitmap_first_clear (wg_itf_instances);
      if (bit >= WG_ITF_MAX_INSTANCE)
	{
	  return ~0;
	}
      wg_itf_instances = clib_bitmap_set (wg_itf_instances, bit, 1);
      return bit;
    }

  /*
   * In range?
   */
  if (want >= WG_ITF_MAX_INSTANCE)
    {
      return ~0;
    }

  /*
   * Already in use?
   */
  if (clib_bitmap_get (wg_itf_instances, want))
    {
      return ~0;
    }

  /*
   * Grant allocation request.
   */
  wg_itf_instances = clib_bitmap_set (wg_itf_instances, want, 1);

  return want;
}

static int
wg_itf_instance_free (u32 instance)
{
  if (instance >= WG_ITF_MAX_INSTANCE)
    {
      return -1;
    }

  if (clib_bitmap_get (wg_itf_instances, instance) == 0)
    {
      return -1;
    }

  wg_itf_instances = clib_bitmap_set (wg_itf_instances, instance, 0);
  return 0;
}


int
wg_itf_create (u32 user_instance,
	       const u8 private_key_64[NOISE_KEY_LEN_BASE64], u16 port,
	       u32 * sw_if_indexp)
{
  vnet_main_t *vnm = vnet_get_main ();
  u32 instance, hw_if_index;
  vnet_hw_interface_t *hi;
  wg_itf_t *wg_itf;
  u8 private_key[NOISE_PUBLIC_KEY_LEN];

  ASSERT (sw_if_indexp);

  *sw_if_indexp = (u32) ~ 0;

  /*
   * Allocate a wg_itf instance. Either select on dynamically
   * or try to use the desired user_instance number.
   */
  instance = wg_itf_instance_alloc (user_instance);
  if (instance == ~0)
    return VNET_API_ERROR_INVALID_REGISTRATION;

  pool_get (wg_itf_pool, wg_itf);

  /* tunnel index (or instance) */
  u32 t_idx = wg_itf - wg_itf_pool;

  wg_itf->user_instance = instance;
  if (~0 == wg_itf->user_instance)
    wg_itf->user_instance = t_idx;

  if (!key_from_base64 (private_key_64, NOISE_KEY_LEN_BASE64, private_key))
    return (VNET_API_ERROR_KEY_LENGTH);

  udp_dst_port_info_t *pi = udp_get_dst_port_info (&udp_main, port, UDP_IP4);
  if (pi)
    return (VNET_API_ERROR_VALUE_EXIST);
  udp_register_dst_port (vlib_get_main (), port, wg_input_node.index, 1);

  wg_itf->port = port;
  struct noise_upcall upcall;
//    upcall.u_remote_get = wg_remote_get;
//    upcall.u_index_set = wg_index_set;
//    upcall.u_index_drop = wg_index_drop;

  noise_local_init (&wg_itf->local, &upcall);
  noise_local_set_private (&wg_itf->local, private_key);
  cookie_checker_update (&wg_itf->cookie_checker, wg_itf->local.l_public);

  hw_if_index = vnet_register_interface (vnm,
					 wg_itf_device_class.index,
					 t_idx,
					 wg_hw_interface_class.index, t_idx);

  hi = vnet_get_hw_interface (vnm, hw_if_index);

  vec_validate_init_empty (wg_itf_index_by_sw_if_index, hi->sw_if_index,
			   INDEX_INVALID);
  wg_itf_index_by_sw_if_index[hi->sw_if_index] = t_idx;

  wg_itf->sw_if_index = *sw_if_indexp = hi->sw_if_index;

  return 0;
}

int
wg_itf_delete (u32 sw_if_index)
{
  vnet_main_t *vnm = vnet_get_main ();

  if (pool_is_free_index (vnm->interface_main.sw_interfaces, sw_if_index))
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  vnet_hw_interface_t *hw = vnet_get_sup_hw_interface (vnm, sw_if_index);
  if (hw == 0 || hw->dev_class_index != wg_itf_device_class.index)
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  wg_itf_t *wg_itf;
  wg_itf = wg_itf_find_by_sw_if_index (sw_if_index);
  if (NULL == wg_itf)
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  if (wg_itf_instance_free (hw->dev_instance) < 0)
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  vnet_delete_hw_interface (vnm, hw->hw_if_index);
  pool_put (wg_itf_pool, wg_itf);

  return 0;
}

static clib_error_t *
wg_itf_create_cli (vlib_main_t * vm,
		   unformat_input_t * input, vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u32 instance, sw_if_index;
  u8 *private_key_64;
  u32 port;
  clib_error_t *error;
  int rv;

  error = NULL;
  instance = sw_if_index = ~0;
  private_key_64 = 0;
  port = 0;

  if (unformat_user (input, unformat_line_input, line_input))
    {
      while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
	{
	  if (unformat (line_input, "instance %d", &instance))
	    ;
	  else if (unformat (line_input, "private-key %s", &private_key_64))
	    ;
	  else if (unformat (line_input, "listen-port %d", &port))
	    ;
	  else if (unformat (line_input, "port %d", &port))
	    ;
	  else
	    {
	      error = clib_error_return (0, "unknown input: %U",
					 format_unformat_error, line_input);
	      break;
	    }
	}

      unformat_free (line_input);

      if (error)
	return error;
    }

  rv = wg_itf_create (instance, private_key_64, port, &sw_if_index);

  if (rv)
    return clib_error_return (0, "wg interface create failed");

  vlib_cli_output (vm, "%U\n", format_vnet_sw_if_index_name, vnet_get_main (),
		   sw_if_index);
  return 0;
}

/*?
 * Create a Wireguard interface.
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (wg_itf_create_command, static) = {
  .path = "wireguard itf create",
  .short_help = "wireguard itf create listen-port <port> private-key <key>",
  .function = wg_itf_create_cli,
};
/* *INDENT-ON* */

static clib_error_t *
wg_itf_delete_cli (vlib_main_t * vm,
		   unformat_input_t * input, vlib_cli_command_t * cmd)
{
  vnet_main_t *vnm;
  u32 sw_if_index;
  int rv;

  vnm = vnet_get_main ();
  sw_if_index = ~0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat
	  (input, "%U", unformat_vnet_sw_interface, vnm, &sw_if_index))
	;
      else
	break;
    }

  if (~0 != sw_if_index)
    {
      rv = wg_itf_delete (sw_if_index);

      if (rv)
	return clib_error_return (0, "wireguard interface delete failed");
    }
  else
    return clib_error_return (0, "no such interface: %U",
			      format_unformat_error, input);

  return 0;
}

/*?
 * Delete a Wireguard interface.
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (wg_itf_delete_command, static) = {
  .path = "wireguard itf delete",
  .short_help = "wireguard itf delete <interface>",
  .function = wg_itf_delete_cli,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
