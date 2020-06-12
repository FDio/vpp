/*
 *------------------------------------------------------------------
 * Copyright (c) 2018 Cisco and/or its affiliates.
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
 *------------------------------------------------------------------
 */

#include <stdio.h>
#include <linux/if.h>		/* IFNAMSIZ */
#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vlib/pci/pci.h>
#include <vnet/ethernet/ethernet.h>
#include "af_xdp.h"

af_xdp_main_t af_xdp_main;

typedef struct
{
  u32 prod;
  u32 cons;
} gdb_af_xdp_pair_t;

gdb_af_xdp_pair_t
gdb_af_xdp_get_prod (const struct xsk_ring_prod *prod)
{
  gdb_af_xdp_pair_t pair = { *prod->producer, *prod->consumer };
  return pair;
}

gdb_af_xdp_pair_t
gdb_af_xdp_get_cons (const struct xsk_ring_cons * cons)
{
  gdb_af_xdp_pair_t pair = { *cons->producer, *cons->consumer };
  return pair;
}

static clib_error_t *
af_xdp_mac_change (vnet_hw_interface_t * hw, const u8 * old, const u8 * new)
{
  af_xdp_main_t *am = &af_xdp_main;
  af_xdp_device_t *ad = vec_elt_at_index (am->devices, hw->dev_instance);
  errno_t err = memcpy_s (ad->hwaddr, sizeof (ad->hwaddr), new, 6);
  if (err)
    return clib_error_return_code (0, -err, CLIB_ERROR_ERRNO_VALID,
				   "mac change failed");
  return 0;
}

static u32
af_xdp_flag_change (vnet_main_t * vnm, vnet_hw_interface_t * hw, u32 flags)
{
  af_xdp_main_t *am = &af_xdp_main;
  af_xdp_device_t *ad = vec_elt_at_index (am->devices, hw->dev_instance);

  switch (flags)
    {
    case 0:
      af_xdp_log (VLIB_LOG_LEVEL_ERR, ad, "set unicast not supported yet");
      return ~0;
    case ETHERNET_INTERFACE_FLAG_ACCEPT_ALL:
      af_xdp_log (VLIB_LOG_LEVEL_ERR, ad,
		  "set promiscuous not supported yet");
      return ~0;
    case ETHERNET_INTERFACE_FLAG_MTU:
      af_xdp_log (VLIB_LOG_LEVEL_ERR, ad, "set mtu not supported yet");
      return ~0;
    }

  af_xdp_log (VLIB_LOG_LEVEL_ERR, ad, "unknown flag %x requested", flags);
  return ~0;
}

void
af_xdp_delete_if (vlib_main_t * vm, af_xdp_device_t * ad)
{
  vnet_main_t *vnm = vnet_get_main ();
  af_xdp_main_t *axm = &af_xdp_main;

  if (ad->hw_if_index)
    {
      vnet_hw_interface_set_flags (vnm, ad->hw_if_index, 0);
      vnet_hw_interface_unassign_rx_thread (vnm, ad->hw_if_index, 0);
      ethernet_delete_interface (vnm, ad->hw_if_index);
    }

  xsk_socket__delete (ad->xsk);
  xsk_umem__delete (ad->umem);

  clib_error_free (ad->error);
  clib_memset (ad, 0, sizeof (*ad));
  pool_put (axm->devices, ad);
}

static int
af_xdp_create_qp (vlib_main_t * vm, af_xdp_create_if_args_t * args,
		  af_xdp_device_t * ad, int qid)
{
  struct xsk_umem_config umem_config;
  struct xsk_socket_config sock_config;
  struct xdp_options opt;
  af_xdp_rxq_t *rxq;
  af_xdp_txq_t *txq;
  socklen_t optlen;

  vec_validate_aligned (ad->rxqs, qid, CLIB_CACHE_LINE_BYTES);
  rxq = vec_elt_at_index (ad->rxqs, qid);

  vec_validate_aligned (ad->txqs, qid, CLIB_CACHE_LINE_BYTES);
  txq = vec_elt_at_index (ad->txqs, qid);

  memset (&umem_config, 0, sizeof (umem_config));
  umem_config.fill_size = args->rxq_size;
  umem_config.comp_size = args->txq_size;
  umem_config.frame_size =
    sizeof (vlib_buffer_t) + vlib_buffer_get_default_data_size (vm);
  umem_config.flags = XDP_UMEM_UNALIGNED_CHUNK_FLAG;
  if (xsk_umem__create
      (&ad->umem,
       uword_to_pointer (vm->buffer_main->buffer_mem_start, void *),
       vm->buffer_main->buffer_mem_size, &rxq->fq, &txq->cq, &umem_config))
    {
      args->rv = VNET_API_ERROR_SYSCALL_ERROR_1;
      args->error = clib_error_return_unix (0, "xsk_umem__create() failed");
      goto err0;
    }

  memset (&sock_config, 0, sizeof (sock_config));
  sock_config.rx_size = args->rxq_size;
  sock_config.tx_size = args->txq_size;
  sock_config.bind_flags = XDP_USE_NEED_WAKEUP;
  switch (args->mode)
    {
    case AF_XDP_MODE_AUTO:
      break;
    case AF_XDP_MODE_COPY:
      sock_config.bind_flags |= XDP_COPY;
      break;
    case AF_XDP_MODE_ZERO_COPY:
      sock_config.bind_flags |= XDP_ZEROCOPY;
      break;
    }
  vec_validate (args->ifname, IFNAMSIZ - 1);	/* libbpf expects ifname to be at least IFNAMSIZ */
  if (xsk_socket__create (&ad->xsk, args->ifname, 0 /* queue id */ , ad->umem,
			  &ad->rxqs->rx, &ad->txqs->tx, &sock_config))
    {
      args->rv = VNET_API_ERROR_SYSCALL_ERROR_2;
      args->error = clib_error_return_unix (0, "xsk_socket__create() failed");
      goto err1;
    }

  rxq->xsk_fd = txq->xsk_fd = xsk_socket__fd (ad->xsk);

  optlen = sizeof (opt);
  if (getsockopt (rxq->xsk_fd, SOL_XDP, XDP_OPTIONS, &opt, &optlen))
    {
      args->rv = VNET_API_ERROR_SYSCALL_ERROR_3;
      args->error =
	clib_error_return_unix (0, "getsockopt(XDP_OPTIONS) failed");
      goto err1;
    }
  if (opt.flags & XDP_OPTIONS_ZEROCOPY)
    ad->flags |= AF_XDP_DEVICE_F_ZEROCOPY;

  return 0;

err1:
  xsk_umem__delete (ad->umem);
err0:
  ad->umem = 0;
  ad->xsk = 0;
  return -1;
}

static int
af_xdp_get_numa (const char *ifname)
{
  FILE *fptr;
  int numa;
  char *s;

  s = (char *) format (0, "/sys/class/net/%s/device/numa_node%c", ifname, 0);
  fptr = fopen (s, "rb");
  vec_free (s);

  if (!fptr)
    return 0;

  if (fscanf (fptr, "%d\n", &numa) != 1)
    numa = 0;

  fclose (fptr);
  return numa;
}

void
af_xdp_create_if (vlib_main_t * vm, af_xdp_create_if_args_t * args)
{
  vnet_main_t *vnm = vnet_get_main ();
  af_xdp_main_t *am = &af_xdp_main;
  af_xdp_device_t *ad;
  int qid;

  args->rxq_size = args->rxq_size ? args->rxq_size : 2 * VLIB_FRAME_SIZE;
  args->txq_size = args->txq_size ? args->txq_size : 2 * VLIB_FRAME_SIZE;
  args->rxq_num = args->rxq_num ? args->rxq_num : 1;

  if (args->rxq_size < VLIB_FRAME_SIZE || args->txq_size < VLIB_FRAME_SIZE ||
      args->rxq_size > 65535 || args->txq_size > 65535 ||
      !is_pow2 (args->rxq_size) || !is_pow2 (args->txq_size))
    {
      args->rv = VNET_API_ERROR_INVALID_VALUE;
      args->error = clib_error_return (0, "queue size must be a power of two "
				       "between %i and 65535",
				       VLIB_FRAME_SIZE);
      goto err0;
    }

  pool_get (am->devices, ad);

  if (af_xdp_create_qp (vm, args, ad, 0))
    goto err1;

  ad->dev_instance = ad - am->devices;
  ad->per_interface_next_index = VNET_DEVICE_INPUT_NEXT_ETHERNET_INPUT;
  ad->pool =
    vlib_buffer_pool_get_default_for_numa (vm,
					   af_xdp_get_numa (args->ifname));
  ad->linux_ifname = format (0, "%s", args->ifname);
  if (!args->name || 0 == args->name[0])
    ad->name = format (0, "%s/%d", args->ifname, ad->dev_instance);
  else
    ad->name = format (0, "%s", args->name);

  ethernet_mac_address_generate (ad->hwaddr);

  /* create interface */
  if (ethernet_register_interface (vnm, af_xdp_device_class.index,
				   ad->dev_instance, ad->hwaddr,
				   &ad->hw_if_index, af_xdp_flag_change))
    {
      args->rv = VNET_API_ERROR_INVALID_INTERFACE;
      args->error =
	clib_error_return (0, "ethernet_register_interface() failed");
      goto err1;
    }

  vnet_sw_interface_t *sw = vnet_get_hw_sw_interface (vnm, ad->hw_if_index);
  args->sw_if_index = ad->sw_if_index = sw->sw_if_index;

  /*
   * FIXME: add support for interrupt mode
   * vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, ad->hw_if_index);
   * hw->flags |= VNET_HW_INTERFACE_FLAG_SUPPORTS_INT_MODE;
   */

  vnet_hw_interface_set_input_node (vnm, ad->hw_if_index,
				    af_xdp_input_node.index);

  vec_foreach_index (qid, ad->rxqs)
    vnet_hw_interface_assign_rx_thread (vnm, ad->hw_if_index, qid, ~0);

  /* buffer template */
  vec_validate_aligned (ad->buffer_template, 1, CLIB_CACHE_LINE_BYTES);
  ad->buffer_template->flags = VLIB_BUFFER_TOTAL_LENGTH_VALID;
  ad->buffer_template->ref_count = 1;
  vnet_buffer (ad->buffer_template)->sw_if_index[VLIB_RX] = ad->sw_if_index;
  vnet_buffer (ad->buffer_template)->sw_if_index[VLIB_TX] = (u32) ~ 0;
  ad->buffer_template->buffer_pool_index = ad->pool;

  return;

err1:
  af_xdp_delete_if (vm, ad);
err0:
  vlib_log_err (am->log_class, "%U", format_clib_error, args->error);
}

static clib_error_t *
af_xdp_interface_admin_up_down (vnet_main_t * vnm, u32 hw_if_index, u32 flags)
{
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, hw_if_index);
  af_xdp_main_t *am = &af_xdp_main;
  af_xdp_device_t *ad = vec_elt_at_index (am->devices, hi->dev_instance);
  uword is_up = (flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP) != 0;

  if (ad->flags & AF_XDP_DEVICE_F_ERROR)
    return clib_error_return (0, "device is in error state");

  if (is_up)
    {
      vnet_hw_interface_set_flags (vnm, ad->hw_if_index,
				   VNET_HW_INTERFACE_FLAG_LINK_UP);
      ad->flags |= AF_XDP_DEVICE_F_ADMIN_UP;
    }
  else
    {
      vnet_hw_interface_set_flags (vnm, ad->hw_if_index, 0);
      ad->flags &= ~AF_XDP_DEVICE_F_ADMIN_UP;
    }
  return 0;
}

static void
af_xdp_set_interface_next_node (vnet_main_t * vnm, u32 hw_if_index,
				u32 node_index)
{
  af_xdp_main_t *am = &af_xdp_main;
  vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, hw_if_index);
  af_xdp_device_t *ad = pool_elt_at_index (am->devices, hw->dev_instance);

  /* Shut off redirection */
  if (node_index == ~0)
    {
      ad->per_interface_next_index = node_index;
      return;
    }

  ad->per_interface_next_index =
    vlib_node_add_next (vlib_get_main (), af_xdp_input_node.index,
			node_index);
}

static char *af_xdp_tx_func_error_strings[] = {
#define _(n,s) s,
  foreach_af_xdp_tx_func_error
#undef _
};

/* *INDENT-OFF* */
VNET_DEVICE_CLASS (af_xdp_device_class) =
{
  .name = "AF_XDP interface",
  .format_device = format_af_xdp_device,
  .format_device_name = format_af_xdp_device_name,
  .admin_up_down_function = af_xdp_interface_admin_up_down,
  .rx_redirect_to_node = af_xdp_set_interface_next_node,
  .tx_function_n_errors = AF_XDP_TX_N_ERROR,
  .tx_function_error_strings = af_xdp_tx_func_error_strings,
  .mac_addr_change_function = af_xdp_mac_change,
};
/* *INDENT-ON* */

clib_error_t *
af_xdp_init (vlib_main_t * vm)
{
  af_xdp_main_t *am = &af_xdp_main;

  am->log_class = vlib_log_register_class ("af_xdp", 0);

  return 0;
}

VLIB_INIT_FUNCTION (af_xdp_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
