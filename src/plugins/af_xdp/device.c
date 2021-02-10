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
#include <net/if.h>
#include <linux/if_link.h>
#include <bpf/libbpf.h>
#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vlib/pci/pci.h>
#include <vppinfra/linux/sysfs.h>
#include <vppinfra/unix.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/interface/rx_queue_funcs.h>
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
  struct xsk_socket **xsk;
  struct xsk_umem **umem;
  af_xdp_rxq_t *rxq;
  af_xdp_txq_t *txq;

  if (ad->hw_if_index)
    {
      vnet_hw_interface_set_flags (vnm, ad->hw_if_index, 0);
      ethernet_delete_interface (vnm, ad->hw_if_index);
    }

  vec_foreach (rxq, ad->rxqs) clib_file_del_by_index (&file_main,
						      rxq->file_index);
  vec_foreach (txq, ad->txqs) clib_spinlock_free (&txq->lock);
  vec_foreach (xsk, ad->xsk) xsk_socket__delete (*xsk);
  vec_foreach (umem, ad->umem) xsk_umem__delete (*umem);

  if (ad->bpf_obj)
    {
      bpf_set_link_xdp_fd (ad->linux_ifindex, -1, 0);
      bpf_object__unload (ad->bpf_obj);
    }

  vec_free (ad->xsk);
  vec_free (ad->umem);
  vec_free (ad->buffer_template);
  vec_free (ad->rxqs);
  vec_free (ad->txqs);
  clib_error_free (ad->error);
  pool_put (axm->devices, ad);
}

static int
af_xdp_load_program (af_xdp_create_if_args_t * args, af_xdp_device_t * ad)
{
  int fd;

  ad->linux_ifindex = if_nametoindex (ad->linux_ifname);
  if (!ad->linux_ifindex)
    {
      args->rv = VNET_API_ERROR_INVALID_VALUE;
      args->error =
	clib_error_return_unix (0, "if_nametoindex(%s) failed",
				ad->linux_ifname);
      goto err0;
    }

  if (bpf_prog_load (args->prog, BPF_PROG_TYPE_XDP, &ad->bpf_obj, &fd))
    {
      args->rv = VNET_API_ERROR_SYSCALL_ERROR_5;
      args->error =
	clib_error_return_unix (0, "bpf_prog_load(%s) failed", args->prog);
      goto err0;
    }

#ifndef XDP_FLAGS_REPLACE
#define XDP_FLAGS_REPLACE 0
#endif
  if (bpf_set_link_xdp_fd (ad->linux_ifindex, fd, XDP_FLAGS_REPLACE))
    {
      args->rv = VNET_API_ERROR_SYSCALL_ERROR_6;
      args->error =
	clib_error_return_unix (0, "bpf_set_link_xdp_fd(%s) failed",
				ad->linux_ifname);
      goto err1;
    }

  return 0;

err1:
  bpf_object__unload (ad->bpf_obj);
  ad->bpf_obj = 0;
err0:
  ad->linux_ifindex = ~0;
  return -1;
}

static int
af_xdp_create_queue (vlib_main_t * vm, af_xdp_create_if_args_t * args,
		     af_xdp_device_t * ad, int qid, int rxq_num, int txq_num)
{
  struct xsk_umem **umem;
  struct xsk_socket **xsk;
  af_xdp_rxq_t *rxq;
  af_xdp_txq_t *txq;
  struct xsk_umem_config umem_config;
  struct xsk_socket_config sock_config;
  struct xdp_options opt;
  socklen_t optlen;

  vec_validate_aligned (ad->umem, qid, CLIB_CACHE_LINE_BYTES);
  umem = vec_elt_at_index (ad->umem, qid);

  vec_validate_aligned (ad->xsk, qid, CLIB_CACHE_LINE_BYTES);
  xsk = vec_elt_at_index (ad->xsk, qid);

  vec_validate_aligned (ad->rxqs, qid, CLIB_CACHE_LINE_BYTES);
  rxq = vec_elt_at_index (ad->rxqs, qid);

  vec_validate_aligned (ad->txqs, qid, CLIB_CACHE_LINE_BYTES);
  txq = vec_elt_at_index (ad->txqs, qid);

  /*
   * fq and cq must always be allocated even if unused
   * whereas rx and tx indicates whether we want rxq, txq, or both
   */
  struct xsk_ring_cons *rx = qid < rxq_num ? &rxq->rx : 0;
  struct xsk_ring_prod *fq = &rxq->fq;
  struct xsk_ring_prod *tx = qid < txq_num ? &txq->tx : 0;
  struct xsk_ring_cons *cq = &txq->cq;
  int fd;

  memset (&umem_config, 0, sizeof (umem_config));
  umem_config.fill_size = args->rxq_size;
  umem_config.comp_size = args->txq_size;
  umem_config.frame_size =
    sizeof (vlib_buffer_t) + vlib_buffer_get_default_data_size (vm);
  umem_config.flags = XDP_UMEM_UNALIGNED_CHUNK_FLAG;
  if (xsk_umem__create
      (umem, uword_to_pointer (vm->buffer_main->buffer_mem_start, void *),
       vm->buffer_main->buffer_mem_size, fq, cq, &umem_config))
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
  if (xsk_socket__create
      (xsk, ad->linux_ifname, qid, *umem, rx, tx, &sock_config))
    {
      args->rv = VNET_API_ERROR_SYSCALL_ERROR_2;
      args->error =
	clib_error_return_unix (0,
				"xsk_socket__create() failed (is linux netdev %s up?)",
				ad->linux_ifname);
      goto err1;
    }

  fd = xsk_socket__fd (*xsk);
  optlen = sizeof (opt);
  if (getsockopt (fd, SOL_XDP, XDP_OPTIONS, &opt, &optlen))
    {
      args->rv = VNET_API_ERROR_SYSCALL_ERROR_3;
      args->error =
	clib_error_return_unix (0, "getsockopt(XDP_OPTIONS) failed");
      goto err2;
    }
  if (opt.flags & XDP_OPTIONS_ZEROCOPY)
    ad->flags |= AF_XDP_DEVICE_F_ZEROCOPY;

  rxq->xsk_fd = qid < rxq_num ? fd : -1;
  txq->xsk_fd = qid < txq_num ? fd : -1;

  return 0;

err2:
  xsk_socket__delete (*xsk);
err1:
  xsk_umem__delete (*umem);
err0:
  *umem = 0;
  *xsk = 0;
  return -1;
}

static int
af_xdp_get_numa (const char *ifname)
{
  char *path;
  clib_error_t *err;
  int numa;

  path =
    (char *) format (0, "/sys/class/net/%s/device/numa_node%c", ifname, 0);
  err = clib_sysfs_read (path, "%d", &numa);
  if (err || numa < 0)
    numa = 0;

  clib_error_free (err);
  vec_free (path);
  return numa;
}

static clib_error_t *
af_xdp_device_rxq_read_ready (clib_file_t * f)
{
  vnet_hw_if_rx_queue_set_int_pending (vnet_get_main (), f->private_data);
  return 0;
}

static void
af_xdp_device_set_rxq_mode (af_xdp_rxq_t *rxq, int is_polling)
{
  clib_file_main_t *fm = &file_main;
  clib_file_t *f;

  if (rxq->is_polling == is_polling)
    return;

  f = clib_file_get (fm, rxq->file_index);
  fm->file_update (f, is_polling ? UNIX_FILE_UPDATE_DELETE :
				   UNIX_FILE_UPDATE_ADD);
  rxq->is_polling = !!is_polling;
}

void
af_xdp_create_if (vlib_main_t * vm, af_xdp_create_if_args_t * args)
{
  vnet_main_t *vnm = vnet_get_main ();
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  af_xdp_main_t *am = &af_xdp_main;
  af_xdp_device_t *ad;
  vnet_sw_interface_t *sw;
  vnet_hw_interface_t *hw;
  int rxq_num, txq_num, q_num;
  int i;

  args->rxq_size = args->rxq_size ? args->rxq_size : 2 * VLIB_FRAME_SIZE;
  args->txq_size = args->txq_size ? args->txq_size : 2 * VLIB_FRAME_SIZE;
  rxq_num = args->rxq_num ? args->rxq_num : 1;
  txq_num = tm->n_vlib_mains;

  if (!args->linux_ifname)
    {
      args->rv = VNET_API_ERROR_INVALID_VALUE;
      args->error = clib_error_return (0, "missing host interface");
      goto err0;
    }

  if (args->rxq_size < VLIB_FRAME_SIZE || args->txq_size < VLIB_FRAME_SIZE ||
      args->rxq_size > 65535 || args->txq_size > 65535 ||
      !is_pow2 (args->rxq_size) || !is_pow2 (args->txq_size))
    {
      args->rv = VNET_API_ERROR_INVALID_VALUE;
      args->error =
	clib_error_return (0,
			   "queue size must be a power of two between %i and 65535",
			   VLIB_FRAME_SIZE);
      goto err0;
    }

  pool_get_zero (am->devices, ad);

  ad->linux_ifname = (char *) format (0, "%s", args->linux_ifname);
  vec_validate (ad->linux_ifname, IFNAMSIZ - 1);	/* libbpf expects ifname to be at least IFNAMSIZ */

  if (args->prog && af_xdp_load_program (args, ad))
    goto err1;

  q_num = clib_max (rxq_num, txq_num);
  ad->txq_num = txq_num;
  for (i = 0; i < q_num; i++)
    {
      if (af_xdp_create_queue (vm, args, ad, i, rxq_num, txq_num))
	{
	  /*
	   * queue creation failed
	   * it is only a fatal error if we could not create the number of rx
	   * queues requested explicitely by the user and the user did not
	   * requested 'max'
	   * we might create less tx queues than workers but this is ok
	   */

	  /* fixup vectors length */
	  vec_set_len (ad->umem, i);
	  vec_set_len (ad->xsk, i);
	  vec_set_len (ad->rxqs, i);
	  vec_set_len (ad->txqs, i);

	  if (i < rxq_num && AF_XDP_NUM_RX_QUEUES_ALL != rxq_num)
	    goto err1;		/* failed creating requested rxq: fatal error, bailing out */

	  if (i < txq_num)
	    {
	      /* we created less txq than threads not an error but initialize lock for shared txq */
	      af_xdp_txq_t *txq;
	      ad->txq_num = i;
	      vec_foreach (txq, ad->txqs) clib_spinlock_init (&txq->lock);
	    }

	  args->rv = 0;
	  clib_error_free (args->error);
	  break;
	}
    }

  ad->dev_instance = ad - am->devices;
  ad->per_interface_next_index = VNET_DEVICE_INPUT_NEXT_ETHERNET_INPUT;
  ad->pool =
    vlib_buffer_pool_get_default_for_numa (vm,
					   af_xdp_get_numa
					   (ad->linux_ifname));
  if (!args->name)
    ad->name =
      (char *) format (0, "%s/%d", ad->linux_ifname, ad->dev_instance);
  else
    ad->name = (char *) format (0, "%s", args->name);

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

  sw = vnet_get_hw_sw_interface (vnm, ad->hw_if_index);
  hw = vnet_get_hw_interface (vnm, ad->hw_if_index);
  args->sw_if_index = ad->sw_if_index = sw->sw_if_index;
  hw->caps |= VNET_HW_INTERFACE_CAP_SUPPORTS_INT_MODE;

  vnet_hw_if_set_input_node (vnm, ad->hw_if_index, af_xdp_input_node.index);

  for (i = 0; i < vec_len (ad->rxqs); i++)
    {
      af_xdp_rxq_t *rxq = vec_elt_at_index (ad->rxqs, i);
      rxq->queue_index = vnet_hw_if_register_rx_queue (
	vnm, ad->hw_if_index, i, VNET_HW_IF_RXQ_THREAD_ANY);
      u8 *desc = format (0, "%U rxq %d", format_af_xdp_device_name,
			 ad->dev_instance, i);
      clib_file_t f = {
	.file_descriptor = rxq->xsk_fd,
	.flags = UNIX_FILE_EVENT_EDGE_TRIGGERED,
	.private_data = rxq->queue_index,
	.read_function = af_xdp_device_rxq_read_ready,
	.description = desc,
      };
      rxq->file_index = clib_file_add (&file_main, &f);
      vnet_hw_if_set_rx_queue_file_index (vnm, rxq->queue_index,
					  rxq->file_index);
      af_xdp_device_set_rxq_mode (rxq, 1 /* polling */);
    }

  vnet_hw_if_update_runtime_data (vnm, ad->hw_if_index);

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

static clib_error_t *
af_xdp_interface_rx_mode_change (vnet_main_t *vnm, u32 hw_if_index, u32 qid,
				 vnet_hw_if_rx_mode mode)
{
  af_xdp_main_t *am = &af_xdp_main;
  vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, hw_if_index);
  af_xdp_device_t *ad = pool_elt_at_index (am->devices, hw->dev_instance);
  af_xdp_rxq_t *rxq = vec_elt_at_index (ad->rxqs, qid);

  switch (mode)
    {
    case VNET_HW_IF_RX_MODE_UNKNOWN:
    case VNET_HW_IF_NUM_RX_MODES: /* fallthrough */
      return clib_error_create ("uknown rx mode - doing nothing");
    case VNET_HW_IF_RX_MODE_DEFAULT:
    case VNET_HW_IF_RX_MODE_POLLING: /* fallthrough */
      if (rxq->is_polling)
	break;
      af_xdp_device_set_rxq_mode (rxq, 1 /* polling */);
      break;
    case VNET_HW_IF_RX_MODE_INTERRUPT:
    case VNET_HW_IF_RX_MODE_ADAPTIVE: /* fallthrough */
      if (0 == rxq->is_polling)
	break;
      af_xdp_device_set_rxq_mode (rxq, 0 /* interrupt */);
      break;
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

static void
af_xdp_clear (u32 dev_instance)
{
  af_xdp_main_t *am = &af_xdp_main;
  af_xdp_device_t *ad = pool_elt_at_index (am->devices, dev_instance);
  clib_error_free (ad->error);
}

/* *INDENT-OFF* */
VNET_DEVICE_CLASS (af_xdp_device_class) = {
  .name = "AF_XDP interface",
  .format_device = format_af_xdp_device,
  .format_device_name = format_af_xdp_device_name,
  .admin_up_down_function = af_xdp_interface_admin_up_down,
  .rx_mode_change_function = af_xdp_interface_rx_mode_change,
  .rx_redirect_to_node = af_xdp_set_interface_next_node,
  .tx_function_n_errors = AF_XDP_TX_N_ERROR,
  .tx_function_error_strings = af_xdp_tx_func_error_strings,
  .mac_addr_change_function = af_xdp_mac_change,
  .clear_counters = af_xdp_clear,
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
