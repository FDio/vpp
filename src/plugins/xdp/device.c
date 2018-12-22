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

#include <net/if.h>
#include <linux/if_link.h>
#include <linux/if_xdp.h>
#include <linux/if_ether.h>

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vlib/pci/pci.h>
#include <vnet/ethernet/ethernet.h>

#include <xdp/xdp.h>

#define xdp_log_err(dev, f, ...)                        \
  vlib_log (VLIB_LOG_LEVEL_ERR, xdp_main.log_class, "%s: " f, dev->ifname, ## __VA_ARGS__)
#define xdp_log_debug(dev, f, ...)                        \
  vlib_log (VLIB_LOG_LEVEL_DEBUG, xdp_main.log_class, "%s: " f, dev->ifname, ## __VA_ARGS__)

xdp_main_t xdp_main;

static u32
xdp_flag_change (vnet_main_t * vnm, vnet_hw_interface_t * hw, u32 flags)
{
  xdp_main_t *xm = &xdp_main;
  vlib_log_warn (xm->log_class, "TODO");
  return 0;
}

void
xdp_delete_if (vlib_main_t * vm, xdp_device_t * xd)
{
  vnet_main_t *vnm = vnet_get_main ();
  xdp_main_t *xm = &xdp_main;

  if (xd->fd != -1)
    close (xd->fd);

  if (xd->hw_if_index)
    {
      vnet_hw_interface_set_flags (vnm, xd->hw_if_index, 0);
      vnet_hw_interface_unassign_rx_thread (vnm, xd->hw_if_index, 0);
      ethernet_delete_interface (vnm, xd->hw_if_index);
    }

  vec_free (xd->ifname);
  clib_error_free (xd->err);
  clib_memset (xd, 0, sizeof (*xd));
  pool_put (xm->devices, xd);
}

#ifndef SOL_XDP
#define SOL_XDP 283
#endif

#ifndef AF_XDP
#define AF_XDP 44
#endif

#ifndef PF_XDP
#define PF_XDP AF_XDP
#endif

#define DEFAULT_COMPLETION_RING_SIZE 32
#define DEFAULT_FILL_RING_SIZE 1024
#define DEFAULT_RX_RING_SIZE 1024
#define DEFAULT_TX_RING_SIZE 1024
#define NUM_FRAMES 2048
#define FRAME_SIZE 2048

clib_error_t *
xdp_setsockopt (xdp_device_t * xd, int optname, void *optval,
		socklen_t optlen)
{
  if (setsockopt (xd->fd, SOL_XDP, optname, optval, optlen) >= 0)
    return 0;

  xd->err = clib_error_return_unix (0, "xdp setsockopt failed");
  xdp_log_err (xd, "error: %U", format_clib_error, xd->err);
  return xd->err;
}

clib_error_t *
xdp_getsockopt (xdp_device_t * xd, int optname, void *optval,
		socklen_t * optlen)
{
  if (getsockopt (xd->fd, SOL_XDP, optname, optval, optlen) >= 0)
    return 0;

  xd->err = clib_error_return_unix (0, "xdp getsockopt failed");
  xdp_log_err (xd, "error: %U", format_clib_error, xd->err);
  return xd->err;
}

clib_error_t *
xdp_mmap (xdp_device_t * xd, size_t size, off_t offset, void **map)
{
  clib_error_t *err = 0;
  xdp_log_debug (xd, "mmap size %u offset %u", size, offset);
  *map = mmap (0, size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE,
	       xd->fd, offset);

  if (*map == MAP_FAILED)
    {
      err = xd->err = clib_error_return_unix (0, "xdp_mmap failed");
      xdp_log_err (xd, "xdp mmap failed: %U", format_clib_error, xd->err);
    }

  return err;
}

void
xdp_create_if (vlib_main_t * vm, xdp_create_if_args_t * args)
{
  vnet_main_t *vnm = vnet_get_main ();
  xdp_main_t *xm = &xdp_main;
  xdp_device_t *xd;
  unsigned int ifindex;
  struct xdp_umem_reg umem;
  int sz;

  pool_get_zero (xm->devices, xd);
  xd->dev_instance = xd - xm->devices;
  xd->per_interface_next_index = ~0;
  xd->ifname = args->ifname;
  xd->fd = -1;
  args->ifname = 0;

  if ((ifindex = if_nametoindex ((char *) xd->ifname)) == 0)
    {
      args->rv = VNET_API_ERROR_NO_MATCHING_INTERFACE;
      args->err = clib_error_return (0, "unknown interface '%s'",
				     args->ifname);
      xdp_log_err (xd, "error: %U", format_clib_error, args->err);
      goto error;
    }

  xdp_log_debug (xd, "ifindex %d", ifindex);

  if ((xd->fd = socket (AF_XDP, SOCK_RAW, 0)) < 0)
    {
      args->rv = VNET_API_ERROR_SYSCALL_ERROR_1;
      args->err = clib_error_return_unix (0, "cannot open AF_XDP socket");
      xdp_log_err (xd, "error: %U", format_clib_error, args->err);
      goto error;
    }
  xdp_log_debug (xd, "socket fd %d", xd->fd);

  /* XDP_UMEM_REG */
  umem.headroom = 0;
  umem.chunk_size = FRAME_SIZE;
  umem.len = NUM_FRAMES * umem.chunk_size;
  umem.addr = pointer_to_uword
    (clib_mem_alloc_aligned (umem.len, clib_mem_get_page_size ()));

  xdp_log_debug (xd, "XDP_UMEM_REG headroom %u chunk_sz %u, len %u addr %x",
		 umem.headroom, umem.chunk_size, umem.len, umem.addr);
  if (xdp_setsockopt (xd, XDP_UMEM_REG, &umem, sizeof (umem)))
    goto error;

  /* XDP_UMEM_FILL_RING */
  sz = DEFAULT_FILL_RING_SIZE;
  xdp_log_debug (xd, "XDP_UMEM_FILL_RING fill_ring_sz %u", sz);
  if (xdp_setsockopt (xd, XDP_UMEM_FILL_RING, &sz, sizeof (int)))
    goto error;

  /* XDP_UMEM_COMPLETION_RING */
  sz = DEFAULT_COMPLETION_RING_SIZE;
  xdp_log_debug (xd, "XDP_UMEM_COMPLETION_RING comp_ring_sz %u", sz);
  if (xdp_setsockopt (xd, XDP_UMEM_COMPLETION_RING, &sz, sizeof (int)))
    goto error;

#if 0
  int rx_ring_size = DEFAULT_RX_RING_SIZE;
  if (setsockopt
      (xd->fd, SOL_XDP, XDP_RX_RING, &rx_ring_size,
       sizeof (rx_ring_size)) < 0)
    {
      args->rv = VNET_API_ERROR_SYSCALL_ERROR_5;
      args->error =
	clib_error_return_unix (0, "XDP_UMEM_COMPLETION_RING failed");
      xdp_log_err (xd, "error: %U", format_clib_error, args->error);
      goto error;
    }

  int tx_ring_size = DEFAULT_TX_RING_SIZE;
  if (setsockopt
      (xd->fd, SOL_XDP, XDP_TX_RING, &tx_ring_size,
       sizeof (tx_ring_size)) < 0)
    {
      args->rv = VNET_API_ERROR_SYSCALL_ERROR_5;
      args->error =
	clib_error_return_unix (0, "XDP_UMEM_COMPLETION_RING failed");
      xdp_log_err (xd, "error: %U", format_clib_error, args->error);
      goto error;
    }
#endif

  socklen_t opt_length;
  struct xdp_mmap_offsets offsets;
  opt_length = sizeof (offsets);
  if (xdp_getsockopt (xd, XDP_MMAP_OFFSETS, &offsets, &opt_length))
    goto error;

  xdp_log_debug (xd, "rx offset prod %u cons %u desc %u", offsets.rx.producer,
		offsets.rx.consumer, offsets.rx.desc);
  xdp_log_debug (xd, "tx offset prod %u cons %u desc %u", offsets.tx.producer,
		offsets.tx.consumer, offsets.tx.desc);
  xdp_log_debug (xd, "fr offset prod %u cons %u desc %u", offsets.fr.producer,
		offsets.fr.consumer, offsets.fr.desc);
  xdp_log_debug (xd, "cr offset prod %u cons %u desc %u", offsets.cr.producer,
		offsets.cr.consumer, offsets.cr.desc);

  void *fq_map, *cq_map, *rx_map, *tx_map;
  sz = offsets.fr.desc + DEFAULT_FILL_RING_SIZE * sizeof (u64);
  if (xdp_mmap (xd, sz, XDP_UMEM_PGOFF_FILL_RING, &fq_map))
    goto error;

  sz = offsets.cr.desc + DEFAULT_COMPLETION_RING_SIZE * sizeof (u64);
  if (xdp_mmap (xd, sz, XDP_UMEM_PGOFF_COMPLETION_RING, &cq_map))
    goto error;

  if (0) {
  sz = offsets.rx.desc + DEFAULT_RX_RING_SIZE * sizeof (struct xdp_desc);
  if (xdp_mmap (xd, sz, XDP_PGOFF_RX_RING, &rx_map))
    goto error;

  sz = offsets.tx.desc + DEFAULT_TX_RING_SIZE * sizeof (struct xdp_desc);
  if (xdp_mmap (xd, sz, XDP_PGOFF_TX_RING, &tx_map))
    goto error;

  }
  struct sockaddr_xdp sxdp = { };
  sxdp.sxdp_family = PF_XDP;
  sxdp.sxdp_ifindex = ifindex;
  sxdp.sxdp_queue_id = 0;
  sxdp.sxdp_flags = XDP_COPY;

  xdp_log_debug (xd, "bind ifindex %u queue %u", sxdp.sxdp_ifindex, sxdp.sxdp_queue_id);
  if (bind (xd->fd, (struct sockaddr *) &sxdp, sizeof (sxdp)) != 0)
    {
      xd->err = clib_error_return_unix (0, "bind");
      xdp_log_err (xd, "xdp bind failed: %U", format_clib_error, xd->err);
      goto error;
    }

  /* create interface */
  if ((xd->err = ethernet_register_interface (vnm, xdp_device_class.index,
					 xd->dev_instance, xd->hwaddr,
					 &xd->hw_if_index, xdp_flag_change)))
    goto error;

  vnet_sw_interface_t *sw = vnet_get_hw_sw_interface (vnm, xd->hw_if_index);
  args->sw_if_index = xd->sw_if_index = sw->sw_if_index;

  vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, xd->hw_if_index);
  hw->flags |= VNET_HW_INTERFACE_FLAG_SUPPORTS_INT_MODE;
  vnet_hw_interface_set_input_node (vnm, xd->hw_if_index,
				    xdp_input_node.index);

  return;

error:
  xdp_delete_if (vm, xd);
  args->rv = VNET_API_ERROR_SYSCALL_ERROR_1;
}

static clib_error_t *
xdp_interface_admin_up_down (vnet_main_t * vnm, u32 hw_if_index, u32 flags)
{
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, hw_if_index);
  xdp_main_t *xm = &xdp_main;
  xdp_device_t *xd = vec_elt_at_index (xm->devices, hi->dev_instance);
  uword is_up = (flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP) != 0;

  if (xd->flags & XDP_DEVICE_F_ERROR)
    return clib_error_return (0, "device is in error state");

  if (is_up)
    {
      vnet_hw_interface_set_flags (vnm, xd->hw_if_index,
				   VNET_HW_INTERFACE_FLAG_LINK_UP);
      xd->flags |= XDP_DEVICE_F_ADMIN_UP;
    }
  else
    {
      vnet_hw_interface_set_flags (vnm, xd->hw_if_index, 0);
      xd->flags &= ~XDP_DEVICE_F_ADMIN_UP;
    }
  return 0;
}

static void
xdp_set_interface_next_node (vnet_main_t * vnm, u32 hw_if_index,
			     u32 node_index)
{
  xdp_main_t *xm = &xdp_main;
  vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, hw_if_index);
  xdp_device_t *xd = pool_elt_at_index (xm->devices, hw->dev_instance);

  /* Shut off redirection */
  if (node_index == ~0)
    {
      xd->per_interface_next_index = node_index;
      return;
    }

  xd->per_interface_next_index =
    vlib_node_add_next (vlib_get_main (), xdp_input_node.index, node_index);
}

static char *xdp_tx_func_error_strings[] = {
#define _(n,s) s,
  foreach_xdp_tx_func_error
#undef _
};

/* *INDENT-OFF* */
VNET_DEVICE_CLASS (xdp_device_class,) =
{
  .name = "XDP interface",
  .format_device = format_xdp_device,
  .format_device_name = format_xdp_device_name,
  .admin_up_down_function = xdp_interface_admin_up_down,
  .rx_redirect_to_node = xdp_set_interface_next_node,
  .tx_function_n_errors = AVF_TX_N_ERROR,
  .tx_function_error_strings = xdp_tx_func_error_strings,
};
/* *INDENT-ON* */

clib_error_t *
xdp_init (vlib_main_t * vm)
{
  xdp_main_t *xm = &xdp_main;

  xm->log_class = vlib_log_register_class ("xdp", 0);

  return 0;
}

VLIB_INIT_FUNCTION (xdp_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
