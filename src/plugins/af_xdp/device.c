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

#include <af_xdp/af_xdp.h>

af_xdp_main_t af_xdp_main;

static u32
af_xdp_flag_change (vnet_main_t * vnm, vnet_hw_interface_t * hw, u32 flags)
{
  af_xdp_main_t *am = &af_xdp_main;
  vlib_log_warn (am->log_class, "TODO");
  return 0;
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

  clib_error_free (ad->error);
  clib_memset (ad, 0, sizeof (*ad));
  pool_put (axm->devices, ad);
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

void
af_xdp_create_if (vlib_main_t * vm, af_xdp_create_if_args_t * args)
{
  vnet_main_t *vnm = vnet_get_main ();
  af_xdp_main_t *am = &af_xdp_main;
  af_xdp_device_t *ad;
  clib_error_t *error = 0;
  unsigned int ifindex;
  int fd;
  struct xdp_umem_reg umem;

  if ((ifindex = if_nametoindex((char *) args->ifname)) == 0)
    {
      args->rv = VNET_API_ERROR_NO_MATCHING_INTERFACE;
      args->error = clib_error_return (error, "unknown interface '%s'",
				       args->ifname);
      return;
    }

  if ((fd = socket(AF_XDP, SOCK_RAW, 0)) < 0)
    {
      args->rv = VNET_API_ERROR_SYSCALL_ERROR_1;
      args->error = clib_error_return (error, "cannot open AF_XDP socket");
      return;
    }

  umem.headroom = 0;
  umem.chunk_size = FRAME_SIZE;
  umem.len = NUM_FRAMES * umem.chunk_size;
  umem.addr = pointer_to_uword
    (clib_mem_alloc_aligned (umem.len,clib_mem_get_page_size ()));

  if (setsockopt(fd, SOL_XDP, XDP_UMEM_REG, &umem, sizeof(umem)) < 0)
    {
      args->rv = VNET_API_ERROR_SYSCALL_ERROR_2;
      args->error = clib_error_return (error, "XDP_UMEM_REG failed");
      close(fd);
      return;
  }

  int fill_ring_size = DEFAULT_FILL_RING_SIZE;
  if (setsockopt(fd, SOL_XDP, XDP_UMEM_FILL_RING, &fill_ring_size,
		 sizeof(fill_ring_size)) < 0)
    {
      args->rv = VNET_API_ERROR_SYSCALL_ERROR_3;
      args->error = clib_error_return (error, "XDP_UMEM_FILL_RING failed");
      close(fd);
      return;
    }

  int completion_ring_size = DEFAULT_COMPLETION_RING_SIZE;
  if (setsockopt(fd, SOL_XDP, XDP_UMEM_COMPLETION_RING, &completion_ring_size,
		 sizeof(completion_ring_size)) < 0)
    {
      args->rv = VNET_API_ERROR_SYSCALL_ERROR_4;
      args->error = clib_error_return (error, "XDP_UMEM_COMPLETION_RING failed");
      close(fd);
      return;
    }

  int rx_ring_size = DEFAULT_RX_RING_SIZE;
  if (setsockopt(fd, SOL_XDP, XDP_RX_RING, &rx_ring_size, sizeof(rx_ring_size)) < 0)
    {
      args->rv = VNET_API_ERROR_SYSCALL_ERROR_5;
      args->error = clib_error_return (error, "XDP_RX_RING failed");
      close(fd);
      return;
    }

  int tx_ring_size = DEFAULT_TX_RING_SIZE;
  if (setsockopt(fd, SOL_XDP, XDP_TX_RING, &tx_ring_size, sizeof(tx_ring_size)) < 0)
    {
      args->rv = VNET_API_ERROR_SYSCALL_ERROR_5;
      args->error = clib_error_return (error, "XDP_RX_RING failed");
      close(fd);
      return;
    }

  socklen_t opt_length;
  struct xdp_mmap_offsets offsets;
  opt_length = sizeof(offsets);
  if (getsockopt(fd, SOL_XDP, XDP_MMAP_OFFSETS, &offsets, &opt_length) < 0)
    {
      args->rv = VNET_API_ERROR_SYSCALL_ERROR_6;
      args->error = clib_error_return (error, "XDP_MMAP_OFFSETS failed");
      close(fd);
      return;
    }
  clib_warning ("rx offset prod %u cons %u desc %u", offsets.rx.producer, offsets.rx.consumer, offsets.rx.desc);
  clib_warning ("tx offset prod %u cons %u desc %u", offsets.tx.producer, offsets.tx.consumer, offsets.tx.desc);
  clib_warning ("fr offset prod %u cons %u desc %u", offsets.fr.producer, offsets.fr.consumer, offsets.fr.desc);
  clib_warning ("cr offset prod %u cons %u desc %u", offsets.cr.producer, offsets.cr.consumer, offsets.cr.desc);

  void *fq_map;
  fq_map = mmap(0, offsets.fr.desc + DEFAULT_FILL_RING_SIZE * sizeof(u64),
		PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, fd,
		XDP_UMEM_PGOFF_FILL_RING);

  if (fq_map == MAP_FAILED)
    {
      args->rv = VNET_API_ERROR_SYSCALL_ERROR_7;
      args->error = clib_error_return (error, "mmap cq failed");
      close(fd);
      return;
    }

  void *cq_map;
  cq_map = mmap(0, offsets.cr.desc + DEFAULT_COMPLETION_RING_SIZE * sizeof(u64),
		PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, fd,
		XDP_UMEM_PGOFF_COMPLETION_RING);

  if (cq_map == MAP_FAILED)
    {
      args->rv = VNET_API_ERROR_SYSCALL_ERROR_7;
      args->error = clib_error_return (error, "mmap cq failed");
      close(fd);
      return;
    }

  void *rx_map;
  rx_map = mmap(0, offsets.rx.desc + DEFAULT_RX_RING_SIZE * sizeof(struct xdp_desc),
		PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, fd,
		XDP_PGOFF_RX_RING);

  if (rx_map == MAP_FAILED)
    {
      args->rv = VNET_API_ERROR_SYSCALL_ERROR_7;
      args->error = clib_error_return (error, "mmap rx failed");
      close(fd);
      return;
    }

  void *tx_map;
  tx_map = mmap(0, offsets.tx.desc + DEFAULT_TX_RING_SIZE * sizeof(struct xdp_desc),
		PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, fd,
		XDP_PGOFF_TX_RING);

  if (tx_map == MAP_FAILED)
    {
      args->rv = VNET_API_ERROR_SYSCALL_ERROR_7;
      args->error = clib_error_return (error, "mmap rx failed");
      close(fd);
      return;
    }

  struct sockaddr_xdp sxdp = {};
  sxdp.sxdp_family = PF_XDP;
  sxdp.sxdp_ifindex = ifindex;
  sxdp.sxdp_queue_id = 0;
  sxdp.sxdp_flags = XDP_COPY;

  if (bind(fd, (struct sockaddr *)&sxdp, sizeof(sxdp)) != 0)
    {
      args->rv = VNET_API_ERROR_SYSCALL_ERROR_7;
      args->error = clib_error_return (error, "bind");
      close(fd);
      return;
    }

  pool_get (am->devices, ad);
  ad->dev_instance = ad - am->devices;
  ad->per_interface_next_index = ~0;


  /* create interface */
  error = ethernet_register_interface (vnm, af_xdp_device_class.index,
				       ad->dev_instance, ad->hwaddr,
				       &ad->hw_if_index, af_xdp_flag_change);

  if (error)
    goto error;

  vnet_sw_interface_t *sw = vnet_get_hw_sw_interface (vnm, ad->hw_if_index);
  args->sw_if_index = ad->sw_if_index = sw->sw_if_index;

  vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, ad->hw_if_index);
  hw->flags |= VNET_HW_INTERFACE_FLAG_SUPPORTS_INT_MODE;
  vnet_hw_interface_set_input_node (vnm, ad->hw_if_index,
				    af_xdp_input_node.index);


  return;

error:
  af_xdp_delete_if (vm, ad);
  args->rv = VNET_API_ERROR_INVALID_INTERFACE;
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
VNET_DEVICE_CLASS (af_xdp_device_class,) =
{
  .name = "AF_XDP interface",
  .format_device = format_af_xdp_device,
  .format_device_name = format_af_xdp_device_name,
  .admin_up_down_function = af_xdp_interface_admin_up_down,
  .rx_redirect_to_node = af_xdp_set_interface_next_node,
  .tx_function_n_errors = AVF_TX_N_ERROR,
  .tx_function_error_strings = af_xdp_tx_func_error_strings,
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
