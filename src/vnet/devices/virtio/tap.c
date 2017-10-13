/*
 *------------------------------------------------------------------
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
 *------------------------------------------------------------------
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <linux/virtio_net.h>
#include <linux/vhost.h>
#include <sys/eventfd.h>

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/devices/virtio/virtio.h>

virtio_main_t virtio_main;

#define _IOCTL(fd,a,...) \
  if (ioctl (fd, a, __VA_ARGS__) < 0) \
    { \
      err = clib_error_return_unix (0, "ioctl(" #a ")"); \
      goto error; \
    }

static u32
virtio_eth_flag_change (vnet_main_t * vnm, vnet_hw_interface_t * hi,
			u32 flags)
{
  /* nothing for now */
  return 0;
}

static clib_error_t *
call_read_ready (clib_file_t * uf)
{
  return 0;
}

clib_error_t *
virtio_vring_init (vlib_main_t * vm, virtio_if_t * vif, u16 idx, u16 sz)
{
  clib_error_t *err = 0;
  virtio_vring_t *vring;
  struct vhost_vring_state state;
  struct vhost_vring_addr addr;
  struct vhost_vring_file file;
  clib_file_t t = { 0 };
  int i;

  vec_validate_aligned (vif->vrings, idx, CLIB_CACHE_LINE_BYTES);
  vring = vec_elt_at_index (vif->vrings, idx);

  i = sizeof (struct vring_desc) * sz;
  i = round_pow2 (i, CLIB_CACHE_LINE_BYTES);
  vring->desc = clib_mem_alloc_aligned (i, CLIB_CACHE_LINE_BYTES);
  memset (vring->desc, 0, i);

  i = sizeof (struct vring_avail) + sz * sizeof (vring->avail->ring[0]);
  i = round_pow2 (i, CLIB_CACHE_LINE_BYTES);
  vring->avail = clib_mem_alloc_aligned (i, CLIB_CACHE_LINE_BYTES);
  memset (vring->avail, 0, i);

  i = sizeof (struct vring_used) + sz * sizeof (struct vring_used_elem);
  i = round_pow2 (i, CLIB_CACHE_LINE_BYTES);
  vring->used = clib_mem_alloc_aligned (i, CLIB_CACHE_LINE_BYTES);
  memset (vring->used, 0, i);

  ASSERT (vring->buffers == 0);
  vec_validate_init_empty_aligned (vring->buffers, sz - 1, ~0,
				   CLIB_CACHE_LINE_BYTES);
  if ((idx & 1) == 0)
    {
      /* RX ring */
      u32 n_alloc = vlib_buffer_alloc (vm, vring->buffers, sz);
      for (i = 0; i < n_alloc; i++)
	{
	  vlib_buffer_t *b = vlib_get_buffer (vm, vring->buffers[i]);
	  vring->desc[i].addr =
	    pointer_to_uword (vlib_buffer_get_current (b)) - 10;
	  vring->desc[i].len = VLIB_BUFFER_DATA_SIZE + 10;
	  vring->desc[i].flags = VRING_DESC_F_WRITE;
	  vring->avail->ring[i] = i;
	}
      vring->avail->idx = n_alloc;
    }

  vring->size = sz;
  vring->call_fd = eventfd (0, EFD_NONBLOCK | EFD_CLOEXEC);
  vring->kick_fd = eventfd (0, EFD_CLOEXEC);

  t.read_function = call_read_ready;
  t.file_descriptor = vring->call_fd;
  t.private_data = vif->dev_instance << 16 | idx;
  vring->call_file_index = clib_file_add (&file_main, &t);

  state.index = idx;
  state.num = sz;
  _IOCTL (vif->fd, VHOST_SET_VRING_NUM, &state);

  addr.index = idx;
  addr.flags = 0;
  addr.desc_user_addr = pointer_to_uword (vring->desc);
  addr.avail_user_addr = pointer_to_uword (vring->avail);
  addr.used_user_addr = pointer_to_uword (vring->used);
  _IOCTL (vif->fd, VHOST_SET_VRING_ADDR, &addr);

  file.index = idx;
  file.fd = vring->kick_fd;
  _IOCTL (vif->fd, VHOST_SET_VRING_KICK, &file);
  file.fd = vring->call_fd;
  _IOCTL (vif->fd, VHOST_SET_VRING_CALL, &file);
  file.fd = vif->tap_fd;
  _IOCTL (vif->fd, VHOST_NET_SET_BACKEND, &file);

  if ((idx & 1) == 0)
    {
      u64 b = 1;
      write (vring->kick_fd, &b, sizeof (b));
    }

error:
  return err;
}

clib_error_t *
virtio_vring_free (virtio_if_t * vif, u32 idx)
{
  virtio_vring_t *vring = vec_elt_at_index (vif->vrings, idx);
  if (vring->desc)
    clib_mem_free (vring->desc);
  if (vring->avail)
    clib_mem_free (vring->avail);
  if (vring->used)
    clib_mem_free (vring->used);
  clib_file_del_by_index (&file_main, vring->call_file_index);
  close (vring->kick_fd);
  close (vring->call_fd);
  return 0;
}

clib_error_t *
tap_create_if (vlib_main_t * vm, tap_create_if_args_t * args)
{
  vnet_main_t *vnm = vnet_get_main ();
  virtio_main_t *vim = &virtio_main;
  vnet_sw_interface_t *sw;
  vnet_hw_interface_t *hw;
  int i;
  clib_error_t *err = 0;
  struct ifreq ifr = { 0 };
  size_t hdrsz;
  struct vhost_memory *vhost_mem = 0;
  virtio_if_t *vif = 0;

  pool_get (vim->interfaces, vif);
  vif->dev_instance = vif - vim->interfaces;
  vif->tap_fd = -1;

  if ((vif->fd = open ("/dev/vhost-net", O_RDWR | O_NONBLOCK)) < 0)
    {
      err = clib_error_return_unix (0, "open '/dev/vhost-net'");
      goto error;
    }

  _IOCTL (vif->fd, VHOST_GET_FEATURES, &vif->remote_features);
  vif->features = 0;		//1ULL << VIRTIO_NET_F_MRG_RXBUF;
#if 0
  vif->features = 1ULL << VIRTIO_NET_F_MRG_RXBUF |
    1ULL << VIRTIO_F_VERSION_1 | 1ULL << VIRTIO_F_ANY_LAYOUT;
#endif
  clib_warning ("features %llx %llx", vif->remote_features, vif->features);
  _IOCTL (vif->fd, VHOST_SET_FEATURES, &vif->features);

  if ((vif->tap_fd = open ("/dev/net/tun", O_RDWR | O_NONBLOCK)) < 0)
    {
      err = clib_error_return_unix (0, "open '/dev/net/tun'");
      goto error;
    }

  ifr.ifr_flags = IFF_TAP | IFF_NO_PI | IFF_ONE_QUEUE | IFF_VNET_HDR;
  strncpy (ifr.ifr_ifrn.ifrn_name, (char *) args->name, IF_NAMESIZE);
  _IOCTL (vif->tap_fd, TUNSETIFF, (void *) &ifr);

  unsigned int offload = 0;
  hdrsz = vif->features & VIRTIO_NET_F_MRG_RXBUF ? 12 : 10;
  // sizeof(virtio_net_hdr_mrg) : sizeof(virtio_net_hdr);
  _IOCTL (vif->tap_fd, TUNSETOFFLOAD, offload);
  _IOCTL (vif->tap_fd, TUNSETVNETHDRSZ, &hdrsz);
  _IOCTL (vif->fd, VHOST_SET_OWNER, 0);

  /* Set vhost memory table */
  i = sizeof (struct vhost_memory) + sizeof (struct vhost_memory_region);
  vhost_mem = clib_mem_alloc (i);
  memset (vhost_mem, 0, i);
  vhost_mem->nregions = 1;
  vhost_mem->regions[0].memory_size = (1ULL << 47) - 4096;
  _IOCTL (vif->fd, VHOST_SET_MEM_TABLE, vhost_mem);

  if ((err = virtio_vring_init (vm, vif, 0, 256)))
    goto error;

  if ((err = virtio_vring_init (vm, vif, 1, 256)))
    goto error;

  if (!args->hw_addr_set)
    {
      f64 now = vlib_time_now (vm);
      u32 rnd;
      rnd = (u32) (now * 1e6);
      rnd = random_u32 (&rnd);

      memcpy (args->hw_addr + 2, &rnd, sizeof (rnd));
      args->hw_addr[0] = 2;
      args->hw_addr[1] = 0xfe;
    }
  err = ethernet_register_interface (vnm, virtio_device_class.index,
				     vif->dev_instance, args->hw_addr,
				     &vif->hw_if_index,
				     virtio_eth_flag_change);

  sw = vnet_get_hw_sw_interface (vnm, vif->hw_if_index);
  vif->sw_if_index = sw->sw_if_index;
  args->sw_if_index = vif->sw_if_index;
  hw = vnet_get_hw_interface (vnm, vif->hw_if_index);
  hw->flags |= VNET_HW_INTERFACE_FLAG_SUPPORTS_INT_MODE;
  vnet_hw_interface_set_input_node (vnm, vif->hw_if_index,
				    virtio_input_node.index);
  vnet_hw_interface_assign_rx_thread (vnm, vif->hw_if_index, 0, ~0);
  vnet_hw_interface_set_rx_mode (vnm, vif->hw_if_index, 0,
				 VNET_HW_INTERFACE_RX_MODE_DEFAULT);
  vif->per_interface_next_index = ~0;
  vif->flags |= VIRTIO_IF_FLAG_ADMIN_UP;
  vnet_hw_interface_set_flags (vnm, vif->hw_if_index,
			       VNET_HW_INTERFACE_FLAG_LINK_UP);
  goto done;

error:
  if (vif->tap_fd != -1)
    close (vif->tap_fd);
  if (vif->fd != -1)
    close (vif->fd);
  vec_foreach_index (i, vif->vrings) virtio_vring_free (vif, i);
  memset (vif, 0, sizeof (virtio_if_t));
  pool_put (vim->interfaces, vif);

done:
  if (vhost_mem)
    clib_mem_free (vhost_mem);
  return err;
}

static clib_error_t *
tap_init (vlib_main_t * vm)
{

  return 0;
}

VLIB_INIT_FUNCTION (tap_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
