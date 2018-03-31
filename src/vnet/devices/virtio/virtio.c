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
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/devices/virtio/virtio.h>

virtio_main_t virtio_main;

#define _IOCTL(fd,a,...) \
  if (ioctl (fd, a, __VA_ARGS__) < 0) \
    { \
      err = clib_error_return_unix (0, "ioctl(" #a ")"); \
      goto error; \
    }

static clib_error_t *
call_read_ready (clib_file_t * uf)
{
  virtio_main_t *nm = &virtio_main;
  vnet_main_t *vnm = vnet_get_main ();
  u16 qid = uf->private_data & 0xFFFF;
  virtio_if_t *vif =
    vec_elt_at_index (nm->interfaces, uf->private_data >> 16);
  u64 b;

  CLIB_UNUSED (ssize_t size) = read (uf->file_descriptor, &b, sizeof (b));
  if ((qid & 1) == 0)
    vnet_device_input_set_interrupt_pending (vnm, vif->hw_if_index, qid);

  return 0;
}


clib_error_t *
virtio_vring_init (vlib_main_t * vm, virtio_if_t * vif, u16 idx, u16 sz)
{
  clib_error_t *err = 0;
  virtio_vring_t *vring;
  struct vhost_vring_state state = { 0 };
  struct vhost_vring_addr addr = { 0 };
  struct vhost_vring_file file = { 0 };
  clib_file_t t = { 0 };
  int i;

  if (!is_pow2 (sz))
    return clib_error_return (0, "ring size must be power of 2");

  if (sz > 32768)
    return clib_error_return (0, "ring size must be 32768 or lower");

  if (sz == 0)
    sz = 256;

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
  // tell kernel that we don't need interrupt
  vring->avail->flags = VIRTIO_RING_FLAG_MASK_INT;

  i = sizeof (struct vring_used) + sz * sizeof (struct vring_used_elem);
  i = round_pow2 (i, CLIB_CACHE_LINE_BYTES);
  vring->used = clib_mem_alloc_aligned (i, CLIB_CACHE_LINE_BYTES);
  memset (vring->used, 0, i);

  ASSERT (vring->buffers == 0);
  vec_validate_aligned (vring->buffers, sz, CLIB_CACHE_LINE_BYTES);

  vring->size = sz;
  vring->call_fd = eventfd (0, EFD_NONBLOCK | EFD_CLOEXEC);
  vring->kick_fd = eventfd (0, EFD_CLOEXEC);

  t.read_function = call_read_ready;
  t.file_descriptor = vring->call_fd;
  t.private_data = vif->dev_instance << 16 | idx;
  t.description = format (0, "%U vring %u", format_virtio_device_name,
			  vif->dev_instance, idx);
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

error:
  return err;
}

static_always_inline void
virtio_free_rx_buffers (vlib_main_t * vm, virtio_vring_t * vring)
{
  u16 used = vring->desc_in_use;
  u16 last = vring->last_used_idx;
  u16 mask = vring->size - 1;

  while (used)
    {
      vlib_buffer_free (vm, &vring->buffers[last & mask], 1);
      last++;
      used--;
    }
}

clib_error_t *
virtio_vring_free (vlib_main_t * vm, virtio_if_t * vif, u32 idx)
{
  virtio_vring_t *vring = vec_elt_at_index (vif->vrings, idx);

  clib_file_del_by_index (&file_main, vring->call_file_index);
  close (vring->kick_fd);
  close (vring->call_fd);
  if (vring->used)
    {
      if ((idx & 1) == 1)
	virtio_free_used_desc (vm, vring);
      else
	virtio_free_rx_buffers (vm, vring);
      clib_mem_free (vring->used);
    }
  if (vring->desc)
    clib_mem_free (vring->desc);
  if (vring->avail)
    clib_mem_free (vring->avail);
  vec_free (vring->buffers);
  return 0;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
