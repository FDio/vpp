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


#define _GNU_SOURCE
#include <stdint.h>
#include <net/if.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/uio.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/eventfd.h>
#include <inttypes.h>
#include <limits.h>

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vppinfra/linux/syscall.h>
#include <vnet/plugin/plugin.h>
#include <vnet/ethernet/ethernet.h>
#include <lina/shared.h>
#include <lina/lina.h>

lina_main_t lina_main;

void
lina_create_instance (vlib_main_t * vm, lina_create_instance_args_t * a)
{
  vnet_main_t *vnm = vnet_get_main ();
  lina_main_t *lm = &lina_main;
  lina_instance_t *lin;
  vlib_physmem_map_t *pm;
  u32 i, n_rings;

  pool_get_aligned_zero (lm->instances, lin, CLIB_CACHE_LINE_BYTES);
  lin->index = lin - lm->instances;
  lin->listener_filename = format (0, "%s%c", a->filename, 0);

  lin->log2_ring_sz = min_log2 (a->ring_size);

  if ((1 << lin->log2_ring_sz) != a->ring_size)
    {
      a->error = clib_error_return (0, "ring size must be power of 2");
      goto error;
    }

  /* allocate shared memory */
  n_rings = vec_len (vlib_mains);
  lin->shm_size = sizeof (lina_shm_hdr_t) +
    n_rings * sizeof (lina_shm_ring_hdr_t) +
    (n_rings << lin->log2_ring_sz) * sizeof (lina_shm_desc_t);

  a->error = vlib_physmem_shared_map_create (vm, "lina", lin->shm_size, 0,
					     -1, &lin->shm_map_index);
  pm = vlib_physmem_get_map (vm, lin->shm_map_index);
  lin->fd = pm->fd;
  lin->shm_hdr = pm->base;
  lin->shm_size = pm->n_pages << pm->log2_page_size;

  clib_memset (lin->shm_hdr, 0, lin->shm_size);
  lin->shm_hdr->cookie = LINA_SHM_HDR_COOKIE;
  lin->shm_hdr->n_rings = vec_len (vlib_mains);
  lin->shm_hdr->log2_ring_sz = lin->log2_ring_sz;
  if ((a->error = lina_socket_listener_create (vm, lin)))
    goto error;

  for (i = 0; i < n_rings; i++)
    {
      lina_ring_t *ring;
      vec_add2 (lin->rings, ring, 1);
      ring->hdr = lina_get_shm_ring (lin->shm_hdr, i);
      ring->descs = lina_get_shm_desc (lin->shm_hdr, i, 0);
      vec_validate_aligned (ring->bufs, (1 << lin->log2_ring_sz) - 1,
			    CLIB_CACHE_LINE_BYTES);
    }

  vnet_hw_interface_rx_redirect_to_node (vnm, a->hw_if_index,
					 lina_enqueue_node.index);

  return;

error:
  pool_put (lm->instances, lin);
}

static clib_error_t *
lina_init (vlib_main_t * vm)
{
  lina_main_t *mm = &lina_main;

  clib_memset (mm, 0, sizeof (lina_main_t));

  mm->log_class = vlib_log_register_class ("lina", 0);

  return 0;
}

VLIB_INIT_FUNCTION (lina_init);

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () = {
    .version = "1.0",
    .description = "lina enqueue/dequeue plugin",
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
