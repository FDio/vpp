/*
 *------------------------------------------------------------------
 * Copyright (c) 2016 Cisco and/or its affiliates.
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

#include <stdint.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <fcntl.h>

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vnet/ethernet/ethernet.h>

#include <netmap/net_netmap.h>
#include <netmap/netmap.h>
#include <netmap/netmap.api_enum.h>
#include <netmap/netmap.api_types.h>

netmap_main_t netmap_main;

static clib_error_t *
netmap_fd_read_ready (clib_file_t * uf)
{
  vlib_main_t *vm = vlib_get_main ();
  netmap_main_t *nm = &netmap_main;
  u32 idx = uf->private_data;

  nm->pending_input_bitmap =
    clib_bitmap_set (nm->pending_input_bitmap, idx, 1);

  /* Schedule the rx node */
  vlib_node_set_interrupt_pending (vm, netmap_input_node.index);

  return 0;
}

static void
close_netmap_if (netmap_main_t * nm, netmap_if_t * nif)
{
  if (nif->clib_file_index != ~0)
    {
      clib_file_del (&file_main, file_main.file_pool + nif->clib_file_index);
      nif->clib_file_index = ~0;
    }
  else if (nif->fd > -1)
    close (nif->fd);

  if (nif->mem_region)
    {
      netmap_mem_region_t *reg = &nm->mem_regions[nif->mem_region];
      if (--reg->refcnt == 0)
	{
	  munmap (reg->mem, reg->region_size);
	  reg->region_size = 0;
	}
    }


  mhash_unset (&nm->if_index_by_host_if_name, nif->host_if_name,
	       &nif->if_index);
  vec_free (nif->host_if_name);
  vec_free (nif->req);

  clib_memset (nif, 0, sizeof (*nif));
  pool_put (nm->interfaces, nif);
}

int
netmap_worker_thread_enable ()
{
  /* if worker threads are enabled, switch to polling mode */
  foreach_vlib_main ()
    {
      vlib_node_set_state (this_vlib_main, netmap_input_node.index,
			   VLIB_NODE_STATE_POLLING);
    }

  return 0;
}

int
netmap_worker_thread_disable ()
{
  foreach_vlib_main ()
    {
      vlib_node_set_state (this_vlib_main, netmap_input_node.index,
			   VLIB_NODE_STATE_INTERRUPT);
    }

  return 0;
}

int
netmap_create_if (vlib_main_t * vm, u8 * if_name, u8 * hw_addr_set,
		  u8 is_pipe, u8 is_master, u32 * sw_if_index)
{
  netmap_main_t *nm = &netmap_main;
  int ret = 0;
  uint32_t nr_reg;
  netmap_if_t *nif = 0;
  u8 hw_addr[6];
  vnet_sw_interface_t *sw;
  vnet_main_t *vnm = vnet_get_main ();
  uword *p;
  struct nmreq *req = 0;
  netmap_mem_region_t *reg;
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  int fd;

  p = mhash_get (&nm->if_index_by_host_if_name, if_name);
  if (p)
    return VNET_API_ERROR_SUBIF_ALREADY_EXISTS;

  fd = open ("/dev/netmap", O_RDWR);
  if (fd < 0)
    return VNET_API_ERROR_SUBIF_ALREADY_EXISTS;

  pool_get (nm->interfaces, nif);
  nif->if_index = nif - nm->interfaces;
  nif->fd = fd;
  nif->clib_file_index = ~0;

  vec_validate (req, 0);
  nif->req = req;
  req->nr_version = NETMAP_API;
  req->nr_flags = NR_REG_ALL_NIC;

  if (is_pipe)
    req->nr_flags = is_master ? NR_REG_PIPE_MASTER : NR_REG_PIPE_SLAVE;
  else
    req->nr_flags = NR_REG_ALL_NIC;

  req->nr_flags |= NR_ACCEPT_VNET_HDR;
  snprintf (req->nr_name, IFNAMSIZ, "%s", if_name);
  req->nr_name[IFNAMSIZ - 1] = 0;

  if (ioctl (nif->fd, NIOCREGIF, req))
    {
      ret = VNET_API_ERROR_NOT_CONNECTED;
      goto error;
    }

  nif->mem_region = req->nr_arg2;
  vec_validate (nm->mem_regions, nif->mem_region);
  reg = &nm->mem_regions[nif->mem_region];
  if (reg->region_size == 0)
    {
      reg->mem = mmap (NULL, req->nr_memsize, PROT_READ | PROT_WRITE,
		       MAP_SHARED, fd, 0);
      clib_warning ("mem %p", reg->mem);
      if (reg->mem == MAP_FAILED)
	{
	  ret = VNET_API_ERROR_NOT_CONNECTED;
	  goto error;
	}
      reg->region_size = req->nr_memsize;
    }
  reg->refcnt++;

  nif->nifp = NETMAP_IF (reg->mem, req->nr_offset);
  nr_reg = nif->req->nr_flags & NR_REG_MASK;

  if (nr_reg == NR_REG_SW)
    { /* host stack */
      nif->first_tx_ring = nif->last_tx_ring = nif->req->nr_tx_rings;
      nif->first_rx_ring = nif->last_rx_ring = nif->req->nr_rx_rings;
    }
  else if (nr_reg == NR_REG_ALL_NIC)
    { /* only nic */
      nif->first_tx_ring = 0;
      nif->first_rx_ring = 0;
      nif->last_tx_ring = nif->req->nr_tx_rings - 1;
      nif->last_rx_ring = nif->req->nr_rx_rings - 1;
    }
  else if (nr_reg == NR_REG_NIC_SW)
    {
      nif->first_tx_ring = 0;
      nif->first_rx_ring = 0;
      nif->last_tx_ring = nif->req->nr_tx_rings;
      nif->last_rx_ring = nif->req->nr_rx_rings;
    }
  else if (nr_reg == NR_REG_ONE_NIC)
    {
      /* XXX check validity */
      nif->first_tx_ring = nif->last_tx_ring = nif->first_rx_ring =
	nif->last_rx_ring = nif->req->nr_ringid & NETMAP_RING_MASK;
    }
  else
    { /* pipes */
      nif->first_tx_ring = nif->last_tx_ring = 0;
      nif->first_rx_ring = nif->last_rx_ring = 0;
    }

  nif->host_if_name = if_name;
  nif->per_interface_next_index = ~0;

  if (tm->n_vlib_mains > 1)
    clib_spinlock_init (&nif->lockp);

  {
    clib_file_t _template = { 0 };
    _template.read_function = netmap_fd_read_ready;
    _template.file_descriptor = nif->fd;
    _template.private_data = nif->if_index;
    _template.description = format (0, "netmap socket");
    nif->clib_file_index = clib_file_add (&file_main, &_template);
  }

  /*use configured or generate random MAC address */
  if (hw_addr_set)
    memcpy (hw_addr, hw_addr_set, 6);
  else
    {
      f64 now = vlib_time_now (vm);
      u32 rnd;
      rnd = (u32) (now * 1e6);
      rnd = random_u32 (&rnd);

      memcpy (hw_addr + 2, &rnd, sizeof (rnd));
      hw_addr[0] = 2;
      hw_addr[1] = 0xfe;
    }

  vnet_eth_interface_registration_t eir = {};

  eir.dev_class_index = netmap_device_class.index;
  eir.dev_instance = nif->if_index;
  eir.address = hw_addr;
  eir.cb.set_max_frame_size = NULL;

  nif->hw_if_index = vnet_eth_register_interface (vnm, &eir);

  sw = vnet_get_hw_sw_interface (vnm, nif->hw_if_index);
  nif->sw_if_index = sw->sw_if_index;

  mhash_set_mem (&nm->if_index_by_host_if_name, if_name, &nif->if_index, 0);

  if (sw_if_index)
    *sw_if_index = nif->sw_if_index;

  if (tm->n_vlib_mains > 1 && pool_elts (nm->interfaces) == 1)
    netmap_worker_thread_enable ();

  return 0;

error:
  close_netmap_if (nm, nif);
  return ret;
}

int
netmap_delete_if (vlib_main_t * vm, u8 * host_if_name)
{
  vnet_main_t *vnm = vnet_get_main ();
  netmap_main_t *nm = &netmap_main;
  netmap_if_t *nif;
  uword *p;
  vlib_thread_main_t *tm = vlib_get_thread_main ();

  p = mhash_get (&nm->if_index_by_host_if_name, host_if_name);
  if (p == NULL)
    {
      clib_warning ("Host interface %s does not exist", host_if_name);
      return VNET_API_ERROR_SYSCALL_ERROR_1;
    }
  nif = pool_elt_at_index (nm->interfaces, p[0]);

  /* bring down the interface */
  vnet_hw_interface_set_flags (vnm, nif->hw_if_index, 0);

  ethernet_delete_interface (vnm, nif->hw_if_index);

  close_netmap_if (nm, nif);

  if (tm->n_vlib_mains > 1 && pool_elts (nm->interfaces) == 0)
    netmap_worker_thread_disable ();

  return 0;
}

static clib_error_t *
netmap_init (vlib_main_t * vm)
{
  netmap_main_t *nm = &netmap_main;
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  vlib_thread_registration_t *tr;
  uword *p;

  clib_memset (nm, 0, sizeof (netmap_main_t));

  nm->input_cpu_first_index = 0;
  nm->input_cpu_count = 1;

  /* find out which cpus will be used for input */
  p = hash_get_mem (tm->thread_registrations_by_name, "workers");
  tr = p ? (vlib_thread_registration_t *) p[0] : 0;

  if (tr && tr->count > 0)
    {
      nm->input_cpu_first_index = tr->first_index;
      nm->input_cpu_count = tr->count;
    }

  mhash_init_vec_string (&nm->if_index_by_host_if_name, sizeof (uword));

  vec_validate_aligned (nm->rx_buffers, tm->n_vlib_mains - 1,
			CLIB_CACHE_LINE_BYTES);

  return 0;
}

VLIB_INIT_FUNCTION (netmap_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
