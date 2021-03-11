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
#include <vnet/interface/rx_queue_funcs.h>
#include <vpp/app/version.h>
#include <memif/memif.h>
#include <memif/private.h>

memif_main_t memif_main;

static u32
memif_eth_flag_change (vnet_main_t * vnm, vnet_hw_interface_t * hi, u32 flags)
{
  /* nothing for now */
  return 0;
}

static void
memif_queue_intfd_close (memif_queue_t * mq)
{
  if (mq->int_clib_file_index != ~0)
    {
      memif_file_del_by_index (mq->int_clib_file_index);
      mq->int_clib_file_index = ~0;
      mq->int_fd = -1;
    }
  else if (mq->int_fd > -1)
    {
      close (mq->int_fd);
      mq->int_fd = -1;
    }
}

static void
memif_disconnect_free_zc_queue_buffer (memif_queue_t * mq, u8 is_rx)
{
  vlib_main_t *vm = vlib_get_main ();
  u16 ring_size, n_slots, mask, start;

  ring_size = 1 << mq->log2_ring_size;
  mask = ring_size - 1;
  n_slots = mq->ring->head - mq->last_tail;
  start = mq->last_tail & mask;
  if (is_rx)
    vlib_buffer_free_from_ring (vm, mq->buffers, start, ring_size, n_slots);
  else
    vlib_buffer_free_from_ring_no_next (vm, mq->buffers, start, ring_size,
					n_slots);
  vec_free (mq->buffers);
}

void
memif_disconnect (memif_if_t * mif, clib_error_t * err)
{
  memif_main_t *mm = &memif_main;
  vnet_main_t *vnm = vnet_get_main ();
  memif_region_t *mr;
  memif_queue_t *mq;
  int i;

  if (mif == 0)
    return;

  memif_log_debug (mif, "disconnect %u (%v)", mif->dev_instance,
		   err ? err->what : 0);

  if (err)
    {
      clib_error_t *e = 0;
      mif->local_disc_string = vec_dup (err->what);
      if (mif->sock && clib_socket_is_connected (mif->sock))
	e = memif_msg_send_disconnect (mif, err);
      clib_error_free (e);
    }

  /* set interface down */
  mif->flags &= ~(MEMIF_IF_FLAG_CONNECTED | MEMIF_IF_FLAG_CONNECTING);
  if (mif->hw_if_index != ~0)
    vnet_hw_interface_set_flags (vnm, mif->hw_if_index, 0);

  /* close connection socket */
  if (mif->sock && mif->sock->fd)
    {
      memif_socket_file_t *msf = vec_elt_at_index (mm->socket_files,
						   mif->socket_file_index);
      hash_unset (msf->dev_instance_by_fd, mif->sock->fd);
      memif_socket_close (&mif->sock);
    }
  else if (mif->sock)
    {
      clib_error_t *err;
      err = clib_socket_close (mif->sock);
      if (err)
	{
	  memif_log_err (mif, "%U", format_clib_error, err);
	  clib_error_free (err);
	}
      clib_mem_free (mif->sock);
    }

  /* *INDENT-OFF* */
  vec_foreach_index (i, mif->rx_queues)
    {
      mq = vec_elt_at_index (mif->rx_queues, i);
      if (mq->ring)
	{
	  if (mif->flags & MEMIF_IF_FLAG_ZERO_COPY)
	  {
	    memif_disconnect_free_zc_queue_buffer(mq, 1);
	  }
	  mq->ring = 0;
	}
    }
  vnet_hw_if_unregister_all_rx_queues (vnm, mif->hw_if_index);
  vnet_hw_if_update_runtime_data (vnm, mif->hw_if_index);

  /* *INDENT-OFF* */
  vec_foreach_index (i, mif->tx_queues)
  {
    mq = vec_elt_at_index (mif->tx_queues, i);
    if (mq->ring)
    {
      if (mif->flags & MEMIF_IF_FLAG_ZERO_COPY)
      {
        memif_disconnect_free_zc_queue_buffer(mq, 0);
      }
    }
    mq->ring = 0;
  }

  /* free tx and rx queues */
  vec_foreach (mq, mif->rx_queues)
    memif_queue_intfd_close (mq);
  vec_free (mif->rx_queues);

  vec_foreach (mq, mif->tx_queues)
    memif_queue_intfd_close (mq);
  vec_free (mif->tx_queues);

  /* free memory regions */
  vec_foreach (mr, mif->regions)
    {
      int rv;
      if (mr->is_external)
	continue;
      if ((rv = munmap (mr->shm, mr->region_size)))
	memif_log_err (mif, "munmap failed, rv = %d", rv);
      if (mr->fd > -1)
	close (mr->fd);
    }
  /* *INDENT-ON* */
  vec_free (mif->regions);
  vec_free (mif->remote_name);
  vec_free (mif->remote_if_name);
  clib_fifo_free (mif->msg_queue);
}

static clib_error_t *
memif_int_fd_write_ready (clib_file_t * uf)
{
  memif_main_t *mm = &memif_main;
  u16 qid = uf->private_data & 0xFFFF;
  memif_if_t *mif = vec_elt_at_index (mm->interfaces, uf->private_data >> 16);

  memif_log_warn (mif, "unexpected EPOLLOUT on RX for queue %u", qid);
  return 0;
}

static clib_error_t *
memif_int_fd_read_ready (clib_file_t * uf)
{
  memif_main_t *mm = &memif_main;
  vnet_main_t *vnm = vnet_get_main ();
  u16 qid = uf->private_data & 0xFFFF;
  memif_if_t *mif = vec_elt_at_index (mm->interfaces, uf->private_data >> 16);
  memif_queue_t *mq = vec_elt_at_index (mif->rx_queues, qid);
  u64 b;
  ssize_t size;

  size = read (uf->file_descriptor, &b, sizeof (b));
  if (size < 0)
    {
      memif_log_debug (mif, "Failed to read from socket");
      return 0;
    }

  vnet_hw_if_rx_queue_set_int_pending (vnm, mq->queue_index);
  mq->int_count++;

  return 0;
}


clib_error_t *
memif_connect (memif_if_t * mif)
{
  vlib_main_t *vm = vlib_get_main ();
  vnet_main_t *vnm = vnet_get_main ();
  clib_file_t template = { 0 };
  memif_region_t *mr;
  int i;
  clib_error_t *err = NULL;

  memif_log_debug (mif, "connect %u", mif->dev_instance);

  vec_free (mif->local_disc_string);
  vec_free (mif->remote_disc_string);

  /* *INDENT-OFF* */
  vec_foreach (mr, mif->regions)
    {
      if (mr->shm)
	continue;

      if (mr->fd < 0)
	{
	  err = clib_error_return (0, "no memory region fd");
	  goto error;
	}

      if ((mr->shm = mmap (NULL, mr->region_size, PROT_READ | PROT_WRITE,
			   MAP_SHARED, mr->fd, 0)) == MAP_FAILED)
	{
	  err = clib_error_return_unix (0, "mmap");
	  goto error;
	}
    }
  /* *INDENT-ON* */

  template.read_function = memif_int_fd_read_ready;
  template.write_function = memif_int_fd_write_ready;

  /* *INDENT-OFF* */
  vec_foreach_index (i, mif->tx_queues)
    {
      memif_queue_t *mq = vec_elt_at_index (mif->tx_queues, i);

      mq->ring = mif->regions[mq->region].shm + mq->offset;
      if (mq->ring->cookie != MEMIF_COOKIE)
	{
	  err = clib_error_return (0, "wrong cookie on tx ring %u", i);
	  goto error;
	}
    }

  vec_foreach_index (i, mif->rx_queues)
    {
      memif_queue_t *mq = vec_elt_at_index (mif->rx_queues, i);
      u32 ti;
      u32 qi;
      int rv;

      mq->ring = mif->regions[mq->region].shm + mq->offset;
      if (mq->ring->cookie != MEMIF_COOKIE)
	{
	  err = clib_error_return (0, "wrong cookie on tx ring %u", i);
	  goto error;
	}
      qi = vnet_hw_if_register_rx_queue (vnm, mif->hw_if_index, i,
					 VNET_HW_IF_RXQ_THREAD_ANY);
      mq->queue_index = qi;
      if (mq->int_fd > -1)
	{
	  template.file_descriptor = mq->int_fd;
	  template.private_data = (mif->dev_instance << 16) | (i & 0xFFFF);
	  template.description = format (0, "%U rx %u int",
					 format_memif_device_name,
					 mif->dev_instance, i);
	  memif_file_add (&mq->int_clib_file_index, &template);
	  vnet_hw_if_set_rx_queue_file_index (vnm, qi,
					      mq->int_clib_file_index);
	}
      ti = vnet_hw_if_get_rx_queue_thread_index (vnm, qi);
      mq->buffer_pool_index =
	vlib_buffer_pool_get_default_for_numa (vm, vlib_mains[ti]->numa_node);
      rv = vnet_hw_if_set_rx_queue_mode (vnm, qi, VNET_HW_IF_RX_MODE_DEFAULT);
      vnet_hw_if_update_runtime_data (vnm, mif->hw_if_index);

      if (rv)
	memif_log_err
	  (mif, "Warning: unable to set rx mode for interface %d queue %d: "
	   "rc=%d", mif->hw_if_index, i, rv);
      else
	{
	  vnet_hw_if_rx_mode rxmode = vnet_hw_if_get_rx_queue_mode (vnm, qi);

	  if (rxmode == VNET_HW_IF_RX_MODE_POLLING)
	    mq->ring->flags |= MEMIF_RING_FLAG_MASK_INT;
	  else
	    vnet_hw_if_rx_queue_set_int_pending (vnm, qi);
	}
    }
  /* *INDENT-ON* */

  mif->flags &= ~MEMIF_IF_FLAG_CONNECTING;
  mif->flags |= MEMIF_IF_FLAG_CONNECTED;

  vnet_hw_interface_set_flags (vnm, mif->hw_if_index,
			       VNET_HW_INTERFACE_FLAG_LINK_UP);
  return 0;

error:
  memif_log_err (mif, "%U", format_clib_error, err);
  return err;
}

static_always_inline memif_ring_t *
memif_get_ring (memif_if_t * mif, memif_ring_type_t type, u16 ring_num)
{
  if (vec_len (mif->regions) == 0)
    return NULL;
  void *p = mif->regions[0].shm;
  int ring_size =
    sizeof (memif_ring_t) +
    sizeof (memif_desc_t) * (1 << mif->run.log2_ring_size);
  p += (ring_num + type * mif->run.num_s2m_rings) * ring_size;

  return (memif_ring_t *) p;
}

clib_error_t *
memif_init_regions_and_queues (memif_if_t * mif)
{
  vlib_main_t *vm = vlib_get_main ();
  memif_socket_file_t *msf;
  memif_ring_t *ring = NULL;
  int fd, i, j;
  u64 buffer_offset;
  memif_region_t *r;
  clib_error_t *err;

  ASSERT (vec_len (mif->regions) == 0);
  vec_add2_aligned (mif->regions, r, 1, CLIB_CACHE_LINE_BYTES);

  buffer_offset = (mif->run.num_s2m_rings + mif->run.num_m2s_rings) *
    (sizeof (memif_ring_t) +
     sizeof (memif_desc_t) * (1 << mif->run.log2_ring_size));

  r->region_size = buffer_offset;

  if ((mif->flags & MEMIF_IF_FLAG_ZERO_COPY) == 0)
    r->region_size += mif->run.buffer_size * (1 << mif->run.log2_ring_size) *
      (mif->run.num_s2m_rings + mif->run.num_m2s_rings);

  if ((fd = clib_mem_vm_create_fd (CLIB_MEM_PAGE_SZ_DEFAULT, "%U region 0",
				   format_memif_device_name,
				   mif->dev_instance)) == -1)
    {
      err = clib_mem_get_last_error ();
      goto error;
    }

  if ((ftruncate (fd, r->region_size)) == -1)
    {
      err = clib_error_return_unix (0, "ftruncate");
      goto error;
    }

  msf = pool_elt_at_index (memif_main.socket_files, mif->socket_file_index);
  r->shm = clib_mem_vm_map_shared (0, r->region_size, fd, 0, "memif%lu/%lu:0",
				   msf->socket_id, mif->id);

  if (r->shm == CLIB_MEM_VM_MAP_FAILED)
    {
      err = clib_error_return_unix (0, "memif shared region map failed");
      goto error;
    }

  r->fd = fd;

  if (mif->flags & MEMIF_IF_FLAG_ZERO_COPY)
    {
      vlib_buffer_pool_t *bp;
      /* *INDENT-OFF* */
      vec_foreach (bp, vm->buffer_main->buffer_pools)
	{
	  vlib_physmem_map_t *pm;
	  pm = vlib_physmem_get_map (vm, bp->physmem_map_index);
	  vec_add2_aligned (mif->regions, r, 1, CLIB_CACHE_LINE_BYTES);
	  r->fd = pm->fd;
	  r->region_size = pm->n_pages << pm->log2_page_size;
	  r->shm = pm->base;
	  r->is_external = 1;
	}
      /* *INDENT-ON* */
    }

  for (i = 0; i < mif->run.num_s2m_rings; i++)
    {
      ring = memif_get_ring (mif, MEMIF_RING_S2M, i);
      ring->head = ring->tail = 0;
      ring->cookie = MEMIF_COOKIE;

      if (mif->flags & MEMIF_IF_FLAG_ZERO_COPY)
	continue;

      for (j = 0; j < (1 << mif->run.log2_ring_size); j++)
	{
	  u16 slot = i * (1 << mif->run.log2_ring_size) + j;
	  ring->desc[j].region = 0;
	  ring->desc[j].offset =
	    buffer_offset + (u32) (slot * mif->run.buffer_size);
	  ring->desc[j].length = mif->run.buffer_size;
	}
    }
  for (i = 0; i < mif->run.num_m2s_rings; i++)
    {
      ring = memif_get_ring (mif, MEMIF_RING_M2S, i);
      ring->head = ring->tail = 0;
      ring->cookie = MEMIF_COOKIE;

      if (mif->flags & MEMIF_IF_FLAG_ZERO_COPY)
	continue;

      for (j = 0; j < (1 << mif->run.log2_ring_size); j++)
	{
	  u16 slot =
	    (i + mif->run.num_s2m_rings) * (1 << mif->run.log2_ring_size) + j;
	  ring->desc[j].region = 0;
	  ring->desc[j].offset =
	    buffer_offset + (u32) (slot * mif->run.buffer_size);
	  ring->desc[j].length = mif->run.buffer_size;
	}
    }

  ASSERT (mif->tx_queues == 0);
  vec_validate_aligned (mif->tx_queues, mif->run.num_s2m_rings - 1,
			CLIB_CACHE_LINE_BYTES);

  /* *INDENT-OFF* */
  vec_foreach_index (i, mif->tx_queues)
    {
      memif_queue_t *mq = vec_elt_at_index (mif->tx_queues, i);
      if ((mq->int_fd = eventfd (0, EFD_NONBLOCK)) < 0)
	{
	  err = clib_error_return_unix (0, "eventfd[tx queue %u]", i);
	  goto error;
	}
      mq->int_clib_file_index = ~0;
      mq->ring = memif_get_ring (mif, MEMIF_RING_S2M, i);
      mq->log2_ring_size = mif->cfg.log2_ring_size;
      mq->region = 0;
      mq->offset = (void *) mq->ring - (void *) mif->regions[mq->region].shm;
      mq->last_head = 0;
      mq->type = MEMIF_RING_S2M;
      if (mif->flags & MEMIF_IF_FLAG_ZERO_COPY)
	vec_validate_aligned (mq->buffers, 1 << mq->log2_ring_size,
			      CLIB_CACHE_LINE_BYTES);
    }
  /* *INDENT-ON* */

  ASSERT (mif->rx_queues == 0);
  vec_validate_aligned (mif->rx_queues, mif->run.num_m2s_rings - 1,
			CLIB_CACHE_LINE_BYTES);

  /* *INDENT-OFF* */
  vec_foreach_index (i, mif->rx_queues)
    {
      memif_queue_t *mq = vec_elt_at_index (mif->rx_queues, i);
      if ((mq->int_fd = eventfd (0, EFD_NONBLOCK)) < 0)
	{
	  err = clib_error_return_unix (0, "eventfd[rx queue %u]", i);
	  goto error;
	}
      mq->int_clib_file_index = ~0;
      mq->ring = memif_get_ring (mif, MEMIF_RING_M2S, i);
      mq->log2_ring_size = mif->cfg.log2_ring_size;
      mq->region = 0;
      mq->offset = (void *) mq->ring - (void *) mif->regions[mq->region].shm;
      mq->last_head = 0;
      mq->type = MEMIF_RING_M2S;
      if (mif->flags & MEMIF_IF_FLAG_ZERO_COPY)
	vec_validate_aligned (mq->buffers, 1 << mq->log2_ring_size,
			      CLIB_CACHE_LINE_BYTES);
    }
  /* *INDENT-ON* */

  return 0;

error:
  memif_log_err (mif, "%U", format_clib_error, err);
  return err;
}

static uword
memif_process (vlib_main_t * vm, vlib_node_runtime_t * rt, vlib_frame_t * f)
{
  memif_main_t *mm = &memif_main;
  memif_if_t *mif;
  clib_socket_t *sock;
  uword *event_data = 0, event_type;
  u8 enabled = 0;
  f64 start_time, last_run_duration = 0, now;
  clib_error_t *err;

  sock = clib_mem_alloc (sizeof (clib_socket_t));
  clib_memset (sock, 0, sizeof (clib_socket_t));

  while (1)
    {
      if (enabled)
	vlib_process_wait_for_event_or_clock (vm, (f64) 3 -
					      last_run_duration);
      else
	vlib_process_wait_for_event (vm);

      event_type = vlib_process_get_events (vm, &event_data);
      vec_reset_length (event_data);

      switch (event_type)
	{
	case ~0:
	  break;
	case MEMIF_PROCESS_EVENT_START:
	  enabled = 1;
	  break;
	case MEMIF_PROCESS_EVENT_STOP:
	  enabled = 0;
	  continue;
	case MEMIF_PROCESS_EVENT_ADMIN_UP_DOWN:
	  break;
	default:
	  ASSERT (0);
	}

start:

      last_run_duration = start_time = vlib_time_now (vm);
      /* *INDENT-OFF* */
      mm->interfaces_invalidate = 0;
      pool_foreach (mif, mm->interfaces)
         {
	  memif_socket_file_t * msf = vec_elt_at_index (mm->socket_files, mif->socket_file_index);
	  /* Allow no more than 10us without a pause */
	  now = vlib_time_now (vm);
	  if (now > start_time + 10e-6)
	    {
	      vlib_process_suspend (vm, 100e-6);	/* suspend for 100 us */
	      if (mm->interfaces_invalidate) {
		      /*
		       * if someone reallocated the pool while we were suspended,
		       * restart. Or else it will end in tears.
		       */
		  goto start;
	      }
	      start_time = vlib_time_now (vm);
	    }

	  if ((mif->flags & MEMIF_IF_FLAG_ADMIN_UP) == 0)
	    continue;

	  if (mif->flags & MEMIF_IF_FLAG_CONNECTING)
	    continue;

	  if (mif->flags & MEMIF_IF_FLAG_CONNECTED)
	    continue;

	  if (mif->flags & MEMIF_IF_FLAG_IS_SLAVE)
	    {
              clib_memset (sock, 0, sizeof(clib_socket_t));
	      sock->config = (char *) msf->filename;
              sock->flags = CLIB_SOCKET_F_IS_CLIENT| CLIB_SOCKET_F_SEQPACKET;

              if ((err = clib_socket_init (sock)))
		{
	          clib_error_free (err);
		}
	      else
	        {
		  clib_file_t t = { 0 };

		  t.read_function = memif_slave_conn_fd_read_ready;
		  t.write_function = memif_slave_conn_fd_write_ready;
		  t.error_function = memif_slave_conn_fd_error;
		  t.file_descriptor = sock->fd;
		  t.private_data = mif->dev_instance;
		  memif_file_add (&sock->private_data, &t);
	          t.description = format (0, "%U ctl",
					  format_memif_device_name,
					  mif->dev_instance);
		  hash_set (msf->dev_instance_by_fd, sock->fd, mif->dev_instance);

		  mif->flags |= MEMIF_IF_FLAG_CONNECTING;
		  mif->sock = sock;
                  sock = clib_mem_alloc (sizeof(clib_socket_t));
	        }
	    }
        }
      /* *INDENT-ON* */
      last_run_duration = vlib_time_now (vm) - last_run_duration;
    }
  return 0;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (memif_process_node,static) = {
  .function = memif_process,
  .type = VLIB_NODE_TYPE_PROCESS,
  .name = "memif-process",
};
/* *INDENT-ON* */

static int
memif_add_socket_file (u32 sock_id, u8 * socket_filename)
{
  memif_main_t *mm = &memif_main;
  uword *p;
  memif_socket_file_t *msf;

  p = hash_get (mm->socket_file_index_by_sock_id, sock_id);
  if (p)
    {
      msf = pool_elt_at_index (mm->socket_files, *p);
      if (strcmp ((char *) msf->filename, (char *) socket_filename) == 0)
	{
	  /* Silently accept identical "add". */
	  return 0;
	}

      /* But don't allow a direct add of a different filename. */
      return VNET_API_ERROR_ENTRY_ALREADY_EXISTS;
    }

  pool_get (mm->socket_files, msf);
  clib_memset (msf, 0, sizeof (memif_socket_file_t));

  msf->filename = socket_filename;
  msf->socket_id = sock_id;

  hash_set (mm->socket_file_index_by_sock_id, sock_id,
	    msf - mm->socket_files);

  return 0;
}

static int
memif_delete_socket_file (u32 sock_id)
{
  memif_main_t *mm = &memif_main;
  uword *p;
  memif_socket_file_t *msf;

  p = hash_get (mm->socket_file_index_by_sock_id, sock_id);
  if (!p)
    {
      /* Don't delete non-existent entries. */
      return VNET_API_ERROR_INVALID_ARGUMENT;
    }

  msf = pool_elt_at_index (mm->socket_files, *p);
  if (msf->ref_cnt > 0)
    {
      return VNET_API_ERROR_UNEXPECTED_INTF_STATE;
    }

  vec_free (msf->filename);
  pool_put (mm->socket_files, msf);

  hash_unset (mm->socket_file_index_by_sock_id, sock_id);

  return 0;
}

int
memif_socket_filename_add_del (u8 is_add, u32 sock_id, u8 * sock_filename)
{
  char *dir = 0, *tmp;
  u32 idx = 0;

  /* allow adding socket id 0 */
  if ((sock_id == 0 && is_add == 0) || sock_id == ~0)
    {
      return VNET_API_ERROR_INVALID_ARGUMENT;
    }

  if (is_add == 0)
    {
      return memif_delete_socket_file (sock_id);
    }

  if (sock_filename == 0 || sock_filename[0] == 0)
    {
      return VNET_API_ERROR_INVALID_ARGUMENT;
    }

  if (sock_filename[0] != '/')
    {
      clib_error_t *error;

      /* copy runtime dir path */
      vec_add (dir, vlib_unix_get_runtime_dir (),
	       strlen (vlib_unix_get_runtime_dir ()));
      vec_add1 (dir, '/');

      /* if sock_filename contains dirs, add them to path */
      tmp = strrchr ((char *) sock_filename, '/');
      if (tmp)
	{
	  idx = tmp - (char *) sock_filename;
	  vec_add (dir, sock_filename, idx);
	}

      vec_add1 (dir, '\0');
      /* create socket dir */
      error = vlib_unix_recursive_mkdir (dir);
      if (error)
	{
	  clib_error_free (error);
	  return VNET_API_ERROR_SYSCALL_ERROR_1;
	}

      sock_filename = format (0, "%s/%s%c", vlib_unix_get_runtime_dir (),
			      sock_filename, 0);
    }
  else
    {
      sock_filename = vec_dup (sock_filename);

      /* check if directory exists */
      tmp = strrchr ((char *) sock_filename, '/');
      if (tmp)
	{
	  idx = tmp - (char *) sock_filename;
	  vec_add (dir, sock_filename, idx);
	  vec_add1 (dir, '\0');
	}

      /* check dir existance and access rights for effective user/group IDs */
      if ((dir == NULL)
	  ||
	  (faccessat ( /* ignored */ -1, dir, F_OK | R_OK | W_OK, AT_EACCESS)
	   < 0))
	{
	  vec_free (dir);
	  return VNET_API_ERROR_INVALID_ARGUMENT;
	}
    }
  vec_free (dir);

  return memif_add_socket_file (sock_id, sock_filename);
}

int
memif_delete_if (vlib_main_t * vm, memif_if_t * mif)
{
  vnet_main_t *vnm = vnet_get_main ();
  memif_main_t *mm = &memif_main;
  memif_socket_file_t *msf =
    vec_elt_at_index (mm->socket_files, mif->socket_file_index);
  clib_error_t *err;

  mif->flags |= MEMIF_IF_FLAG_DELETING;
  vec_free (mif->local_disc_string);
  vec_free (mif->remote_disc_string);

  /* bring down the interface */
  vnet_hw_interface_set_flags (vnm, mif->hw_if_index, 0);
  vnet_sw_interface_set_flags (vnm, mif->sw_if_index, 0);

  err = clib_error_return (0, "interface deleted");
  memif_disconnect (mif, err);
  clib_error_free (err);

  if (mif->hw_if_index != ~0)
    {
      /* remove the interface */
      if (mif->mode == MEMIF_INTERFACE_MODE_IP)
	vnet_delete_hw_interface (vnm, mif->hw_if_index);
      else
	ethernet_delete_interface (vnm, mif->hw_if_index);
      mif->hw_if_index = ~0;
    }

  /* free interface data structures */
  clib_spinlock_free (&mif->lockp);
  mhash_unset (&msf->dev_instance_by_id, &mif->id, 0);

  /* remove socket file */
  if (--(msf->ref_cnt) == 0)
    {
      if (msf->is_listener)
	{
	  int i;
	  /* *INDENT-OFF* */
	  vec_foreach_index (i, msf->pending_clients)
	    memif_socket_close (msf->pending_clients + i);
	  /* *INDENT-ON* */
	  memif_socket_close (&msf->sock);
	  vec_free (msf->pending_clients);
	}
      mhash_free (&msf->dev_instance_by_id);
      hash_free (msf->dev_instance_by_fd);
      if (msf->sock)
	{
	  err = clib_socket_close (msf->sock);
	  if (err)
	    {
	      memif_log_err (mif, "%U", format_clib_error, err);
	      clib_error_free (err);
	    }
	  clib_mem_free (msf->sock);
	}
    }

  clib_memset (mif, 0, sizeof (*mif));
  pool_put (mm->interfaces, mif);

  if (pool_elts (mm->interfaces) == 0)
    vlib_process_signal_event (vm, memif_process_node.index,
			       MEMIF_PROCESS_EVENT_STOP, 0);

  return 0;
}

/* *INDENT-OFF* */
VNET_HW_INTERFACE_CLASS (memif_ip_hw_if_class, static) =
{
  .name = "memif-ip",
  .flags = VNET_HW_INTERFACE_CLASS_FLAG_P2P,
};
/* *INDENT-ON* */

int
memif_create_if (vlib_main_t * vm, memif_create_if_args_t * args)
{
  memif_main_t *mm = &memif_main;
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  vnet_main_t *vnm = vnet_get_main ();
  memif_if_t *mif = 0;
  vnet_sw_interface_t *sw;
  clib_error_t *error = 0;
  int ret = 0;
  uword *p;
  vnet_hw_interface_t *hw;
  memif_socket_file_t *msf = 0;
  int rv = 0;
  void *save_mm_interfaces;

  p = hash_get (mm->socket_file_index_by_sock_id, args->socket_id);
  if (p == 0)
    {
      rv = VNET_API_ERROR_INVALID_ARGUMENT;
      goto done;
    }

  msf = vec_elt_at_index (mm->socket_files, p[0]);

  /* existing socket file can be either master or slave but cannot be both */
  if (msf->ref_cnt > 0)
    {
      if ((!msf->is_listener != !args->is_master))
	{
	  rv = VNET_API_ERROR_SUBIF_ALREADY_EXISTS;
	  goto done;
	}

      p = mhash_get (&msf->dev_instance_by_id, &args->id);
      if (p)
	{
	  rv = VNET_API_ERROR_SUBIF_ALREADY_EXISTS;
	  goto done;
	}
    }

  /* Create new socket file */
  if (msf->ref_cnt == 0)
    {
      struct stat file_stat;

      /* If we are creating listener make sure file doesn't exist or if it
       * exists thn delete it if it is old socket file */
      if (args->is_master && (stat ((char *) msf->filename, &file_stat) == 0))
	{
	  if (S_ISSOCK (file_stat.st_mode))
	    {
	      unlink ((char *) msf->filename);
	    }
	  else
	    {
	      error = clib_error_return (0, "File exists for %s",
					 msf->filename);
	      rv = VNET_API_ERROR_VALUE_EXIST;
	      goto done;
	    }
	}

      mhash_init (&msf->dev_instance_by_id, sizeof (uword),
		  sizeof (memif_interface_id_t));
      msf->dev_instance_by_fd = hash_create (0, sizeof (uword));
      msf->is_listener = (args->is_master != 0);

      memif_log_debug (0, "initializing socket file %s", msf->filename);
    }

  if (mm->per_thread_data == 0)
    {
      int i;

      vec_validate_aligned (mm->per_thread_data, tm->n_vlib_mains - 1,
			    CLIB_CACHE_LINE_BYTES);

      for (i = 0; i < tm->n_vlib_mains; i++)
	{
	  memif_per_thread_data_t *ptd =
	    vec_elt_at_index (mm->per_thread_data, i);
	  vlib_buffer_t *bt = &ptd->buffer_template;
	  clib_memset (bt, 0, sizeof (vlib_buffer_t));
	  bt->flags = VLIB_BUFFER_TOTAL_LENGTH_VALID;
	  bt->total_length_not_including_first_buffer = 0;
	  vnet_buffer (bt)->sw_if_index[VLIB_TX] = (u32) ~ 0;

	  /* initially prealloc copy_ops so we can use
	     _vec_len instead of vec_elen */
	  vec_validate_aligned (ptd->copy_ops, 0, CLIB_CACHE_LINE_BYTES);
	  vec_reset_length (ptd->copy_ops);
	  vec_validate_aligned (ptd->buffers, 0, CLIB_CACHE_LINE_BYTES);
	  vec_reset_length (ptd->buffers);
	}
    }

  save_mm_interfaces = mm->interfaces;
  pool_get (mm->interfaces, mif);
  if (save_mm_interfaces != mm->interfaces) {
	  mm->interfaces_invalidate = 1;
  }
  clib_memset (mif, 0, sizeof (*mif));
  mif->dev_instance = mif - mm->interfaces;
  mif->socket_file_index = msf - mm->socket_files;
  mif->id = args->id;
  mif->sw_if_index = mif->hw_if_index = mif->per_interface_next_index = ~0;
  mif->mode = args->mode;
  if (args->secret)
    mif->secret = vec_dup (args->secret);

  if (tm->n_vlib_mains > 1)
    clib_spinlock_init (&mif->lockp);

  if (mif->mode == MEMIF_INTERFACE_MODE_ETHERNET)
    {

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
      error = ethernet_register_interface (vnm, memif_device_class.index,
					   mif->dev_instance, args->hw_addr,
					   &mif->hw_if_index,
					   memif_eth_flag_change);
    }
  else if (mif->mode == MEMIF_INTERFACE_MODE_IP)
    {
      mif->hw_if_index =
	vnet_register_interface (vnm, memif_device_class.index,
				 mif->dev_instance,
				 memif_ip_hw_if_class.index,
				 mif->dev_instance);
    }
  else
    error = clib_error_return (0, "unsupported interface mode");

  if (error)
    {
      ret = VNET_API_ERROR_SYSCALL_ERROR_2;
      goto error;
    }

  sw = vnet_get_hw_sw_interface (vnm, mif->hw_if_index);
  mif->sw_if_index = sw->sw_if_index;

  mif->cfg.log2_ring_size = args->log2_ring_size;
  mif->cfg.buffer_size = args->buffer_size;
  mif->cfg.num_s2m_rings =
    args->is_master ? args->rx_queues : args->tx_queues;
  mif->cfg.num_m2s_rings =
    args->is_master ? args->tx_queues : args->rx_queues;

  args->sw_if_index = mif->sw_if_index;

  /* If this is new one, start listening */
  if (msf->is_listener && msf->ref_cnt == 0)
    {
      struct stat file_stat;
      clib_socket_t *s = clib_mem_alloc (sizeof (clib_socket_t));

      ASSERT (msf->sock == 0);
      msf->sock = s;

      clib_memset (s, 0, sizeof (clib_socket_t));
      s->config = (char *) msf->filename;
      s->flags = CLIB_SOCKET_F_IS_SERVER |
	CLIB_SOCKET_F_ALLOW_GROUP_WRITE |
	CLIB_SOCKET_F_SEQPACKET | CLIB_SOCKET_F_PASSCRED;

      if ((error = clib_socket_init (s)))
	{
	  ret = VNET_API_ERROR_SYSCALL_ERROR_4;
	  goto error;
	}

      if (stat ((char *) msf->filename, &file_stat) == -1)
	{
	  ret = VNET_API_ERROR_SYSCALL_ERROR_8;
	  goto error;
	}

      clib_file_t template = { 0 };
      template.read_function = memif_conn_fd_accept_ready;
      template.file_descriptor = msf->sock->fd;
      template.private_data = mif->socket_file_index;
      template.description = format (0, "memif listener %s", msf->filename);
      memif_file_add (&msf->sock->private_data, &template);
    }

  msf->ref_cnt++;

  if (args->is_master == 0)
    {
      mif->flags |= MEMIF_IF_FLAG_IS_SLAVE;
      if (args->is_zero_copy)
	mif->flags |= MEMIF_IF_FLAG_ZERO_COPY;
    }

  hw = vnet_get_hw_interface (vnm, mif->hw_if_index);
  hw->flags |= VNET_HW_INTERFACE_FLAG_SUPPORTS_INT_MODE;
  vnet_hw_if_set_input_node (vnm, mif->hw_if_index, memif_input_node.index);
  mhash_set (&msf->dev_instance_by_id, &mif->id, mif->dev_instance, 0);

  if (pool_elts (mm->interfaces) == 1)
    {
      vlib_process_signal_event (vm, memif_process_node.index,
				 MEMIF_PROCESS_EVENT_START, 0);
    }
  goto done;

error:
  if (mif->hw_if_index != ~0)
    {
      if (mif->mode == MEMIF_INTERFACE_MODE_IP)
	vnet_delete_hw_interface (vnm, mif->hw_if_index);
      else
	ethernet_delete_interface (vnm, mif->hw_if_index);
      mif->hw_if_index = ~0;
    }
  memif_delete_if (vm, mif);
  if (error)
    {
      memif_log_err (mif, "%U", format_clib_error, error);
      clib_error_free (error);
    }
  return ret;

done:
  return rv;
}

clib_error_t *
memif_interface_admin_up_down (vnet_main_t *vnm, u32 hw_if_index, u32 flags)
{
  memif_main_t *mm = &memif_main;
  vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, hw_if_index);
  memif_if_t *mif = pool_elt_at_index (mm->interfaces, hw->dev_instance);
  static clib_error_t *error = 0;

  if (flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP)
    mif->flags |= MEMIF_IF_FLAG_ADMIN_UP;
  else
    mif->flags &= ~MEMIF_IF_FLAG_ADMIN_UP;

  vlib_process_signal_event (vnm->vlib_main, memif_process_node.index,
			     MEMIF_PROCESS_EVENT_ADMIN_UP_DOWN, 0);
  return error;
}

static clib_error_t *
memif_init (vlib_main_t * vm)
{
  memif_main_t *mm = &memif_main;

  clib_memset (mm, 0, sizeof (memif_main_t));

  mm->log_class = vlib_log_register_class ("memif_plugin", 0);
  memif_log_debug (0, "initialized");

  /* initialize binary API */
  memif_plugin_api_hookup (vm);

  /*
   * Pre-stuff socket filename pool with a non-modifieable mapping
   * for socket-id 0 to MEMIF_DEFAULT_SOCKET_FILENAME in the
   * default run-time directory.
   */
  memif_socket_filename_add_del (1, 0, (u8 *) MEMIF_DEFAULT_SOCKET_FILENAME);

  return 0;
}

VLIB_INIT_FUNCTION (memif_init);

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () = {
    .version = VPP_BUILD_VER,
    .description = "Packet Memory Interface (memif) -- Experimental",
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
