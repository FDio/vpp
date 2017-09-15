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

  DBG ("disconnect %u (%v)", mif->dev_instance, err ? err->what : 0);

  if (err)
    {
      clib_error_t *e = 0;
      mif->local_disc_string = vec_dup (err->what);
      if (mif->conn_fd > -1)
	e = memif_msg_send_disconnect (mif, err);
      clib_error_free (e);
    }

  /* set interface down */
  mif->flags &= ~(MEMIF_IF_FLAG_CONNECTED | MEMIF_IF_FLAG_CONNECTING);
  if (mif->hw_if_index != ~0)
    vnet_hw_interface_set_flags (vnm, mif->hw_if_index, 0);

  /* close connection socket */
  if (mif->conn_clib_file_index != ~0)
    {
      memif_socket_file_t *msf = vec_elt_at_index (mm->socket_files,
						   mif->socket_file_index);
      hash_unset (msf->dev_instance_by_fd, mif->conn_fd);
      memif_file_del_by_index (mif->conn_clib_file_index);
      mif->conn_clib_file_index = ~0;
    }
  else if (mif->conn_fd > -1)
    close (mif->conn_fd);
  mif->conn_fd = -1;

  vec_foreach_index (i, mif->rx_queues)
  {
    mq = vec_elt_at_index (mif->rx_queues, i);
    if (mq->ring)
      {
	int rv;
	rv = vnet_hw_interface_unassign_rx_thread (vnm, mif->hw_if_index, i);
	if (rv)
	  DBG ("Warning: unable to unassign interface %d, "
	       "queue %d: rc=%d", mif->hw_if_index, i, rv);
	mq->ring = 0;
      }
  }

  /* free tx and rx queues */
  vec_foreach (mq, mif->rx_queues) memif_queue_intfd_close (mq);
  vec_free (mif->rx_queues);

  vec_foreach (mq, mif->tx_queues) memif_queue_intfd_close (mq);
  vec_free (mif->tx_queues);

  /* free memory regions */
  vec_foreach (mr, mif->regions)
  {
    int rv;
    if ((rv = munmap (mr->shm, mr->region_size)))
      clib_warning ("munmap failed, rv = %d", rv);
    if (mr->fd > -1)
      close (mr->fd);
  }
  vec_free (mif->regions);

  mif->remote_pid = 0;
  vec_free (mif->remote_name);
  vec_free (mif->remote_if_name);
  clib_fifo_free (mif->msg_queue);
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
      DBG_UNIX_LOG ("Failed to read from socket");
      return 0;
    }

  vnet_device_input_set_interrupt_pending (vnm, mif->hw_if_index, qid);
  mq->int_count++;

  return 0;
}


clib_error_t *
memif_connect (memif_if_t * mif)
{
  vnet_main_t *vnm = vnet_get_main ();
  clib_file_t template = { 0 };
  memif_region_t *mr;
  int i;

  DBG ("connect %u", mif->dev_instance);

  vec_free (mif->local_disc_string);
  vec_free (mif->remote_disc_string);

  vec_foreach (mr, mif->regions)
  {
    if (mr->shm)
      continue;

    if (mr->fd < 0)
      clib_error_return (0, "no memory region fd");

    if ((mr->shm = mmap (NULL, mr->region_size, PROT_READ | PROT_WRITE,
			 MAP_SHARED, mr->fd, 0)) == MAP_FAILED)
      return clib_error_return_unix (0, "mmap");
  }

  template.read_function = memif_int_fd_read_ready;

  vec_foreach_index (i, mif->tx_queues)
  {
    memif_queue_t *mq = vec_elt_at_index (mif->tx_queues, i);

    mq->ring = mif->regions[mq->region].shm + mq->offset;
    if (mq->ring->cookie != MEMIF_COOKIE)
      return clib_error_return (0, "wrong cookie on tx ring %u", i);
  }

  vec_foreach_index (i, mif->rx_queues)
  {
    memif_queue_t *mq = vec_elt_at_index (mif->rx_queues, i);
    int rv;

    mq->ring = mif->regions[mq->region].shm + mq->offset;
    if (mq->ring->cookie != MEMIF_COOKIE)
      return clib_error_return (0, "wrong cookie on tx ring %u", i);

    if (mq->int_fd > -1)
      {
	template.file_descriptor = mq->int_fd;
	template.private_data = (mif->dev_instance << 16) | (i & 0xFFFF);
	memif_file_add (&mq->int_clib_file_index, &template);
      }
    vnet_hw_interface_assign_rx_thread (vnm, mif->hw_if_index, i, ~0);
    rv = vnet_hw_interface_set_rx_mode (vnm, mif->hw_if_index, i,
					VNET_HW_INTERFACE_RX_MODE_DEFAULT);
    if (rv)
      clib_warning
	("Warning: unable to set rx mode for interface %d queue %d: "
	 "rc=%d", mif->hw_if_index, i, rv);
    else
      {
	vnet_hw_interface_rx_mode rxmode;
	vnet_hw_interface_get_rx_mode (vnm, mif->hw_if_index, i, &rxmode);

	if (rxmode == VNET_HW_INTERFACE_RX_MODE_POLLING)
	  mq->ring->flags |= MEMIF_RING_FLAG_MASK_INT;
      }
  }

  mif->flags &= ~MEMIF_IF_FLAG_CONNECTING;
  mif->flags |= MEMIF_IF_FLAG_CONNECTED;

  vnet_hw_interface_set_flags (vnm, mif->hw_if_index,
			       VNET_HW_INTERFACE_FLAG_LINK_UP);
  return 0;
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
  memif_ring_t *ring = NULL;
  int i, j;
  u64 buffer_offset;
  memif_region_t *r;
  clib_mem_vm_alloc_t alloc = { 0 };
  clib_error_t *err;

  vec_validate_aligned (mif->regions, 0, CLIB_CACHE_LINE_BYTES);
  r = vec_elt_at_index (mif->regions, 0);

  buffer_offset = (mif->run.num_s2m_rings + mif->run.num_m2s_rings) *
    (sizeof (memif_ring_t) +
     sizeof (memif_desc_t) * (1 << mif->run.log2_ring_size));

  r->region_size = buffer_offset +
    mif->run.buffer_size * (1 << mif->run.log2_ring_size) *
    (mif->run.num_s2m_rings + mif->run.num_m2s_rings);

  alloc.name = "memif region";
  alloc.size = r->region_size;
  alloc.flags = CLIB_MEM_VM_F_SHARED;

  err = clib_mem_vm_ext_alloc (&alloc);
  if (err)
    return err;

  r->fd = alloc.fd;

  for (i = 0; i < mif->run.num_s2m_rings; i++)
    {
      ring = memif_get_ring (mif, MEMIF_RING_S2M, i);
      ring->head = ring->tail = 0;
      ring->cookie = MEMIF_COOKIE;
      for (j = 0; j < (1 << mif->run.log2_ring_size); j++)
	{
	  u16 slot = i * (1 << mif->run.log2_ring_size) + j;
	  ring->desc[j].region = 0;
	  ring->desc[j].offset =
	    buffer_offset + (u32) (slot * mif->run.buffer_size);
	  ring->desc[j].buffer_length = mif->run.buffer_size;
	}
    }
  for (i = 0; i < mif->run.num_m2s_rings; i++)
    {
      ring = memif_get_ring (mif, MEMIF_RING_M2S, i);
      ring->head = ring->tail = 0;
      ring->cookie = MEMIF_COOKIE;
      for (j = 0; j < (1 << mif->run.log2_ring_size); j++)
	{
	  u16 slot =
	    (i + mif->run.num_s2m_rings) * (1 << mif->run.log2_ring_size) + j;
	  ring->desc[j].region = 0;
	  ring->desc[j].offset =
	    buffer_offset + (u32) (slot * mif->run.buffer_size);
	  ring->desc[j].buffer_length = mif->run.buffer_size;
	}
    }

  ASSERT (mif->tx_queues == 0);
  vec_validate_aligned (mif->tx_queues, mif->run.num_s2m_rings - 1,
			CLIB_CACHE_LINE_BYTES);
  vec_foreach_index (i, mif->tx_queues)
  {
    memif_queue_t *mq = vec_elt_at_index (mif->tx_queues, i);
    if ((mq->int_fd = eventfd (0, EFD_NONBLOCK)) < 0)
      return clib_error_return_unix (0, "eventfd[tx queue %u]", i);
    mq->int_clib_file_index = ~0;
    mq->ring = memif_get_ring (mif, MEMIF_RING_S2M, i);
    mq->log2_ring_size = mif->cfg.log2_ring_size;
    mq->region = 0;
    mq->offset = (void *) mq->ring - (void *) mif->regions[mq->region].shm;
    mq->last_head = 0;
  }

  ASSERT (mif->rx_queues == 0);
  vec_validate_aligned (mif->rx_queues, mif->run.num_m2s_rings - 1,
			CLIB_CACHE_LINE_BYTES);
  vec_foreach_index (i, mif->rx_queues)
  {
    memif_queue_t *mq = vec_elt_at_index (mif->rx_queues, i);
    if ((mq->int_fd = eventfd (0, EFD_NONBLOCK)) < 0)
      return clib_error_return_unix (0, "eventfd[rx queue %u]", i);
    mq->int_clib_file_index = ~0;
    mq->ring = memif_get_ring (mif, MEMIF_RING_M2S, i);
    mq->log2_ring_size = mif->cfg.log2_ring_size;
    mq->region = 0;
    mq->offset = (void *) mq->ring - (void *) mif->regions[mq->region].shm;
    mq->last_head = 0;
  }

  return 0;
}

static uword
memif_process (vlib_main_t * vm, vlib_node_runtime_t * rt, vlib_frame_t * f)
{
  memif_main_t *mm = &memif_main;
  memif_if_t *mif;
  struct sockaddr_un sun;
  int sockfd;
  uword *event_data = 0, event_type;
  u8 enabled = 0;
  f64 start_time, last_run_duration = 0, now;

  sockfd = socket (AF_UNIX, SOCK_SEQPACKET, 0);
  if (sockfd < 0)
    {
      DBG_UNIX_LOG ("socket AF_UNIX");
      return 0;
    }
  sun.sun_family = AF_UNIX;

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
	default:
	  ASSERT (0);
	}

      last_run_duration = start_time = vlib_time_now (vm);
      /* *INDENT-OFF* */
      pool_foreach (mif, mm->interfaces,
        ({
	  memif_socket_file_t * msf = vec_elt_at_index (mm->socket_files, mif->socket_file_index);
	  /* Allow no more than 10us without a pause */
	  now = vlib_time_now (vm);
	  if (now > start_time + 10e-6)
	    {
	      vlib_process_suspend (vm, 100e-6);	/* suspend for 100 us */
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
	      strncpy (sun.sun_path, (char *) msf->filename,
		       sizeof (sun.sun_path) - 1);

	      if (connect
		  (sockfd, (struct sockaddr *) &sun,
		   sizeof (struct sockaddr_un)) == 0)
	        {
		  clib_file_t t = { 0 };

		  mif->conn_fd = sockfd;
		  t.read_function = memif_slave_conn_fd_read_ready;
		  t.write_function = memif_slave_conn_fd_write_ready;
		  t.error_function = memif_slave_conn_fd_error;
		  t.file_descriptor = mif->conn_fd;
		  t.private_data = mif->dev_instance;
		  memif_file_add (&mif->conn_clib_file_index, &t);
		  hash_set (msf->dev_instance_by_fd, mif->conn_fd, mif->dev_instance);

		  mif->flags |= MEMIF_IF_FLAG_CONNECTING;

		  /* grab another fd */
		  sockfd = socket (AF_UNIX, SOCK_SEQPACKET, 0);
		  if (sockfd < 0)
		    {
		      DBG_UNIX_LOG ("socket AF_UNIX");
		      return 0;
		    }
	        }
	    }
        }));
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

  /* remove the interface */
  if (mif->mode == MEMIF_INTERFACE_MODE_IP)
    vnet_delete_hw_interface (vnm, mif->hw_if_index);
  else
    ethernet_delete_interface (vnm, mif->hw_if_index);
  mif->hw_if_index = ~0;

  /* free interface data structures */
  clib_spinlock_free (&mif->lockp);
  mhash_unset (&msf->dev_instance_by_id, &mif->id, 0);

  /* remove socket file */
  if (--(msf->ref_cnt) == 0)
    {
      if (msf->is_listener)
	{
	  uword *x;
	  memif_file_del_by_index (msf->clib_file_index);
	  vec_foreach (x, msf->pending_file_indices)
	  {
	    memif_file_del_by_index (*x);
	  }
	  vec_free (msf->pending_file_indices);
	}
      mhash_free (&msf->dev_instance_by_id);
      hash_free (msf->dev_instance_by_fd);
      mhash_unset (&mm->socket_file_index_by_filename, msf->filename, 0);
      vec_free (msf->filename);
      pool_put (mm->socket_files, msf);
    }

  memset (mif, 0, sizeof (*mif));
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
  u8 *socket_filename;
  int rv = 0;

  if (args->socket_filename == 0 || args->socket_filename[0] != '/')
    {
      clib_error_t *error;
      error = vlib_unix_recursive_mkdir (vlib_unix_get_runtime_dir ());
      if (error)
	{
	  clib_error_free (error);
	  return VNET_API_ERROR_SYSCALL_ERROR_1;
	}

      if (args->socket_filename == 0)
	socket_filename = format (0, "%s/%s%c", vlib_unix_get_runtime_dir (),
				  MEMIF_DEFAULT_SOCKET_FILENAME, 0);
      else
	socket_filename = format (0, "%s/%s%c", vlib_unix_get_runtime_dir (),
				  args->socket_filename, 0);

    }
  else
    socket_filename = vec_dup (args->socket_filename);

  p = mhash_get (&mm->socket_file_index_by_filename, socket_filename);

  if (p)
    {
      msf = vec_elt_at_index (mm->socket_files, p[0]);

      /* existing socket file can be either master or slave but cannot be both */
      if (!msf->is_listener != !args->is_master)
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
  if (msf == 0)
    {
      struct stat file_stat;
      /* If we are creating listener make sure file doesn't exist or if it
       * exists thn delete it if it is old socket file */
      if (args->is_master &&
	  (stat ((char *) socket_filename, &file_stat) == 0))
	{
	  if (S_ISSOCK (file_stat.st_mode))
	    {
	      unlink ((char *) socket_filename);
	    }
	  else
	    {
	      error = clib_error_return (0, "File exists for %s",
					 socket_filename);
	      clib_error_report (error);
	      rv = VNET_API_ERROR_VALUE_EXIST;
	      goto done;
	    }
	}
      pool_get (mm->socket_files, msf);
      memset (msf, 0, sizeof (memif_socket_file_t));
      mhash_init (&msf->dev_instance_by_id, sizeof (uword),
		  sizeof (memif_interface_id_t));
      msf->dev_instance_by_fd = hash_create (0, sizeof (uword));
      msf->filename = socket_filename;
      msf->fd = -1;
      msf->is_listener = (args->is_master != 0);
      socket_filename = 0;
      mhash_set (&mm->socket_file_index_by_filename, msf->filename,
		 msf - mm->socket_files, 0);
      DBG ("creating socket file %s", msf->filename);
    }

  pool_get (mm->interfaces, mif);
  memset (mif, 0, sizeof (*mif));
  mif->dev_instance = mif - mm->interfaces;
  mif->socket_file_index = msf - mm->socket_files;
  mif->id = args->id;
  mif->sw_if_index = mif->hw_if_index = mif->per_interface_next_index = ~0;
  mif->conn_clib_file_index = ~0;
  mif->conn_fd = -1;
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
      clib_error_report (error);
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
      struct sockaddr_un un = { 0 };
      struct stat file_stat;
      int on = 1;

      if ((msf->fd = socket (AF_UNIX, SOCK_SEQPACKET, 0)) < 0)
	{
	  ret = VNET_API_ERROR_SYSCALL_ERROR_4;
	  goto error;
	}

      un.sun_family = AF_UNIX;
      strncpy ((char *) un.sun_path, (char *) msf->filename,
	       sizeof (un.sun_path) - 1);

      if (setsockopt (msf->fd, SOL_SOCKET, SO_PASSCRED, &on, sizeof (on)) < 0)
	{
	  ret = VNET_API_ERROR_SYSCALL_ERROR_5;
	  goto error;
	}
      if (bind (msf->fd, (struct sockaddr *) &un, sizeof (un)) == -1)
	{
	  ret = VNET_API_ERROR_SYSCALL_ERROR_6;
	  goto error;
	}
      if (listen (msf->fd, 1) == -1)
	{
	  ret = VNET_API_ERROR_SYSCALL_ERROR_7;
	  goto error;
	}

      if (stat ((char *) msf->filename, &file_stat) == -1)
	{
	  ret = VNET_API_ERROR_SYSCALL_ERROR_8;
	  goto error;
	}

      msf->clib_file_index = ~0;
      clib_file_t template = { 0 };
      template.read_function = memif_conn_fd_accept_ready;
      template.file_descriptor = msf->fd;
      template.private_data = mif->socket_file_index;
      memif_file_add (&msf->clib_file_index, &template);
    }

  msf->ref_cnt++;

  if (args->is_master == 0)
    mif->flags |= MEMIF_IF_FLAG_IS_SLAVE;

  hw = vnet_get_hw_interface (vnm, mif->hw_if_index);
  hw->flags |= VNET_HW_INTERFACE_FLAG_SUPPORTS_INT_MODE;
  vnet_hw_interface_set_input_node (vnm, mif->hw_if_index,
				    memif_input_node.index);

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
  return ret;

done:
  vec_free (socket_filename);
  return rv;
}


static clib_error_t *
memif_init (vlib_main_t * vm)
{
  memif_main_t *mm = &memif_main;
  vlib_thread_main_t *tm = vlib_get_thread_main ();

  memset (mm, 0, sizeof (memif_main_t));

  /* initialize binary API */
  memif_plugin_api_hookup (vm);

  mhash_init_c_string (&mm->socket_file_index_by_filename, sizeof (uword));

  vec_validate_aligned (mm->rx_buffers, tm->n_vlib_mains - 1,
			CLIB_CACHE_LINE_BYTES);

  return 0;
}

VLIB_INIT_FUNCTION (memif_init);

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () = {
    .version = VPP_BUILD_VER,
    .description = "Packet Memory Interface (experimetal)",
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
