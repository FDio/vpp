/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2021 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
#include <snort/snort.h>

#include <sys/eventfd.h>

snort_main_t snort_main;

VLIB_REGISTER_LOG_CLASS (snort_log, static) = {
  .class_name = "snort",
};

#define log_debug(fmt, ...) vlib_log_debug (snort_log.class, fmt, __VA_ARGS__)
#define log_err(fmt, ...)   vlib_log_err (snort_log.class, fmt, __VA_ARGS__)

static void
snort_client_disconnect (clib_file_t *uf)
{
  vlib_main_t *vm = vlib_get_main ();
  snort_qpair_t *qp;
  snort_main_t *sm = &snort_main;
  snort_client_t *c = pool_elt_at_index (sm->clients, uf->private_data);

  if (c->instance_index != ~0)
    {
      snort_per_thread_data_t *ptd =
	vec_elt_at_index (sm->per_thread_data, vm->thread_index);
      snort_instance_t *si =
	pool_elt_at_index (sm->instances, c->instance_index);
      vec_foreach (qp, si->qpairs)
	__atomic_store_n (&qp->ready, 1, __ATOMIC_RELEASE);

      si->client_index = ~0;
      clib_interrupt_set (ptd->interrupts, uf->private_data);
      vlib_node_set_interrupt_pending (vm, snort_deq_node.index);
    }

  clib_file_del (&file_main, uf);
  clib_socket_close (&c->socket);
  pool_put (sm->clients, c);
}

static snort_instance_t *
snort_get_instance_by_name (char *name)
{
  snort_main_t *sm = &snort_main;
  uword *p;
  if ((p = hash_get_mem (sm->instance_by_name, name)) == 0)
    return 0;

  return vec_elt_at_index (sm->instances, p[0]);
  ;
}

static clib_error_t *
snort_conn_fd_read_ready (clib_file_t *uf)
{
  vlib_main_t *vm = vlib_get_main ();
  snort_main_t *sm = &snort_main;
  snort_client_t *c = pool_elt_at_index (sm->clients, uf->private_data);
  vlib_buffer_pool_t *bp;
  snort_instance_t *si;
  snort_qpair_t *qp;
  snort_client_msg_queue_elt *e;
  clib_error_t *err;
  daq_vpp_msg_t msg;
  char *name;
  u8 *base;

  log_debug ("fd_read_ready: client %u", uf->private_data);

  if ((err = clib_socket_recvmsg (&c->socket, &msg, sizeof (msg), 0, 0)))
    {
      log_err ("client recvmsg error: %U", format_clib_error, err);
      snort_client_disconnect (uf);
      clib_error_free (err);
      return 0;
    }

  if (msg.type != DAQ_VPP_MSG_TYPE_HELLO)
    {
      log_err ("unexpeced message recieved from client", 0);
      snort_client_disconnect (uf);
      return 0;
    }

  msg.hello.inst_name[DAQ_VPP_INST_NAME_LEN - 1] = 0;
  name = msg.hello.inst_name;

  log_debug ("fd_read_ready: connect instance %s", name);

  if ((si = snort_get_instance_by_name (name)) == 0)
    {
      log_err ("unknown instance '%s' requested by client", name);
      snort_client_disconnect (uf);
      return 0;
    }

  vec_foreach (qp, si->qpairs)
    {
      u32 ready = __atomic_load_n (&qp->ready, __ATOMIC_ACQUIRE);
      if (!ready)
	{
	  log_err ("instance '%s' is not ready to accept connections", name);
	  snort_client_disconnect (uf);
	  return 0;
	}
    }

  base = (u8 *) si->shm_base;

  if (si->client_index != ~0)
    {
      log_err ("client already connected to instance '%s'", name);
      snort_client_disconnect (uf);
      return 0;
    }
  si->client_index = uf->private_data;
  c->instance_index = si->index;

  log_debug ("fd_read_ready: connect instance index %u", si->index);

  clib_fifo_add2 (c->msg_queue, e);
  e->msg.type = DAQ_VPP_MSG_TYPE_CONFIG;
  e->msg.config.num_bpools = vec_len (vm->buffer_main->buffer_pools);
  e->msg.config.num_qpairs = vec_len (si->qpairs);
  e->msg.config.shm_size = si->shm_size;
  e->fds[0] = si->shm_fd;
  e->n_fds = 1;

  vec_foreach (bp, vm->buffer_main->buffer_pools)
    {
      vlib_physmem_map_t *pm;
      pm = vlib_physmem_get_map (vm, bp->physmem_map_index);
      clib_fifo_add2 (c->msg_queue, e);
      e->msg.type = DAQ_VPP_MSG_TYPE_BPOOL;
      e->msg.bpool.size = pm->n_pages << pm->log2_page_size;
      e->fds[0] = pm->fd;
      e->n_fds = 1;
    }

  vec_foreach (qp, si->qpairs)
    {
      clib_fifo_add2 (c->msg_queue, e);
      e->msg.type = DAQ_VPP_MSG_TYPE_QPAIR;
      e->msg.qpair.log2_queue_size = qp->log2_queue_size;
      e->msg.qpair.desc_table_offset = (u8 *) qp->descriptors - base;
      e->msg.qpair.enq_ring_offset = (u8 *) qp->enq_ring - base;
      e->msg.qpair.deq_ring_offset = (u8 *) qp->deq_ring - base;
      e->msg.qpair.enq_head_offset = (u8 *) qp->enq_head - base;
      e->msg.qpair.deq_head_offset = (u8 *) qp->deq_head - base;
      e->fds[0] = qp->enq_fd;
      e->fds[1] = qp->deq_fd;
      e->n_fds = 2;
    }

  clib_file_set_data_available_to_write (&file_main, c->file_index, 1);
  return 0;
}

static clib_error_t *
snort_conn_fd_write_ready (clib_file_t *uf)
{
  snort_main_t *sm = &snort_main;
  snort_client_t *c = pool_elt_at_index (sm->clients, uf->private_data);
  snort_client_msg_queue_elt *e;

  log_debug ("fd_write_ready: client %u", uf->private_data);
  clib_fifo_sub2 (c->msg_queue, e);

  if (clib_fifo_elts (c->msg_queue) == 0)
    clib_file_set_data_available_to_write (&file_main, c->file_index, 0);

  return clib_socket_sendmsg (&c->socket, &e->msg, sizeof (*e), e->fds,
			      e->n_fds);
}

clib_error_t *
snort_conn_fd_error (clib_file_t *uf)
{
  log_debug ("fd_error: client %u", uf->private_data);
  return 0;
}

static clib_error_t *
snort_deq_ready (clib_file_t *uf)
{
  vlib_main_t *vm = vlib_get_main ();
  snort_main_t *sm = &snort_main;
  snort_per_thread_data_t *ptd =
    vec_elt_at_index (sm->per_thread_data, vm->thread_index);
  u64 counter;
  ssize_t bytes_read;

  bytes_read = read (uf->file_descriptor, &counter, sizeof (counter));
  if (bytes_read < 0)
    {
      return clib_error_return (0, "client closed socket");
    }

  if (bytes_read < sizeof (counter))
    {
      return clib_error_return (0, "unexpected truncated read");
    }

  clib_interrupt_set (ptd->interrupts, uf->private_data);
  vlib_node_set_interrupt_pending (vm, snort_deq_node.index);
  return 0;
}

static clib_error_t *
snort_conn_fd_accept_ready (clib_file_t *uf)
{
  snort_main_t *sm = &snort_main;
  snort_client_t *c;
  clib_socket_t *s;
  clib_error_t *err = 0;
  clib_file_t t = { 0 };

  pool_get_zero (sm->clients, c);
  c->instance_index = ~0;
  s = &c->socket;

  if ((err = clib_socket_accept (sm->listener, s)))
    {
      log_err ("%U", format_clib_error, err);
      pool_put (sm->clients, c);
      return err;
    }

  t.read_function = snort_conn_fd_read_ready;
  t.write_function = snort_conn_fd_write_ready;
  t.error_function = snort_conn_fd_error;
  t.file_descriptor = s->fd;
  t.private_data = c - sm->clients;
  t.description = format (0, "snort client");
  c->file_index = clib_file_add (&file_main, &t);

  log_debug ("snort_conn_fd_accept_ready: client %u", t.private_data);
  return 0;
}

static clib_error_t *
snort_listener_init (vlib_main_t *vm)
{
  snort_main_t *sm = &snort_main;
  clib_error_t *err;
  clib_file_t t = { 0 };
  clib_socket_t *s;

  if (sm->listener)
    return 0;

  s = clib_mem_alloc (sizeof (clib_socket_t));
  clib_memset (s, 0, sizeof (clib_socket_t));
  s->config = (char *) sm->socket_name;
  s->flags = CLIB_SOCKET_F_IS_SERVER | CLIB_SOCKET_F_ALLOW_GROUP_WRITE |
	     CLIB_SOCKET_F_SEQPACKET | CLIB_SOCKET_F_PASSCRED;

  if ((err = clib_socket_init (s)))
    {
      clib_mem_free (s);
      return err;
    }

  t.read_function = snort_conn_fd_accept_ready;
  t.file_descriptor = s->fd;
  t.description = format (0, "snort listener %s", s->config);
  log_debug ("%v", t.description);
  clib_file_add (&file_main, &t);

  sm->listener = s;

  return 0;
}

clib_error_t *
snort_instance_create (vlib_main_t *vm, char *name, u8 log2_queue_sz,
		       u8 drop_on_disconnect)
{
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  snort_main_t *sm = &snort_main;
  snort_instance_t *si;
  clib_error_t *err = 0;
  u32 index, i;
  u8 *base = CLIB_MEM_VM_MAP_FAILED;
  u32 size;
  int fd = -1;
  u32 qpair_mem_sz = 0;
  u32 qsz = 1 << log2_queue_sz;
  u8 align = CLIB_CACHE_LINE_BYTES;

  if (snort_get_instance_by_name (name))
    return clib_error_return (0, "instance already exists");

  /* descriptor table */
  qpair_mem_sz += round_pow2 (qsz * sizeof (daq_vpp_desc_t), align);

  /* enq and deq ring */
  qpair_mem_sz += 2 * round_pow2 (qsz * sizeof (u32), align);

  /* enq and deq head pointer */
  qpair_mem_sz += 2 * round_pow2 (sizeof (u32), align);

  size = round_pow2 ((uword) tm->n_vlib_mains * qpair_mem_sz,
		     clib_mem_get_page_size ());
  fd = clib_mem_vm_create_fd (CLIB_MEM_PAGE_SZ_DEFAULT, "snort instance %s",
			      name);

  if (fd == -1)
    {
      err = clib_error_return (0, "memory fd failure: %U", format_clib_error,
			       clib_mem_get_last_error ());
      goto done;
    }

  if ((ftruncate (fd, size)) == -1)
    {
      err = clib_error_return (0, "ftruncate failure");
      goto done;
    }

  base = clib_mem_vm_map_shared (0, size, fd, 0, "snort instance %s", name);

  if (base == CLIB_MEM_VM_MAP_FAILED)
    {
      err = clib_error_return (0, "mmap failure");
      goto done;
    }

  pool_get_zero (sm->instances, si);
  si->index = si - sm->instances;
  si->client_index = ~0;
  si->shm_base = base;
  si->shm_fd = fd;
  si->shm_size = size;
  si->name = format (0, "%s%c", name, 0);
  si->drop_on_disconnect = drop_on_disconnect;
  index = si - sm->instances;
  hash_set_mem (sm->instance_by_name, si->name, index);

  log_debug ("instnce '%s' createed with fd %d at %p, len %u", name, fd, base,
	     size);

  vec_validate_aligned (sm->per_thread_data, tm->n_vlib_mains - 1,
			CLIB_CACHE_LINE_BYTES);
  vec_validate_aligned (si->qpairs, tm->n_vlib_mains - 1,
			CLIB_CACHE_LINE_BYTES);

  for (int i = 0; i < tm->n_vlib_mains; i++)
    {
      snort_qpair_t *qp = vec_elt_at_index (si->qpairs, i);
      snort_per_thread_data_t *ptd = vec_elt_at_index (sm->per_thread_data, i);
      clib_file_t t = { 0 };

      qp->log2_queue_size = log2_queue_sz;
      qp->descriptors = (void *) base;
      base += round_pow2 (qsz * sizeof (daq_vpp_desc_t), align);
      qp->enq_ring = (void *) base;
      base += round_pow2 (qsz * sizeof (u32), align);
      qp->deq_ring = (void *) base;
      base += round_pow2 (qsz * sizeof (u32), align);
      qp->enq_head = (void *) base;
      base += round_pow2 (sizeof (u32), align);
      qp->deq_head = (void *) base;
      base += round_pow2 (sizeof (u32), align);
      qp->enq_fd = eventfd (0, EFD_NONBLOCK);
      qp->deq_fd = eventfd (0, EFD_NONBLOCK);
      vec_validate_aligned (qp->buffer_indices, qsz - 1,
			    CLIB_CACHE_LINE_BYTES);
      vec_validate_aligned (qp->next_indices, qsz - 1, CLIB_CACHE_LINE_BYTES);
      clib_memset_u32 (qp->buffer_indices, ~0, qsz);

      /* pre-populate freelist */
      vec_validate_aligned (qp->freelist, qsz - 1, CLIB_CACHE_LINE_BYTES);
      snort_freelist_init (qp->freelist);

      /* listen on dequeue events */
      t.read_function = snort_deq_ready;
      t.file_descriptor = qp->deq_fd;
      t.private_data = si->index;
      t.description =
	format (0, "snort dequeue for instance '%s' qpair %u", si->name, i);
      qp->deq_fd_file_index = clib_file_add (&file_main, &t);
      qp->ready = 1;
      clib_file_set_polling_thread (&file_main, qp->deq_fd_file_index, i);
      clib_interrupt_resize (&ptd->interrupts, vec_len (sm->instances));
    }

  for (i = 0; i < vlib_get_n_threads (); i++)
    vlib_node_set_state (vlib_get_main_by_index (i), snort_deq_node.index,
			 sm->input_mode);

done:
  if (err)
    {
      if (base != CLIB_MEM_VM_MAP_FAILED)
	clib_mem_vm_unmap (base);
      if (fd != -1)
	close (fd);
    }
  return err;
}

clib_error_t *
snort_interface_enable_disable (vlib_main_t *vm, char **instance_name,
				u8 count, u32 sw_if_index, int is_enable)
{
  snort_main_t *sm = &snort_main;
  vnet_main_t *vnm = vnet_get_main ();
  snort_instance_t *si;
  clib_error_t *err = 0;
  u32 index, id;

  if (is_enable)
    {
      vec_validate (sm->instance_vec_by_sw_if_index, sw_if_index);
      for (id = 0; id < count; id++)
	{
	  if ((si = snort_get_instance_by_name (instance_name[id])) == 0)
	    {
	      err = clib_error_return (0, "unknown instance '%s'",
				       instance_name[id]);
	      goto done;
	    }

	  index = vec_search (sm->instance_vec_by_sw_if_index[sw_if_index],
			      si->index);

	  if (index != ~0)
	    {
	      si = vec_elt_at_index (sm->instances, index);
	      err = clib_error_return (0,
				       "interface %U already assgined to "
				       "instance '%s'",
				       format_vnet_sw_if_index_name, vnm,
				       sw_if_index, si->name);
	      goto done;
	    }
	  else
	    {
	      vec_add1 (sm->instance_vec_by_sw_if_index[sw_if_index],
			si->index);
	    }
	}
      vnet_feature_enable_disable (
	"ip4-unicast", "snort-enq", sw_if_index, 1,
	&sm->instance_vec_by_sw_if_index[sw_if_index], sizeof (u32 **));
    }
  else
    {
      if (sw_if_index >= vec_len (sm->instance_vec_by_sw_if_index))
	{
	  err =
	    clib_error_return (0,
			       "interface %U is not assigned to snort "
			       "instance!",
			       format_vnet_sw_if_index_name, vnm, sw_if_index);
	  goto done;
	}
      vec_delete (sm->instance_vec_by_sw_if_index[sw_if_index],
		  vec_len (sm->instance_vec_by_sw_if_index[sw_if_index]), 0);
      vnet_feature_enable_disable (
	"ip4-unicast", "snort-enq", sw_if_index, 0,
	&sm->instance_vec_by_sw_if_index[sw_if_index], sizeof (u64 *));
    }

done:
  if (err)
    log_err ("%U", format_clib_error, err);
  return 0;
}

clib_error_t *
snort_set_node_mode (vlib_main_t *vm, u32 mode)
{
  int i;
  snort_main.input_mode = mode;
  for (i = 0; i < vlib_get_n_threads (); i++)
    vlib_node_set_state (vlib_get_main_by_index (i), snort_deq_node.index,
			 mode);
  return 0;
}

static void
snort_set_default_socket (snort_main_t *sm, u8 *socket_name)
{
  if (sm->socket_name)
    return;

  if (!socket_name)
    socket_name = (u8 *) DAQ_VPP_DEFAULT_SOCKET_FILE;

  sm->socket_name =
    format (0, "%s/%s", vlib_unix_get_runtime_dir (), socket_name);
  vec_terminate_c_string (sm->socket_name);
}

static clib_error_t *
snort_init (vlib_main_t *vm)
{
  snort_main_t *sm = &snort_main;
  sm->input_mode = VLIB_NODE_STATE_INTERRUPT;
  sm->instance_by_name = hash_create_string (0, sizeof (uword));
  sm->key_s = clib_toeplitz_hash_key_init (0, 0);
  vlib_buffer_pool_t *bp;

  vec_foreach (bp, vm->buffer_main->buffer_pools)
    {
      vlib_physmem_map_t *pm =
	vlib_physmem_get_map (vm, bp->physmem_map_index);
      vec_add1 (sm->buffer_pool_base_addrs, pm->base);
    }

  if (!sm->socket_name)
    snort_set_default_socket (sm, 0);

  return snort_listener_init (vm);
}

VLIB_INIT_FUNCTION (snort_init);

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "Snort",
};

VNET_FEATURE_INIT (snort_enq, static) = {
  .arc_name = "ip4-unicast",
  .node_name = "snort-enq",
  .runs_before = VNET_FEATURES ("ip4-lookup"),
};
