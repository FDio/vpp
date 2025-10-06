/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Cisco Systems, Inc.
 * Copyright(c) 2024 Arm Limited
 */

#include <vlib/vlib.h>
#include <vlib/file.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
#include <snort/snort.h>
#include <vnet/vnet.h>

#include <sys/eventfd.h>

snort_main_t snort_main;

VLIB_REGISTER_LOG_CLASS (snort_log, static) = {
  .class_name = "snort",
};

vlib_node_registration_t snort_deq_node;

static clib_error_t *
snort_deq_ready (clib_file_t *uf)
{
  vlib_main_t *vm = vlib_get_main ();
  snort_qpair_t *qp = (snort_qpair_t *) uf->private_data;
  u64 counter;
  ssize_t __clib_unused bytes_read;

  bytes_read = read ((int) uf->file_descriptor, &counter, sizeof (counter));
  __atomic_store_n (&qp->hdr->deq.interrupt_pending, 0, __ATOMIC_RELAXED);
  vlib_node_set_interrupt_pending (vm, qp->dequeue_node_index);
  return 0;
}

static char *snort_deq_error_strings[] = {
#define _(sym, string) string,
  foreach_snort_deq_error
#undef _
};

__clib_export int
snort_instance_get_index_by_name (vlib_main_t *vm, const char *name,
				  snort_instance_index_t *instance_index)
{
  snort_instance_t *si = snort_get_instance_by_name ((char *) name);

  if (!si)
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  *instance_index = si->index;

  return 0;
}

__clib_export int
snort_instance_create (vlib_main_t *vm, snort_instance_create_args_t *args,
		       char *fmt, ...)

{
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  snort_main_t *sm = &snort_main;
  snort_instance_t *si;
  va_list va;
  u32 size, index, qpair_mem_sz;
  u8 *base = CLIB_MEM_VM_MAP_FAILED, *name;
  int rv = 0, fd = -1;
  u32 qsz = 1 << args->log2_queue_sz;
  u32 ebuf_qsz = 1 << args->log2_ebuf_queue_sz;
  u32 qpairs_per_thread, total_qpairs, n_threads = tm->n_vlib_mains;
  u8 align = CLIB_CACHE_LINE_BYTES;

  if (sm->listener == 0)
    {
      clib_error_t *err;
      err = snort_listener_init ();
      if (err)
	{
	  log_err ("listener init failed: %U", format_clib_error, err);
	  clib_error_free (err);
	  return VNET_API_ERROR_INIT_FAILED;
	}
    }

  va_start (va, fmt);
  name = va_format (0, fmt, &va);
  va_end (va);
  vec_add1 (name, 0);

  if (snort_get_instance_by_name ((char *) name))
    return VNET_API_ERROR_ENTRY_ALREADY_EXISTS;

  qpairs_per_thread = clib_max (1, args->qpairs_per_thread);
  total_qpairs = qpairs_per_thread * n_threads;

  /* header and descriptor table */
  qpair_mem_sz = round_pow2 (
    sizeof (daq_vpp_qpair_header_t) + qsz * sizeof (daq_vpp_desc_t), align);

  /* enq and deq ring */
  qpair_mem_sz += 2 * round_pow2 (qsz * sizeof (daq_vpp_desc_index_t), align);

  /* empty buffers ring */
  qpair_mem_sz += round_pow2 (ebuf_qsz * sizeof (daq_vpp_ebuf_desc_t), align);

  /* total size of shared memory */
  size = round_pow2 ((uword) total_qpairs * qpair_mem_sz,
		     clib_mem_get_page_size ());

  fd = clib_mem_vm_create_fd (CLIB_MEM_PAGE_SZ_DEFAULT, "snort instance %s",
			      name);

  if (fd == -1)
    {
      rv = VNET_API_ERROR_SYSCALL_ERROR_1;
      goto done;
    }

  if ((ftruncate (fd, size)) == -1)
    {
      rv = VNET_API_ERROR_SYSCALL_ERROR_2;
      goto done;
    }

  base = clib_mem_vm_map_shared (0, size, fd, 0, "snort instance %s", name);

  if (base == CLIB_MEM_VM_MAP_FAILED)
    {
      rv = VNET_API_ERROR_SYSCALL_ERROR_3;
      goto done;
    }

  pool_get_zero (sm->instances, si);
  si->index = si - sm->instances;
  si->shm_base = base;
  si->drop_bitmap = args->drop_bitmap;
  si->shm_fd = fd;
  si->shm_size = size;
  si->name = name;
  si->drop_on_disconnect = args->drop_on_disconnect;
  si->qpairs_per_thread = qpairs_per_thread;
  si->ip4_hash_fn = vnet_hash_default_function (VNET_HASH_FN_TYPE_IP4);

  index = si - sm->instances;
  hash_set_mem (sm->instance_by_name, si->name, index);

  if (vec_len (sm->snort_deleted_deq_nodes) > 0)
    {
      snort_deleted_deq_node_t *dn = vec_end (sm->snort_deleted_deq_nodes) - 1;
      si->dequeue_node_index = dn->dequeue_node_index;
      vlib_node_rename (vm, si->dequeue_node_index, "snort-deq-%s", si->name);
      foreach_vlib_main ()
	{
	  vlib_node_runtime_t *nrt;
	  snort_deq_runtime_data_t *rt;
	  nrt = vlib_node_get_runtime (this_vlib_main, dn->dequeue_node_index);
	  vlib_node_runtime_perf_counter (this_vlib_main, nrt, 0, 0, 0,
					  VLIB_NODE_RUNTIME_PERF_RESET);
	  rt = vlib_node_get_runtime_data (this_vlib_main,
					   dn->dequeue_node_index);
	  ASSERT (rt->is_deleted == 1);
	  rt->is_deleted = 0;
	  rt->instance_index = index;
	}

      vlib_node_set_state (vm, si->dequeue_node_index,
			   VLIB_NODE_STATE_INTERRUPT);
      vec_dec_len (sm->snort_deleted_deq_nodes, 1);
    }
  else
    {
      snort_deq_runtime_data_t rt = {};
      rt.instance_index = index;
      rt.is_deleted = 0;

      vlib_node_registration_t snort_deq_reg = {
	.sibling_of = "snort-enq",
	.type = VLIB_NODE_TYPE_SCHED,
	.state = VLIB_NODE_STATE_INTERRUPT,
	.vector_size = sizeof (u32),
	.runtime_data = &rt,
	.runtime_data_bytes = sizeof (snort_deq_runtime_data_t),
	.flags = VLIB_NODE_FLAG_TRACE_SUPPORTED,
	.node_fn_registrations = snort_deq_node.node_fn_registrations,
	.format_trace = format_snort_deq_trace,
	.error_strings = snort_deq_error_strings,
	.n_errors = ARRAY_LEN (snort_deq_error_strings),
      };

      si->dequeue_node_index =
	vlib_register_node (vm, &snort_deq_reg, "snort-deq-%s", si->name);
    }

  si->ip4_input_dequeue_node_next_index = vlib_node_add_named_next (
    vm, si->dequeue_node_index, "snort-ip4-input-next");
  si->ip4_output_dequeue_node_next_index = vlib_node_add_named_next (
    vm, si->dequeue_node_index, "snort-ip4-output-next");
  vlib_worker_thread_node_runtime_update ();

  log_debug ("instnce '%s' created with fd %d at %p, len %u", name, fd, base,
	     size);

  vec_validate_aligned (si->qpairs, total_qpairs - 1, CLIB_CACHE_LINE_BYTES);

  for (int thread_id = 0; thread_id < n_threads; thread_id++)
    for (int queue_id = 0; queue_id < qpairs_per_thread; queue_id++)
      {
	snort_qpair_t *qp;
	u32 sz = sizeof (snort_qpair_t) + qsz * sizeof (snort_qpair_entry_t);

	qp = clib_mem_alloc_aligned (sz, CLIB_CACHE_LINE_BYTES);
	si->qpairs[thread_id * qpairs_per_thread + queue_id] = qp;

	*qp = (snort_qpair_t){
	  .client_index = SNORT_INVALID_CLIENT_INDEX,
	  .dequeue_node_index = si->dequeue_node_index,
	  .log2_queue_size = args->log2_queue_sz,
	  .log2_ebuf_queue_size = args->log2_ebuf_queue_sz,
	  .qpair_id.thread_id = thread_id,
	  .qpair_id.queue_id = queue_id,
	  .enq_fd = eventfd (0, EFD_NONBLOCK),
	  .deq_fd = eventfd (0, EFD_NONBLOCK),
	};

	qp->hdr = (void *) base;
	base += round_pow2 (sizeof (daq_vpp_qpair_header_t) +
			      qsz * sizeof (daq_vpp_desc_t),
			    align);
	qp->enq_ring = (void *) base;
	base += round_pow2 (qsz * sizeof (daq_vpp_desc_index_t), align);
	qp->deq_ring = (void *) base;
	base += round_pow2 (qsz * sizeof (daq_vpp_desc_index_t), align);
	qp->ebuf_ring = (void *) base;
	base += round_pow2 (ebuf_qsz * sizeof (daq_vpp_ebuf_desc_t), align);

	qp->hdr->enq.cookie = DAQ_VPP_COOKIE;
	snort_qpair_init (qp);
	snort_qpair_ebuf_alloc_buffers (vm, qp);

	/* listen on dequeue events */
	qp->deq_fd_file_index = clib_file_add (
	  &file_main, &(clib_file_t){
			.read_function = snort_deq_ready,
			.file_descriptor = qp->deq_fd,
			.description = format (
			  0, "snort dequeue for instance '%s' qpair %u.%u",
			  si->name, thread_id, queue_id),
			.polling_thread_index = thread_id,
			.private_data = (u64) qp,
		      });

	log_debug ("qpair %u.%u created at %p size %u enq_fd %u deq_fd %d",
		   thread_id, queue_id, qp, qsz, qp->enq_fd, qp->deq_fd);
      }

done:
  if (rv)
    {
      if (base != CLIB_MEM_VM_MAP_FAILED)
	clib_mem_vm_unmap (base);
      if (fd != -1)
	close (fd);
      vec_free (name);
    }
  return rv;
}

__clib_export int
snort_instance_delete (vlib_main_t *vm, snort_instance_index_t instance_index)
{
  snort_main_t *sm = &snort_main;
  snort_instance_t *si;
  snort_deleted_deq_node_t *dn;
  int rv = 0;

  si = snort_get_instance_by_index (instance_index);
  if (!si)
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  vec_foreach_pointer (qp, si->qpairs)
    if (qp->client_index != SNORT_INVALID_CLIENT_INDEX)
      return VNET_API_ERROR_INSTANCE_IN_USE;

  if ((rv = snort_strip_instance_interfaces (vm, si)))
    return rv;

  hash_unset_mem (sm->instance_by_name, si->name);

  // disable deq node and put it on recycle list
  vlib_node_set_state (vm, si->dequeue_node_index, VLIB_NODE_STATE_DISABLED);
  foreach_vlib_main ()
    {
      snort_deq_runtime_data_t *rt =
	vlib_node_get_runtime_data (this_vlib_main, si->dequeue_node_index);

      /* Mark node runtime as deleted so (if called)
       * will drop packets. */
      rt->is_deleted = 1;
      rt->instance_index = ~0;
    }
  vlib_node_rename (vm, si->dequeue_node_index, "snort-deq-%s-deleted",
		    si->name);
  vlib_unregister_errors (vm, si->dequeue_node_index);
  vec_add2 (sm->snort_deleted_deq_nodes, dn, 1);
  dn->dequeue_node_index = si->dequeue_node_index;

  clib_mem_vm_unmap (si->shm_base);
  close (si->shm_fd);

  vec_foreach_pointer (qp, si->qpairs)
    {
      snort_qpair_ebuf_free_buffers (vm, qp);
      clib_file_del_by_index (&file_main, qp->deq_fd_file_index);
      close (qp->enq_fd);
      close (qp->deq_fd);
      clib_mem_free (qp);
    }

  log_debug ("deleting instance '%s'", si->name);

  vec_free (si->qpairs);
  vec_free (si->name);
  pool_put (sm->instances, si);

  return rv;
}

static clib_error_t *
snort_init (vlib_main_t *vm)
{
  snort_main_t *sm = &snort_main;
  sm->instance_by_name = hash_create_string (0, sizeof (uword));
  vlib_buffer_pool_t *bp;

  vec_foreach (bp, vm->buffer_main->buffer_pools)
    {
      vlib_physmem_map_t *pm =
	vlib_physmem_get_map (vm, bp->physmem_map_index);
      vec_add1 (sm->buffer_pool_base_addrs, pm->base);
    }

  sm->socket_name = format (0, "%s/%s%c", vlib_unix_get_runtime_dir (),
			    DAQ_VPP_DEFAULT_SOCKET_FILE, 0);

  return 0;
}

VLIB_INIT_FUNCTION (snort_init);

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "Snort",
};
