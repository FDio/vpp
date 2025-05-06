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

static clib_error_t *
snort_deq_ready (clib_file_t *uf)
{
  vlib_main_t *vm = vlib_get_main ();
  snort_main_t *sm = &snort_main;
  snort_per_thread_data_t *ptd =
    vec_elt_at_index (sm->per_thread_data, vm->thread_index);
  u64 counter;
  ssize_t __clib_unused bytes_read;

  bytes_read = read ((int) uf->file_descriptor, &counter, sizeof (counter));
  clib_interrupt_set (ptd->interrupts, (int) uf->private_data);
  vlib_node_set_interrupt_pending (vm, snort_deq_node.index);
  return 0;
}

int
snort_instance_create (vlib_main_t *vm, snort_instance_create_args_t *args,
		       char *fmt, ...)

{
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  snort_main_t *sm = &snort_main;
  snort_instance_t *si;
  va_list va;
  u32 size, index, i, qpair_mem_sz = 0;
  u8 *base = CLIB_MEM_VM_MAP_FAILED, *name;
  int rv = 0, fd = -1;
  u32 qsz = 1 << args->log2_queue_sz;
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
  si->shm_fd = fd;
  si->shm_size = size;
  si->name = name;
  si->drop_on_disconnect = args->drop_on_disconnect;
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

      qp->client_index = SNORT_INVALID_CLIENT_INDEX;
      qp->log2_queue_size = args->log2_queue_sz;
      qp->qpair_id.thread_id = i;
      qp->qpair_id.queue_id = 0;
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

      qp->buffer_indices = clib_mem_alloc_aligned (
	sizeof (qp->buffer_indices[0]) * qsz, CLIB_CACHE_LINE_BYTES);
      clib_memset_u32 (qp->buffer_indices, ~0, qsz);
      qp->next_indices = clib_mem_alloc_aligned (
	sizeof (qp->next_indices[0]) * qsz, CLIB_CACHE_LINE_BYTES);
      qp->freelist = clib_mem_alloc_aligned (sizeof (qp->freelist[0]) * qsz,
					     CLIB_CACHE_LINE_BYTES);
      snort_freelist_init (qp);

      /* listen on dequeue events */
      t.read_function = snort_deq_ready;
      t.file_descriptor = qp->deq_fd;
      t.private_data = si->index;
      t.description =
	format (0, "snort dequeue for instance '%s' qpair %u", si->name, i);
      qp->deq_fd_file_index = clib_file_add (&file_main, &t);
      clib_file_set_polling_thread (&file_main, qp->deq_fd_file_index, i);
      clib_interrupt_resize (&ptd->interrupts, vec_len (sm->instances));
    }

  for (i = 0; i < vlib_get_n_threads (); i++)
    vlib_node_set_state (vlib_get_main_by_index (i), snort_deq_node.index,
			 sm->input_mode);

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

int
snort_instance_delete (vlib_main_t *vm, u32 instance_index)
{
  snort_main_t *sm = &snort_main;
  snort_instance_t *si;
  snort_qpair_t *qp;
  int rv = 0;

  si = snort_get_instance_by_index (instance_index);
  if (!si)
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  vec_foreach (qp, si->qpairs)
    if (qp->client_index != SNORT_INVALID_CLIENT_INDEX)
      return VNET_API_ERROR_INSTANCE_IN_USE;

  if ((rv = snort_strip_instance_interfaces (vm, si)))
    return rv;

  hash_unset_mem (sm->instance_by_name, si->name);

  clib_mem_vm_unmap (si->shm_base);
  close (si->shm_fd);

  vec_foreach (qp, si->qpairs)
    {
      clib_file_del_by_index (&file_main, qp->deq_fd_file_index);
      clib_mem_free (qp->freelist);
      clib_mem_free (qp->buffer_indices);
      clib_mem_free (qp->next_indices);
      close (qp->enq_fd);
      close (qp->deq_fd);
    }

  log_debug ("deleting instance '%s'", si->name);

  vec_free (si->qpairs);
  vec_free (si->name);
  pool_put (sm->instances, si);

  return rv;
}

int
snort_set_node_mode (vlib_main_t __clib_unused *vm, u32 mode)
{
  int i;
  snort_main.input_mode = mode;
  for (i = 0; i < vlib_get_n_threads (); i++)
    vlib_node_set_state (vlib_get_main_by_index (i), snort_deq_node.index,
			 mode);
  return 0;
}

static clib_error_t *
snort_init (vlib_main_t *vm)
{
  snort_main_t *sm = &snort_main;
  sm->input_mode = VLIB_NODE_STATE_INTERRUPT;
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

VNET_FEATURE_INIT (snort_enq, static) = {
  .arc_name = "ip4-unicast",
  .node_name = "snort-enq",
  .runs_before = VNET_FEATURES ("ip4-lookup"),
};

VNET_FEATURE_INIT (snort_enq_out, static) = {
  .arc_name = "ip4-output",
  .node_name = "snort-enq",
  .runs_before = VNET_FEATURES ("interface-output"),
};
