/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2021 Cisco Systems, Inc.
 * Copyright(c) 2024 Arm Limited
 */

#include <vlib/vlib.h>
#include <vlib/file.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
#include <click/click.h>

#include <click/vppclick.h>
#include <click/click.h>

VLIB_REGISTER_LOG_CLASS (click_log, static) = {
  .class_name = "click",
  .subclass_name = "file",
};

static clib_error_t *
click_fd_read_fn (clib_file_t *f)
{
  vlib_main_t *vm = vlib_get_main ();
  click_main_t *cm = &click_main;
  click_instance_t *ci = pool_elt_at_index (cm->instances, f->private_data);
  click_thread_t *ct = vec_elt_at_index (ci->threads, vm->thread_index);
  click_file_t *cf = vec_elt_at_index (cm->files, f->file_descriptor);

  u32 node_index = ci->sched_node_index;
  vppclick_pending_select_t *psp, ps = {
    .read = cf->read,
    .fd = (int) f->file_descriptor,
  };

  click_elog_fd_event (vm->thread_index, 2 /* read */, ps.fd);

  if (vlib_node_is_scheduled (vm, node_index))
    vlib_node_unschedule (vm, node_index);
  vlib_node_set_interrupt_pending (vm, node_index);

  vec_foreach (psp, ct->pending_selects)
    if (psp->fd == ps.fd)
      {
	psp->read = read;
	return 0;
      }

  vec_add1 (ct->pending_selects, ps);

  return 0;
}

static clib_error_t *
click_fd_write_fn (clib_file_t *f)
{
  vlib_main_t *vm = vlib_get_main ();
  click_main_t *cm = &click_main;
  click_instance_t *ci = pool_elt_at_index (cm->instances, f->private_data);
  click_thread_t *ct = vec_elt_at_index (ci->threads, vm->thread_index);
  click_file_t *cf = vec_elt_at_index (cm->files, f->file_descriptor);

  u32 node_index = ci->sched_node_index;
  vppclick_pending_select_t *psp, ps = {
    .write = cf->write,
    .fd = (int) f->file_descriptor,
  };

  click_elog_fd_event (vm->thread_index, 3 /* read */, ps.fd);

  if (vlib_node_is_scheduled (vm, node_index))
    vlib_node_unschedule (vm, node_index);
  vlib_node_set_interrupt_pending (vm, node_index);

  vec_foreach (psp, ct->pending_selects)
    if (psp->fd == ps.fd)
      {
	psp->write = write;
	return 0;
      }

  vec_add1 (ct->pending_selects, ps);

  return 0;
}

int
click_add_select (vppclick_inst_index_t inst_index,
		  vppclick_thread_index_t thread_index, vppclick_elt_t elt,
		  int fd, bool read, bool write)
{
  vlib_main_t *vm = vlib_get_main ();
  click_main_t *cm = &click_main;
  u32 file_index;
  char name_and_class[128];

  vppclick_get_elt_name_and_class (elt, name_and_class,
				   sizeof (name_and_class));

  clib_file_t f = {
    .file_descriptor = fd,
    .description = format (0, "click: select %s", name_and_class),
    .read_function = read ? click_fd_read_fn : 0,
    .write_function = write ? click_fd_write_fn : 0,
    .polling_thread_index = thread_index,
    .private_data = inst_index,
    .dont_close = 1,
  };

  vlib_worker_thread_barrier_sync (vm);

  vec_validate (cm->files, fd);
  file_index = clib_file_add (&file_main, &f);

  vlib_worker_thread_barrier_release (vm);

  cm->files[fd] = (click_file_t){
    .inst_index = inst_index,
    .file_index = file_index,
    .read = read ? elt : 0,
    .write = write ? elt : 0,
  };

  click_elog_fd_event (thread_index, 0 /* register */, fd);
  return 0;
}

int
click_remove_select (int fd, bool read, bool write)
{
  click_main_t *cm = &click_main;
  click_file_t *cf = vec_elt_at_index (cm->files, fd);

  if (read)
    cf->read = 0;
  if (write)
    cf->write = 0;

  if (cf->read == 0 && cf->write == 0)
    {
      vlib_main_t *vm = vlib_get_main ();
      vlib_worker_thread_barrier_sync (vm);
      clib_file_del_by_index (&file_main, cf->file_index);
      vlib_worker_thread_barrier_release (vm);
    }

  return 0;
}

void
click_get_pending_selects (vppclick_inst_index_t inst_index,
			   vppclick_pending_selects_t *ps)
{
  vlib_main_t *vm = vlib_get_main ();
  click_main_t *cm = &click_main;
  click_instance_t *ci = pool_elt_at_index (cm->instances, inst_index);
  click_thread_t *ct = vec_elt_at_index (ci->threads, vm->thread_index);

  ps->n_pending_selects = vec_len (ct->pending_selects);
  ps->pending_selects = ct->pending_selects;
  vec_reset_length (ct->pending_selects);
}
