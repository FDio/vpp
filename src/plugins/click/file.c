/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2021 Cisco Systems, Inc.
 * Copyright(c) 2024 Arm Limited
 */

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
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
  u32 node_index = ci->input_node_index;
  vppclick_fd_event_t *ep, e = {
    .is_read = 1,
    .fd = (int) f->file_descriptor,
  };

  fformat (stderr, "click_fd_read: %d\n", f->file_descriptor);

  if (vlib_node_is_scheduled (vm, node_index))
    vlib_node_unschedule (vm, node_index);
  vlib_node_set_interrupt_pending (vm, node_index);

  vec_foreach (ep, ct->fd_events)
    if (ep->fd == e.fd && ep->is_read == e.is_read)
      return 0;

  vec_add1 (ct->fd_events, e);

  return 0;
}

static clib_error_t *
click_fd_write_fn (clib_file_t *f)
{
  vlib_main_t *vm = vlib_get_main ();
  click_main_t *cm = &click_main;
  click_instance_t *ci = pool_elt_at_index (cm->instances, f->private_data);
  click_thread_t *ct = vec_elt_at_index (ci->threads, vm->thread_index);
  u32 node_index = ci->input_node_index;
  vppclick_fd_event_t *ep, e = {
    .is_write = 1,
    .fd = (int) f->file_descriptor,
  };

  fformat (stderr, "click_fd_write: %d\n", f->file_descriptor);

  if (vlib_node_is_scheduled (vm, node_index))
    vlib_node_unschedule (vm, node_index);
  vlib_node_set_interrupt_pending (vm, node_index);

  vec_foreach (ep, ct->fd_events)
    if (ep->fd == e.fd && ep->is_write == e.is_write)
      return 0;

  vec_add1 (ct->fd_events, e);

  return 0;
}

void
click_register_fd (u32 inst_index, int fd, bool read, bool write,
		   const char *desc)
{
  vlib_main_t *vm = vlib_get_main ();

  clib_file_add (&file_main, &(clib_file_t){
			       .file_descriptor = fd,
			       .description = format (0, "click: %s", desc),
			       .read_function = read ? click_fd_read_fn : 0,
			       .write_function = write ? click_fd_write_fn : 0,
			       .polling_thread_index = vm->thread_index,
			       .private_data = inst_index,
			     });

  fformat (stderr, "%s[%u]: fd %d read %d write %d desc '%s'\n", __func__,
	   vm->thread_index, fd, read, write, desc);
}

void
click_get_fd_events (u32 inst_index, vppclick_fd_events_t *events)
{
  vlib_main_t *vm = vlib_get_main ();
  click_main_t *cm = &click_main;
  click_instance_t *ci = pool_elt_at_index (cm->instances, inst_index);
  click_thread_t *ct = vec_elt_at_index (ci->threads, vm->thread_index);

  events->n_events = vec_len (ct->fd_events);
  events->events = ct->fd_events;
  vec_reset_length (ct->fd_events);
}
