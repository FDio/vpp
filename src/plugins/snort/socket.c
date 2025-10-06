/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <vlib/file.h>
#include <snort/snort.h>
#include <vnet/vnet.h>
#include <sys/eventfd.h>

VLIB_REGISTER_LOG_CLASS (snort_log, static) = {
  .class_name = "snort",
  .subclass_name = "socket",
};

int
snort_client_disconnect (vlib_main_t *vm, u32 client_index)
{
  snort_main_t *sm = &snort_main;
  snort_client_t *c = pool_elt_at_index (sm->clients, client_index);
  snort_client_qpair_t *cqp;

  if (pool_is_free_index (sm->clients, client_index))
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  vec_foreach (cqp, c->qpairs)
    {
      snort_instance_t *si = snort_get_instance_by_index (cqp->instance_index);
      snort_qpair_t *qp = *vec_elt_at_index (si->qpairs, cqp->qpair_index);
      qp->client_index = SNORT_INVALID_CLIENT_INDEX;
      vlib_node_set_interrupt_pending (
	vlib_get_main_by_index (qp->qpair_id.thread_id),
	si->dequeue_node_index);
      __atomic_store_n (&qp->cleanup_needed, 1, __ATOMIC_RELEASE);
    }

  clib_file_del_by_index (&file_main, c->file_index);
  clib_socket_close (&c->socket);
  clib_fifo_free (c->msg_queue);
  vec_free (c->qpairs);
  pool_put (sm->clients, c);
  return 0;
}

static void
snort_msg_connect (vlib_main_t *vm, snort_client_t *c, daq_vpp_msg_req_t *req,
		   snort_client_msg_queue_elt *e)
{
  log_debug ("daq_version %U num_snort_instances %u mode %U",
	     format_snort_daq_version, req->connect.daq_version,
	     req->connect.num_snort_instances, format_snort_mode,
	     req->connect.mode);

  e->msg.connect.num_bpools = vec_len (vm->buffer_main->buffer_pools);
  c->n_instances = req->connect.num_snort_instances;
  c->daq_version = req->connect.daq_version;
  c->mode = req->connect.mode;
}

static void
snort_msg_get_buffer_pool (vlib_main_t *vm, daq_vpp_msg_req_t *req,
			   snort_client_msg_queue_elt *e)
{
  vlib_buffer_pool_t *bp;
  vlib_physmem_map_t *pm;
  daq_vpp_msg_reply_get_buffer_pool_t *r = &e->msg.get_buffer_pool;

  log_debug ("buffer_pool_index %u", req->get_buffer_pool.buffer_pool_index);

  u32 i = req->get_buffer_pool.buffer_pool_index;

  if (i >= vec_len (vm->buffer_main->buffer_pools))
    {
      e->msg.err = DAQ_VPP_ERR_INVALID_MESSAGE;
      return;
    }

  bp = vec_elt_at_index (vm->buffer_main->buffer_pools, i);
  pm = vlib_physmem_get_map (vm, bp->physmem_map_index);
  r->buffer_pool_index = i;
  r->size = pm->n_pages << pm->log2_page_size;
  e->fds[0] = pm->fd;
  e->n_fds = 1;
}

static void
snort_msg_get_input (daq_vpp_msg_req_t *req, snort_client_msg_queue_elt *e)
{
  daq_vpp_msg_reply_get_input_t *r = &e->msg.get_input;
  snort_instance_t *si;

  log_debug ("input name '%s'", req->get_input.input_name);
  si = snort_get_instance_by_name (req->get_input.input_name);

  if (!si)
    {
      e->msg.err = DAQ_VPP_ERR_UNKNOWN_INPUT;
      return;
    }

  r->input_index = si->index;
  r->shm_size = si->shm_size;
  r->num_qpairs = vec_len (si->qpairs);
  e->fds[0] = si->shm_fd;
  e->n_fds = 1;

  log_debug ("input_index %u num_qpairs %u shm_size %u fd %d", r->input_index,
	     r->num_qpairs, r->shm_size, e->fds[0]);
}

static void
snort_msg_attach_qpair (snort_client_t *c, daq_vpp_msg_req_t *req,
			snort_client_msg_queue_elt *e)
{
  snort_main_t *sm = &snort_main;
  daq_vpp_msg_reply_attach_qpair_t *r = &e->msg.attach_qpair;
  u32 instance_index = req->attach_qpair.input_index;
  u32 qpair_index = req->attach_qpair.qpair_index;
  snort_instance_t *si;
  snort_qpair_t *qp = 0;
  u8 *base;

  snort_client_qpair_t cqp = { .instance_index = instance_index,
			       .qpair_index = qpair_index };

  si = snort_get_instance_by_index (instance_index);

  if (!si)
    {
      e->msg.err = DAQ_VPP_ERR_UNKNOWN_INPUT;
      log_err ("instance %u doesn't exist", instance_index);
      return;
    }

  if (qpair_index >= vec_len (si->qpairs))
    {
      e->msg.err = DAQ_VPP_ERR_INVALID_INDEX;
      log_err ("apair with index %u on instance %s doesn't exist", qpair_index,
	       si->name);
      return;
    }

  qp = *vec_elt_at_index (si->qpairs, qpair_index);

  if (qp->client_index != SNORT_INVALID_CLIENT_INDEX)
    {
      e->msg.err = DAQ_VPP_ERR_QPAIR_IN_USE;
      log_err ("apair %u.%u is used by client %u", qp->qpair_id.thread_id,
	       qp->qpair_id.queue_id, qp->client_index);
      return;
    }

  if (qp->cleanup_needed)
    {
      e->msg.err = DAQ_VPP_ERR_QPAIR_NOT_READY;
      log_err ("apair %u.%u is not ready", qp->qpair_id.thread_id,
	       qp->qpair_id.queue_id);
      return;
    }

  qp->client_index = c - sm->clients;

  base = (u8 *) si->shm_base;
  r->qpair_id = qp->qpair_id;
  r->input_index = si->index;
  r->log2_queue_size = qp->log2_queue_size;
  r->log2_empty_buf_queue_size = qp->log2_empty_buf_queue_size;
  r->qpair_header_offset = (u8 *) qp->hdr - base;
  r->enq_ring_offset = (u8 *) qp->enq_ring - base;
  r->deq_ring_offset = (u8 *) qp->deq_ring - base;
  r->empty_buf_ring_offset = (u8 *) qp->empty_buf_ring - base;
  e->fds[0] = qp->enq_fd;
  e->fds[1] = qp->deq_fd;
  e->n_fds = 2;

  vec_add1 (c->qpairs, cqp);

  log_debug (
    "qpair_id %u.%u input_index %u log2_queue_size %u qpair_header_offset %u "
    "enq_ring_offset %u deq_ring_offset %u enq_fd %d deq_fd %d "
    "log2_empty_buf_queue_size %u empty_buf_ring_offset %u",
    r->qpair_id.thread_id, r->qpair_id.queue_id, r->input_index,
    r->log2_queue_size, r->qpair_header_offset, r->enq_ring_offset,
    r->deq_ring_offset, e->fds[0], e->fds[1], r->log2_empty_buf_queue_size,
    r->empty_buf_ring_offset);
}

static clib_error_t *
snort_conn_fd_read_ready (clib_file_t *uf)
{
  vlib_main_t *vm = vlib_get_main ();
  snort_main_t *sm = &snort_main;
  u32 client_index = uf->private_data;
  snort_client_t *c = pool_elt_at_index (sm->clients, client_index);
  snort_client_msg_queue_elt *e;
  clib_error_t *err;
  daq_vpp_msg_req_t req;

  log_debug ("fd_read_ready: client %u", uf->private_data);

  err = clib_socket_recvmsg (&c->socket, &req, sizeof (req), 0, 0);
  if (err)
    {
      log_err ("client recvmsg error: %U", format_clib_error, err);
      clib_error_free (err);
      snort_client_disconnect (vm, client_index);
      return 0;
    }

  clib_fifo_add2 (c->msg_queue, e);
  *e = (snort_client_msg_queue_elt){
    .msg.type = req.type,
    .msg.err = DAQ_VPP_OK,
  };

  switch (req.type)
    {
    case DAQ_VPP_MSG_TYPE_CONNECT:
      snort_msg_connect (vm, c, &req, e);
      break;

    case DAQ_VPP_MSG_TYPE_GET_BUFFER_POOL:
      snort_msg_get_buffer_pool (vm, &req, e);
      break;

    case DAQ_VPP_MSG_TYPE_GET_INPUT:
      snort_msg_get_input (&req, e);
      break;

    case DAQ_VPP_MSG_TYPE_ATTACH_QPAIR:
      snort_msg_attach_qpair (c, &req, e);
      break;

    default:
      e->msg.err = DAQ_VPP_ERR_INVALID_MESSAGE;
      break;
    }

  clib_file_set_data_available_to_write (&file_main, c->file_index, 1);
  return 0;
}

static clib_error_t *
snort_conn_fd_write_ready (clib_file_t *uf)
{
  snort_main_t *sm = &snort_main;
  snort_client_t *c;
  snort_client_msg_queue_elt *e;

  log_debug ("fd_write_ready: client %u", uf->private_data);

  if (pool_is_free_index (sm->clients, uf->private_data))
    {
      clib_file_set_data_available_to_write (&file_main, uf->index, 0);
      return 0;
    }

  c = pool_elt_at_index (sm->clients, uf->private_data);
  clib_fifo_sub2 (c->msg_queue, e);
  if (clib_fifo_elts (c->msg_queue) == 0)
    clib_file_set_data_available_to_write (&file_main, uf->index, 0);

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
snort_conn_fd_accept_ready (clib_file_t __clib_unused *uf)
{
  snort_main_t *sm = &snort_main;
  snort_client_t *c;
  clib_socket_t *s;
  clib_error_t *err = 0;
  clib_file_t t = { 0 };
  u32 client_index;

  pool_get_zero (sm->clients, c);
  client_index = c - sm->clients;
  s = &c->socket;

  err = clib_socket_accept (sm->listener, s);
  if (err)
    {
      log_err ("%U", format_clib_error, err);
      pool_put (sm->clients, c);
      return err;
    }

  t.read_function = snort_conn_fd_read_ready;
  t.write_function = snort_conn_fd_write_ready;
  t.error_function = snort_conn_fd_error;
  t.file_descriptor = s->fd;
  t.private_data = client_index;
  t.description = format (0, "snort client %u", client_index);
  c->file_index = clib_file_add (&file_main, &t);

  log_debug ("snort_conn_fd_accept_ready: client %u", client_index);
  return 0;
}

clib_error_t *
snort_listener_init ()
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
  s->is_server = 1;
  s->allow_group_write = 1;
  s->is_seqpacket = 1;
  s->passcred = 1;

  err = clib_socket_init (s);
  if (err)
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
