/*
 *------------------------------------------------------------------
 * Copyright (c) 2021 Cisco and/or its affiliates.
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

#include <vlib/vlib.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>

#include <sys/eventfd.h>

#include <snort/daq_vpp.h>

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  u8 log2_queue_size;
  daq_vpp_desc_t *descriptors;
  volatile u32 *enq_head;
  volatile u32 *deq_head;
  volatile u32 *enq_ring;
  volatile u32 *deq_ring;
  int enq_fd, deq_fd;
  u32 *buffer_indices;
} snort_qpair_t;

typedef struct
{
  u32 index;
  clib_socket_t *client_socket;
  u32 client_index;
  void *shm_base;
  u32 shm_size;
  int shm_fd;
  snort_qpair_t *qpairs;
} snort_instance_t;

typedef struct
{
  daq_vpp_msg_t msg;
  int fds[2];
  int n_fds;
} snort_client_msg_queue_elt;

typedef struct
{
  clib_socket_t socket;
  u32 instance_index;
  u32 file_index;
  snort_client_msg_queue_elt *msg_queue;
} snort_client_t;

typedef struct
{
  clib_socket_t *listener;
  snort_client_t *clients;
  snort_instance_t *instances;
  uword *instance_by_name;
} snort_main_t;

snort_main_t snort_main;

VLIB_REGISTER_LOG_CLASS (snort_log, static) = {
  .class_name = "snort",
  .default_syslog_level = VLIB_LOG_LEVEL_DEBUG,
};

#define log_debug(fmt, ...) vlib_log_debug (snort_log.class, fmt, __VA_ARGS__)
#define log_err(fmt, ...)   vlib_log_err (snort_log.class, fmt, __VA_ARGS__)

static void
snort_client_disconnect (clib_file_t *uf)
{
  snort_main_t *sm = &snort_main;
  snort_client_t *c = pool_elt_at_index (sm->clients, uf->private_data);

  if (c->instance_index != ~0)
    {
      snort_instance_t *si =
	pool_elt_at_index (sm->instances, c->instance_index);
      si->client_index = ~0;
    }

  clib_file_del (&file_main, uf);
  clib_socket_close (&c->socket);
  pool_put (sm->clients, c);
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
  uword *p;
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

  if ((p = hash_get_mem (sm->instance_by_name, name)) == 0)
    {
      log_err ("unknown instance '%s' requested by client", name);
      snort_client_disconnect (uf);
      return 0;
    }

  si = pool_elt_at_index (sm->instances, p[0]);
  base = (u8 *) si->shm_base;

  if (si->client_index != ~0)
    {
      log_err ("client already connected to instance '%s'", name);
      snort_client_disconnect (uf);
      return 0;
    }
  si->client_index = uf->private_data;
  c->instance_index = p[0];

  log_debug ("fd_read_ready: connect instance index %u", p[0]);

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
      e->fds[0] = qp->deq_fd;
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
  s->config = DAQ_VPP_DEFAULT_SOCKET_FILE;
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
  clib_file_add (&file_main, &t);

  sm->listener = s;

  return 0;
}

static clib_error_t *
snort_instance_create (vlib_main_t *vm, char *name, u8 log2_queue_sz)
{
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  snort_main_t *sm = &snort_main;
  snort_instance_t *si;
  clib_error_t *err = 0;
  u32 index;
  u8 *base = CLIB_MEM_VM_MAP_FAILED;
  u32 size;
  int fd = -1;
  u32 qpair_mem_sz = 0;
  u32 qsz = 1 << log2_queue_sz;
  u8 align = CLIB_CACHE_LINE_BYTES;

  /* descriptor table */
  qpair_mem_sz += round_pow2 (qsz * sizeof (daq_vpp_desc_t), align);

  /* enq and deq ring */
  qpair_mem_sz += 2 * round_pow2 (qsz * sizeof (u32), align);

  /* enq and deq head pointer */
  qpair_mem_sz += 2 * round_pow2 (sizeof (u32), align);

  size = tm->n_vlib_mains * qpair_mem_sz;
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
  si->client_index = ~0;
  si->shm_base = base;
  si->shm_fd = fd;
  si->shm_size = size;
  index = si - sm->instances;
  hash_set_mem (sm->instance_by_name, name, index);

  log_debug ("instnce '%s' createed with fd %d at %p, len %u", name, fd, base,
	     size);

  vec_validate_aligned (si->qpairs, tm->n_vlib_mains - 1,
			CLIB_CACHE_LINE_BYTES);

  for (int i = 0; i < tm->n_vlib_mains; i++)
    {
      snort_qpair_t *qp = vec_elt_at_index (si->qpairs, i);
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
    }

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

static clib_error_t *
snort_init (vlib_main_t *vm)
{
  snort_main_t *sm = &snort_main;
  clib_error_t *err = 0;
  sm->instance_by_name = hash_create_string (0, sizeof (uword));
  if ((err = snort_instance_create (vm, "eno1", 10)))
    return err;
  return snort_listener_init (vm);
}

VLIB_INIT_FUNCTION (snort_init);

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "Snort",
};
