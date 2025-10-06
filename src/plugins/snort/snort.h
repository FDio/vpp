/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2021 Cisco Systems, Inc.
 * Copyright(c) 2024 Arm Limited
 */

#ifndef __snort_snort_h__
#define __snort_snort_h__

#include <vppinfra/error.h>
#include <vppinfra/socket.h>
#include <vppinfra/file.h>
#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <snort/export.h>
#include <snort/daq_vpp_shared.h>

#define SNORT_INVALID_CLIENT_INDEX CLIB_U32_MAX

STATIC_ASSERT (VNET_BUFFER_OPAQUE_SIZE >= sizeof (daq_vpp_pkt_metadata_t),
	       "metadata must fit into vnet buffer opaque");

typedef struct
{
  u32 buffer_index;
  u16 next_index;
  daq_vpp_desc_index_t freelist_next;
} snort_qpair_entry_t;

typedef struct
{
  daq_vpp_qpair_header_t *hdr;
  daq_vpp_desc_index_t *enq_ring;
  daq_vpp_desc_index_t *deq_ring;
  daq_vpp_desc_index_t *ebuf_ring;
  int enq_fd, deq_fd;
  u32 client_index;
  daq_vpp_desc_index_t next_free_desc;
  u16 n_free_descs;
  daq_vpp_head_tail_t deq_tail;
  daq_vpp_head_tail_t ebuf_tail;
  u8 log2_queue_size;
  u8 log2_ebuf_queue_size;
  u8 cleanup_needed;
  daq_vpp_qpair_id_t qpair_id;
  u32 deq_fd_file_index;
  u32 dequeue_node_index;
  u64 n_packets_by_verdict[DAQ_VPP_MAX_DAQ_VERDICT];
  snort_qpair_entry_t entries[];
} snort_qpair_t;

typedef struct
{
  snort_instance_index_t index;
  u8 drop_bitmap;
  u8 drop_on_disconnect;
  u32 dequeue_node_index;
  void *shm_base;
  u32 shm_size;
  int shm_fd;
  snort_qpair_t **qpairs;
  u8 *name;
  vnet_hash_fn_t ip4_hash_fn;
  u16 ip4_input_dequeue_node_next_index;
  u16 ip4_output_dequeue_node_next_index;
  u16 qpairs_per_thread;
} snort_instance_t;

typedef struct
{
  daq_vpp_msg_reply_t msg;
  int fds[2];
  int n_fds;
} snort_client_msg_queue_elt;

typedef struct
{
  u32 instance_index;
  u32 qpair_index;
} snort_client_qpair_t;

typedef struct
{
  clib_socket_t socket;
  u32 file_index;
  u32 daq_version;
  u16 n_instances;
  u8 mode;
  snort_client_msg_queue_elt *msg_queue;
  snort_client_qpair_t *qpairs;
} snort_client_t;

typedef struct
{
  u16 instance_index;
  u16 is_deleted;
} snort_deq_runtime_data_t;

typedef struct
{
  u32 dequeue_node_index;
} snort_deleted_deq_node_t;

typedef struct
{
  clib_socket_t *listener;
  snort_client_t *clients;
  snort_instance_t *instances;
  snort_deleted_deq_node_t *snort_deleted_deq_nodes;
  uword *instance_by_name;
  u16 *input_instance_by_interface;
  u16 *output_instance_by_interface;
  u8 **buffer_pool_base_addrs;
  u8 *socket_name;
  /* API message ID base */
  u16 msg_id_base;
} snort_main_t;

extern snort_main_t snort_main;

typedef enum
{
  SNORT_ENQ_NEXT_DROP,
  SNORT_ENQ_N_NEXT_NODES,
} snort_enq_next_t;

#define SNORT_ENQ_NEXT_NODES                                                  \
  {                                                                           \
    [SNORT_ENQ_NEXT_DROP] = "error-drop",                                     \
  }

/* functions */
snort_main_t *snort_get_main ();

/* interface.c */
int snort_interface_enable_disable (vlib_main_t *vm, char *instance_name,
				    u32 sw_if_index, int is_enable, int in,
				    int out);
int snort_interface_disable_all (vlib_main_t *vm, u32 sw_if_index);
int snort_strip_instance_interfaces (vlib_main_t *vm,
				     snort_instance_t *instance);

/* socket.c */
int snort_client_disconnect (vlib_main_t *vm, u32 client_index);
clib_error_t *snort_listener_init ();

/* format.c */
format_function_t format_snort_enq_trace;
format_function_t format_snort_arc_input_trace;
format_function_t format_snort_arc_next_trace;
format_function_t format_snort_deq_trace;
format_function_t format_snort_daq_version;
format_function_t format_snort_verdict;
format_function_t format_snort_mode;
format_function_t format_snort_desc_flags;

/* enqueue.c */
typedef struct
{
  u32 next_index;
  u32 sw_if_index;
  u16 instance;
  daq_vpp_qpair_id_t qpair_id;
  daq_vpp_desc_t desc;
} snort_enq_trace_t;

typedef struct
{
  u32 sw_if_index;
  u16 instance;
} snort_arc_input_trace_t;

#define foreach_snort_enq_error                                               \
  _ (SOCKET_ERROR, "write socket error")                                      \
  _ (NO_CLIENT, "no snort client attached")                                   \
  _ (NO_ENQ_SLOTS, "no enqueue slots (packet dropped)")

typedef enum
{
#define _(sym, str) SNORT_ENQ_ERROR_##sym,
  foreach_snort_enq_error
#undef _
    SNORT_ENQ_N_ERROR,
} snort_enq_error_t;

/* dequeue.c */
typedef struct
{
  u32 next_index;
  u32 sw_if_index;
  u32 buffer_index;
  u8 verdict;
} snort_deq_trace_t;

typedef struct
{
  u32 buffer_index;
  u32 next_index;
} snort_arc_next_trace_t;

#define foreach_snort_deq_error                                               \
  _ (BAD_DESC, "bad descriptor")                                              \
  _ (BAD_DESC_INDEX, "bad descriptor index")                                  \
  _ (NO_CLIENT_FREE, "packets freed on client dissapear")

typedef enum
{
#define _(sym, str) SNORT_DEQ_ERROR_##sym,
  foreach_snort_deq_error
#undef _
    SNORT_DEQ_N_ERROR,
} snort_deq_error_t;

/* inlines */
always_inline void
snort_qpair_init (snort_qpair_t *qp)
{
  u16 qsz = 1 << qp->log2_queue_size;
  u16 mask = qsz - 1;
  for (int j = 0; j < qsz; j++)
    {
      qp->entries[j].freelist_next = (j + 1) & mask;
      qp->hdr->descs[j].flags = DAQ_VPP_DESC_FLAG_FREE;
      qp->entries[j].buffer_index = VLIB_BUFFER_INVALID_INDEX;
    }
  qp->next_free_desc = 0;
  qp->hdr->enq.head = qp->hdr->deq.head = 0;
  qp->hdr->enq.interrupt_pending = qp->hdr->deq.interrupt_pending = 0;
  qp->deq_tail = 0;
  qp->hdr->ebuf.head = 0;
  qp->hdr->ebuf.interrupt_pending = 0;
  qp->ebuf_tail = 0;
  qp->n_free_descs = qsz;
}

static_always_inline snort_qpair_t **
snort_get_qpairs (snort_instance_t *si, clib_thread_index_t thread_index)
{
  return si->qpairs + (uword) thread_index * si->qpairs_per_thread;
}

static_always_inline snort_instance_t *
snort_get_instance_by_name (char *name)
{
  snort_main_t *sm = &snort_main;
  uword *p;
  if ((p = hash_get_mem (sm->instance_by_name, name)) == 0)
    return 0;

  return vec_elt_at_index (sm->instances, p[0]);
}

static_always_inline snort_instance_t *
snort_get_instance_by_index (u32 instance_index)
{
  snort_main_t *sm = &snort_main;

  if (pool_is_free_index (sm->instances, instance_index))
    return 0;
  return pool_elt_at_index (sm->instances, instance_index);
}

static_always_inline daq_vpp_pkt_metadata_t *
snort_get_buffer_metadata (vlib_buffer_t *b)
{
  return vnet_buffer_get_opaque (b);
}

#define log_debug(fmt, ...)                                                   \
  vlib_log_debug (snort_log.class, "%s: " fmt, __func__, __VA_ARGS__)
#define log_err(fmt, ...) vlib_log_err (snort_log.class, fmt, __VA_ARGS__)

#endif /* __snort_snort_h__ */
