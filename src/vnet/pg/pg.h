/* SPDX-License-Identifier: Apache-2.0 OR MIT
 * Copyright (c) 2015 Cisco and/or its affiliates.
 * Copyright (c) 2008 Eliot Dresselhaus
 */

/* pg.h: VLIB packet generator */

#ifndef included_vlib_pg_h
#define included_vlib_pg_h

#include <vlib/vlib.h>		/* for VLIB_N_RX_TX */
#include <vnet/pg/edit.h>
#include <vppinfra/fifo.h>	/* for buffer_fifo */
#include <vppinfra/pcap.h>
#include <vnet/interface.h>
#include <vnet/ethernet/mac_address.h>
#include <vnet/gso/gro.h>

extern vnet_device_class_t pg_dev_class;

struct pg_main_t;
struct pg_stream_t;

typedef struct pg_edit_group_t
{
  /* Edits in this group. */
  pg_edit_t *edits;

  /* Vector of non-fixed edits for this group. */
  pg_edit_t *non_fixed_edits;

  /* Fixed edits for this group. */
  u8 *fixed_packet_data;
  u8 *fixed_packet_data_mask;

  /* Byte offset where packet data begins. */
  u32 start_byte_offset;

  /* Number of packet bytes for this edit group. */
  u32 n_packet_bytes;

  /* Function to perform miscellaneous edits (e.g. set IP checksum, ...). */
  void (*edit_function) (struct pg_main_t * pg,
			 struct pg_stream_t * s,
			 struct pg_edit_group_t * g,
			 u32 * buffers, u32 n_buffers);

  /* Opaque data for edit function's use. */
  uword edit_function_opaque;
} pg_edit_group_t;

/* Packets are made of multiple buffers chained together.
   This struct keeps track of data per-chain index. */
typedef struct
{
  /* Vector of buffer edits for this stream and buffer index. */
  pg_edit_t *edits;

  /* Buffers pre-initialized with fixed buffer data for this stream. */
  u32 *buffer_fifo;

} pg_buffer_index_t;

typedef struct pg_stream_t
{
  /* Stream name. */
  u8 *name;

  u32 flags;

  /* Stream is currently enabled. */
#define PG_STREAM_FLAGS_IS_ENABLED (1 << 0)

  /* Edit groups are created by each protocol level (e.g. ethernet,
     ip4, tcp, ...). */
  pg_edit_group_t *edit_groups;

  pg_edit_type_t packet_size_edit_type;

  /* Min/max packet size. */
  u32 min_packet_bytes, max_packet_bytes;

  /* Vector of non-fixed edits for this stream.
     All fixed edits are performed and placed into fixed_packet_data. */
  pg_edit_t *non_fixed_edits;

  /* Packet data with all fixed edits performed.
     All packets in stream are initialized according with this data.
     Mask specifies which bits of packet data are covered by fixed edits. */
  u8 *fixed_packet_data, *fixed_packet_data_mask;

  /* Size to use for buffers.  0 means use buffers big enough
     for max_packet_bytes. */
  u32 buffer_bytes;

  /* Buffer flags to set in each packet e.g. l2 valid  flags */
  u32 buffer_flags;

  /* GSO size to set in each packet, when buffer is gso-ed */
  u32 gso_size;

  /* Buffer offload flags to set in each packet e.g. checksum offload flags */
  u32 buffer_oflags;

  /* Last packet length if packet size edit type is increment. */
  u32 last_increment_packet_size;

  /* Index into main interface pool for this stream. */
  u32 pg_if_index;

  /* Interface used to mark packets for this stream.  May be different
     than hw/sw index from pg main interface pool.  They will be
     different if this stream is being used generate buffers as if
     they were received on a non-pg interface.  For example, suppose you
     are trying to test vlan code and you want to generate buffers that
     appear to come from an ethernet interface. */
  u32 sw_if_index[VLIB_N_RX_TX];

  /* Node where stream's buffers get put. */
  u32 node_index;

  /* Worker thread index */
  u32 worker_index;

  /* Output next index to reach output node from stream input node. */
  u32 next_index;

  u32 if_id;

  /* Number of packets currently generated. */
  u64 n_packets_generated;

  /* Stream is disabled when packet limit is reached.
     Zero means no packet limit. */
  u64 n_packets_limit;

  /* Only generate up to n_max_frame per frame. */
  u32 n_max_frame;

  /* Rate for this stream in packets/second.
     Zero means unlimited rate. */
  f64 rate_packets_per_second;

  f64 time_last_generate;

  f64 packet_accumulator;

  pg_buffer_index_t *buffer_indices;

  u8 **replay_packet_templates;
  u64 *replay_packet_timestamps;
  u32 current_replay_packet_index;
} pg_stream_t;

always_inline void
pg_free_buffers (pg_buffer_index_t *bi)
{
  vlib_main_t *vm = vlib_get_main ();
  uword n_elts, head, len;

  if (!bi || !bi->buffer_fifo)
    return;

  n_elts = clib_fifo_elts (bi->buffer_fifo);
  if (n_elts)
    {
      len = clib_fifo_len (bi->buffer_fifo);
      head = clib_fifo_head_index (bi->buffer_fifo);

      if (head + n_elts <= len)
	vlib_buffer_free (vm, &bi->buffer_fifo[head], n_elts);
      else
	{
	  vlib_buffer_free (vm, &bi->buffer_fifo[head], len - head);
	  vlib_buffer_free (vm, bi->buffer_fifo, n_elts - (len - head));
	}
    }
}

always_inline void
pg_buffer_index_free (pg_buffer_index_t *bi)
{
  if (bi)
    {
      vec_free (bi->edits);
      clib_fifo_free (bi->buffer_fifo);
    }
}

always_inline void
pg_edit_group_free (pg_edit_group_t * g)
{
  pg_edit_t *e;
  vec_foreach (e, g->edits) pg_edit_free (e);
  vec_free (g->edits);
  vec_free (g->fixed_packet_data);
  vec_free (g->fixed_packet_data_mask);
}

always_inline void
pg_stream_free (pg_stream_t * s)
{
  int i;
  pg_edit_group_t *g;
  pg_edit_t *e;
  vec_foreach (e, s->non_fixed_edits) pg_edit_free (e);
  vec_free (s->non_fixed_edits);
  vec_foreach (g, s->edit_groups) pg_edit_group_free (g);
  vec_free (s->edit_groups);
  vec_free (s->fixed_packet_data);
  vec_free (s->fixed_packet_data_mask);
  vec_free (s->name);
  for (i = 0; i < vec_len (s->replay_packet_templates); i++)
    vec_free (s->replay_packet_templates[i]);
  vec_free (s->replay_packet_templates);
  vec_free (s->replay_packet_timestamps);

  if (s->buffer_indices)
    {
      pg_buffer_index_t *bi;
      // We only need to free the buffers from the first array, as the buffers
      // are chained when packet-generator enable is issued.
      pg_free_buffers (s->buffer_indices);
      vec_foreach (bi, s->buffer_indices)
	pg_buffer_index_free (bi);
      vec_free (s->buffer_indices);
    }
}

always_inline int
pg_stream_is_enabled (pg_stream_t * s)
{
  return (s->flags & PG_STREAM_FLAGS_IS_ENABLED) != 0;
}

always_inline pg_edit_group_t *
pg_stream_get_group (pg_stream_t * s, u32 group_index)
{
  return vec_elt_at_index (s->edit_groups, group_index);
}

always_inline void *
pg_create_edit_group (pg_stream_t * s,
		      int n_edit_bytes, int n_packet_bytes, u32 * group_index)
{
  pg_edit_group_t *g;
  int n_edits;

  vec_add2 (s->edit_groups, g, 1);
  if (group_index)
    *group_index = g - s->edit_groups;

  ASSERT (n_edit_bytes % sizeof (pg_edit_t) == 0);
  n_edits = n_edit_bytes / sizeof (pg_edit_t);
  vec_resize (g->edits, n_edits);

  g->n_packet_bytes = n_packet_bytes;

  return g->edits;
}

always_inline void *
pg_add_edits (pg_stream_t * s, int n_edit_bytes, int n_packet_bytes,
	      u32 group_index)
{
  pg_edit_group_t *g = pg_stream_get_group (s, group_index);
  pg_edit_t *e;
  int n_edits;
  ASSERT (n_edit_bytes % sizeof (pg_edit_t) == 0);
  n_edits = n_edit_bytes / sizeof (pg_edit_t);
  vec_add2 (g->edits, e, n_edits);
  g->n_packet_bytes += n_packet_bytes;
  return e;
}

always_inline void *
pg_get_edit_group (pg_stream_t * s, u32 group_index)
{
  pg_edit_group_t *g = pg_stream_get_group (s, group_index);
  return g->edits;
}

/* Number of bytes for all groups >= given group. */
always_inline uword
pg_edit_group_n_bytes (pg_stream_t * s, u32 group_index)
{
  pg_edit_group_t *g;
  uword n_bytes = 0;

  for (g = s->edit_groups + group_index; g < vec_end (s->edit_groups); g++)
    n_bytes += g->n_packet_bytes;
  return n_bytes;
}

always_inline void
pg_free_edit_group (pg_stream_t * s)
{
  ASSERT (vec_len (s->edit_groups) > 0);
  uword i = vec_len (s->edit_groups) - 1;
  pg_edit_group_t *g = pg_stream_get_group (s, i);

  pg_edit_group_free (g);
  clib_memset (g, 0, sizeof (g[0]));
  vec_set_len (s->edit_groups, i);
}

#define foreach_pg_tx_func_error                                              \
  _ (GSO_PACKET_DROP, "gso disabled on itf  -- gso packet drop")              \
  _ (CSUM_OFFLOAD_PACKET_DROP,                                                \
     "checksum offload disabled on itf -- csum offload packet drop")

typedef enum
{
#define _(f, s) PG_TX_ERROR_##f,
  foreach_pg_tx_func_error
#undef _
    PG_TX_N_ERROR,
} pg_tx_func_error_t;

typedef enum pg_interface_mode_t_
{
  PG_MODE_ETHERNET,
  PG_MODE_IP4,
  PG_MODE_IP6,
} pg_interface_mode_t;

always_inline pcap_packet_type_t
pg_intf_mode_to_pcap_packet_type (pg_interface_mode_t mode)
{
  if ((mode == PG_MODE_IP4) || (mode == PG_MODE_IP6))
    return PCAP_PACKET_TYPE_ip;
  else
    return PCAP_PACKET_TYPE_ethernet;
}

#define foreach_pg_interface_flags                                            \
  _ (CSUM_OFFLOAD, 0)                                                         \
  _ (GSO, 1)                                                                  \
  _ (GRO_COALESCE, 2)

typedef enum
{
#define _(a, b) PG_INTERFACE_FLAG_##a = (1 << b),
  foreach_pg_interface_flags
#undef _
} pg_interface_flags_t;

typedef struct
{
  u32 if_id;
  pg_interface_mode_t mode;
  pg_interface_flags_t flags;
  u32 gso_size;
  mac_address_t hw_addr;
  u8 hw_addr_set;
  int rv;
} pg_interface_args_t;

typedef struct
{
  /* TX lock */
  volatile u32 *lockp;

  /* VLIB interface indices. */
  u32 hw_if_index, sw_if_index;

  /* Identifies stream for this interface. */
  u32 id;

  mac_address_t hw_addr;

  u8 coalesce_enabled;
  gro_flow_table_t *flow_table;
  u8 gso_enabled;
  u8 csum_offload_enabled;
  u32 gso_size;
  pcap_main_t pcap_main;
  char *pcap_file_name;
  pg_interface_mode_t mode;

  mac_address_t *allowed_mcast_macs;
} pg_interface_t;

typedef struct
{
  u32 hw_if_index;
  u32 id;
  mac_address_t hw_addr;
  u8 coalesce_enabled;
  u8 gso_enabled;
  u8 csum_offload_enabled;
  u32 gso_size;
  pg_interface_mode_t mode;
} pg_interface_details_t;

/* Per VLIB node data. */
typedef struct
{
  /* Parser function indexed by node index. */
  unformat_function_t *unformat_edit;
} pg_node_t;

typedef struct pg_main_t
{
  /* Pool of streams. */
  pg_stream_t *streams;

  /* Bitmap indicating which streams are currently enabled. */
  uword **enabled_streams;

  /* Hash mapping name -> stream index. */
  uword *stream_index_by_name;

  /* Pool of interfaces. */
  pg_interface_t *interfaces;
  uword *if_index_by_if_id;
  uword *if_index_by_sw_if_index;

  /* Vector of buffer indices for use in pg_stream_fill_replay, per thread */
  u32 **replay_buffers_by_thread;

  /* Per VLIB node information. */
  pg_node_t *nodes;

  u16 msg_id_base;
} pg_main_t;

/* Global main structure. */
extern pg_main_t pg_main;

/* Global node. */
extern vlib_node_registration_t pg_input_node;

/* Buffer generator input, output node functions. */
vlib_node_function_t pg_input, pg_output;

/* Stream add/delete. */
void pg_stream_del (pg_main_t * pg, uword index);
void pg_stream_add (pg_main_t * pg, pg_stream_t * s_init);
void pg_stream_change (pg_main_t * pg, pg_stream_t * s);

/* Enable/disable stream. */
void pg_stream_enable_disable (pg_main_t * pg, pg_stream_t * s,
			       int is_enable);

/* Enable/disable packet coalesce on given interface */
void pg_interface_enable_disable_coalesce (pg_interface_t * pi, u8 enable,
					   u32 tx_node_index);

/* Find/create free packet-generator interface index. */
u32 pg_interface_add_or_get (pg_main_t *pg, pg_interface_args_t *args);

int pg_interface_delete (u32 sw_if_index);
int pg_interface_details (u32 sw_if_index, pg_interface_details_t *pid);

always_inline pg_node_t *
pg_get_node (uword node_index)
{
  pg_main_t *pg = &pg_main;
  vec_validate (pg->nodes, node_index);
  return pg->nodes + node_index;
}

void pg_edit_group_get_fixed_packet_data (pg_stream_t * s,
					  u32 group_index,
					  void *fixed_packet_data,
					  void *fixed_packet_data_mask);

void pg_enable_disable (u32 stream_index, int is_enable);

typedef struct
{
  u32 hw_if_index;
  u32 dev_instance;
  u8 is_enabled;
  char *pcap_file_name;
  u32 count;
} pg_capture_args_t;

clib_error_t *pg_capture (pg_capture_args_t * a);

typedef struct
{
  pg_interface_mode_t mode;
  u32 buffer_index;
  vlib_buffer_t buffer;
}
pg_output_trace_t;

#endif /* included_vlib_pg_h */
