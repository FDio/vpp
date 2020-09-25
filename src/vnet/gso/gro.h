/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
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
 */

#ifndef included_gro_h
#define included_gro_h

#include <vlib/vlib.h>
#include <vppinfra/error.h>
#include <vnet/ip/ip46_address.h>

#define GRO_FLOW_TABLE_MAX_SIZE 16
#define GRO_FLOW_TABLE_FLUSH 1e-5
#define GRO_FLOW_N_BUFFERS 64
#define GRO_FLOW_TIMEOUT 1e-5	/* 10 micro-seconds */
#define GRO_TO_VECTOR_SIZE(X)   (X + GRO_FLOW_TABLE_MAX_SIZE)

typedef union
{
  struct
  {
    u32 sw_if_index[VLIB_N_RX_TX];
    ip46_address_t src_address;
    ip46_address_t dst_address;
    u16 src_port;
    u16 dst_port;
  };

  u64 flow_data[5];
  u32 flow_data_u32;
} gro_flow_key_t;

typedef struct
{
  gro_flow_key_t flow_key;
  f64 next_timeout_ts;
  u32 last_ack_number;
  u32 buffer_index;
  u16 n_buffers;
} gro_flow_t;

typedef struct
{
  f64 timeout_ts;
  u64 total_vectors;
  u32 n_vectors;
  u32 node_index;
  u8 is_enable;
  u8 is_l2;
  u8 flow_table_size;
  gro_flow_t gro_flow[GRO_FLOW_TABLE_MAX_SIZE];
} gro_flow_table_t;

static_always_inline void
gro_flow_set_flow_key (gro_flow_t * to, gro_flow_key_t * from)
{
  to->flow_key.flow_data[0] = from->flow_data[0];
  to->flow_key.flow_data[1] = from->flow_data[1];
  to->flow_key.flow_data[2] = from->flow_data[2];
  to->flow_key.flow_data[3] = from->flow_data[3];
  to->flow_key.flow_data[4] = from->flow_data[4];
  to->flow_key.flow_data_u32 = from->flow_data_u32;
}

static_always_inline u8
gro_flow_is_equal (gro_flow_key_t * first, gro_flow_key_t * second)
{
  if (first->flow_data[0] == second->flow_data[0] &&
      first->flow_data[1] == second->flow_data[1] &&
      first->flow_data[2] == second->flow_data[2] &&
      first->flow_data[3] == second->flow_data[3] &&
      first->flow_data[4] == second->flow_data[4] &&
      first->flow_data_u32 == second->flow_data_u32)
    return 1;

  return 0;
}

/**
 * timeout_expire is in between 3 to 10 microseconds
 * 3e-6 1e-5
 */
static_always_inline void
gro_flow_set_timeout (vlib_main_t * vm, gro_flow_t * gro_flow,
		      f64 timeout_expire)
{
  gro_flow->next_timeout_ts = vlib_time_now (vm) + timeout_expire;
}

static_always_inline u8
gro_flow_is_timeout (vlib_main_t * vm, gro_flow_t * gro_flow)
{
  if (gro_flow->next_timeout_ts < vlib_time_now (vm))
    return 1;
  return 0;
}

static_always_inline void
gro_flow_store_packet (gro_flow_t * gro_flow, u32 bi0)
{
  if (gro_flow->n_buffers == 0)
    {
      gro_flow->buffer_index = bi0;
    }
  gro_flow->n_buffers++;
}

static_always_inline u32
gro_flow_table_init (gro_flow_table_t ** flow_table, u8 is_l2, u32 node_index)
{
  if (*flow_table)
    return 0;

  gro_flow_table_t *flow_table_temp = 0;
  flow_table_temp =
    (gro_flow_table_t *) clib_mem_alloc (sizeof (gro_flow_table_t));
  if (!flow_table_temp)
    return 0;
  clib_memset (flow_table_temp, 0, sizeof (gro_flow_table_t));
  flow_table_temp->node_index = node_index;
  flow_table_temp->is_enable = 1;
  flow_table_temp->is_l2 = is_l2;
  *flow_table = flow_table_temp;
  return 1;
}

static_always_inline void
gro_flow_table_set_timeout (vlib_main_t * vm, gro_flow_table_t * flow_table,
			    f64 timeout_expire)
{
  if (flow_table)
    flow_table->timeout_ts = vlib_time_now (vm) + timeout_expire;
}

static_always_inline u8
gro_flow_table_is_timeout (vlib_main_t * vm, gro_flow_table_t * flow_table)
{
  if (flow_table && (flow_table->timeout_ts < vlib_time_now (vm)))
    return 1;
  return 0;
}

static_always_inline u8
gro_flow_table_is_enable (gro_flow_table_t * flow_table)
{
  if (flow_table)
    return flow_table->is_enable;

  return 0;
}

static_always_inline void
gro_flow_table_set_is_enable (gro_flow_table_t * flow_table, u8 is_enable)
{
  if (flow_table)
    flow_table->is_enable = is_enable;
}

static_always_inline void
gro_flow_table_free (gro_flow_table_t * flow_table)
{
  if (flow_table)
    clib_mem_free (flow_table);
}

static_always_inline void
gro_flow_table_set_node_index (gro_flow_table_t * flow_table, u32 node_index)
{
  if (flow_table)
    flow_table->node_index = node_index;
}

static_always_inline gro_flow_t *
gro_flow_table_new_flow (gro_flow_table_t * flow_table)
{
  if (PREDICT_TRUE (flow_table->flow_table_size < GRO_FLOW_TABLE_MAX_SIZE))
    {
      gro_flow_t *gro_flow;
      u32 i = 0;
      while (i < GRO_FLOW_TABLE_MAX_SIZE)
	{
	  gro_flow = &flow_table->gro_flow[i];
	  if (gro_flow->n_buffers == 0)
	    {
	      flow_table->flow_table_size++;
	      return gro_flow;
	    }
	  i++;
	}
    }

  return (0);
}

static_always_inline gro_flow_t *
gro_flow_table_get_flow (gro_flow_table_t * flow_table,
			 gro_flow_key_t * flow_key)
{
  gro_flow_t *gro_flow = 0;
  u32 i = 0;
  while (i < GRO_FLOW_TABLE_MAX_SIZE)
    {
      gro_flow = &flow_table->gro_flow[i];
      if (gro_flow_is_equal (flow_key, &gro_flow->flow_key))
	return gro_flow;
      i++;
    }
  return (0);
}

static_always_inline gro_flow_t *
gro_flow_table_find_or_add_flow (gro_flow_table_t * flow_table,
				 gro_flow_key_t * flow_key)
{
  gro_flow_t *gro_flow = 0;

  gro_flow = gro_flow_table_get_flow (flow_table, flow_key);
  if (gro_flow)
    return gro_flow;

  gro_flow = gro_flow_table_new_flow (flow_table);

  if (gro_flow)
    {
      gro_flow_set_flow_key (gro_flow, flow_key);
      return gro_flow;
    }

  return (0);
}

static_always_inline void
gro_flow_table_reset_flow (gro_flow_table_t * flow_table,
			   gro_flow_t * gro_flow)
{
  if (PREDICT_TRUE (flow_table->flow_table_size > 0))
    {
      clib_memset (gro_flow, 0, sizeof (gro_flow_t));
      flow_table->flow_table_size--;
    }
}

static_always_inline u8 *
gro_flow_table_format (u8 * s, va_list * args)
{
  gro_flow_table_t *flow_table = va_arg (*args, gro_flow_table_t *);

  if (!flow_table)
    return s;

  if (flow_table->is_enable)
    s = format (s, "packet-coalesce: enable\n");
  else
    s = format (s, "packet-coalesce: disable\n");
  s =
    format (s,
	    "flow-table: size %u gro-total-vectors %lu gro-n-vectors %u",
	    flow_table->flow_table_size, flow_table->total_vectors,
	    flow_table->n_vectors);
  if (flow_table->n_vectors)
    {
      double average_rate =
	(double) flow_table->total_vectors / (double) flow_table->n_vectors;
      s = format (s, " gro-average-rate %.2f", average_rate);
    }
  else
    s = format (s, " gro-average-rate 0.00");

  return s;
}
#endif /* included_gro_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
