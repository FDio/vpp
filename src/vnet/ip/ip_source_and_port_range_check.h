/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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

#ifndef included_ip_ip_source_and_port_range_check_h
#define included_ip_ip_source_and_port_range_check_h


typedef struct
{
  /* convenience */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
} source_range_check_main_t;

extern source_range_check_main_t source_range_check_main;

typedef enum
{
  IP_SOURCE_AND_PORT_RANGE_CHECK_PROTOCOL_TCP_OUT,
  IP_SOURCE_AND_PORT_RANGE_CHECK_PROTOCOL_UDP_OUT,
  IP_SOURCE_AND_PORT_RANGE_CHECK_PROTOCOL_TCP_IN,
  IP_SOURCE_AND_PORT_RANGE_CHECK_PROTOCOL_UDP_IN,
  IP_SOURCE_AND_PORT_RANGE_CHECK_N_PROTOCOLS,
} ip_source_and_port_range_check_protocol_t;

typedef struct
{
  u32 fib_index[IP_SOURCE_AND_PORT_RANGE_CHECK_N_PROTOCOLS];
} ip_source_and_port_range_check_config_t;

#define IP_SOURCE_AND_PORT_RANGE_CHECK_RANGE_LIMIT VLIB_BUFFER_PRE_DATA_SIZE/(2*sizeof(u16x8));

typedef struct
{
  union
  {
    u16x8 as_u16x8;
    u16 as_u16[8];
  };
} u16x8vec_t;

typedef struct
{
  u16x8vec_t low;
  u16x8vec_t hi;
} protocol_port_range_t;

/**
 * @brief The number of supported ranges per-data path object.
 * If more ranges are required, bump this number.
 */
#define N_PORT_RANGES_PER_DPO  64
#define N_RANGES_PER_BLOCK (sizeof(u16x8vec_t)/2)
#define N_BLOCKS_PER_DPO (N_PORT_RANGES_PER_DPO/N_RANGES_PER_BLOCK)

/**
 * @brief
 *  The object that is in the data-path to perform the check.
 *
 * Some trade-offs here; memory vs performance.
 *
 * performance:
 *  the principle factor is d-cache line misses/hits.
 *  so we want the data layout to minimise the d-cache misses. This
 *  means not following dependent reads. i.e. not doing
 *
 *   struct B {
 *     u16 n_ranges;
 *     range_t *ragnes; // vector of ranges.
 *   }
 *
 *   so to read ranges[0] we would first d-cache miss on the address
 *   of the object of type B, for which we would need to wait before we
 *   can get the address of B->ranges.
 *   So this layout is better:
 *
 *  struct B {
 *    u16 n_ranges;
 *    range_t ragnes[N];
 *  }
 *
 * memory:
 *  the latter layout above is more memory hungry. And N needs to be:
 *   1 - sized for the maximum required
 *   2 - fixed, so that objects of type B can be pool allocated and so
 *       'get'-able using an index.
 *       An option over fixed might be to allocate contiguous chunk from
 *       the pool (like we used to do for multi-path adjs).
 */
typedef struct protocol_port_range_dpo_t_
{
  /**
   * The number of blocks from the 'block' array below
   * that have rnages configured. We keep this count so that in the data-path
   * we can limit the loop to be only over the blocks we need
   */
  u16 n_used_blocks;

  /**
   * The total number of free ranges from all blocks.
   * Used to prevent overrun of the ranges available.
   */
  u16 n_free_ranges;

  /**
   * the fixed size array of ranges
   */
  protocol_port_range_t blocks[N_BLOCKS_PER_DPO];
} protocol_port_range_dpo_t;

int ip4_source_and_port_range_check_add_del (ip4_address_t * address,
					     u32 length,
					     u32 vrf_id,
					     u16 * low_ports,
					     u16 * hi_ports, int is_add);

// This will be moved to another file in another patch -- for API freeze
int ip6_source_and_port_range_check_add_del (ip6_address_t * address,
					     u32 length,
					     u32 vrf_id,
					     u16 * low_ports,
					     u16 * hi_ports, int is_add);

int set_ip_source_and_port_range_check (vlib_main_t * vm,
					u32 * fib_index,
					u32 sw_if_index, u32 is_add);

#endif /* included ip_source_and_port_range_check_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
