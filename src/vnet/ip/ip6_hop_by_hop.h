/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
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
#ifndef __included_ip6_hop_by_hop_ioam_h__
#define __included_ip6_hop_by_hop_ioam_h__

#include <vnet/ip/ip6_hop_by_hop_packet.h>
#include <vnet/ip/ip.h>


#define MAX_IP6_HBH_OPTION      256

/* To determine whether a node is decap MS bit is set */
#define IOAM_DECAP_BIT 0x80000000

#define IOAM_DEAP_ENABLED(opaque_data) (opaque_data & IOAM_DECAP_BIT)

#define IOAM_SET_DECAP(opaque_data) \
    (opaque_data |= IOAM_DECAP_BIT)

#define IOAM_MASK_DECAP_BIT(x) (x & ~IOAM_DECAP_BIT)

/*
 * Stores the run time flow data of hbh options
 */
typedef struct
{
  u32 ctx[MAX_IP6_HBH_OPTION];
  u8 flow_name[64];
} flow_data_t;

typedef struct
{
  /* The current rewrite we're using */
  u8 *rewrite;

  /* Trace data processing callback */
  void *ioam_end_of_path_cb;
  /* Configuration data */
  /* Adjacency */
  ip6_address_t adj;
#define IOAM_HBYH_ADD  0
#define IOAM_HBYH_MOD  1
#define IOAM_HBYH_POP  2
  u8 ioam_flag;
  /* time scale transform. Joy. */
  u32 unix_time_0;
  f64 vlib_time_0;


  /* Trace option */
  u8 has_trace_option;

  /* Pot option */
  u8 has_pot_option;

  /* Per Packet Counter option */
  u8 has_seqno_option;

  /* Enabling analyis of iOAM data on decap node */
  u8 has_analyse_option;

  /* Array of function pointers to ADD and POP HBH option handling routines */
  u8 options_size[MAX_IP6_HBH_OPTION];
  int (*add_options[MAX_IP6_HBH_OPTION]) (u8 * rewrite_string,
					  u8 * rewrite_size);
  int (*pop_options[MAX_IP6_HBH_OPTION]) (vlib_buffer_t * b,
					  ip6_header_t * ip,
					  ip6_hop_by_hop_option_t * opt);
  int (*get_sizeof_options[MAX_IP6_HBH_OPTION]) (u32 * rewrite_size);
  int (*config_handler[MAX_IP6_HBH_OPTION]) (void *data, u8 disable);

  /* Array of function pointers to handle hbh options being used with classifier */
    u32 (*flow_handler[MAX_IP6_HBH_OPTION]) (u32 flow_ctx, u8 add);
  flow_data_t *flows;

  /* convenience */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
} ip6_hop_by_hop_ioam_main_t;

extern ip6_hop_by_hop_ioam_main_t ip6_hop_by_hop_ioam_main;

extern clib_error_t *ip6_ioam_enable (int has_trace_option,
				      int has_pot_option,
				      int has_seqno_option,
				      int has_analyse_option);

extern int ip6_ioam_set_destination (ip6_address_t * addr, u32 mask_width,
				     u32 vrf_id, int is_add, int is_pop,
				     int is_none);

extern clib_error_t *clear_ioam_rewrite_fn (void);

static inline u8
is_zero_ip4_address (ip4_address_t * a)
{
  return (a->as_u32 == 0);
}

static inline void
copy_ip6_address (ip6_address_t * dst, ip6_address_t * src)
{
  dst->as_u64[0] = src->as_u64[0];
  dst->as_u64[1] = src->as_u64[1];
}

static inline void
set_zero_ip6_address (ip6_address_t * a)
{
  a->as_u64[0] = 0;
  a->as_u64[1] = 0;
}

static inline u8
cmp_ip6_address (ip6_address_t * a1, ip6_address_t * a2)
{
  return ((a1->as_u64[0] == a2->as_u64[0])
	  && (a1->as_u64[1] == a2->as_u64[1]));
}

static inline u8
is_zero_ip6_address (ip6_address_t * a)
{
  return ((a->as_u64[0] == 0) && (a->as_u64[1] == 0));
}

int ip6_hbh_add_register_option (u8 option,
				 u8 size,
				 int rewrite_options (u8 * rewrite_string,
						      u8 * size));
int ip6_hbh_add_unregister_option (u8 option);

int ip6_hbh_pop_register_option (u8 option,
				 int options (vlib_buffer_t * b,
					      ip6_header_t * ip,
					      ip6_hop_by_hop_option_t * opt));
int ip6_hbh_pop_unregister_option (u8 option);

int
ip6_hbh_get_sizeof_register_option (u8 option,
				    int get_sizeof_hdr_options (u32 *
								rewrite_size));

int
ip6_ioam_set_rewrite (u8 ** rwp, int has_trace_option,
		      int has_pot_option, int has_seq_no);

int
ip6_hbh_config_handler_register (u8 option,
				 int config_handler (void *data, u8 disable));

int ip6_hbh_config_handler_unregister (u8 option);

int ip6_hbh_flow_handler_register (u8 option,
				   u32 ioam_flow_handler (u32 flow_ctx,
							  u8 add));

int ip6_hbh_flow_handler_unregister (u8 option);

u8 *get_flow_name_from_flow_ctx (u32 flow_ctx);

static inline flow_data_t *
get_flow (u32 index)
{
  flow_data_t *flow = NULL;
  ip6_hop_by_hop_ioam_main_t *hm = &ip6_hop_by_hop_ioam_main;

  if (pool_is_free_index (hm->flows, index))
    return NULL;

  flow = pool_elt_at_index (hm->flows, index);
  return flow;
}

static inline u32
get_flow_data_from_flow_ctx (u32 flow_ctx, u8 option)
{
  flow_data_t *flow = NULL;
  ip6_hop_by_hop_ioam_main_t *hm = &ip6_hop_by_hop_ioam_main;
  u32 index;

  index = IOAM_MASK_DECAP_BIT (flow_ctx);
  //flow = pool_elt_at_index (hm->flows, index);
  flow = &hm->flows[index];
  return (flow->ctx[option]);
}

static inline u8
is_seqno_enabled (void)
{
  return (ip6_hop_by_hop_ioam_main.has_seqno_option);
}

int ip6_trace_profile_setup ();

static inline u32
ioam_flow_add (u8 encap, u8 * flow_name)
{
  ip6_hop_by_hop_ioam_main_t *hm = &ip6_hop_by_hop_ioam_main;
  flow_data_t *flow = 0;
  u32 index = 0;
  u8 i;

  pool_get (hm->flows, flow);
  clib_memset (flow, 0, sizeof (flow_data_t));

  index = flow - hm->flows;
  strncpy ((char *) flow->flow_name, (char *) flow_name, 31);

  if (!encap)
    IOAM_SET_DECAP (index);

  for (i = 0; i < 255; i++)
    {
      if (hm->flow_handler[i])
	flow->ctx[i] = hm->flow_handler[i] (index, 1);
    }
  return (index);
}

always_inline ip6_hop_by_hop_option_t *
ip6_hbh_get_option (ip6_hop_by_hop_header_t * hbh0, u8 option_to_search)
{
  ip6_hop_by_hop_option_t *opt0, *limit0;
  u8 type0;

  if (!hbh0)
    return NULL;

  opt0 = (ip6_hop_by_hop_option_t *) (hbh0 + 1);
  limit0 = (ip6_hop_by_hop_option_t *)
    ((u8 *) hbh0 + ((hbh0->length + 1) << 3));

  /* Scan the set of h-b-h options, process ones that we understand */
  while (opt0 < limit0)
    {
      type0 = opt0->type;
      switch (type0)
	{
	case 0:		/* Pad1 */
	  opt0 = (ip6_hop_by_hop_option_t *) ((u8 *) opt0) + 1;
	  continue;
	case 1:		/* PadN */
	  break;
	default:
	  if (type0 == option_to_search)
	    return opt0;
	  break;
	}
      opt0 =
	(ip6_hop_by_hop_option_t *) (((u8 *) opt0) + opt0->length +
				     sizeof (ip6_hop_by_hop_option_t));
    }
  return NULL;
}

#endif /* __included_ip6_hop_by_hop_ioam_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
