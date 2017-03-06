/*
 * l2_vtr.h : layer 2 vlan tag rewrite processing
 *
 * Copyright (c) 2013 Cisco and/or its affiliates.
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

#ifndef included_vnet_l2_vtr_h
#define included_vnet_l2_vtr_h

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/ethernet/packet.h>
#include <vnet/l2/l2_vtr.h>

/* VTR config options for API and CLI support */
typedef enum
{
  L2_VTR_DISABLED,
  L2_VTR_PUSH_1,
  L2_VTR_PUSH_2,
  L2_VTR_POP_1,
  L2_VTR_POP_2,
  L2_VTR_TRANSLATE_1_1,
  L2_VTR_TRANSLATE_1_2,
  L2_VTR_TRANSLATE_2_1,
  L2_VTR_TRANSLATE_2_2
} l2_vtr_op_t;

/**
 * Per-interface vlan tag rewrite configuration
 * There will be one instance of this struct for each sw_if_index
 * for both input vtr and output vtr
 */
typedef struct
{
  union
  {
    /*
     * Up to two vlan tags to push.
     * if there is only one vlan tag to push, it is in tags[1].
     */
    ethernet_vlan_header_tv_t tags[2];
    u64 raw_tags;
  };

  union
  {
    struct
    {
      u8 push_bytes;		/* number of bytes to push for up to 2 vlans (0,4,8) */
      u8 pop_bytes;		/* number of bytes to pop for up to 2 vlans (0,4,8) */
    };
    u16 push_and_pop_bytes;	/* if 0 then the feature is disabled */
  };
} vtr_config_t;


/**
 * Perform the configured tag rewrite on the packet.
 * Return 0 if ok, 1 if packet should be dropped (e.g. tried to pop
 * too many tags)
 */
always_inline u32
l2_vtr_process (vlib_buffer_t * b0, vtr_config_t * config)
{
  u64 temp_8;
  u32 temp_4;
  u8 *eth;

  eth = vlib_buffer_get_current (b0);

  /* copy the 12B dmac and smac to a temporary location */
  temp_8 = *((u64 *) eth);
  temp_4 = *((u32 *) (eth + 8));

  /* adjust for popped tags */
  eth += config->pop_bytes;

  /* if not enough tags to pop then drop packet */
  if (PREDICT_FALSE ((vnet_buffer (b0)->l2.l2_len - 12) < config->pop_bytes))
    {
      return 1;
    }

  /* copy the 2 new tags to the start of the packet  */
  *((u64 *) (eth + 12 - 8)) = config->raw_tags;

  /* TODO: set cos bits */

  /* adjust for pushed tags: */
  eth -= config->push_bytes;

  /* copy the 12 dmac and smac back to the packet */
  *((u64 *) eth) = temp_8;
  *((u32 *) (eth + 8)) = temp_4;

  /* Update l2_len */
  vnet_buffer (b0)->l2.l2_len +=
    (word) config->push_bytes - (word) config->pop_bytes;

  /* Update vlan tag count */
  ethernet_buffer_adjust_vlan_count_by_bytes (b0,
					      (word) config->push_bytes -
					      (word) config->pop_bytes);

  /* Update packet len */
  vlib_buffer_advance (b0,
		       (word) config->pop_bytes - (word) config->push_bytes);

  return 0;
}


/*
 *  Perform the egress pre-vlan tag rewrite EFP Filter check.
 * The post-vlan tag rewrite check is a separate graph node.
 *
 *  This check insures that a packet being output to an interface
 * (before output vtr is performed) has vlan tags that match those
 * on a packet received from that interface (after vtr has been performed).
 * This means verifying that any tags pushed by input vtr are present
 * on the packet.
 *
 *  Return 0 if ok, 1 if packet should be dropped.
 * This function should be passed the input vtr config for the interface.
 */
always_inline u8
l2_efp_filter_process (vlib_buffer_t * b0, vtr_config_t * in_config)
{
  u8 *eth;
  u64 packet_tags;
  u64 tag_mask;

  eth = vlib_buffer_get_current (b0);

  /*
   * If there are 2 tags pushed, they must match config->tags[0] and
   * config->tags[1].
   * If there is one tag pushed, it must match config->tag[1].
   * If there are 0 tags pushed, the check passes.
   */

  /* mask for two vlan id and ethertypes, no cos bits */
  tag_mask = clib_net_to_host_u64 (0xFFFF0FFFFFFF0FFF);
  /* mask for one vlan id and ethertype, no cos bits */
  tag_mask =
    (in_config->push_bytes ==
     4) ? clib_net_to_host_u64 (0xFFFF0FFF) : tag_mask;
  /* mask for always match */
  tag_mask = (in_config->push_bytes == 0) ? 0 : tag_mask;

  /*
   * Read 8B from the packet, getting the proper set of vlan tags
   * For 0 push bytes, the address doesn't matter since the mask
   * clears the data to 0.
   */
  packet_tags = *((u64 *) (eth + 4 + in_config->push_bytes));

  /* Check if the packet tags match the configured tags */
  return (packet_tags & tag_mask) != in_config->raw_tags;
}

typedef struct
{
  union
  {
    ethernet_pbb_header_t macs_tags;
    struct
    {
      u64 data1;
      u64 data2;
      u16 data3;
      u32 data4;
    } raw_data;
  };
  union
  {
    struct
    {
      u8 push_bytes;		/* number of bytes to push pbb tags */
      u8 pop_bytes;		/* number of bytes to pop pbb tags */
    };
    u16 push_and_pop_bytes;	/* if 0 then the feature is disabled */
  };
} ptr_config_t;

always_inline u32
l2_pbb_process (vlib_buffer_t * b0, ptr_config_t * config)
{
  u8 *eth = vlib_buffer_get_current (b0);

  if (config->pop_bytes > 0)
    {
      ethernet_pbb_header_packed_t *ph = (ethernet_pbb_header_packed_t *) eth;

      // drop packet without PBB header or with wrong I-tag or B-tag
      if (clib_net_to_host_u16 (ph->priority_dei_id) !=
	  clib_net_to_host_u16 (config->macs_tags.priority_dei_id)
	  || clib_net_to_host_u32 (ph->priority_dei_uca_res_sid) !=
	  clib_net_to_host_u32 (config->macs_tags.priority_dei_uca_res_sid))
	return 1;

      eth += config->pop_bytes;
    }

  if (config->push_bytes > 0)
    {
      eth -= config->push_bytes;
      // copy the B-DA (6B), B-SA (6B), B-TAG (4B), I-TAG (6B)
      *((u64 *) eth) = config->raw_data.data1;
      *((u64 *) (eth + 8)) = config->raw_data.data2;
      *((u16 *) (eth + 16)) = config->raw_data.data3;
      *((u32 *) (eth + 18)) = config->raw_data.data4;
    }

  /* Update l2_len */
  vnet_buffer (b0)->l2.l2_len +=
    (word) config->push_bytes - (word) config->pop_bytes;
  /* Update packet len */
  vlib_buffer_advance (b0,
		       (word) config->pop_bytes - (word) config->push_bytes);

  return 0;
}

u32 l2pbb_configure (vlib_main_t * vlib_main,
		     vnet_main_t * vnet_main, u32 sw_if_index, u32 vtr_op,
		     u8 * b_dmac, u8 * b_smac,
		     u16 b_vlanid, u32 i_sid, u16 vlan_outer_tag);

/**
 * Configure vtag tag rewrite on the given interface.
 * Return 1 if there is an error, 0 if ok
 */
u32 l2vtr_configure (vlib_main_t * vlib_main,
		     vnet_main_t * vnet_main,
		     u32 sw_if_index,
		     u32 vtr_op, u32 push_dot1q, u32 vtr_tag1, u32 vtr_tag2);

/**
 * Get vtag tag rewrite on the given interface.
 * Return 1 if there is an error, 0 if ok
 */
u32 l2vtr_get (vlib_main_t * vlib_main,
	       vnet_main_t * vnet_main,
	       u32 sw_if_index,
	       u32 * vtr_op,
	       u32 * push_dot1q, u32 * vtr_tag1, u32 * vtr_tag2);

/**
 * Get pbb tag rewrite on the given interface.
 * Return 1 if there is an error, 0 if ok
 */
u32 l2pbb_get (vlib_main_t * vlib_main,
	       vnet_main_t * vnet_main,
	       u32 sw_if_index,
	       u32 * vtr_op,
	       u16 * outer_tag,
	       ethernet_header_t * eth_hdr, u16 * b_vlanid, u32 * i_sid);

#endif /* included_vnet_l2_vtr_h */


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
