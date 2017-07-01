/*
 * Copyright (c) 2011-2016 Cisco and/or its affiliates.
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
/**
 * @file
 * @brief LLDP packet generation implementation
 */
#include <vnet/lldp/lldp_node.h>

static void
lldp_add_chassis_id (const vnet_hw_interface_t * hw, u8 ** t0p)
{
  lldp_chassis_id_tlv_t *t = (lldp_chassis_id_tlv_t *) * t0p;

  lldp_tlv_set_code ((lldp_tlv_t *) t, LLDP_TLV_NAME (chassis_id));
  t->subtype = LLDP_CHASS_ID_SUBTYPE_NAME (mac_addr);

  const size_t addr_len = 6;
  clib_memcpy (&t->id, hw->hw_address, addr_len);
  const size_t len =
    STRUCT_SIZE_OF (lldp_chassis_id_tlv_t, subtype) + addr_len;
  lldp_tlv_set_length ((lldp_tlv_t *) t, len);
  *t0p += STRUCT_SIZE_OF (lldp_tlv_t, head) + len;
}

static void
lldp_add_port_id (const vnet_hw_interface_t * hw, u8 ** t0p)
{
  lldp_port_id_tlv_t *t = (lldp_port_id_tlv_t *) * t0p;

  lldp_tlv_set_code ((lldp_tlv_t *) t, LLDP_TLV_NAME (port_id));
  t->subtype = LLDP_PORT_ID_SUBTYPE_NAME (intf_name);

  const size_t name_len = vec_len (hw->name);
  clib_memcpy (&t->id, hw->name, name_len);
  const size_t len = STRUCT_SIZE_OF (lldp_port_id_tlv_t, subtype) + name_len;
  lldp_tlv_set_length ((lldp_tlv_t *) t, len);
  *t0p += STRUCT_SIZE_OF (lldp_tlv_t, head) + len;
}

static void
lldp_add_ttl (const lldp_main_t * lm, u8 ** t0p, int shutdown)
{
  lldp_ttl_tlv_t *t = (lldp_ttl_tlv_t *) * t0p;
  lldp_tlv_set_code ((lldp_tlv_t *) t, LLDP_TLV_NAME (ttl));
  if (shutdown)
    {
      t->ttl = 0;
    }
  else
    {
      if ((size_t) lm->msg_tx_interval * lm->msg_tx_hold + 1 > (1 << 16) - 1)
	{
	  t->ttl = htons ((1 << 16) - 1);
	}
      else
	{
	  t->ttl = htons (lm->msg_tx_hold * lm->msg_tx_interval + 1);
	}
    }
  const size_t len = STRUCT_SIZE_OF (lldp_ttl_tlv_t, ttl);
  lldp_tlv_set_length ((lldp_tlv_t *) t, len);
  *t0p += STRUCT_SIZE_OF (lldp_tlv_t, head) + len;
}

static void
lldp_add_port_desc (const lldp_main_t * lm, lldp_intf_t * n, u8 ** t0p)
{
  const size_t len = vec_len (n->port_desc);
  if (len)
    {
      lldp_tlv_t *t = (lldp_tlv_t *) * t0p;
      lldp_tlv_set_code (t, LLDP_TLV_NAME (port_desc));
      lldp_tlv_set_length (t, len);
      clib_memcpy (t->v, n->port_desc, len);
      *t0p += STRUCT_SIZE_OF (lldp_tlv_t, head) + len;
    }
}

static void
lldp_add_sys_name (const lldp_main_t * lm, u8 ** t0p)
{
  const size_t len = vec_len (lm->sys_name);
  if (len)
    {
      lldp_tlv_t *t = (lldp_tlv_t *) * t0p;
      lldp_tlv_set_code (t, LLDP_TLV_NAME (sys_name));
      lldp_tlv_set_length (t, len);
      clib_memcpy (t->v, lm->sys_name, len);
      *t0p += STRUCT_SIZE_OF (lldp_tlv_t, head) + len;
    }
}

static void
lldp_add_pdu_end (u8 ** t0p)
{
  lldp_tlv_t *t = (lldp_tlv_t *) * t0p;
  lldp_tlv_set_code (t, LLDP_TLV_NAME (pdu_end));
  lldp_tlv_set_length (t, 0);
  *t0p += STRUCT_SIZE_OF (lldp_tlv_t, head);
}

static void
lldp_add_tlvs (lldp_main_t * lm, vnet_hw_interface_t * hw, u8 ** t0p,
	       int shutdown, lldp_intf_t * n)
{
  lldp_add_chassis_id (hw, t0p);
  lldp_add_port_id (hw, t0p);
  lldp_add_ttl (lm, t0p, shutdown);
  lldp_add_port_desc (lm, n, t0p);
  lldp_add_sys_name (lm, t0p);
  lldp_add_pdu_end (t0p);
}

/*
 * send a lldp pkt on an ethernet interface
 */
void
lldp_send_ethernet (lldp_main_t * lm, lldp_intf_t * n, int shutdown)
{
  u32 *to_next;
  ethernet_header_t *h0;
  vnet_hw_interface_t *hw;
  u32 bi0;
  vlib_buffer_t *b0;
  u8 *t0;
  vlib_frame_t *f;
  vlib_main_t *vm = lm->vlib_main;
  vnet_main_t *vnm = lm->vnet_main;

  /*
   * see lldp_template_init() to understand what's already painted
   * into the buffer by the packet template mechanism
   */
  h0 = vlib_packet_template_get_packet (vm, &lm->packet_template, &bi0);

  /* Add the interface's ethernet source address */
  hw = vnet_get_hw_interface (vnm, n->hw_if_index);

  clib_memcpy (h0->src_address, hw->hw_address, vec_len (hw->hw_address));

  u8 *data = ((u8 *) h0) + sizeof (*h0);
  t0 = data;

  /* add TLVs */
  lldp_add_tlvs (lm, hw, &t0, shutdown, n);

  /* Set the outbound packet length */
  b0 = vlib_get_buffer (vm, bi0);
  b0->current_length = sizeof (*h0) + t0 - data;

  /* And the outbound interface */
  vnet_buffer (b0)->sw_if_index[VLIB_TX] = hw->sw_if_index;

  /* And output the packet on the correct interface */
  f = vlib_get_frame_to_node (vm, hw->output_node_index);
  to_next = vlib_frame_vector_args (f);
  to_next[0] = bi0;
  f->n_vectors = 1;

  vlib_put_frame_to_node (vm, hw->output_node_index, f);
  n->last_sent = vlib_time_now (vm);
}

void
lldp_delete_intf (lldp_main_t * lm, lldp_intf_t * n)
{
  if (n)
    {
      lldp_unschedule_intf (lm, n);
      hash_unset (lm->intf_by_hw_if_index, n->hw_if_index);
      vec_free (n->chassis_id);
      vec_free (n->port_id);
      vec_free (n->port_desc);
      pool_put (lm->intfs, n);
    }
}

static clib_error_t *
lldp_template_init (vlib_main_t * vm)
{
  lldp_main_t *lm = &lldp_main;

  /* Create the ethernet lldp packet template */
  {
    ethernet_header_t h;

    memset (&h, 0, sizeof (h));

    /*
     * Send to 01:80:C2:00:00:0E - propagation constrained to a single
     * physical link - stopped by all type of bridge
     */
    h.dst_address[0] = 0x01;
    h.dst_address[1] = 0x80;
    h.dst_address[2] = 0xC2;
    /* h.dst_address[3] = 0x00; (memset) */
    /* h.dst_address[4] = 0x00; (memset) */
    h.dst_address[5] = 0x0E;

    /* leave src address blank (fill in at send time) */

    h.type = htons (ETHERNET_TYPE_802_1_LLDP);

    vlib_packet_template_init (vm, &lm->packet_template,
			       /* data */ &h, sizeof (h),
			       /* alloc chunk size */ 8, "lldp-ethernet");
  }

  return 0;
}

VLIB_INIT_FUNCTION (lldp_template_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
