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
 * @brief LLDP packet parsing implementation
 */
#include <vnet/lldp/lldp_node.h>
#include <vnet/lldp/lldp_protocol.h>

lldp_tlv_code_t
lldp_tlv_get_code (const lldp_tlv_t * tlv)
{
  return tlv->head.byte1 >> 1;
}

void
lldp_tlv_set_code (lldp_tlv_t * tlv, lldp_tlv_code_t code)
{
  tlv->head.byte1 = (tlv->head.byte1 & 1) + (code << 1);
}

u16
lldp_tlv_get_length (const lldp_tlv_t * tlv)
{
  return (((u16) (tlv->head.byte1 & 1)) << 8) + tlv->head.byte2;
}

void
lldp_tlv_set_length (lldp_tlv_t * tlv, u16 length)
{
  tlv->head.byte2 = length & ((1 << 8) - 1);
  if (length > (1 << 8) - 1)
    {
      tlv->head.byte1 |= 1;
    }
  else
    {
      tlv->head.byte1 &= (1 << 8) - 2;
    }
}

lldp_main_t lldp_main;

static int
lldp_packet_scan (lldp_main_t * lm, lldp_intf_t * n, const lldp_tlv_t * pkt)
{
  lldp_error_t e = LLDP_ERROR_NONE;
  const lldp_tlv_t *tlv = pkt;

/* first check if the header fits in before extracting data from it */
#define TLV_VIOLATES_PKT_BOUNDARY(pkt, tlv)                               \
    (((((u8 *)tlv) + sizeof(lldp_tlv_t)) > ((u8 *)pkt + vec_len(pkt))) || \
     ((((u8 *)tlv) + lldp_tlv_get_length(tlv)) > ((u8 *)pkt + vec_len(pkt))))

  /* first tlv is always chassis id, followed by port id and ttl tlvs */
  if (TLV_VIOLATES_PKT_BOUNDARY (pkt, tlv) ||
      LLDP_TLV_NAME (chassis_id) != lldp_tlv_get_code (tlv))
    {
      return LLDP_ERROR_BAD_TLV;
    }

  u16 l = lldp_tlv_get_length (tlv);
  if (l < STRUCT_SIZE_OF (lldp_chassis_id_tlv_t, subtype) +
      LLDP_MIN_CHASS_ID_LEN ||
      l > STRUCT_SIZE_OF (lldp_chassis_id_tlv_t, subtype) +
      LLDP_MAX_CHASS_ID_LEN)
    {
      return LLDP_ERROR_BAD_TLV;
    }

  u8 chid_subtype = ((lldp_chassis_id_tlv_t *) tlv)->subtype;
  u8 *chid = ((lldp_chassis_id_tlv_t *) tlv)->id;
  u8 chid_len = l - STRUCT_SIZE_OF (lldp_chassis_id_tlv_t, subtype);

  tlv = (lldp_tlv_t *) ((u8 *) tlv + STRUCT_SIZE_OF (lldp_tlv_t, head) + l);

  if (TLV_VIOLATES_PKT_BOUNDARY (pkt, tlv) ||
      LLDP_TLV_NAME (port_id) != lldp_tlv_get_code (tlv))
    {
      return LLDP_ERROR_BAD_TLV;
    }
  l = lldp_tlv_get_length (tlv);
  if (l < STRUCT_SIZE_OF (lldp_port_id_tlv_t, subtype) +
      LLDP_MIN_PORT_ID_LEN ||
      l > STRUCT_SIZE_OF (lldp_chassis_id_tlv_t, subtype) +
      LLDP_MAX_PORT_ID_LEN)
    {
      return LLDP_ERROR_BAD_TLV;
    }

  u8 portid_subtype = ((lldp_port_id_tlv_t *) tlv)->subtype;
  u8 *portid = ((lldp_port_id_tlv_t *) tlv)->id;
  u8 portid_len = l - STRUCT_SIZE_OF (lldp_port_id_tlv_t, subtype);

  tlv = (lldp_tlv_t *) ((u8 *) tlv + STRUCT_SIZE_OF (lldp_tlv_t, head) + l);

  if (TLV_VIOLATES_PKT_BOUNDARY (pkt, tlv) ||
      LLDP_TLV_NAME (ttl) != lldp_tlv_get_code (tlv))
    {
      return LLDP_ERROR_BAD_TLV;
    }
  l = lldp_tlv_get_length (tlv);
  if (l != STRUCT_SIZE_OF (lldp_ttl_tlv_t, ttl))
    {
      return LLDP_ERROR_BAD_TLV;
    }
  u16 ttl = ntohs (((lldp_ttl_tlv_t *) tlv)->ttl);
  tlv = (lldp_tlv_t *) ((u8 *) tlv + STRUCT_SIZE_OF (lldp_tlv_t, head) + l);
  while (!TLV_VIOLATES_PKT_BOUNDARY (pkt, tlv) &&
	 LLDP_TLV_NAME (pdu_end) != lldp_tlv_get_code (tlv))
    {
      switch (lldp_tlv_get_code (tlv))
	{
#define F(num, type, str)         \
    case LLDP_TLV_NAME(type):     \
        /* ignore optional TLV */ \
        break;
	  foreach_lldp_optional_tlv_type (F);
#undef F
	default:
	  return LLDP_ERROR_BAD_TLV;
	}
      if (e)
	{
	  return e;
	}
      tlv = (lldp_tlv_t *) ((u8 *) tlv + STRUCT_SIZE_OF (lldp_tlv_t, head) +
			    lldp_tlv_get_length (tlv));
    }
  /* last tlv is pdu_end */
  if (TLV_VIOLATES_PKT_BOUNDARY (pkt, tlv) ||
      LLDP_TLV_NAME (pdu_end) != lldp_tlv_get_code (tlv) ||
      0 != lldp_tlv_get_length (tlv))
    {
      return LLDP_ERROR_BAD_TLV;
    }
  /* LLDP PDU validated, now store data */
  if (n->chassis_id)
    {
      _vec_len (n->chassis_id) = 0;
    }
  vec_add (n->chassis_id, chid, chid_len);
  n->chassis_id_subtype = chid_subtype;
  if (n->port_id)
    {
      _vec_len (n->port_id) = 0;
    }
  vec_add (n->port_id, portid, portid_len);
  n->port_id_subtype = portid_subtype;
  n->ttl = ttl;
  return LLDP_ERROR_NONE;
}

lldp_intf_t *
lldp_get_intf (lldp_main_t * lm, u32 hw_if_index)
{
  uword *p = hash_get (lm->intf_by_hw_if_index, hw_if_index);

  if (p)
    {
      return pool_elt_at_index (lm->intfs, p[0]);
    }
  return NULL;
}

lldp_intf_t *
lldp_create_intf (lldp_main_t * lm, u32 hw_if_index)
{

  uword *p;
  lldp_intf_t *n;
  p = hash_get (lm->intf_by_hw_if_index, hw_if_index);

  if (p == 0)
    {
      pool_get (lm->intfs, n);
      memset (n, 0, sizeof (*n));
      n->hw_if_index = hw_if_index;
      hash_set (lm->intf_by_hw_if_index, n->hw_if_index, n - lm->intfs);
    }
  else
    {
      n = pool_elt_at_index (lm->intfs, p[0]);
    }
  return n;
}

/*
 * lldp input routine
 */
lldp_error_t
lldp_input (vlib_main_t * vm, vlib_buffer_t * b0, u32 bi0)
{
  lldp_main_t *lm = &lldp_main;
  lldp_error_t e;

  /* find our interface */
  lldp_intf_t *n = lldp_get_intf (lm, vnet_buffer (b0)->sw_if_index[VLIB_RX]);

  if (!n)
    {
      /* lldp disabled on this interface, we're done */
      return LLDP_ERROR_DISABLED;
    }

  /* Actually scan the packet */
  e = lldp_packet_scan (lm, n, vlib_buffer_get_current (b0));

  if (LLDP_ERROR_NONE == e)
    {
      n->last_heard = vlib_time_now (vm);
    }

  return e;
}

/*
 * setup function
 */
static clib_error_t *
lldp_init (vlib_main_t * vm)
{
  clib_error_t *error;
  lldp_main_t *lm = &lldp_main;

  if ((error = vlib_call_init_function (vm, lldp_template_init)))
    return error;

  lm->vlib_main = vm;
  lm->vnet_main = vnet_get_main ();
  lm->msg_tx_hold = 4;		/* default value per IEEE 802.1AB-2009 */
  lm->msg_tx_interval = 30;	/* default value per IEEE 802.1AB-2009 */

  return 0;
}

VLIB_INIT_FUNCTION (lldp_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
