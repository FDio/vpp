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
#include <cdp/cdp.h>

cdp_main_t cdp_main;

#define DEBUG_TLV_DUMP 0	/* 1=> dump TLV's to stdout while processing them */

/*
 * ported from an unspecified Cisco cdp implementation.
 * Compute / return in HOST byte order. 0 => good checksum.
 */
u16
cdp_checksum (void *p, int count)
{
  u32 sum;
  u16 i, *data;

  data = p;
  sum = 0;
  while (count > 1)
    {
      sum += ntohs (*data);
      data++;
      count -= 2;
    }

  if (count > 0)
    sum += *(char *) data;

  while (sum >> 16)
    {
      sum = (sum & 0xFFFF) + (sum >> 16);
    }

  i = (i16) sum;
  return (~i);
}

/* TLV handler table */
typedef struct
{
  char *name;
  u32 tlv_id;
  void *format;
  void *process;
} tlv_handler_t;

static tlv_handler_t tlv_handlers[];

/* Display a generic TLV as a set of hex bytes */
static u8 *
format_generic_tlv (u8 * s, va_list * va)
{
  cdp_tlv_t *t = va_arg (*va, cdp_tlv_t *);
  tlv_handler_t *h = &tlv_handlers[t->t];

  s = format (s, "%s(%d): %U\n", h->name,
	      t->t, format_hex_bytes, t->v, t->l - sizeof (*t));
  return s;
}

/* Ignore / skip a TLV we don't support */
static cdp_error_t
process_generic_tlv (cdp_main_t * cm, cdp_neighbor_t * n, cdp_tlv_t * t)
{
#if DEBUG_TLV_DUMP > 0
  fformat (stdout, "%U", format_generic_tlv, t);
#endif

  return CDP_ERROR_NONE;
}

/* print a text tlv */
static u8 *
format_text_tlv (u8 * s, va_list * va)
{
  cdp_tlv_t *t = va_arg (*va, cdp_tlv_t *);
  tlv_handler_t *h = &tlv_handlers[t->t];
  int i;

  s = format (s, "%s(%d): ", h->name, t->t);

  for (i = 0; i < (t->l - sizeof (*t)); i++)
    vec_add1 (s, t->v[i]);

  vec_add1 (s, '\n');
  return s;
}

#if DEBUG_TLV_DUMP == 0
/* gcc warning be gone */
CLIB_UNUSED (static cdp_error_t
	     process_text_tlv (cdp_main_t * cm, cdp_neighbor_t * n,
			       cdp_tlv_t * t));
#endif

/* process / skip a generic text TLV that we don't support */
static cdp_error_t
process_text_tlv (cdp_main_t * cm, cdp_neighbor_t * n, cdp_tlv_t * t)
{
#if DEBUG_TLV_DUMP > 0
  fformat (stdout, "%U\n", format_text_tlv, t);
#endif

  return CDP_ERROR_NONE;
}

/* per-TLV format function definitions */
#define format_unused_tlv format_generic_tlv
#define format_device_name_tlv format_text_tlv
#define format_address_tlv format_generic_tlv
#define format_port_id_tlv format_text_tlv
#define format_capabilities_tlv format_generic_tlv
#define format_version_tlv format_text_tlv
#define format_platform_tlv format_text_tlv
#define format_ipprefix_tlv format_generic_tlv
#define format_hello_tlv format_generic_tlv
#define format_vtp_domain_tlv format_generic_tlv
#define format_native_vlan_tlv format_generic_tlv
#define format_duplex_tlv format_generic_tlv
#define format_appl_vlan_tlv format_generic_tlv
#define format_trigger_tlv format_generic_tlv
#define format_power_tlv format_generic_tlv
#define format_mtu_tlv format_generic_tlv
#define format_trust_tlv format_generic_tlv
#define format_cos_tlv format_generic_tlv
#define format_sysname_tlv format_generic_tlv
#define format_sysobject_tlv format_generic_tlv
#define format_mgmt_addr_tlv format_generic_tlv
#define format_physical_loc_tlv format_generic_tlv
#define format_mgmt_addr2_tlv format_generic_tlv
#define format_power_requested_tlv format_generic_tlv
#define format_power_available_tlv format_generic_tlv
#define format_port_unidirectional_tlv format_generic_tlv
#define format_unknown_28_tlv format_generic_tlv
#define format_energywise_tlv format_generic_tlv
#define format_unknown_30_tlv format_generic_tlv
#define format_spare_poe_tlv format_generic_tlv

/* tlv ID=0 is a mistake */
static cdp_error_t
process_unused_tlv (cdp_main_t * cm, cdp_neighbor_t * n, cdp_tlv_t * t)
{
  return CDP_ERROR_BAD_TLV;
}

/* list of text TLV's that we snapshoot */
#define foreach_text_to_struct_tlv              \
_(device_name,DEBUG_TLV_DUMP)                   \
_(version,DEBUG_TLV_DUMP)                       \
_(platform,DEBUG_TLV_DUMP)                      \
_(port_id,DEBUG_TLV_DUMP)

#define _(z,dbg)                                                        \
static                                                                  \
cdp_error_t process_##z##_tlv (cdp_main_t *cm, cdp_neighbor_t *n,       \
                                  cdp_tlv_t *t)                         \
{                                                                       \
    int i;                                                              \
    if (dbg)                                                            \
       fformat(stdout, "%U\n", format_text_tlv, t);                     \
                                                                        \
    if (n->z)                                                           \
        _vec_len(n->z) = 0;                                             \
                                                                        \
    for (i = 0; i < (t->l - sizeof (*t)); i++)                          \
        vec_add1(n->z, t->v[i]);                                        \
                                                                        \
    vec_add1(n->z, 0);                                                  \
                                                                        \
    return CDP_ERROR_NONE;                                              \
}

foreach_text_to_struct_tlv
#undef _
#define process_address_tlv process_generic_tlv
#define process_capabilities_tlv process_generic_tlv
#define process_ipprefix_tlv process_generic_tlv
#define process_hello_tlv process_generic_tlv
#define process_vtp_domain_tlv process_generic_tlv
#define process_native_vlan_tlv process_generic_tlv
#define process_duplex_tlv process_generic_tlv
#define process_appl_vlan_tlv process_generic_tlv
#define process_trigger_tlv process_generic_tlv
#define process_power_tlv process_generic_tlv
#define process_mtu_tlv process_generic_tlv
#define process_trust_tlv process_generic_tlv
#define process_cos_tlv process_generic_tlv
#define process_sysname_tlv process_generic_tlv
#define process_sysobject_tlv process_generic_tlv
#define process_mgmt_addr_tlv process_generic_tlv
#define process_physical_loc_tlv process_generic_tlv
#define process_mgmt_addr2_tlv process_generic_tlv
#define process_power_requested_tlv process_generic_tlv
#define process_power_available_tlv process_generic_tlv
#define process_port_unidirectional_tlv process_generic_tlv
#define process_unknown_28_tlv process_generic_tlv
#define process_energywise_tlv process_generic_tlv
#define process_unknown_30_tlv process_generic_tlv
#define process_spare_poe_tlv process_generic_tlv
static tlv_handler_t tlv_handlers[] = {
#define _(a) {#a, CDP_TLV_##a, format_##a##_tlv, process_##a##_tlv},
  foreach_cdp_tlv_type
#undef _
};

#if DEBUG_TLV_DUMP == 0
CLIB_UNUSED (static u8 * format_cdp_hdr (u8 * s, va_list * va));
#endif

static u8 *
format_cdp_hdr (u8 * s, va_list * va)
{
  cdp_hdr_t *h = va_arg (*va, cdp_hdr_t *);

  s = format (s, "version %d, ttl %d(secs), cksum 0x%04x\n",
	      h->version, h->ttl, h->checksum);
  return s;
}

static cdp_error_t
process_cdp_hdr (cdp_main_t * cm, cdp_neighbor_t * n, cdp_hdr_t * h)
{
#if DEBUG_TLV_DUMP > 0
  fformat (stdout, "%U", format_cdp_hdr, h);
#endif

  if (h->version != 1 && h->version != 2)
    return CDP_ERROR_PROTOCOL_VERSION;

  n->ttl_in_seconds = h->ttl;

  return CDP_ERROR_NONE;
}

/* scan a cdp packet; header, then tlv's */
static int
cdp_packet_scan (cdp_main_t * cm, cdp_neighbor_t * n)
{
  u8 *end, *cur = n->last_rx_pkt;
  cdp_hdr_t *h;
  cdp_tlv_t *tlv;
  cdp_error_t e = CDP_ERROR_NONE;
  tlv_handler_t *handler;
  cdp_error_t (*fp) (cdp_main_t *, cdp_neighbor_t *, cdp_tlv_t *);
  u16 computed_checksum;

  computed_checksum = cdp_checksum (cur, vec_len (cur));

  if (computed_checksum)
    return CDP_ERROR_CHECKSUM;

  h = (cdp_hdr_t *) cur;

  e = process_cdp_hdr (cm, n, h);
  if (e)
    return e;

  // there are no tlvs
  if (vec_len (n->last_rx_pkt) <= 0)
    return CDP_ERROR_BAD_TLV;

  cur = (u8 *) (h + 1);
  end = n->last_rx_pkt + vec_len (n->last_rx_pkt) - 1;

  // look ahead 4 bytes (u16 tlv->t + u16 tlv->l)
  while (cur + 3 <= end)
    {
      tlv = (cdp_tlv_t *) cur;
      tlv->t = ntohs (tlv->t);
      tlv->l = ntohs (tlv->l);

      /* tlv length includes t, l and v */
      cur += tlv->l;
      if ((cur - 1) > end)
	return CDP_ERROR_BAD_TLV;
      /*
       * Only process known TLVs. In practice, certain
       * devices send tlv->t = 0xFF, perhaps as an EOF of sorts.
       */
      if (tlv->t < ARRAY_LEN (tlv_handlers))
	{
	  handler = &tlv_handlers[tlv->t];
	  fp = handler->process;
	  e = (*fp) (cm, n, tlv);
	  if (e)
	    return e;
	}
    }

  // did not process all tlvs or none tlv processed
  if ((cur - 1) != end)
    return CDP_ERROR_BAD_TLV;

  return CDP_ERROR_NONE;
}

/*
 * cdp input routine
 */
cdp_error_t
cdp_input (vlib_main_t * vm, vlib_buffer_t * b0, u32 bi0)
{
  cdp_main_t *cm = &cdp_main;
  cdp_neighbor_t *n;
  uword *p, nbytes;
  cdp_error_t e;
  uword last_packet_signature;

  /* find or create a neighbor pool entry for the (sw) interface
     upon which we received this pkt */
  p = hash_get (cm->neighbor_by_sw_if_index,
		vnet_buffer (b0)->sw_if_index[VLIB_RX]);

  if (p == 0)
    {
      pool_get (cm->neighbors, n);
      clib_memset (n, 0, sizeof (*n));
      n->sw_if_index = vnet_buffer (b0)->sw_if_index[VLIB_RX];
      n->packet_template_index = (u8) ~ 0;
      hash_set (cm->neighbor_by_sw_if_index, n->sw_if_index,
		n - cm->neighbors);
    }
  else
    {
      n = pool_elt_at_index (cm->neighbors, p[0]);
    }

  /*
   * typical clib idiom. Don't repeatedly allocate and free
   * the per-neighbor rx buffer. Reset its apparent length to zero
   * and reuse it.
   */

  if (n->last_rx_pkt)
    _vec_len (n->last_rx_pkt) = 0;

  /* cdp disabled on this interface, we're done */
  if (n->disabled)
    return CDP_ERROR_DISABLED;

  /*
   * Make sure the per-neighbor rx buffer is big enough to hold
   * the data we're about to copy
   */
  vec_validate (n->last_rx_pkt, vlib_buffer_length_in_chain (vm, b0) - 1);

  /*
   * Coalesce / copy e the buffer chain into the per-neighbor
   * rx buffer
   */
  nbytes = vlib_buffer_contents (vm, bi0, n->last_rx_pkt);
  ASSERT (nbytes <= vec_len (n->last_rx_pkt));

  /*
   * Compute Jenkins hash of the new packet, decide if we need to
   * actually parse through the TLV's. CDP packets are all identical,
   * so unless we time out the peer, we don't need to process the packet.
   */
  last_packet_signature =
    hash_memory (n->last_rx_pkt, vec_len (n->last_rx_pkt), 0xd00b);

  if (n->last_packet_signature_valid &&
      n->last_packet_signature == last_packet_signature)
    {
      e = CDP_ERROR_CACHE_HIT;
    }
  else
    {
      /* Actually scan the packet */
      e = cdp_packet_scan (cm, n);
      n->last_packet_signature_valid = 1;
      n->last_packet_signature = last_packet_signature;
    }

  if (e == CDP_ERROR_NONE)
    {
      n->last_heard = vlib_time_now (vm);
    }

  return e;
}

/*
 * setup neighbor hash table
 */
static clib_error_t *
cdp_input_init (vlib_main_t * vm)
{
  clib_error_t *error;
  cdp_main_t *cm = &cdp_main;
  void vnet_cdp_node_reference (void);

  vnet_cdp_node_reference ();

  if ((error = vlib_call_init_function (vm, cdp_periodic_init)))
    return error;

  cm->vlib_main = vm;
  cm->vnet_main = vnet_get_main ();
  cm->neighbor_by_sw_if_index = hash_create (0, sizeof (uword));

  return 0;
}

VLIB_INIT_FUNCTION (cdp_input_init);


static u8 *
format_cdp_neighbors (u8 * s, va_list * va)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*va, vlib_main_t *);
  cdp_main_t *cm = va_arg (*va, cdp_main_t *);
  vnet_main_t *vnm = &vnet_main;
  cdp_neighbor_t *n;
  vnet_hw_interface_t *hw;

  s = format (s,
	      "%=25s %=15s %=25s %=10s\n",
	      "Our Port", "Peer System", "Peer Port", "Last Heard");

  /* *INDENT-OFF* */
  pool_foreach (n, cm->neighbors,
  ({
    hw = vnet_get_sup_hw_interface (vnm, n->sw_if_index);

    if (n->disabled == 0)
      s = format (s, "%=25s %=15s %=25s %=10.1f\n",
                  hw->name, n->device_name, n->port_id,
                  n->last_heard);
  }));
  /* *INDENT-ON* */
  return s;
}

static clib_error_t *
show_cdp (vlib_main_t * vm,
	  unformat_input_t * input, vlib_cli_command_t * cmd)
{
  cdp_main_t *cm = &cdp_main;

  if (cm->enabled == 0)
    vlib_cli_output (vm, "CDP is not enabled...");
  else
    vlib_cli_output (vm, "%U\n", format_cdp_neighbors, vm, cm);

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_cdp_command, static) = {
  .path = "show cdp",
  .short_help = "Show cdp command",
  .function = show_cdp,
};
/* *INDENT-ON* */


/*
 * packet trace format function, very similar to
 * cdp_packet_scan except that we call the per TLV format
 * functions instead of the per TLV processing functions
 */
u8 *
cdp_input_format_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  cdp_input_trace_t *t = va_arg (*args, cdp_input_trace_t *);
  u8 *cur;
  cdp_hdr_t *h;
  cdp_tlv_t *tlv;
  tlv_handler_t *handler;
  u8 *(*fp) (cdp_tlv_t *);

  cur = t->data;

  h = (cdp_hdr_t *) cur;
  s = format (s, "%U", format_cdp_hdr, h);

  cur = (u8 *) (h + 1);

  while (cur < t->data + t->len)
    {
      tlv = (cdp_tlv_t *) cur;
      tlv->t = ntohs (tlv->t);
      tlv->l = ntohs (tlv->l);
      if (tlv->t >= ARRAY_LEN (tlv_handlers))
	{
	  s = format (s, "BAD_TLV\n");
	  break;
	}
      handler = &tlv_handlers[tlv->t];
      fp = handler->format;
      s = format (s, "  %U", fp, tlv);
      /* tlv length includes (t, l) */
      cur += tlv->l;
    }

  return s;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
