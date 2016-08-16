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
#include <vnet/cdp/cdp_node.h>
#include <vppinfra/hash.h>
#include <vnet/unix/pcap.h>
#include <vnet/srp/srp.h>
#include <vnet/ppp/ppp.h>
#include <vnet/hdlc/hdlc.h>
#include <vnet/srp/packet.h>

/*
 * Generate a set of specific CDP TLVs.
 *
 * $$$ eventually these need to fish better data from
 * other data structures; e.g. the hostname, software version info
 * etc.
 */

static void
add_device_name_tlv (vnet_hw_interface_t * hw, u8 ** t0p)
{
  cdp_tlv_t *t = (cdp_tlv_t *) * t0p;

  t->t = htons (CDP_TLV_device_name);
  t->l = htons (3 + sizeof (*t));
  clib_memcpy (&t->v, "VPP", 3);

  *t0p += ntohs (t->l);
}

static void
add_port_id_tlv (vnet_hw_interface_t * hw, u8 ** t0p)
{
  cdp_tlv_t *t = (cdp_tlv_t *) * t0p;

  t->t = htons (CDP_TLV_port_id);
  t->l = htons (vec_len (hw->name) + sizeof (*t));
  clib_memcpy (&t->v, hw->name, vec_len (hw->name));
  *t0p += ntohs (t->l);
}

static void
add_version_tlv (vnet_hw_interface_t * hw, u8 ** t0p)
{
  cdp_tlv_t *t = (cdp_tlv_t *) * t0p;

  t->t = htons (CDP_TLV_version);
  t->l = htons (12 + sizeof (*t));
  clib_memcpy (&t->v, "VPP Software", 12);
  *t0p += ntohs (t->l);
}

static void
add_platform_tlv (vnet_hw_interface_t * hw, u8 ** t0p)
{
  cdp_tlv_t *t = (cdp_tlv_t *) * t0p;

  t->t = htons (CDP_TLV_platform);
  t->l = htons (2 + sizeof (*t));
  clib_memcpy (&t->v, "SW", 2);
  *t0p += ntohs (t->l);
}

static void
add_capability_tlv (vnet_hw_interface_t * hw, u8 ** t0p)
{
  cdp_tlv_t *t = (cdp_tlv_t *) * t0p;
  u32 capabilities;

  t->t = htons (CDP_TLV_capabilities);
  t->l = htons (4 + sizeof (*t));
  capabilities = CDP_ROUTER_DEVICE;
  capabilities = htonl (capabilities);
  clib_memcpy (&t->v, &capabilities, sizeof (capabilities));
  *t0p += ntohs (t->l);
}

static void
add_tlvs (cdp_main_t * cm, vnet_hw_interface_t * hw, u8 ** t0p)
{
  add_device_name_tlv (hw, t0p);
  add_port_id_tlv (hw, t0p);
  add_version_tlv (hw, t0p);
  add_platform_tlv (hw, t0p);
  add_capability_tlv (hw, t0p);
}

/*
 * send a cdp pkt on an ethernet interface
 */
static void
send_ethernet_hello (cdp_main_t * cm, cdp_neighbor_t * n, int count)
{
  u32 *to_next;
  ethernet_llc_snap_and_cdp_header_t *h0;
  vnet_hw_interface_t *hw;
  u32 bi0;
  vlib_buffer_t *b0;
  u8 *t0;
  u16 checksum;
  int nbytes_to_checksum;
  int i;
  vlib_frame_t *f;
  vlib_main_t *vm = cm->vlib_main;
  vnet_main_t *vnm = cm->vnet_main;

  for (i = 0; i < count; i++)
    {
      /*
       * see cdp_periodic_init() to understand what's already painted
       * into the buffer by the packet template mechanism
       */
      h0 = vlib_packet_template_get_packet
	(vm, &cm->packet_templates[n->packet_template_index], &bi0);

      /* Add the interface's ethernet source address */
      hw = vnet_get_sup_hw_interface (vnm, n->sw_if_index);

      clib_memcpy (h0->ethernet.src_address, hw->hw_address,
		   vec_len (hw->hw_address));

      t0 = (u8 *) & h0->cdp.data;

      /* add TLVs */
      add_tlvs (cm, hw, &t0);

      /* add the cdp packet checksum */
      nbytes_to_checksum = t0 - (u8 *) & h0->cdp;
      checksum = cdp_checksum (&h0->cdp, nbytes_to_checksum);
      h0->cdp.checksum = htons (checksum);

      /* Set the outbound packet length */
      b0 = vlib_get_buffer (vm, bi0);
      b0->current_length = nbytes_to_checksum + sizeof (*h0)
	- sizeof (cdp_hdr_t);

      /* And the outbound interface */
      vnet_buffer (b0)->sw_if_index[VLIB_TX] = hw->sw_if_index;

      /* Set the 802.3 ethernet length */
      h0->ethernet.len = htons (b0->current_length
				- sizeof (ethernet_802_3_header_t));

      /* And output the packet on the correct interface */
      f = vlib_get_frame_to_node (vm, hw->output_node_index);
      to_next = vlib_frame_vector_args (f);
      to_next[0] = bi0;
      f->n_vectors = 1;

      vlib_put_frame_to_node (vm, hw->output_node_index, f);
      n->last_sent = vlib_time_now (vm);
    }
}

/*
 * send a cdp pkt on an hdlc interface
 */
static void
send_hdlc_hello (cdp_main_t * cm, cdp_neighbor_t * n, int count)
{
  u32 *to_next;
  hdlc_and_cdp_header_t *h0;
  vnet_hw_interface_t *hw;
  u32 bi0;
  vlib_buffer_t *b0;
  u8 *t0;
  u16 checksum;
  int nbytes_to_checksum;
  int i;
  vlib_frame_t *f;
  vlib_main_t *vm = cm->vlib_main;
  vnet_main_t *vnm = cm->vnet_main;

  for (i = 0; i < count; i++)
    {
      /*
       * see cdp_periodic_init() to understand what's already painted
       * into the buffer by the packet template mechanism
       */
      h0 = vlib_packet_template_get_packet
	(vm, &cm->packet_templates[n->packet_template_index], &bi0);

      hw = vnet_get_sup_hw_interface (vnm, n->sw_if_index);

      t0 = (u8 *) & h0->cdp.data;

      /* add TLVs */
      add_tlvs (cm, hw, &t0);

      /* add the cdp packet checksum */
      nbytes_to_checksum = t0 - (u8 *) & h0->cdp;
      checksum = cdp_checksum (&h0->cdp, nbytes_to_checksum);
      h0->cdp.checksum = htons (checksum);

      /* Set the outbound packet length */
      b0 = vlib_get_buffer (vm, bi0);
      b0->current_length = nbytes_to_checksum + sizeof (*h0)
	- sizeof (cdp_hdr_t);

      /* And output the packet on the correct interface */
      f = vlib_get_frame_to_node (vm, hw->output_node_index);
      to_next = vlib_frame_vector_args (f);
      to_next[0] = bi0;
      f->n_vectors = 1;

      vlib_put_frame_to_node (vm, hw->output_node_index, f);
      n->last_sent = vlib_time_now (vm);
    }
}

/*
 * send a cdp pkt on an srp interface
 */
static void
send_srp_hello (cdp_main_t * cm, cdp_neighbor_t * n, int count)
{
  u32 *to_next;
  srp_and_cdp_header_t *h0;
  vnet_hw_interface_t *hw;
  u32 bi0;
  vlib_buffer_t *b0;
  u8 *t0;
  u16 checksum;
  int nbytes_to_checksum;
  int i;
  vlib_frame_t *f;
  vlib_main_t *vm = cm->vlib_main;
  vnet_main_t *vnm = cm->vnet_main;

  for (i = 0; i < count; i++)
    {
      /*
       * see cdp_periodic_init() to understand what's already painted
       * into the buffer by the packet template mechanism
       */
      h0 = vlib_packet_template_get_packet
	(vm, &cm->packet_templates[n->packet_template_index], &bi0);

      hw = vnet_get_sup_hw_interface (vnm, n->sw_if_index);

      t0 = (u8 *) & h0->cdp.data;

      /* add TLVs */
      add_tlvs (cm, hw, &t0);

      /* Add the interface's ethernet source address */
      clib_memcpy (h0->ethernet.src_address, hw->hw_address,
		   vec_len (hw->hw_address));

      /* add the cdp packet checksum */
      nbytes_to_checksum = t0 - (u8 *) & h0->cdp;
      checksum = cdp_checksum (&h0->cdp, nbytes_to_checksum);
      h0->cdp.checksum = htons (checksum);

      /* Set the outbound packet length */
      b0 = vlib_get_buffer (vm, bi0);
      b0->current_length = nbytes_to_checksum + sizeof (*h0)
	- sizeof (cdp_hdr_t);

      /* And output the packet on the correct interface */
      f = vlib_get_frame_to_node (vm, hw->output_node_index);
      to_next = vlib_frame_vector_args (f);
      to_next[0] = bi0;
      f->n_vectors = 1;

      vlib_put_frame_to_node (vm, hw->output_node_index, f);
      n->last_sent = vlib_time_now (vm);
    }
}

/*
 * Decide which cdp packet template to use
 */
static int
pick_packet_template (cdp_main_t * cm, cdp_neighbor_t * n)
{
  n->packet_template_index = CDP_PACKET_TEMPLATE_ETHERNET;

  return 0;
}

/* Send a cdp neighbor announcement */
static void
send_hello (cdp_main_t * cm, cdp_neighbor_t * n, int count)
{
  if (n->packet_template_index == (u8) ~ 0)
    {
      /* If we don't know how to talk to this peer, don't try again */
      if (pick_packet_template (cm, n))
	{
	  n->last_sent = 1e70;
	  return;
	}
    }

  switch (n->packet_template_index)
    {
    case CDP_PACKET_TEMPLATE_ETHERNET:
      send_ethernet_hello (cm, n, count);
      break;

    case CDP_PACKET_TEMPLATE_HDLC:
      send_hdlc_hello (cm, n, count);
      break;

    case CDP_PACKET_TEMPLATE_SRP:
      send_srp_hello (cm, n, count);
      break;

    default:
      ASSERT (0);
    }
  n->last_sent = vlib_time_now (cm->vlib_main);
}

static void
delete_neighbor (cdp_main_t * cm, cdp_neighbor_t * n, int want_broadcast)
{
  hash_unset (cm->neighbor_by_sw_if_index, n->sw_if_index);
  vec_free (n->device_name);
  vec_free (n->version);
  vec_free (n->port_id);
  vec_free (n->platform);
  vec_free (n->last_rx_pkt);
  pool_put (cm->neighbors, n);
}

void
cdp_periodic (vlib_main_t * vm)
{
  cdp_main_t *cm = &cdp_main;
  cdp_neighbor_t *n;
  f64 now = vlib_time_now (vm);
  vnet_sw_interface_t *sw;
  static u32 *delete_list = 0;
  int i;
  static cdp_neighbor_t **n_list = 0;

  /* *INDENT-OFF* */
  pool_foreach (n, cm->neighbors,
  ({
    vec_add1 (n_list, n);
  }));
  /* *INDENT-ON* */

  /* Across all cdp neighbors known to the system */
  for (i = 0; i < vec_len (n_list); i++)
    {
      n = n_list[i];

      /* "no cdp run" provisioned on the interface? */
      if (n->disabled == 1)
	continue;

      sw = vnet_get_sw_interface (cm->vnet_main, n->sw_if_index);

      /* Interface shutdown or rx timeout? */
      if (!(sw->flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP)
	  || (now > (n->last_heard + (f64) n->ttl_in_seconds)))
	/* add to list of neighbors to delete */
	vec_add1 (delete_list, n - cm->neighbors);
      else if (n->last_sent == 0.0)
	/* First time, send 3 hellos */
	send_hello (cm, n, 3 /* three to begin with */ );
      else if (now > (n->last_sent + (((f64) n->ttl_in_seconds) / 6.0)))
	/* Normal keepalive, send one */
	send_hello (cm, n, 1 /* one as a keepalive */ );
    }

  for (i = 0; i < vec_len (delete_list); i++)
    {
      n = vec_elt_at_index (cm->neighbors, delete_list[i]);
      delete_neighbor (cm, n, 1);
    }
  if (delete_list)
    _vec_len (delete_list) = 0;
  if (n_list)
    _vec_len (n_list) = 0;
}

static clib_error_t *
cdp_periodic_init (vlib_main_t * vm)
{
  cdp_main_t *cm = &cdp_main;

  /* Create the ethernet cdp hello packet template */
  {
    ethernet_llc_snap_and_cdp_header_t h;

    memset (&h, 0, sizeof (h));

    /* Send to 01:00:0c:cc:cc */
    h.ethernet.dst_address[0] = 0x01;
    /* h.ethernet.dst_address[1] = 0x00; (memset) */
    h.ethernet.dst_address[2] = 0x0C;
    h.ethernet.dst_address[3] = 0xCC;
    h.ethernet.dst_address[4] = 0xCC;
    h.ethernet.dst_address[5] = 0xCC;

    /* leave src address blank (fill in at send time) */

    /* leave length blank (fill in at send time) */

    /* LLC */
    h.llc.dst_sap = h.llc.src_sap = 0xAA;	/* SNAP */
    h.llc.control = 0x03;	/* UI (no extended control bytes) */

    /* SNAP */
    /* h.snap.oui[0] = 0x00; (memset) */
    /* h.snap.oui[1] = 0x00; (memset) */
    h.snap.oui[2] = 0x0C;	/* Cisco = 0x00000C */
    h.snap.protocol = htons (0x2000);	/* CDP = 0x2000 */

    /* CDP */
    h.cdp.version = 2;
    h.cdp.ttl = 180;

    vlib_packet_template_init
      (vm, &cm->packet_templates[CDP_PACKET_TEMPLATE_ETHERNET],
       /* data */ &h,
       sizeof (h),
       /* alloc chunk size */ 8,
       "cdp-ethernet");
  }

#if 0				/* retain for reference */

  /* Create the hdlc cdp hello packet template */
  {
    hdlc_and_cdp_header_t h;

    memset (&h, 0, sizeof (h));

    h.hdlc.address = 0x0f;
    /* h.hdlc.control = 0; (memset) */
    h.hdlc.protocol = htons (0x2000);	/* CDP = 0x2000 */

    /* CDP */
    h.cdp.version = 2;
    h.cdp.ttl = 180;

    vlib_packet_template_init
      (vm, &cm->packet_templates[CDP_PACKET_TEMPLATE_HDLC],
       /* data */ &h,
       sizeof (h),
       /* alloc chunk size */ 8,
       "cdp-hdlc");
  }

  /* Create the srp cdp hello packet template */
  {
    srp_and_cdp_header_t h;

    memset (&h, 0, sizeof (h));

    /* Send to 01:00:0c:cc:cc */
    h.ethernet.dst_address[0] = 0x01;
    /* h.ethernet.dst_address[1] = 0x00; (memset) */
    h.ethernet.dst_address[2] = 0x0C;
    h.ethernet.dst_address[3] = 0xCC;
    h.ethernet.dst_address[4] = 0xCC;
    h.ethernet.dst_address[5] = 0xCC;

    /* leave src address blank (fill in at send time) */

    /* The srp header is filled in at xmt */
    h.srp.ttl = 1;
    h.srp.priority = 7;
    h.srp.mode = SRP_MODE_data;
    srp_header_compute_parity (&h.srp);

    /* Inner ring and parity will be set at send time */

    h.ethernet.type = htons (0x2000);	/* CDP = 0x2000 */

    /* CDP */
    h.cdp.version = 2;
    h.cdp.ttl = 180;

    vlib_packet_template_init
      (vm, &cm->packet_templates[CDP_PACKET_TEMPLATE_SRP],
       /* data */ &h,
       sizeof (h),
       /* alloc chunk size */ 8,
       "cdp-srp");
  }
#endif

  return 0;
}

VLIB_INIT_FUNCTION (cdp_periodic_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
