/*
 * Copyright 2019-2020 Rubicon Communications, LLC (Netgate)
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include <vnet/vnet.h>
#include <vnet/api_errno.h>
#include <vnet/ip/ip.h>
#include <vnet/interface.h>

#include <plugins/vrrp/vrrp.h>
#include <plugins/vrrp/vrrp_packet.h>

u8 *
format_vrrp_vr_flags (u8 * s, va_list * args)
{
  vrrp_vr_flags_t flags = va_arg (*args, vrrp_vr_flags_t);

  s = format (s, "preempt %s accept %s unicast %s",
	      (flags & VRRP_VR_PREEMPT) ? "yes" : "no",
	      (flags & VRRP_VR_ACCEPT) ? "yes" : "no",
	      (flags & VRRP_VR_UNICAST) ? "yes" : "no");

  return s;
}

u8 *
format_vrrp_vr_addrs (u8 * s, va_list * args)
{
  int is_ipv6 = va_arg (*args, int);
  ip46_address_t *addrs = va_arg (*args, ip46_address_t *);
  ip46_address_t *addr;

  vec_foreach (addr, addrs)
  {
    s = format (s, "%U ",
		(is_ipv6) ? format_ip6_address : format_ip4_address,
		(is_ipv6) ? (u8 *) & addr->ip6 : (u8 *) & addr->ip4);
  }

  return s;
}

u8 *
format_vrrp_vr_state (u8 * s, va_list * args)
{
  vrrp_vr_state_t state = va_arg (*args, vrrp_vr_state_t);

  switch (state)
    {
#define _(v,f,n) case VRRP_VR_STATE_##f: s = format (s, n); break;
      foreach_vrrp_vr_state
#undef _
    default:
      s = format (s, "Unknown");
      break;
    }

  return s;
}

u8 *
format_vrrp_vr_key (u8 * s, va_list * args)
{
  vrrp_main_t *vmp = &vrrp_main;
  vrrp_vr_t *vr = va_arg (*args, vrrp_vr_t *);
  vrrp_vr_config_t *vrc = &vr->config;

  s = format (s, "[%d] sw_if_index %u VR ID %u IPv%d",
	      vr - vmp->vrs, vrc->sw_if_index,
	      vrc->vr_id, (vrc->flags & VRRP_VR_IPV6) ? 6 : 4);

  return s;
}

u8 *
format_vrrp_vr_track_ifs (u8 * s, va_list * args)
{
  vrrp_vr_tracking_if_t *track_ifs = va_arg (*args, vrrp_vr_tracking_if_t *);
  vrrp_vr_tracking_if_t *track_if;

  vec_foreach (track_if, track_ifs)
    s = format (s, "sw_if_index %u priority %u ",
		track_if->sw_if_index, track_if->priority);

  return s;
}

u8 *
format_vrrp_vr (u8 * s, va_list * args)
{
  vrrp_vr_t *vr = va_arg (*args, vrrp_vr_t *);

  s = format (s, "%U\n", format_vrrp_vr_key, vr);

  s = format (s, "   state %U flags: %U\n",
	      format_vrrp_vr_state, vr->runtime.state,
	      format_vrrp_vr_flags, vr->config.flags);
  s = format (s, "   priority: configured %u adjusted %u\n",
	      vr->config.priority, vrrp_vr_priority (vr));
  s = format (s, "   timers: adv interval %u "
	      "master adv %u skew %u master down %u\n",
	      vr->config.adv_interval, vr->runtime.master_adv_int,
	      vr->runtime.skew, vr->runtime.master_down_int);

  s = format (s, "   virtual MAC %U\n", format_ethernet_address,
	      &vr->runtime.mac);

  s = format (s, "   addresses %U\n", format_vrrp_vr_addrs,
	      (vr->config.flags & VRRP_VR_IPV6) != 0, vr->config.vr_addrs);

  s = format (s, "   peer addresses %U\n", format_vrrp_vr_addrs,
	      (vr->config.flags & VRRP_VR_IPV6) != 0, vr->config.peer_addrs);

  s = format (s, "   tracked interfaces %U\n", format_vrrp_vr_track_ifs,
	      vr->tracking.interfaces);

  return s;
}

u8 *
format_vrrp_packet_hdr (u8 * s, va_list * args)
{
  vrrp_header_t *pkt = va_arg (*args, vrrp_header_t *);
  u32 version = pkt->vrrp_version_and_type >> 4;

  s = format (s, "ver %u, type %u, VRID %u, prio %u, "
	      "n_addrs %u, interval %u%ss, csum 0x%x",
	      version, pkt->vrrp_version_and_type & 0xf,
	      pkt->vr_id, pkt->priority, pkt->n_addrs,
	      clib_net_to_host_u16 (pkt->rsvd_and_max_adv_int),
	      (version == 3) ? "c" : "", pkt->checksum);

  return s;
}


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
