/* SPDX-License-Identifier: Apache-2.0 */
/*
 *------------------------------------------------------------------
 * Copyright (c) 2017 RaydoNetworks.
 *
 * Copyright (c) 2026 Hi-Jiajun.
 *------------------------------------------------------------------
 */
#include <stdint.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <inttypes.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>

#include <vlib/vlib.h>
#include <vlib/log.h>
#include <vlib/unix/unix.h>
#include <vlib/unix/plugin.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/dpo/interface_tx_dpo.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
#include <vnet/ip/ip_interface.h>
#include <dhcp/dhcp6_ia_na_client_dp.h>
#include <dhcp/dhcp6_pd_client_dp.h>
#include <ppp/packet.h>
#include <pppoeclient/pppox/pppox.h>
#include <pppoeclient/pppoeclient.h>

#include <vppinfra/hash.h>
#include <vppinfra/random.h>
#include <vppinfra/bihash_template.c>

pppoeclient_main_t pppoeclient_main;

static vlib_log_class_t pppoeclient_log_class;

/* BAS/RADIUS typically needs 10–30 seconds to fully clear a PPPoE session
 * after PADT.  If we retry too quickly, RADIUS still sees the old session
 * and rejects CHAP with "TOO MANY CONNECTIONS".  30s is conservative but
 * reliable for China Telecom / China Mobile BAS equipment. */
#define PPPOECLIENT_REDISCOVERY_COOLDOWN       30.0
#define PPPOECLIENT_NEXT_TRANSMIT_PARKED       1e18
#define PPPOECLIENT_NEXT_TRANSMIT_IS_PARKED(t) ((t) >= 1e17)
#define PPPOECLIENT_RAW_PADT_LINK_UP_WAIT_US   200000
#define PPPOECLIENT_UNEXPECTED_PKT_COOLDOWN    5.0
#define PPPOECLIENT_PROCESS_IDLE_TIMEOUT       100.0
static vlib_node_registration_t pppoeclient_process_node;
static pppox_main_t *pppox_main_p = 0;

static pppox_main_t *
get_pppox_main (void)
{
  if (pppox_main_p == 0)
    pppox_main_p = vlib_get_plugin_symbol ("pppoeclient_plugin.so", "pppox_main");

  return pppox_main_p;
}

static int send_pppoe_pkt (pppoeclient_main_t *pem, pppoeclient_t *c, u8 packet_code,
			   u16 session_id, int is_broadcast);
static int pppoeclient_get_linux_ifname (vnet_main_t *vnm, u32 sw_if_index, char *buf,
					 size_t buf_len, u8 noisy);
static void pppoeclient_send_padt_raw (const char *linux_ifname, const u8 *src_mac,
				       const u8 *dst_mac, u16 session_id);
static void pppoeclient_control_event_capture_raw_tags (pppoeclient_control_event_t *event,
							pppoe_header_t *pppoe,
							uword available_payload_len);
static void
pppoeclient_dispatch_ref (pppoeclient_main_t *pem, u32 sw_if_index)
{
  vec_validate_init_empty (pem->dispatch_refcount_by_sw_if_index, sw_if_index, 0);
  if (pem->dispatch_refcount_by_sw_if_index[sw_if_index]++ == 0)
    vnet_feature_enable_disable ("device-input", "pppoeclient-dispatch", sw_if_index, 1, 0, 0);
}

static u8 *
format_pppoeclient_control_match_reason (u8 *s, va_list *args)
{
  pppoeclient_control_match_reason_t reason = va_arg (*args, int);

  switch (reason)
    {
    case PPPOECLIENT_CONTROL_MATCH_NONE:
      return format (s, "none");
    case PPPOECLIENT_CONTROL_MATCH_HOST_UNIQ:
      return format (s, "host-uniq");
    case PPPOECLIENT_CONTROL_MATCH_AC_NAME:
      return format (s, "ac-name");
    case PPPOECLIENT_CONTROL_MATCH_SERVICE_NAME:
      return format (s, "service-name");
    case PPPOECLIENT_CONTROL_MATCH_ANY:
      return format (s, "any");
    case PPPOECLIENT_CONTROL_MATCH_COOKIE:
      return format (s, "cookie");
    case PPPOECLIENT_CONTROL_MATCH_UNIQUE:
      return format (s, "unique");
    case PPPOECLIENT_CONTROL_MATCH_SESSION:
      return format (s, "session");
    case PPPOECLIENT_CONTROL_MATCH_AC_AND_SERVICE:
      return format (s, "ac+service");
    case PPPOECLIENT_CONTROL_MATCH_AC_MAC:
      return format (s, "ac-mac");
    case PPPOECLIENT_CONTROL_MATCH_AC_MAC_AND_SERVICE:
      return format (s, "ac-mac+service");
    case PPPOECLIENT_CONTROL_MATCH_COOKIE_AND_SERVICE:
      return format (s, "cookie+service");
    default:
      return format (s, "%u", reason);
    }
}

static u8 *
format_pppoeclient_control_disposition (u8 *s, va_list *args)
{
  pppoeclient_control_disposition_t disposition = va_arg (*args, int);

  switch (disposition)
    {
    case PPPOECLIENT_CONTROL_DISPOSITION_NONE:
      return format (s, "none");
    case PPPOECLIENT_CONTROL_DISPOSITION_ACCEPTED:
      return format (s, "accepted");
    case PPPOECLIENT_CONTROL_DISPOSITION_IGNORED:
      return format (s, "ignored");
    case PPPOECLIENT_CONTROL_DISPOSITION_ERROR:
      return format (s, "error");
    case PPPOECLIENT_CONTROL_DISPOSITION_ORPHAN:
      return format (s, "orphan");
    default:
      return format (s, "%u", disposition);
    }
}

static u8 *format_pppoe_packet_code_name (u8 *s, va_list *args);

static u8 *
format_pppoeclient_control_host_uniq (u8 *s, va_list *args)
{
  u32 host_uniq = va_arg (*args, u32);
  u32 present = va_arg (*args, u32);

  if (!present)
    return format (s, "<none>");

  return format (s, "%u", host_uniq);
}

static pppoeclient_control_client_state_t
pppoeclient_control_client_state_from_client_state (pppoeclient_state_t state)
{
  switch (state)
    {
    case PPPOE_CLIENT_DISCOVERY:
      return PPPOECLIENT_CONTROL_CLIENT_STATE_DISCOVERY;
    case PPPOE_CLIENT_REQUEST:
      return PPPOECLIENT_CONTROL_CLIENT_STATE_REQUEST;
    case PPPOE_CLIENT_SESSION:
      return PPPOECLIENT_CONTROL_CLIENT_STATE_SESSION;
    default:
      return PPPOECLIENT_CONTROL_CLIENT_STATE_UNKNOWN;
    }
}

static u8 *
format_pppoeclient_control_client_state (u8 *s, va_list *args)
{
  pppoeclient_control_client_state_t state = va_arg (*args, int);

  switch (state)
    {
    case PPPOECLIENT_CONTROL_CLIENT_STATE_UNKNOWN:
      return format (s, "unknown");
    case PPPOECLIENT_CONTROL_CLIENT_STATE_DISCOVERY:
      return format (s, "discovery");
    case PPPOECLIENT_CONTROL_CLIENT_STATE_REQUEST:
      return format (s, "request");
    case PPPOECLIENT_CONTROL_CLIENT_STATE_SESSION:
      return format (s, "session");
    default:
      return format (s, "%u", state);
    }
}

typedef struct
{
  u32 max_events;
  u8 filter_code;
  u8 code;
  u8 parse_errors_only;
  u8 filter_disposition;
  u8 disposition;
  u8 filter_match_reason;
  u8 match_reason;
} pppoeclient_history_cli_filter_t;

static_always_inline int
pppoeclient_history_cli_filter_active (pppoeclient_history_cli_filter_t *filter)
{
  return filter->filter_code || filter->parse_errors_only || filter->filter_disposition ||
	 filter->filter_match_reason;
}

static u8 pppoeclient_score_pado_candidate (pppoeclient_t *c,
					    pppoeclient_control_match_reason_t *reason);

static u8 pppoeclient_score_pads_candidate (pppoeclient_t *c, pppoeclient_control_event_t *summary,
					    pppoeclient_control_match_reason_t *reason);

typedef enum
{
  PPPOECLIENT_MATCH_FLAG_AC_NAME = 1 << 0,
  PPPOECLIENT_MATCH_FLAG_SERVICE_NAME = 1 << 1,
  PPPOECLIENT_MATCH_FLAG_AC_MAC = 1 << 2,
  PPPOECLIENT_MATCH_FLAG_COOKIE = 1 << 3,
} pppoeclient_match_flags_t;

typedef struct
{
  pppoeclient_t *selected_candidate;
  pppoeclient_t *unique_candidate;
  pppoeclient_control_match_reason_t selected_reason;
  pppoeclient_control_match_reason_t top_match_reason;
  u8 selected_score;
  u8 candidate_count;
  u8 top_match_count;
  u8 top_match_score;
} pppoeclient_fallback_selection_t;

static_always_inline void
pppoeclient_fallback_selection_init (pppoeclient_fallback_selection_t *selection)
{
  clib_memset (selection, 0, sizeof (*selection));
}

static_always_inline u8
pppoeclient_ac_name_compatible (pppoeclient_t *c, pppoeclient_control_event_t *summary)
{
  return (c->ac_name_filter == 0 || vec_len (c->ac_name_filter) == 0 ||
	  (summary->ac_name_len && vec_len (c->ac_name_filter) == summary->ac_name_len &&
	   clib_memcmp (c->ac_name_filter, summary->ac_name, summary->ac_name_len) == 0));
}

static_always_inline u8
pppoeclient_service_name_compatible (pppoeclient_t *c, pppoeclient_control_event_t *summary)
{
  return (c->service_name == 0 || vec_len (c->service_name) == 0 ||
	  (summary->service_name_len && vec_len (c->service_name) == summary->service_name_len &&
	   clib_memcmp (c->service_name, summary->service_name, summary->service_name_len) == 0));
}

static_always_inline void
pppoeclient_fallback_selection_consider (pppoeclient_fallback_selection_t *selection,
					 pppoeclient_t *candidate,
					 pppoeclient_control_match_reason_t reason, u8 score)
{
  selection->candidate_count++;
  if (selection->candidate_count == 1)
    selection->unique_candidate = candidate;
  else
    selection->unique_candidate = 0;

  if (score > selection->top_match_score)
    {
      selection->top_match_score = score;
      selection->top_match_count = 1;
      selection->selected_candidate = candidate;
      selection->selected_reason = reason;
      selection->top_match_reason = reason;
    }
  else if (score == selection->top_match_score)
    {
      selection->top_match_count++;
      selection->selected_candidate = 0;
    }
}

static_always_inline void
pppoeclient_fill_direct_match_summary (pppoeclient_control_event_t *summary,
				       pppoeclient_control_match_reason_t reason)
{
  summary->match_reason = reason;
  summary->match_score = 0;
  summary->candidate_count = 1;
  summary->top_match_count = 1;
  summary->top_match_reason = reason;
  summary->top_match_score = 0;
}

static_always_inline void
pppoeclient_fill_fallback_selection_summary (pppoeclient_control_event_t *summary,
					     pppoeclient_fallback_selection_t *selection)
{
  summary->candidate_count = selection->candidate_count;
  summary->top_match_count = selection->top_match_count;
  summary->top_match_reason = selection->top_match_reason;
  summary->top_match_score = selection->top_match_score;
}

static_always_inline int
pppoeclient_evaluate_hostuniqless_candidate (pppoeclient_t *candidate, u8 packet_code,
					     const u8 *peer_mac,
					     pppoeclient_control_event_t *summary,
					     pppoeclient_control_match_reason_t *reason, u8 *score)
{
  if (packet_code == PPPOE_PADO)
    {
      if (!pppoeclient_ac_name_compatible (candidate, summary) ||
	  !pppoeclient_service_name_compatible (candidate, summary))
	return 0;

      *score = pppoeclient_score_pado_candidate (candidate, reason);
      return 1;
    }

  if (clib_memcmp (candidate->ac_mac_address, peer_mac, sizeof (candidate->ac_mac_address)) != 0)
    return 0;

  if (!pppoeclient_service_name_compatible (candidate, summary))
    return 0;

  *score = pppoeclient_score_pads_candidate (candidate, summary, reason);
  return 1;
}

static pppoeclient_t *
pppoeclient_select_hostuniqless_candidate (pppoeclient_main_t *pem, u8 packet_code, u32 sw_if_index,
					   const u8 *peer_mac, pppoeclient_control_event_t *summary,
					   pppoeclient_fallback_selection_t *selection)
{
  pppoeclient_t *it;
  pppoeclient_state_t expected_state =
    (packet_code == PPPOE_PADO) ? PPPOE_CLIENT_DISCOVERY : PPPOE_CLIENT_REQUEST;

  pppoeclient_fallback_selection_init (selection);

  pool_foreach (it, pem->clients)
    {
      pppoeclient_control_match_reason_t reason;
      u8 score;

      if (it->sw_if_index != sw_if_index || it->state != expected_state)
	continue;

      if (!pppoeclient_evaluate_hostuniqless_candidate (it, packet_code, peer_mac, summary, &reason,
							&score))
	continue;

      pppoeclient_fallback_selection_consider (selection, it, reason, score);
    }

  if (selection->top_match_count == 1 && selection->selected_candidate)
    {
      selection->selected_score = selection->top_match_score;
      return selection->selected_candidate;
    }

  if (selection->candidate_count == 1 && selection->unique_candidate)
    {
      selection->selected_candidate = selection->unique_candidate;
      selection->selected_reason = PPPOECLIENT_CONTROL_MATCH_UNIQUE;
      selection->selected_score = 1;
      return selection->selected_candidate;
    }

  return 0;
}

static u8
pppoeclient_score_match_flags (u8 flags, u8 packet_code, pppoeclient_control_match_reason_t *reason)
{
  if (packet_code == PPPOE_PADO)
    {
      if ((flags & (PPPOECLIENT_MATCH_FLAG_AC_NAME | PPPOECLIENT_MATCH_FLAG_SERVICE_NAME)) ==
	  (PPPOECLIENT_MATCH_FLAG_AC_NAME | PPPOECLIENT_MATCH_FLAG_SERVICE_NAME))
	{
	  *reason = PPPOECLIENT_CONTROL_MATCH_AC_AND_SERVICE;
	  return 4;
	}
      if (flags & PPPOECLIENT_MATCH_FLAG_AC_NAME)
	{
	  *reason = PPPOECLIENT_CONTROL_MATCH_AC_NAME;
	  return 3;
	}
      if (flags & PPPOECLIENT_MATCH_FLAG_SERVICE_NAME)
	{
	  *reason = PPPOECLIENT_CONTROL_MATCH_SERVICE_NAME;
	  return 2;
	}

      *reason = PPPOECLIENT_CONTROL_MATCH_ANY;
      return 1;
    }

  if ((flags & (PPPOECLIENT_MATCH_FLAG_COOKIE | PPPOECLIENT_MATCH_FLAG_SERVICE_NAME)) ==
      (PPPOECLIENT_MATCH_FLAG_COOKIE | PPPOECLIENT_MATCH_FLAG_SERVICE_NAME))
    {
      *reason = PPPOECLIENT_CONTROL_MATCH_COOKIE_AND_SERVICE;
      return 4;
    }
  if (flags & PPPOECLIENT_MATCH_FLAG_COOKIE)
    {
      *reason = PPPOECLIENT_CONTROL_MATCH_COOKIE;
      return 3;
    }
  if (flags & PPPOECLIENT_MATCH_FLAG_SERVICE_NAME)
    {
      *reason = PPPOECLIENT_CONTROL_MATCH_AC_MAC_AND_SERVICE;
      return 2;
    }

  *reason = PPPOECLIENT_CONTROL_MATCH_AC_MAC;
  return 1;
}

static u8
pppoeclient_score_pado_candidate (pppoeclient_t *c, pppoeclient_control_match_reason_t *reason)
{
  u8 flags = 0;

  if (c->ac_name_filter && vec_len (c->ac_name_filter) > 0)
    flags |= PPPOECLIENT_MATCH_FLAG_AC_NAME;
  if (c->service_name && vec_len (c->service_name) > 0)
    flags |= PPPOECLIENT_MATCH_FLAG_SERVICE_NAME;

  return pppoeclient_score_match_flags (flags, PPPOE_PADO, reason);
}

static u8
pppoeclient_score_pads_candidate (pppoeclient_t *c, pppoeclient_control_event_t *summary,
				  pppoeclient_control_match_reason_t *reason)
{
  u8 flags = PPPOECLIENT_MATCH_FLAG_AC_MAC;
  u8 cookie_matches =
    (summary->cookie_len > 0 && !summary->cookie_value_truncated &&
     vec_len (c->cookie_value) == summary->cookie_len &&
     clib_memcmp (c->cookie_value, summary->cookie_value, summary->cookie_len) == 0);

  if (cookie_matches)
    flags |= PPPOECLIENT_MATCH_FLAG_COOKIE;
  if (c->service_name && vec_len (c->service_name) > 0)
    flags |= PPPOECLIENT_MATCH_FLAG_SERVICE_NAME;

  return pppoeclient_score_match_flags (flags, PPPOE_PADS, reason);
}

static void
pppoeclient_dispatch_unref (pppoeclient_main_t *pem, u32 sw_if_index)
{
  if (sw_if_index >= vec_len (pem->dispatch_refcount_by_sw_if_index))
    return;

  if (pem->dispatch_refcount_by_sw_if_index[sw_if_index] == 0)
    return;

  if (--pem->dispatch_refcount_by_sw_if_index[sw_if_index] == 0)
    vnet_feature_enable_disable ("device-input", "pppoeclient-dispatch", sw_if_index, 0, 0, 0);
}

static void
pppoeclient_clear_runtime_state (pppoeclient_t *c)
{
  c->ip4_addr = 0;
  c->ip4_netmask = 0;
  c->ip4_gateway = 0;
  c->dns1 = 0;
  c->dns2 = 0;
  ip6_address_set_zero (&c->ip6_addr);
  ip6_address_set_zero (&c->ip6_peer_addr);
  c->ipv6_prefix_len = 0;
  c->use_peer_ipv6 = 0;
  c->next_transmit = 0;
  c->retry_count = 0;
  c->lcp_state = 0;
  c->lcp_id = 0;
  c->lcp_nak = 0;
  c->ipcp_state = 0;
  c->ipcp_id = 0;
  c->ipv6cp_state = 0;
  c->ipv6cp_id = 0;

  /* Clear cached data-plane fields so stale values are never visible
   * if the client is reused after teardown. */
  c->discovery_error = 0;
}

/*
 * Session persistence — save session_id + ac_mac to a file so that the next
 * VPP instance can send a proper PADT before starting discovery.  This is
 * necessary because vlib_put_frame_to_node() during VLIB_MAIN_LOOP_EXIT only
 * enqueues the frame; the main loop has already exited and never dispatches
 * it, so the PADT never reaches the wire.
 */
#define PPPOECLIENT_SESSION_DIR "/run/vpp"

static void
pppoeclient_session_file_path (u32 sw_if_index, char *buf, size_t buf_len)
{
  snprintf (buf, buf_len, PPPOECLIENT_SESSION_DIR "/pppoeclient-%u.session", sw_if_index);
}

void
pppoeclient_save_session_to_file (pppoeclient_t *c)
{
  pppoeclient_main_t *pem = &pppoeclient_main;
  vnet_main_t *vnm = pem->vnet_main;
  char path[128];
  char tmp_path[sizeof (path) + 4];
  char linux_ifname[IFNAMSIZ];
  u8 src_mac[6];
  /* layout: session_id (2B) + ac_mac (6B) + src_mac (6B) + linux_ifname (16B) = 30B */
  u8 buf[sizeof (u16) + 6 + 6 + IFNAMSIZ];
  size_t off;
  int fd;

  pppoeclient_session_file_path (c->sw_if_index, path, sizeof (path));
  mkdir (PPPOECLIENT_SESSION_DIR, 0755);

  /* Resolve linux interface name NOW while RDMA is still active */
  clib_memset (linux_ifname, 0, sizeof (linux_ifname));
  clib_memset (src_mac, 0, sizeof (src_mac));
  vnet_hw_interface_t *hw = vnet_get_sup_hw_interface (vnm, c->sw_if_index);
  if (hw)
    {
      clib_memcpy (src_mac, hw->hw_address, 6);
      if (pppoeclient_get_linux_ifname (vnm, c->sw_if_index, linux_ifname, sizeof (linux_ifname),
					1) < 0)
	vlib_log (VLIB_LOG_LEVEL_ERR, pppoeclient_log_class,
		  "save_session: get_linux_ifname FAILED for sw_if_index %u", c->sw_if_index);
      else
	vlib_log (VLIB_LOG_LEVEL_INFO, pppoeclient_log_class,
		  "save_session: resolved linux ifname='%s' for sw_if_index %u", linux_ifname,
		  c->sw_if_index);
    }
  else
    vlib_log (VLIB_LOG_LEVEL_ERR, pppoeclient_log_class,
	      "save_session: no hw interface for sw_if_index %u", c->sw_if_index);

  u16 sid = clib_host_to_net_u16 (c->session_id);
  off = 0;
  clib_memcpy (buf + off, &sid, sizeof (sid));
  off += sizeof (sid);
  clib_memcpy (buf + off, c->ac_mac_address, 6);
  off += 6;
  clib_memcpy (buf + off, src_mac, 6);
  off += 6;
  clib_memcpy (buf + off, linux_ifname, IFNAMSIZ);
  off += IFNAMSIZ;
  ASSERT (off == sizeof (buf));

  /* Atomic replace: write the full record to <path>.tmp, then rename() onto
   * <path>.  Guarantees that a reader on the next boot sees either the
   * previous file or the complete new one, never a torn partial file from
   * a crash between open(O_TRUNC) and the last write(). */
  snprintf (tmp_path, sizeof (tmp_path), "%s.tmp", path);
  fd = open (tmp_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
  if (fd < 0)
    {
      vlib_log (VLIB_LOG_LEVEL_ERR, pppoeclient_log_class, "save_session: cannot create %s: %s",
		tmp_path, strerror (errno));
      return;
    }

  size_t remaining = sizeof (buf);
  while (remaining > 0)
    {
      ssize_t n = write (fd, buf + (sizeof (buf) - remaining), remaining);
      if (n < 0)
	{
	  if (errno == EINTR)
	    continue;
	  vlib_log (VLIB_LOG_LEVEL_ERR, pppoeclient_log_class, "save_session: write %s failed: %s",
		    tmp_path, strerror (errno));
	  close (fd);
	  unlink (tmp_path);
	  return;
	}
      if (n == 0)
	break;
      remaining -= (size_t) n;
    }
  close (fd);

  if (remaining != 0 || rename (tmp_path, path) < 0)
    {
      vlib_log (VLIB_LOG_LEVEL_ERR, pppoeclient_log_class, "save_session: finalize %s failed: %s",
		path, remaining ? "short write" : strerror (errno));
      unlink (tmp_path);
      return;
    }

  vlib_log (VLIB_LOG_LEVEL_INFO, pppoeclient_log_class,
	    "saved session file %s: session_id=%u linux_ifname='%s' "
	    "src_mac=%02x:%02x:%02x:%02x:%02x:%02x ac_mac=%02x:%02x:%02x:%02x:%02x:%02x",
	    path, sid, linux_ifname, src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4],
	    src_mac[5], c->ac_mac_address[0], c->ac_mac_address[1], c->ac_mac_address[2],
	    c->ac_mac_address[3], c->ac_mac_address[4], c->ac_mac_address[5]);
}

static void
pppoeclient_delete_session_file (u32 sw_if_index)
{
  char path[128];
  pppoeclient_session_file_path (sw_if_index, path, sizeof (path));
  unlink (path);
}

static void
pppoeclient_mark_session_down (pppoeclient_t *c)
{
  pppox_main_t *pom = get_pppox_main ();
  u32 unit = ~0;

  if (pom && c->pppox_sw_if_index != ~0 &&
      c->pppox_sw_if_index < vec_len (pom->virtual_interface_index_by_sw_if_index))
    {
      unit = pom->virtual_interface_index_by_sw_if_index[c->pppox_sw_if_index];
      if (unit != ~0 && !pool_is_free_index (pom->virtual_interfaces, unit))
	{
	  pppox_virtual_interface_t *t = pool_elt_at_index (pom->virtual_interfaces, unit);
	  t->pppoe_session_allocated = 0;
	}
    }
}

static void
pppoeclient_teardown_session (pppoeclient_t *c, u8 send_padt)
{
  pppoeclient_main_t *pem = &pppoeclient_main;

  /* Close the session-duration bookkeeping before the session state is
   * cleared.  session_start_time is set to 0 on entry to SESSION only if
   * the client has never actually reached it; guard on the sentinel so
   * spurious teardowns from non-SESSION states don't double-count. */
  if (c->session_start_time > 0)
    {
      f64 now = vlib_time_now (pem->vlib_main);
      f64 duration = now - c->session_start_time;
      if (duration > 0)
	{
	  c->last_session_duration_seconds = (u32) duration;
	  c->total_session_seconds += (u64) duration;
	}
      c->session_start_time = 0;
    }

  if (c->session_id)
    {
      if (send_padt)
	{
	  if (send_pppoe_pkt (pem, c, PPPOE_PADT, c->session_id, 0 /* is_broadcast */) != 0)
	    vlib_log (VLIB_LOG_LEVEL_WARNING, pppoeclient_log_class,
		      "failed to send PADT for session %u on %U, "
		      "BAS will hold stale session until its own timeout",
		      c->session_id, format_vnet_sw_if_index_name, vnet_get_main (),
		      c->sw_if_index);
	}
      /* Do NOT use raw socket here — bringing the Linux interface UP during
       * normal VPP operation destroys the RDMA ibverbs receive path.
       * VPP frame dispatch works fine while the main loop is running.
       * Raw socket PADT is only used in pppoeclient_exit() where the main
       * loop has already stopped and frame dispatch no longer works.
       *
       * Do NOT delete the session file here — pppoeclient_exit() needs it
       * to send raw PADT on shutdown.  The file is overwritten on every new
       * session and cleaned up by pppoeclient_exit(). */
      pppoeclient_delete_session_1 (&pem->session_table, c->sw_if_index, c->ac_mac_address,
				    c->session_id);
      c->session_id = 0;
    }

  pppoeclient_mark_session_down (c);
  pppoeclient_clear_runtime_state (c);
}

static void
pppoeclient_schedule_discovery (pppoeclient_t *c, f64 next_transmit)
{
  pppoeclient_main_t *pem = &pppoeclient_main;
  u32 client_id = c - pem->clients;

  c->state = PPPOE_CLIENT_DISCOVERY;
  c->next_transmit = next_transmit;
  c->retry_count = 0;
  vlib_process_signal_event (pem->vlib_main, pppoeclient_process_node.index,
			     EVENT_PPPOE_CLIENT_WAKEUP, client_id);
}

int
sync_pppoe_client_live_auth (pppoeclient_t *c)
{
  static int (*pppox_set_auth_func) (u32, u8 *, u8 *) = 0;

  if (c->pppox_sw_if_index == ~0 || c->username == 0 || c->password == 0)
    return 0;

  PPPOECLIENT_LAZY_PLUGIN_SYMBOL (pppox_set_auth_func, "pppoeclient_plugin.so", "pppox_set_auth");

  if (pppox_set_auth_func == 0)
    return VNET_API_ERROR_UNSUPPORTED;

  return (*pppox_set_auth_func) (c->pppox_sw_if_index, c->username, c->password);
}

int
sync_pppoe_client_live_default_route4 (pppoeclient_t *c)
{
  static int (*pppox_set_add_default_route4_func) (u32, u8) = 0;

  if (c->pppox_sw_if_index == ~0)
    return 0;

  PPPOECLIENT_LAZY_PLUGIN_SYMBOL (pppox_set_add_default_route4_func, "pppoeclient_plugin.so",
				  "pppox_set_add_default_route4");

  if (pppox_set_add_default_route4_func == 0)
    return VNET_API_ERROR_UNSUPPORTED;

  return (*pppox_set_add_default_route4_func) (c->pppox_sw_if_index, c->use_peer_route4);
}

int
sync_pppoe_client_live_default_route6 (pppoeclient_t *c)
{
  static int (*pppox_set_add_default_route6_func) (u32, u8) = 0;

  if (c->pppox_sw_if_index == ~0)
    return 0;

  PPPOECLIENT_LAZY_PLUGIN_SYMBOL (pppox_set_add_default_route6_func, "pppoeclient_plugin.so",
				  "pppox_set_add_default_route6");

  if (pppox_set_add_default_route6_func == 0)
    return VNET_API_ERROR_UNSUPPORTED;

  return (*pppox_set_add_default_route6_func) (c->pppox_sw_if_index, c->use_peer_route6);
}

int
sync_pppoe_client_live_use_peer_dns (pppoeclient_t *c)
{
  static int (*pppox_set_use_peer_dns_func) (u32, u8) = 0;

  if (c->pppox_sw_if_index == ~0)
    return 0;

  PPPOECLIENT_LAZY_PLUGIN_SYMBOL (pppox_set_use_peer_dns_func, "pppoeclient_plugin.so",
				  "pppox_set_use_peer_dns");

  if (pppox_set_use_peer_dns_func == 0)
    return VNET_API_ERROR_UNSUPPORTED;

  return (*pppox_set_use_peer_dns_func) (c->pppox_sw_if_index, c->use_peer_dns);
}

__clib_export void
pppoeclient_set_peer_dns (u32 pppox_sw_if_index, u32 dns1, u32 dns2)
{
  pppoeclient_main_t *pem = &pppoeclient_main;
  pppoeclient_t *c;
  u32 client_index;

  if (pppox_sw_if_index == ~0 ||
      pppox_sw_if_index >= vec_len (pem->client_index_by_pppox_sw_if_index))
    return;

  client_index = pem->client_index_by_pppox_sw_if_index[pppox_sw_if_index];
  if (client_index == ~0 || pool_is_free_index (pem->clients, client_index))
    return;

  c = pool_elt_at_index (pem->clients, client_index);
  c->dns1 = dns1;
  c->dns2 = dns2;
}

__clib_export void
pppoeclient_set_ipv6_state (u32 pppox_sw_if_index, const ip6_address_t *ip6_addr,
			    const ip6_address_t *ip6_peer_addr, u8 prefix_len)
{
  pppoeclient_main_t *pem = &pppoeclient_main;
  pppoeclient_t *c;
  u32 client_index;

  if (pppox_sw_if_index == ~0 ||
      pppox_sw_if_index >= vec_len (pem->client_index_by_pppox_sw_if_index))
    return;

  client_index = pem->client_index_by_pppox_sw_if_index[pppox_sw_if_index];
  if (client_index == ~0 || pool_is_free_index (pem->clients, client_index))
    return;

  c = pool_elt_at_index (pem->clients, client_index);

  if (ip6_addr)
    c->ip6_addr = *ip6_addr;
  else
    ip6_address_set_zero (&c->ip6_addr);

  if (ip6_peer_addr)
    c->ip6_peer_addr = *ip6_peer_addr;
  else
    ip6_address_set_zero (&c->ip6_peer_addr);

  c->ipv6_prefix_len = prefix_len;
  c->use_peer_ipv6 = (prefix_len != 0 && !ip6_address_is_zero (&c->ip6_peer_addr));
}

static int
send_pppoe_pkt (pppoeclient_main_t *pem, pppoeclient_t *c, u8 packet_code, u16 session_id,
		int is_broadcast)
{
  vlib_main_t *vm = pem->vlib_main;
  vnet_main_t *vnm = pem->vnet_main;
  vnet_hw_interface_t *hw = vnet_get_sup_hw_interface (vnm, c->sw_if_index);
  vnet_sw_interface_t *sup_sw = vnet_get_sup_sw_interface (vnm, c->sw_if_index);
  vnet_sw_interface_t *sw = vnet_get_sw_interface (vnm, c->sw_if_index);
  vlib_buffer_t *b;
  u32 bi;
  pppoe_header_t *pppoe;
  u32 *to_next;
  vlib_frame_t *f;
  u8 src_mac[6];

  if (PREDICT_FALSE (hw == 0 || sup_sw == 0 || sw == 0))
    return -1;

  /* Interface(s) down? */
  if ((hw->flags & VNET_HW_INTERFACE_FLAG_LINK_UP) == 0)
    return -1;
  if ((sup_sw->flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP) == 0)
    return -1;
  if ((sw->flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP) == 0)
    return -1;

  /* Use packet template to get buffer (better performance via buffer reuse) */
  void *pkt = vlib_packet_template_get_packet (vm, &pem->packet_template, &bi);
  if (pkt == 0)
    {
      vlib_log (VLIB_LOG_LEVEL_ERR, pppoeclient_log_class, "buffer allocation failure");
      return -1;
    }

  /* Build a PPPOE discovery pkt from whole cloth */
  b = vlib_get_buffer (vm, bi);

  ASSERT (b->current_data == 0);

  f = vlib_get_frame_to_node (vm, hw->output_node_index);
  {
    static const u8 broadcast_mac[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    const u8 *dst_address = is_broadcast ? broadcast_mac : c->ac_mac_address;
    clib_memcpy (src_mac, hw->hw_address, 6);

    pppoe = pppoeclient_push_l2_header (vnm, c->sw_if_index, b, ETHERNET_TYPE_PPPOE_DISCOVERY,
					src_mac, dst_address);
  }

  pppoe->ver_type = PPPOE_VER_TYPE;
  pppoe->code = packet_code;
  pppoe->session_id = clib_host_to_net_u16 (session_id);
  /*
   * Append the PPPoE discovery tags inline so the final packet layout stays
   * explicit at the call site.
   */
  {
    unsigned char *cursor = (unsigned char *) (pppoe + 1);
    u16 tags_len = 0;
    u16 service_name_len = c->service_name ? vec_len (c->service_name) : 0;
    u16 cookie_len =
      ((packet_code == PPPOE_PADR || packet_code == PPPOE_PADS) && vec_len (c->cookie_value)) ?
	vec_len (c->cookie_value) :
	0;

    /* Compute total packet size BEFORE writing to catch overflow early. */
    u32 total_len = pppoeclient_get_l2_encap_len (vnm, c->sw_if_index) + sizeof (pppoe_header_t) +
		    sizeof (pppoe_tag_header_t) + service_name_len + sizeof (pppoe_tag_header_t) +
		    sizeof (c->host_uniq) +
		    (cookie_len ? sizeof (pppoe_tag_header_t) + cookie_len : 0);

    if (PREDICT_FALSE (total_len > vlib_buffer_get_default_data_size (vm)))
      {
	vlib_log (VLIB_LOG_LEVEL_WARNING, pppoeclient_log_class,
		  "discovery pkt too large (%u > %u), dropping", total_len,
		  vlib_buffer_get_default_data_size (vm));
	vlib_buffer_free (vm, &bi, 1);
	vlib_frame_free (vm, f);
	return -1;
      }

    /* add ServiceName tag. zero length means "accept any service" per RFC 2516. */
    {
      pppoe_tag_header_t *pppoe_tag = (pppoe_tag_header_t *) cursor;
      pppoe_tag->type = clib_host_to_net_u16 (PPPOE_TAG_SERVICE_NAME);
      pppoe_tag->length = clib_host_to_net_u16 (service_name_len);
      if (service_name_len)
	clib_memcpy ((void *) pppoe_tag->value, c->service_name, service_name_len);

      tags_len += sizeof (pppoe_tag_header_t) + service_name_len;
      cursor += sizeof (pppoe_tag_header_t) + service_name_len;
    }

    /* adding HOST-UNIQ tag. */
    {
      pppoe_tag_header_t *pppoe_tag = (pppoe_tag_header_t *) cursor;
      pppoe_tag->type = clib_host_to_net_u16 (PPPOE_TAG_HOST_UNIQ);
      /* host_uniq is arbitrary binary data we choose. */
      pppoe_tag->length = clib_host_to_net_u16 (sizeof (c->host_uniq));
      clib_memcpy ((void *) pppoe_tag->value, (void *) &(c->host_uniq), sizeof (c->host_uniq));

      tags_len += sizeof (pppoe_tag_header_t) + sizeof (c->host_uniq);
      cursor += sizeof (pppoe_tag_header_t) + sizeof (c->host_uniq);
    }

    /* attach cookie for padr/pads. */
    if (cookie_len)
      {
	pppoe_tag_header_t *pppoe_tag = (pppoe_tag_header_t *) cursor;
	pppoe_tag->type = clib_host_to_net_u16 (PPPOE_TAG_AC_COOKIE);
	pppoe_tag->length = clib_host_to_net_u16 (cookie_len);
	clib_memcpy (cursor + sizeof (pppoe_tag_header_t), c->cookie_value, cookie_len);
	tags_len += sizeof (pppoe_tag_header_t) + cookie_len;
	cursor += sizeof (pppoe_tag_header_t) + cookie_len;
      }

    pppoe->length = clib_host_to_net_u16 (tags_len);
    b->current_length =
      pppoeclient_get_l2_encap_len (vnm, c->sw_if_index) + sizeof (pppoe_header_t) + tags_len;
  }

  vnet_buffer (b)->sw_if_index[VLIB_TX] = c->sw_if_index;

  /* Enqueue the packet right now */
  to_next = vlib_frame_vector_args (f);
  to_next[0] = bi;
  f->n_vectors = 1;

  vlib_put_frame_to_node (vm, hw->output_node_index, f);
  return 0;
}

/*
 * pppoeclient_output_ctrl_pkt - Send a PPP control packet directly to the
 * physical interface, bypassing the pppox-output → pppoeclient-session-output
 * path which does not work reliably from the main thread (process node
 * context).
 *
 * @pppox_sw_if_index: software interface index of the pppox virtual interface
 * @ppp_data: PPP payload (protocol field + data, no address/control)
 * @ppp_len: length of ppp_data
 */
__clib_export void
pppoeclient_output_ctrl_pkt (u32 pppox_sw_if_index, u8 *ppp_data, int ppp_len)
{
  pppoeclient_main_t *pem = &pppoeclient_main;
  vlib_main_t *vm = vlib_get_main ();
  vnet_main_t *vnm = pem->vnet_main;
  pppoeclient_t *c;
  vlib_buffer_t *b;
  u32 bi;
  pppoe_header_t *pppoe;
  u32 *to_next;
  vlib_frame_t *f;
  vnet_hw_interface_t *hw;
  u8 src_mac[6];

  c = pppoeclient_get_client_by_pppox_sw_if_index (pem, pppox_sw_if_index, 0);
  if (c == 0 || c->state != PPPOE_CLIENT_SESSION)
    return;

  hw = vnet_get_sup_hw_interface (vnm, c->sw_if_index);
  if (PREDICT_FALSE (hw == 0))
    return;

  if (vlib_buffer_alloc (vm, &bi, 1) != 1)
    return;

  b = vlib_get_buffer (vm, bi);
  ASSERT (b->current_data == 0);

  f = vlib_get_frame_to_node (vm, hw->output_node_index);

  /* Build complete PPPoE session frame: Ethernet + PPPoE + PPP payload.
   * Check total length BEFORE writing into the buffer. */
  u32 l2_len = pppoeclient_get_l2_encap_len (vnm, c->sw_if_index);
  u32 total_len = l2_len + sizeof (pppoe_header_t) + ppp_len;

  if (PREDICT_FALSE (total_len > vlib_buffer_get_default_data_size (vm)))
    {
      vlib_log (VLIB_LOG_LEVEL_WARNING, pppoeclient_log_class,
		"ctrl pkt too large (%u > %u), dropping", total_len,
		vlib_buffer_get_default_data_size (vm));
      vlib_buffer_free (vm, &bi, 1);
      vlib_frame_free (vm, f);
      return;
    }

  clib_memcpy (src_mac, hw->hw_address, 6);
  pppoe = pppoeclient_push_l2_header (vnm, c->sw_if_index, b, ETHERNET_TYPE_PPPOE_SESSION, src_mac,
				      c->ac_mac_address);
  pppoe->ver_type = PPPOE_VER_TYPE;
  pppoe->code = PPPOE_SESSION_DATA;
  pppoe->session_id = clib_host_to_net_u16 (c->session_id);
  pppoe->length = clib_host_to_net_u16 (ppp_len);

  clib_memcpy ((u8 *) (pppoe + 1), ppp_data, ppp_len);
  b->current_length = total_len;

  vnet_buffer (b)->sw_if_index[VLIB_TX] = c->sw_if_index;

  to_next = vlib_frame_vector_args (f);
  to_next[0] = bi;
  f->n_vectors = 1;

  vlib_put_frame_to_node (vm, hw->output_node_index, f);
}

/*
 * Stale-session cleanup is handled exclusively by pppoeclient_exit():
 * when VPP shuts down gracefully, the exit function reads the session file
 * and sends a raw PADT.  We intentionally do NOT send stale PADT at startup
 * because raw AF_PACKET requires the Linux interface to be UP, which breaks
 * RDMA ibverbs receive path when VPP is running.
 *
 * If VPP crashes (no exit function), stale sessions will be cleared by
 * BAS timeout, or the operator can use an external tool (e.g., iKuai)
 * to clear them before restarting VPP.
 */

static int
pppoeclient_discovery_state (pppoeclient_main_t *pem, pppoeclient_t *c, f64 now)
{
  /*
   * State machine "DISCOVERY" state. Send a PADI packet
   * with exponential back-off: 1s → 2s → 4s → 8s → 16s → 30s (cap).
   */
  if (send_pppoe_pkt (pem, c, PPPOE_PADI, 0, 1 /* is_broadcast */) != 0)
    {
      /* Link was down or the buffer pool was exhausted — nothing went on
       * the wire, so don't burn a retry slot.  Poll again in a second. */
      c->next_transmit = now + 1.0;
      return 0;
    }

  c->retry_count++;

  f64 backoff;
  if (c->retry_count <= 5)
    backoff = (f64) (1 << (c->retry_count - 1)); /* 1, 2, 4, 8, 16 */
  else
    backoff = 30.0; /* cap at 30s */

  c->next_transmit = now + backoff;
  return 0;
}

static int
pppoeclient_request_state (pppoeclient_main_t *pem, pppoeclient_t *c, f64 now)
{
  /*
   * State machine "REQUEST" state. Send a PADR packet
   * with back-off: 1s → 2s → 4s → 8s, then fall back to DISCOVERY.
   */
  if (send_pppoe_pkt (pem, c, PPPOE_PADR, 0, 0 /* is_broadcast */) != 0)
    {
      /* Same "didn't hit the wire" short-circuit as in DISCOVERY. */
      c->next_transmit = now + 1.0;
      return 0;
    }

  c->retry_count++;
  if (c->retry_count > 7)
    {
      c->state = PPPOE_CLIENT_DISCOVERY;
      c->next_transmit = now;
      c->retry_count = 0;
      return 1;
    }

  f64 backoff;
  if (c->retry_count <= 4)
    backoff = (f64) (1 << (c->retry_count - 1)); /* 1, 2, 4, 8 */
  else
    backoff = 8.0; /* cap at 8s for REQUEST */

  c->next_transmit = now + backoff;
  return 0;
}

static f64
pppoeclient_sm (f64 now, f64 timeout, uword pool_index)
{
  pppoeclient_main_t *pem = &pppoeclient_main;
  pppoeclient_t *c;

  /* Skip clients that have been freed from the pool. */
  if (pool_is_free_index (pem->clients, pool_index))
    return timeout;

  c = pool_elt_at_index (pem->clients, pool_index);

  /* Time for us to do something with this client? */
  if (now < c->next_transmit)
    {
      if (c->next_transmit < now + timeout)
	return c->next_transmit - now;
      return timeout;
    }

again:
  switch (c->state)
    {
    case PPPOE_CLIENT_DISCOVERY: /* send a discover */
      if (pppoeclient_discovery_state (pem, c, now))
	goto again;
      break;

    case PPPOE_CLIENT_REQUEST: /* send a request */
      if (pppoeclient_request_state (pem, c, now))
	goto again;
      break;

    case PPPOE_CLIENT_SESSION: /* session allocated */
      /* Nothing to be done here since we have set longest timeout. */
      break;

    default:
      vlib_log (VLIB_LOG_LEVEL_WARNING, pppoeclient_log_class, "client %d bogus state %d",
		c - pem->clients, c->state);
      break;
    }

  if (c->next_transmit < now + timeout)
    return c->next_transmit - now;

  return timeout;
}

static_always_inline void
pppoeclient_client_free_resources (pppoeclient_t *c)
{
  vec_free (c->ac_name);
  vec_free (c->ac_name_filter);
  vec_free (c->service_name);
  vec_free (c->username);
  if (c->password)
    clib_memset (c->password, 0, vec_len (c->password));
  vec_free (c->password);
  vec_free (c->cookie_value);
  vec_free (c->control_history);
}

static uword
pppoeclient_process (vlib_main_t *vm, vlib_node_runtime_t *rt, vlib_frame_t *f)
{
  f64 timeout = PPPOECLIENT_PROCESS_IDLE_TIMEOUT;
  f64 now;
  uword event_type;
  uword *event_data = 0;
  pppoeclient_main_t *pem = &pppoeclient_main;
  pppoeclient_t *c;
  int i;

  while (1)
    {
      vlib_process_wait_for_event_or_clock (vm, timeout);

      event_type = vlib_process_get_events (vm, &event_data);

      now = vlib_time_now (vm);
      timeout = PPPOECLIENT_PROCESS_IDLE_TIMEOUT;

      switch (event_type)
	{
	case EVENT_PPPOE_CLIENT_WAKEUP:
	  for (i = 0; i < vec_len (event_data); i++)
	    timeout = pppoeclient_sm (now, timeout, event_data[i]);
	  break;

	case ~0:
	  pool_foreach (c, pem->clients)
	    {
	      timeout = pppoeclient_sm (now, timeout, (uword) (c - pem->clients));
	    };
	  if (pool_elts (pem->clients) == 0)
	    timeout = PPPOECLIENT_PROCESS_IDLE_TIMEOUT;
	  break;
	}

      vec_reset_length (event_data);
    }

  /* NOTREACHED */
  return 0;
}

static_always_inline void
pppoeclient_wakeup (uword client_index)
{
  vlib_process_signal_event_mt (vlib_get_main (), pppoeclient_process_node.index,
				EVENT_PPPOE_CLIENT_WAKEUP, client_index);
}

static_always_inline void pppoeclient_cli_trim_c_string (u8 **s);
static void pppoeclient_record_control_event (pppoeclient_t *c, u8 code, u16 session_id,
					      const u8 *peer_mac,
					      pppoeclient_control_event_t *summary);
static void pppoeclient_record_orphan_control_event (pppoeclient_main_t *pem, u32 sw_if_index,
						     u8 code, u16 session_id, const u8 *peer_mac,
						     pppoeclient_control_event_t *summary);
__clib_export void
pppoeclient_set_auth (u32 client_index, u8 *username, u8 *password)
{
  pppoeclient_main_t *pem = &pppoeclient_main;
  pppoeclient_t *c;
  u8 *new_username = 0;
  u8 *new_password = 0;

  if (pool_is_free_index (pem->clients, client_index))
    return;

  c = pool_elt_at_index (pem->clients, client_index);

  if (username)
    {
      new_username = vec_dup (username);
      pppoeclient_cli_trim_c_string (&new_username);
    }
  if (password)
    {
      new_password = vec_dup (password);
      pppoeclient_cli_trim_c_string (&new_password);
    }

  vec_free (c->username);
  if (c->password)
    clib_memset (c->password, 0, vec_len (c->password));
  vec_free (c->password);
  c->username = new_username;
  c->password = new_password;
}

static_always_inline void
pppoeclient_cli_trim_c_string (u8 **s)
{
  if (s == 0 || *s == 0)
    return;

  if (vec_len (*s) > 0 && vec_elt (*s, vec_len (*s) - 1) == 0)
    vec_set_len (*s, vec_len (*s) - 1);
}

VLIB_REGISTER_NODE (pppoeclient_process_node, static) = {
  .function = pppoeclient_process,
  .type = VLIB_NODE_TYPE_PROCESS,
  .name = "pppoe-client-process",
  .process_log2_n_stack_bytes = 18,
};

int
parse_pppoe_packet (pppoe_header_t *pppoe, parse_func *func, void *extra)
{
  int len = clib_net_to_host_u16 (pppoe->length);
  unsigned char *payload, *cur_tag;
  u16 tag_type, tag_len;

  if (pppoe->ver_type != PPPOE_VER_TYPE)
    {
      return -1;
    }

  if (len > ETH_JUMBO_LEN - sizeof (pppoe_header_t))
    {
      return -1;
    }

  cur_tag = payload = (unsigned char *) (pppoe + 1);
  while (cur_tag - payload + sizeof (pppoe_tag_header_t) <= len)
    {
      tag_type = clib_net_to_host_u16 (clib_mem_unaligned (cur_tag, u16));
      tag_len = clib_net_to_host_u16 (clib_mem_unaligned (cur_tag + 2, u16));
      if (tag_type == PPPOE_TAG_END_OF_LIST)
	{
	  return 0;
	}

      if (tag_len > (u16) (len - (cur_tag - payload) - sizeof (pppoe_tag_header_t)))
	{
	  return -1;
	}
      func (tag_type, tag_len, cur_tag + sizeof (pppoe_tag_header_t), extra);
      cur_tag = cur_tag + sizeof (pppoe_tag_header_t) + tag_len;
    }

  return 0;
}

/* extra is not used for host uniq. */
void
parse_for_host_uniq (u16 type, u16 len, unsigned char *data, void *extra)
{
  u32 *host_uniq = (u32 *) extra;

  if (type == PPPOE_TAG_HOST_UNIQ && len == sizeof (u32))
    {
      /* as we send padi, we do not care about byte order. */
      clib_memcpy (host_uniq, data, len);
    }
}

void
parse_pado_tags (u16 type, u16 len, unsigned char *data, void *extra)
{
  pppoeclient_t *c = (pppoeclient_t *) extra;

  switch (type)
    {
    case PPPOE_TAG_SERVICE_NAME:
    case PPPOE_TAG_RELAY_SESSION_ID:
    case PPPOE_TAG_PPP_MAX_PAYLOAD:
      break;
    case PPPOE_TAG_SERVICE_NAME_ERROR:
      if (len > 0)
	vlib_log (VLIB_LOG_LEVEL_WARNING, pppoeclient_log_class, "Service-Name-Error: %.*s",
		  (int) len, data);
      c->discovery_error = PPPOECLIENT_ERROR_SERVICE_NAME_ERROR;
      break;
    case PPPOE_TAG_AC_SYSTEM_ERROR:
      if (len > 0)
	vlib_log (VLIB_LOG_LEVEL_WARNING, pppoeclient_log_class, "AC-System-Error: %.*s", (int) len,
		  data);
      c->discovery_error = PPPOECLIENT_ERROR_AC_SYSTEM_ERROR;
      break;
    case PPPOE_TAG_GENERIC_ERROR:
      if (len > 0)
	vlib_log (VLIB_LOG_LEVEL_WARNING, pppoeclient_log_class, "Generic-Error: %.*s", (int) len,
		  data);
      c->discovery_error = PPPOECLIENT_ERROR_GENERIC_ERROR;
      break;
    case PPPOE_TAG_AC_NAME:
      /* Record AC-Name for debug purposes */
      if (len > ETH_JUMBO_LEN)
	break; /* name too large, ignore */
      vec_free (c->ac_name);
      if (len > 0)
	{
	  vec_validate (c->ac_name, len - 1);
	  clib_memcpy (c->ac_name, data, len);
	}
      break;
    case PPPOE_TAG_AC_COOKIE:
      if (len > ETH_JUMBO_LEN)
	break; /* cookie too large, ignore */
      vec_reset_length (c->cookie_value);
      if (len > 0)
	{
	  vec_validate (c->cookie_value, len - 1);
	  clib_memcpy (c->cookie_value, data, len);
	}
      break;
    default:
      break;
    }
}

static void
parse_control_event_tags (u16 type, u16 len, unsigned char *data, void *extra)
{
  pppoeclient_control_event_t *event = extra;

  switch (type)
    {
    case PPPOE_TAG_HOST_UNIQ:
      if (len == sizeof (u32))
	{
	  event->host_uniq_present = 1;
	  clib_memcpy (&event->host_uniq, data, len);
	}
      break;
    case PPPOE_TAG_SERVICE_NAME:
      event->service_name_len = clib_min (len, (u16) PPPOECLIENT_CONTROL_SERVICE_NAME_LEN);
      if (event->service_name_len)
	clib_memcpy (event->service_name, data, event->service_name_len);
      event->service_name_truncated = (len > PPPOECLIENT_CONTROL_SERVICE_NAME_LEN);
      break;
    case PPPOE_TAG_AC_NAME:
      event->ac_name_len = clib_min (len, (u16) PPPOECLIENT_CONTROL_AC_NAME_LEN);
      if (event->ac_name_len)
	clib_memcpy (event->ac_name, data, event->ac_name_len);
      event->ac_name_truncated = (len > PPPOECLIENT_CONTROL_AC_NAME_LEN);
      break;
    case PPPOE_TAG_AC_COOKIE:
      event->cookie_len = len;
      event->cookie_value_len = clib_min (len, (u16) PPPOECLIENT_CONTROL_COOKIE_LEN);
      event->cookie_value_truncated = (len > PPPOECLIENT_CONTROL_COOKIE_LEN);
      if (event->cookie_value_len > 0)
	clib_memcpy (event->cookie_value, data, event->cookie_value_len);
      break;
    case PPPOE_TAG_SERVICE_NAME_ERROR:
    case PPPOE_TAG_AC_SYSTEM_ERROR:
    case PPPOE_TAG_GENERIC_ERROR:
      event->error_tag_type = type;
      break;
    default:
      break;
    }
}

static void
pppoeclient_control_event_capture_raw_tags (pppoeclient_control_event_t *event,
					    pppoe_header_t *pppoe, uword available_payload_len)
{
  u16 packet_payload_len;
  u16 copied_len;

  if (event == 0)
    return;

  /* Callers routinely derive available_payload_len as
   * b->current_length - sizeof(pppoe_header_t); if the buffer is shorter
   * than the PPPoE header that subtraction underflows into a huge uword
   * and we would memcpy out of bounds.  Any payload length larger than
   * a jumbo Ethernet frame is nonsensical for a discovery packet, so
   * treat it as "no payload available" rather than trust the caller. */
  if (available_payload_len > ETH_JUMBO_LEN)
    available_payload_len = 0;

  packet_payload_len = clib_net_to_host_u16 (pppoe->length);
  copied_len = clib_min ((u16) available_payload_len, packet_payload_len);
  copied_len = clib_min (copied_len, (u16) PPPOECLIENT_CONTROL_RAW_TAGS_LEN);

  if (copied_len > 0)
    clib_memcpy (event->raw_tags, (u8 *) (pppoe + 1), copied_len);

  event->raw_tags_len = copied_len;
  if (packet_payload_len > copied_len || available_payload_len < packet_payload_len)
    event->raw_tags_truncated = 1;
}

static void
pppoeclient_control_event_copy_summary (pppoeclient_control_event_t *dst,
					pppoeclient_control_event_t *src)
{
  if (src == 0 || dst == 0)
    return;

  dst->disposition = src->disposition;
  dst->client_state = src->client_state;
  dst->parse_error = src->parse_error;
  dst->match_reason = src->match_reason;
  dst->match_score = src->match_score;
  dst->candidate_count = src->candidate_count;
  dst->top_match_count = src->top_match_count;
  dst->top_match_reason = src->top_match_reason;
  dst->top_match_score = src->top_match_score;
  dst->host_uniq_present = src->host_uniq_present;
  dst->host_uniq = src->host_uniq;
  dst->cookie_len = src->cookie_len;
  dst->error_tag_type = src->error_tag_type;

  dst->ac_name_len = src->ac_name_len;
  dst->ac_name_truncated = src->ac_name_truncated;
  if (src->ac_name_len)
    clib_memcpy (dst->ac_name, src->ac_name, src->ac_name_len);

  dst->service_name_len = src->service_name_len;
  dst->service_name_truncated = src->service_name_truncated;
  if (src->service_name_len)
    clib_memcpy (dst->service_name, src->service_name, src->service_name_len);

  dst->cookie_value_len = src->cookie_value_len;
  dst->cookie_value_truncated = src->cookie_value_truncated;
  if (src->cookie_value_len)
    clib_memcpy (dst->cookie_value, src->cookie_value, src->cookie_value_len);

  dst->raw_tags_len = src->raw_tags_len;
  dst->raw_tags_truncated = src->raw_tags_truncated;
  if (src->raw_tags_len)
    clib_memcpy (dst->raw_tags, src->raw_tags, src->raw_tags_len);
}

void
pppoeclient_control_history_summary_accumulate (pppoeclient_control_history_summary_t *summary,
						pppoeclient_control_event_t *event)
{
  f64 now = vlib_time_now (pppoeclient_main.vlib_main);
  u32 age_msec = (u32) clib_max (0.0, (now - event->event_time) * 1000.0);

  if (summary->matched_events == 0)
    {
      summary->min_age_msec = age_msec;
      summary->max_age_msec = age_msec;
    }
  else
    {
      summary->min_age_msec = clib_min (summary->min_age_msec, age_msec);
      summary->max_age_msec = clib_max (summary->max_age_msec, age_msec);
    }

  summary->matched_events++;
  summary->max_match_score = clib_max (summary->max_match_score, (u32) event->match_score);
  summary->max_candidate_count =
    clib_max (summary->max_candidate_count, (u32) event->candidate_count);
  summary->max_top_match_score =
    clib_max (summary->max_top_match_score, (u32) event->top_match_score);
  summary->max_top_match_count =
    clib_max (summary->max_top_match_count, (u32) event->top_match_count);

  switch (event->code)
    {
    case PPPOE_PADO:
      summary->pado_count++;
      break;
    case PPPOE_PADS:
      summary->pads_count++;
      break;
    case PPPOE_PADT:
      summary->padt_count++;
      break;
    default:
      break;
    }

  switch (event->disposition)
    {
    case PPPOECLIENT_CONTROL_DISPOSITION_ACCEPTED:
      summary->accepted_count++;
      break;
    case PPPOECLIENT_CONTROL_DISPOSITION_IGNORED:
      summary->ignored_count++;
      break;
    case PPPOECLIENT_CONTROL_DISPOSITION_ERROR:
      summary->error_count++;
      break;
    case PPPOECLIENT_CONTROL_DISPOSITION_ORPHAN:
      summary->orphan_count++;
      break;
    default:
      break;
    }

  switch (event->client_state)
    {
    case PPPOECLIENT_CONTROL_CLIENT_STATE_DISCOVERY:
      summary->discovery_state_count++;
      break;
    case PPPOECLIENT_CONTROL_CLIENT_STATE_REQUEST:
      summary->request_state_count++;
      break;
    case PPPOECLIENT_CONTROL_CLIENT_STATE_SESSION:
      summary->session_state_count++;
      break;
    default:
      summary->unknown_state_count++;
      break;
    }

  switch (event->match_reason)
    {
    case PPPOECLIENT_CONTROL_MATCH_NONE:
      summary->match_none_count++;
      break;
    case PPPOECLIENT_CONTROL_MATCH_HOST_UNIQ:
      summary->match_host_uniq_count++;
      break;
    case PPPOECLIENT_CONTROL_MATCH_AC_NAME:
      summary->match_ac_name_count++;
      break;
    case PPPOECLIENT_CONTROL_MATCH_SERVICE_NAME:
      summary->match_service_name_count++;
      break;
    case PPPOECLIENT_CONTROL_MATCH_ANY:
      summary->match_any_count++;
      break;
    case PPPOECLIENT_CONTROL_MATCH_COOKIE:
      summary->match_cookie_count++;
      break;
    case PPPOECLIENT_CONTROL_MATCH_UNIQUE:
      summary->match_unique_count++;
      break;
    case PPPOECLIENT_CONTROL_MATCH_SESSION:
      summary->match_session_count++;
      break;
    case PPPOECLIENT_CONTROL_MATCH_AC_AND_SERVICE:
      summary->match_ac_and_service_count++;
      break;
    case PPPOECLIENT_CONTROL_MATCH_AC_MAC:
      summary->match_ac_mac_count++;
      break;
    case PPPOECLIENT_CONTROL_MATCH_AC_MAC_AND_SERVICE:
      summary->match_ac_mac_and_service_count++;
      break;
    case PPPOECLIENT_CONTROL_MATCH_COOKIE_AND_SERVICE:
      summary->match_cookie_and_service_count++;
      break;
    default:
      break;
    }

  switch (event->top_match_reason)
    {
    case PPPOECLIENT_CONTROL_MATCH_NONE:
      summary->top_match_none_count++;
      break;
    case PPPOECLIENT_CONTROL_MATCH_HOST_UNIQ:
      summary->top_match_host_uniq_count++;
      break;
    case PPPOECLIENT_CONTROL_MATCH_AC_NAME:
      summary->top_match_ac_name_count++;
      break;
    case PPPOECLIENT_CONTROL_MATCH_SERVICE_NAME:
      summary->top_match_service_name_count++;
      break;
    case PPPOECLIENT_CONTROL_MATCH_ANY:
      summary->top_match_any_count++;
      break;
    case PPPOECLIENT_CONTROL_MATCH_COOKIE:
      summary->top_match_cookie_count++;
      break;
    case PPPOECLIENT_CONTROL_MATCH_UNIQUE:
      summary->top_match_unique_count++;
      break;
    case PPPOECLIENT_CONTROL_MATCH_SESSION:
      summary->top_match_session_count++;
      break;
    case PPPOECLIENT_CONTROL_MATCH_AC_AND_SERVICE:
      summary->top_match_ac_and_service_count++;
      break;
    case PPPOECLIENT_CONTROL_MATCH_AC_MAC:
      summary->top_match_ac_mac_count++;
      break;
    case PPPOECLIENT_CONTROL_MATCH_AC_MAC_AND_SERVICE:
      summary->top_match_ac_mac_and_service_count++;
      break;
    case PPPOECLIENT_CONTROL_MATCH_COOKIE_AND_SERVICE:
      summary->top_match_cookie_and_service_count++;
      break;
    default:
      break;
    }

  if (event->top_match_count > 1)
    summary->ambiguous_events_count++;

  if (event->parse_error)
    summary->parse_error_count++;

  if (event->host_uniq_present)
    summary->host_uniq_present_count++;
  if (event->cookie_len)
    summary->cookie_present_count++;
  if (event->service_name_len)
    summary->service_name_count++;
  if (event->ac_name_len)
    summary->ac_name_count++;
  if (event->raw_tags_len)
    summary->raw_tags_count++;
  if (event->error_tag_type)
    summary->error_tag_count++;
  if (event->service_name_truncated)
    summary->service_name_truncated_count++;
  if (event->ac_name_truncated)
    summary->ac_name_truncated_count++;
  if (event->cookie_value_truncated)
    summary->cookie_value_truncated_count++;
  if (event->raw_tags_truncated)
    summary->raw_tags_truncated_count++;
}

void
pppoeclient_clear_control_history (pppoeclient_control_event_t *history, u8 *count, u8 *next)
{
  /* history can be NULL when a per-client vec was never allocated because no
   * event ever fired; the count / next trackers are still valid targets. */
  if (history)
    clib_memset (history, 0,
		 PPPOECLIENT_CONTROL_HISTORY_LEN * sizeof (pppoeclient_control_event_t));
  *count = 0;
  *next = 0;
}

static void
pppoeclient_control_history_summarize (pppoeclient_control_event_t *history, u8 count, u8 next,
				       pppoeclient_control_history_summary_t *summary)
{
  u8 i;
  u8 first;

  clib_memset (summary, 0, sizeof (*summary));
  if (count == 0)
    return;

  first = (next + PPPOECLIENT_CONTROL_HISTORY_LEN - count) % PPPOECLIENT_CONTROL_HISTORY_LEN;
  for (i = 0; i < count; i++)
    pppoeclient_control_history_summary_accumulate (
      summary, &history[(first + i) % PPPOECLIENT_CONTROL_HISTORY_LEN]);
}

static int
pppoeclient_control_event_matches_cli_filter (pppoeclient_control_event_t *event,
					      pppoeclient_history_cli_filter_t *filter)
{
  if (filter->filter_code && event->code != filter->code)
    return 0;

  if (filter->parse_errors_only && !event->parse_error)
    return 0;

  if (filter->filter_disposition && event->disposition != filter->disposition)
    return 0;

  if (filter->filter_match_reason && event->match_reason != filter->match_reason)
    return 0;

  return 1;
}

static u8
pppoeclient_collect_control_history_cli_matches (pppoeclient_control_event_t *history, u8 count,
						 u8 next, pppoeclient_history_cli_filter_t *filter,
						 u8 *match_indices)
{
  u8 i;
  u8 matched = 0;
  u8 first = (next + PPPOECLIENT_CONTROL_HISTORY_LEN - count) % PPPOECLIENT_CONTROL_HISTORY_LEN;

  for (i = 0; i < count; i++)
    {
      u8 index = (first + i) % PPPOECLIENT_CONTROL_HISTORY_LEN;
      if (!pppoeclient_control_event_matches_cli_filter (&history[index], filter))
	continue;
      match_indices[matched++] = index;
    }

  return matched;
}

static void
pppoeclient_print_control_history_summary (vlib_main_t *vm, const char *prefix, const char *label,
					   const pppoeclient_control_history_summary_t *summary)
{
  vlib_cli_output (vm,
		   "%s%s total %u age-window %u..%u ms accepted %u ignored %u error %u orphan %u "
		   "parse-error %u ambiguous %u",
		   prefix, label, summary->matched_events, summary->min_age_msec,
		   summary->max_age_msec, summary->accepted_count, summary->ignored_count,
		   summary->error_count, summary->orphan_count, summary->parse_error_count,
		   summary->ambiguous_events_count);
  vlib_cli_output (vm,
		   "%s%s codes pado %u pads %u padt %u states discovery %u request %u session %u "
		   "unknown %u",
		   prefix, label, summary->pado_count, summary->pads_count, summary->padt_count,
		   summary->discovery_state_count, summary->request_state_count,
		   summary->session_state_count, summary->unknown_state_count);
  vlib_cli_output (vm,
		   "%s%s fields host-uniq %u cookie %u service-name %u ac-name %u raw-tags %u "
		   "error-tag %u",
		   prefix, label, summary->host_uniq_present_count, summary->cookie_present_count,
		   summary->service_name_count, summary->ac_name_count, summary->raw_tags_count,
		   summary->error_tag_count);
  vlib_cli_output (vm,
		   "%s%s matches host-uniq %u session %u none %u any %u cookie %u unique %u "
		   "top-any %u top-host-uniq %u top-session %u",
		   prefix, label, summary->match_host_uniq_count, summary->match_session_count,
		   summary->match_none_count, summary->match_any_count, summary->match_cookie_count,
		   summary->match_unique_count, summary->top_match_any_count,
		   summary->top_match_host_uniq_count, summary->top_match_session_count);
  vlib_cli_output (vm, "%s%s max match-score %u candidates %u top-score %u top-count %u", prefix,
		   label, summary->max_match_score, summary->max_candidate_count,
		   summary->max_top_match_score, summary->max_top_match_count);
}

static void
pppoeclient_show_control_history_summary (vlib_main_t *vm, const char *prefix, const char *label,
					  pppoeclient_control_event_t *history, u8 count, u8 next)
{
  pppoeclient_control_history_summary_t summary;

  pppoeclient_control_history_summarize (history, count, next, &summary);
  if (summary.matched_events == 0)
    return;

  pppoeclient_print_control_history_summary (vm, prefix, label, &summary);
}

static void
pppoeclient_show_filtered_control_history_summary (vlib_main_t *vm, const char *prefix,
						   const char *label,
						   pppoeclient_control_event_t *history, u8 count,
						   u8 next,
						   pppoeclient_history_cli_filter_t *filter)
{
  pppoeclient_control_history_summary_t summary;
  u8 i, matched, send_start;
  u8 match_indices[PPPOECLIENT_CONTROL_HISTORY_LEN];

  matched =
    pppoeclient_collect_control_history_cli_matches (history, count, next, filter, match_indices);
  if (matched == 0)
    {
      vlib_cli_output (vm, "%s%s <empty>", prefix, label);
      return;
    }

  clib_memset (&summary, 0, sizeof (summary));
  send_start =
    (filter->max_events > 0 && matched > filter->max_events) ? (matched - filter->max_events) : 0;
  for (i = send_start; i < matched; i++)
    pppoeclient_control_history_summary_accumulate (&summary, &history[match_indices[i]]);

  pppoeclient_print_control_history_summary (vm, prefix, label, &summary);
}

static void
pppoeclient_show_control_history_entries (vlib_main_t *vm, const char *prefix, const char *label,
					  pppoeclient_control_event_t *history, u8 count, u8 next,
					  u8 show_sw_if_index)
{
  f64 now = vlib_time_now (vm);
  u8 i;
  u8 first;

  if (count == 0)
    return;

  first = (next + PPPOECLIENT_CONTROL_HISTORY_LEN - count) % PPPOECLIENT_CONTROL_HISTORY_LEN;
  vlib_cli_output (vm, "%s%s", prefix, label);
  for (i = 0; i < count; i++)
    {
      pppoeclient_control_event_t *event = &history[(first + i) % PPPOECLIENT_CONTROL_HISTORY_LEN];
      u8 *ac_name = 0;
      u8 *service_name = 0;

      if (event->ac_name_len)
	ac_name = format (0, "%.*s%s", event->ac_name_len, event->ac_name,
			  event->ac_name_truncated ? "..." : "");
      else
	ac_name = format (0, "<none>");

      if (event->service_name_len)
	service_name = format (0, "%.*s%s", event->service_name_len, event->service_name,
			       event->service_name_truncated ? "..." : "");
      else
	service_name = format (0, "<none>");

      if (show_sw_if_index)
	vlib_cli_output (
	  vm,
	  "%s  age %.2fs %U sw-if-index %u client-state %U peer %U session-id %u disposition %U "
	  "match %U score %u candidates %u top %U x%u score %u host-uniq %U service-name %v "
	  "ac-name %v cookie-len %u error-tag 0x%04x parse-error %u",
	  prefix, now - event->event_time, format_pppoe_packet_code_name, event->code,
	  event->sw_if_index, format_pppoeclient_control_client_state, event->client_state,
	  format_ethernet_address, event->peer_mac, event->session_id,
	  format_pppoeclient_control_disposition, event->disposition,
	  format_pppoeclient_control_match_reason, event->match_reason, event->match_score,
	  event->candidate_count, format_pppoeclient_control_match_reason, event->top_match_reason,
	  event->top_match_count, event->top_match_score, format_pppoeclient_control_host_uniq,
	  event->host_uniq, event->host_uniq_present, service_name, ac_name, event->cookie_len,
	  event->error_tag_type, event->parse_error);
      else
	vlib_cli_output (
	  vm,
	  "%s  age %.2fs %U client-state %U peer %U session-id %u disposition %U match %U score "
	  "%u candidates %u top %U x%u score %u host-uniq %U service-name %v ac-name %v "
	  "cookie-len %u error-tag 0x%04x parse-error %u",
	  prefix, now - event->event_time, format_pppoe_packet_code_name, event->code,
	  format_pppoeclient_control_client_state, event->client_state, format_ethernet_address,
	  event->peer_mac, event->session_id, format_pppoeclient_control_disposition,
	  event->disposition, format_pppoeclient_control_match_reason, event->match_reason,
	  event->match_score, event->candidate_count, format_pppoeclient_control_match_reason,
	  event->top_match_reason, event->top_match_count, event->top_match_score,
	  format_pppoeclient_control_host_uniq, event->host_uniq, event->host_uniq_present,
	  service_name, ac_name, event->cookie_len, event->error_tag_type, event->parse_error);

      if (event->raw_tags_len)
	vlib_cli_output (vm, "%s    raw-tags %U%s", prefix, format_hex_bytes, event->raw_tags,
			 event->raw_tags_len, event->raw_tags_truncated ? " ..." : "");
      vec_free (ac_name);
      vec_free (service_name);
    }
}

static void
pppoeclient_show_filtered_control_history_entries (vlib_main_t *vm, const char *prefix,
						   const char *label,
						   pppoeclient_control_event_t *history, u8 count,
						   u8 next, u8 show_sw_if_index,
						   pppoeclient_history_cli_filter_t *filter)
{
  f64 now = vlib_time_now (vm);
  u8 i, matched, send_start;
  u8 match_indices[PPPOECLIENT_CONTROL_HISTORY_LEN];

  matched =
    pppoeclient_collect_control_history_cli_matches (history, count, next, filter, match_indices);
  if (matched == 0)
    return;

  vlib_cli_output (vm, "%s%s", prefix, label);
  send_start =
    (filter->max_events > 0 && matched > filter->max_events) ? (matched - filter->max_events) : 0;
  for (i = send_start; i < matched; i++)
    {
      pppoeclient_control_event_t *event = &history[match_indices[i]];
      u8 *ac_name = 0;
      u8 *service_name = 0;

      if (event->ac_name_len)
	ac_name = format (0, "%.*s%s", event->ac_name_len, event->ac_name,
			  event->ac_name_truncated ? "..." : "");
      else
	ac_name = format (0, "<none>");

      if (event->service_name_len)
	service_name = format (0, "%.*s%s", event->service_name_len, event->service_name,
			       event->service_name_truncated ? "..." : "");
      else
	service_name = format (0, "<none>");

      if (show_sw_if_index)
	vlib_cli_output (
	  vm,
	  "%s  age %.2fs %U sw-if-index %u client-state %U peer %U session-id %u disposition %U "
	  "match %U score %u candidates %u top %U x%u score %u host-uniq %U service-name %v "
	  "ac-name %v cookie-len %u error-tag 0x%04x parse-error %u",
	  prefix, now - event->event_time, format_pppoe_packet_code_name, event->code,
	  event->sw_if_index, format_pppoeclient_control_client_state, event->client_state,
	  format_ethernet_address, event->peer_mac, event->session_id,
	  format_pppoeclient_control_disposition, event->disposition,
	  format_pppoeclient_control_match_reason, event->match_reason, event->match_score,
	  event->candidate_count, format_pppoeclient_control_match_reason, event->top_match_reason,
	  event->top_match_count, event->top_match_score, format_pppoeclient_control_host_uniq,
	  event->host_uniq, event->host_uniq_present, service_name, ac_name, event->cookie_len,
	  event->error_tag_type, event->parse_error);
      else
	vlib_cli_output (
	  vm,
	  "%s  age %.2fs %U client-state %U peer %U session-id %u disposition %U match %U score "
	  "%u candidates %u top %U x%u score %u host-uniq %U service-name %v ac-name %v "
	  "cookie-len %u error-tag 0x%04x parse-error %u",
	  prefix, now - event->event_time, format_pppoe_packet_code_name, event->code,
	  format_pppoeclient_control_client_state, event->client_state, format_ethernet_address,
	  event->peer_mac, event->session_id, format_pppoeclient_control_disposition,
	  event->disposition, format_pppoeclient_control_match_reason, event->match_reason,
	  event->match_score, event->candidate_count, format_pppoeclient_control_match_reason,
	  event->top_match_reason, event->top_match_count, event->top_match_score,
	  format_pppoeclient_control_host_uniq, event->host_uniq, event->host_uniq_present,
	  service_name, ac_name, event->cookie_len, event->error_tag_type, event->parse_error);

      if (event->raw_tags_len)
	vlib_cli_output (vm, "%s    raw-tags %U%s", prefix, format_hex_bytes, event->raw_tags,
			 event->raw_tags_len, event->raw_tags_truncated ? " ..." : "");
      vec_free (ac_name);
      vec_free (service_name);
    }
}

static void
pppoeclient_record_control_event (pppoeclient_t *c, u8 code, u16 session_id, const u8 *peer_mac,
				  pppoeclient_control_event_t *summary)
{
  pppoeclient_main_t *pem = &pppoeclient_main;
  pppoeclient_control_event_t *event;
  u8 index;

  if (!c->control_history)
    vec_validate (c->control_history, PPPOECLIENT_CONTROL_HISTORY_LEN - 1);

  index = c->control_history_next % PPPOECLIENT_CONTROL_HISTORY_LEN;
  event = &c->control_history[index];
  clib_memset (event, 0, sizeof (*event));

  event->sw_if_index = c->sw_if_index;
  event->event_time = vlib_time_now (pem->vlib_main);
  event->code = code;
  event->session_id = session_id;
  if (peer_mac)
    clib_memcpy (event->peer_mac, peer_mac, sizeof (event->peer_mac));
  if (summary)
    pppoeclient_control_event_copy_summary (event, summary);
  /* The caller's summary is zero-initialized for fields it doesn't set
   * (e.g. the malformed-discovery path), so assign client_state after the
   * copy so that a live client's actual state wins over a summary default. */
  event->client_state = pppoeclient_control_client_state_from_client_state (c->state);

  c->control_history_next = (index + 1) % PPPOECLIENT_CONTROL_HISTORY_LEN;
  if (c->control_history_count < PPPOECLIENT_CONTROL_HISTORY_LEN)
    c->control_history_count++;
}

static void
pppoeclient_record_orphan_control_event (pppoeclient_main_t *pem, u32 sw_if_index, u8 code,
					 u16 session_id, const u8 *peer_mac,
					 pppoeclient_control_event_t *summary)
{
  pppoeclient_control_event_t *event;
  u8 index;

  index = pem->orphan_control_history_next % PPPOECLIENT_CONTROL_HISTORY_LEN;
  event = &pem->orphan_control_history[index];
  clib_memset (event, 0, sizeof (*event));

  event->sw_if_index = sw_if_index;
  event->event_time = vlib_time_now (pem->vlib_main);
  event->code = code;
  event->session_id = session_id;
  if (peer_mac)
    clib_memcpy (event->peer_mac, peer_mac, sizeof (event->peer_mac));
  if (summary)
    pppoeclient_control_event_copy_summary (event, summary);
  /* Orphan events have no owning client; pin client_state to UNKNOWN after
   * copy_summary so a stray non-zero value in the caller's summary cannot
   * mislabel it (symmetric with the client-bound path above). */
  event->client_state = PPPOECLIENT_CONTROL_CLIENT_STATE_UNKNOWN;

  /* disposition classifies packet fate along the ownership axis and is pinned
   * to ORPHAN here on purpose.  Malformedness is an orthogonal property that
   * the caller conveys via event_summary->parse_error (copied above) and that
   * "parse-errors-only" filters on independently, so a malformed orphan shows
   * up under both "disposition orphan" and "parse-errors-only" without losing
   * either axis.  Do not replace this with the caller's disposition; that
   * would make ERROR win for malformed discovery orphans and hide them from
   * the ORPHAN filter. */
  event->disposition = PPPOECLIENT_CONTROL_DISPOSITION_ORPHAN;

  pem->orphan_control_history_next = (index + 1) % PPPOECLIENT_CONTROL_HISTORY_LEN;
  if (pem->orphan_control_history_count < PPPOECLIENT_CONTROL_HISTORY_LEN)
    pem->orphan_control_history_count++;
}

static void
pppoeclient_update_latest_control_disposition (pppoeclient_t *c,
					       pppoeclient_control_disposition_t disposition)
{
  pppoeclient_control_event_t *event;
  u8 index;

  if (c == 0 || c->control_history_count == 0)
    return;

  index = (c->control_history_next + PPPOECLIENT_CONTROL_HISTORY_LEN - 1) %
	  PPPOECLIENT_CONTROL_HISTORY_LEN;
  event = &c->control_history[index];
  event->disposition = disposition;
}

static pppoeclient_t *
pppoeclient_find_unique_candidate (pppoeclient_main_t *pem, u32 sw_if_index,
				   pppoeclient_state_t expected_state, const u8 *peer_mac)
{
  pppoeclient_t *candidate = 0;
  pppoeclient_t *it;

  pool_foreach (it, pem->clients)
    {
      if (it->sw_if_index != sw_if_index || it->state != expected_state)
	continue;
      if (peer_mac && clib_memcmp (it->ac_mac_address, peer_mac, sizeof (it->ac_mac_address)) != 0)
	continue;

      if (candidate)
	return 0;

      candidate = it;
    }

  return candidate;
}

static void
pppoeclient_record_malformed_discovery_event (pppoeclient_main_t *pem, u8 packet_code,
					      u32 sw_if_index, pppoe_header_t *pppoe,
					      vlib_buffer_t *b)
{
  pppoeclient_control_event_t event_summary;
  pppoeclient_t *malformed_client = 0;
  ethernet_header_t *eth_hdr;
  pppoeclient_state_t expected_state =
    (packet_code == PPPOE_PADO) ? PPPOE_CLIENT_DISCOVERY : PPPOE_CLIENT_REQUEST;

  clib_memset (&event_summary, 0, sizeof (event_summary));
  event_summary.disposition = PPPOECLIENT_CONTROL_DISPOSITION_ERROR;
  event_summary.parse_error = 1;
  pppoeclient_control_event_capture_raw_tags (&event_summary, pppoe,
					      b->current_length - sizeof (*pppoe));

  vlib_buffer_reset (b);
  eth_hdr = vlib_buffer_get_current (b);

  if (packet_code == PPPOE_PADS)
    malformed_client =
      pppoeclient_find_unique_candidate (pem, sw_if_index, expected_state, eth_hdr->src_address);

  if (malformed_client == 0)
    malformed_client = pppoeclient_find_unique_candidate (pem, sw_if_index, expected_state, 0);

  if (malformed_client)
    {
      pppoeclient_record_control_event (malformed_client, packet_code,
					clib_net_to_host_u16 (pppoe->session_id),
					eth_hdr->src_address, &event_summary);
      return;
    }

  pppoeclient_record_orphan_control_event (pem, sw_if_index, packet_code,
					   clib_net_to_host_u16 (pppoe->session_id),
					   eth_hdr->src_address, &event_summary);
}

static int
pppoeclient_parse_and_record_client_control_event (pppoeclient_t *c, u8 packet_code,
						   pppoe_header_t *pppoe, vlib_buffer_t *b,
						   pppoeclient_control_event_t *event_summary,
						   ethernet_header_t **eth_hdr)
{
  int parse_result;
  u16 session_id = (packet_code == PPPOE_PADO) ? 0 : clib_net_to_host_u16 (pppoe->session_id);
  pppoeclient_control_event_t preserved = { 0 };

  if (event_summary)
    {
      preserved.disposition = event_summary->disposition;
      preserved.match_reason = event_summary->match_reason;
      preserved.match_score = event_summary->match_score;
      preserved.candidate_count = event_summary->candidate_count;
      preserved.top_match_count = event_summary->top_match_count;
      preserved.top_match_reason = event_summary->top_match_reason;
      preserved.top_match_score = event_summary->top_match_score;
    }

  clib_memset (event_summary, 0, sizeof (*event_summary));
  event_summary->disposition = preserved.disposition;
  event_summary->match_reason = preserved.match_reason;
  event_summary->match_score = preserved.match_score;
  event_summary->candidate_count = preserved.candidate_count;
  event_summary->top_match_count = preserved.top_match_count;
  event_summary->top_match_reason = preserved.top_match_reason;
  event_summary->top_match_score = preserved.top_match_score;
  pppoeclient_control_event_capture_raw_tags (event_summary, pppoe,
					      b->current_length - sizeof (*pppoe));
  parse_result = parse_pppoe_packet (pppoe, parse_control_event_tags, event_summary);
  vlib_buffer_reset (b);
  *eth_hdr = vlib_buffer_get_current (b);

  if (parse_result < 0)
    {
      event_summary->parse_error = 1;
      pppoeclient_record_control_event (c, packet_code, session_id, (*eth_hdr)->src_address,
					event_summary);
      return parse_result;
    }

  pppoeclient_record_control_event (c, packet_code, session_id, (*eth_hdr)->src_address,
				    event_summary);
  return 0;
}

int
consume_pppoe_discovery_pkt (u32 bi, vlib_buffer_t *b, pppoe_header_t *pppoe)
{
  pppoeclient_main_t *pem = &pppoeclient_main;
  pppoeclient_t *c;
  f64 now = vlib_time_now (pem->vlib_main);
  u32 sw_if_index = ~0;
  u32 host_uniq = 0;
  pppoeclient_result_t result;
  u8 packet_code;
  ethernet_header_t *eth_hdr = 0;
  uword client_id = ~0;
  int parse_result;
  pppoeclient_control_event_t event_summary = { 0 };
  static void (*pppox_lower_up_func) (u32) = 0;
  static void (*pppox_lower_down_func) (u32) = 0;

  /* for pado/pads we locate client through sw_if_index+host_uniq.
   * for padt we locate the established session through ingress if + AC MAC + session id. */
  packet_code = pppoe->code;
  switch (pppoe->code)
    {
    case PPPOE_PADO:
    case PPPOE_PADS: /* for pads, we still have to lookup client by sw_if_index and host_uniq. */
      sw_if_index = vnet_buffer (b)->sw_if_index[VLIB_RX];
      parse_result = parse_pppoe_packet (pppoe, parse_for_host_uniq, &host_uniq);
      if (parse_result < 0)
	{
	  pppoeclient_record_malformed_discovery_event (pem, packet_code, sw_if_index, pppoe, b);
	  return PPPOECLIENT_ERROR_MALFORMED_TAGS;
	}
      pppoeclient_lookup_1 (&pem->client_table, sw_if_index, host_uniq, &result);
      if (PREDICT_FALSE (result.fields.client_index == ~0))
	{
	  /* Some BAS implementations (common in China) do not echo the
	   * Host-Uniq tag in PADO/PADS.  When host_uniq is 0 (meaning
	   * the tag was absent or unparseable), fall back to a linear
	   * scan: find the single client on this interface that is in
	   * the expected state for the incoming packet type.
	   *   - PADO → client should be in DISCOVERY
	   *   - PADS → client should be in REQUEST
	   * If multiple candidates exist we bail out to avoid misrouting.
	   */
	  if (host_uniq == 0)
	    {
	      pppoeclient_fallback_selection_t selection;

	      clib_memset (&event_summary, 0, sizeof (event_summary));
	      pppoeclient_control_event_capture_raw_tags (&event_summary, pppoe,
							  b->current_length - sizeof (*pppoe));
	      parse_result = parse_pppoe_packet (pppoe, parse_control_event_tags, &event_summary);
	      if (parse_result < 0)
		{
		  pppoeclient_record_malformed_discovery_event (pem, packet_code, sw_if_index,
								pppoe, b);
		  return PPPOECLIENT_ERROR_MALFORMED_TAGS;
		}

	      if (pppoe->code == PPPOE_PADS)
		{
		  vlib_buffer_reset (b);
		  eth_hdr = vlib_buffer_get_current (b);
		}

	      c = pppoeclient_select_hostuniqless_candidate (
		pem, pppoe->code, sw_if_index,
		(pppoe->code == PPPOE_PADS) ? eth_hdr->src_address : 0, &event_summary, &selection);

	      pppoeclient_fill_fallback_selection_summary (&event_summary, &selection);

	      if (c)
		{
		  event_summary.match_reason = selection.selected_reason;
		  event_summary.match_score = selection.selected_score;
		  result.fields.client_index = c - pem->clients;
		  break;
		}

	      vlib_buffer_reset (b);
	      eth_hdr = vlib_buffer_get_current (b);
	      pppoeclient_record_orphan_control_event (pem, sw_if_index, packet_code,
						       clib_net_to_host_u16 (pppoe->session_id),
						       eth_hdr->src_address, &event_summary);
	    }

	  return PPPOECLIENT_ERROR_NO_SUCH_CLIENT;
	}

      /* client may be freed by interface type change */
      if (pool_is_free_index (pem->clients, result.fields.client_index))
	{
	  return PPPOECLIENT_ERROR_NO_SUCH_CLIENT;
	}

      c = pool_elt_at_index (pem->clients, result.fields.client_index);
      pppoeclient_fill_direct_match_summary (&event_summary, PPPOECLIENT_CONTROL_MATCH_HOST_UNIQ);
      break;
    case PPPOE_PADT:
      vlib_buffer_reset (b);
      eth_hdr = vlib_buffer_get_current (b);
      pppoeclient_lookup_session_1 (&pem->session_table, vnet_buffer (b)->sw_if_index[VLIB_RX],
				    eth_hdr->src_address, clib_net_to_host_u16 (pppoe->session_id),
				    &result);
      if (result.fields.client_index == ~0)
	{
	  clib_memset (&event_summary, 0, sizeof (event_summary));
	  pppoeclient_record_orphan_control_event (
	    pem, vnet_buffer (b)->sw_if_index[VLIB_RX], packet_code,
	    clib_net_to_host_u16 (pppoe->session_id), eth_hdr->src_address, &event_summary);
	  return PPPOECLIENT_ERROR_NO_SUCH_SESSION;
	}

      /* client may be freed by interface type change */
      if (pool_is_free_index (pem->clients, result.fields.client_index))
	{
	  return PPPOECLIENT_ERROR_NO_SUCH_SESSION;
	}

      c = pool_elt_at_index (pem->clients, result.fields.client_index);
      clib_memset (&event_summary, 0, sizeof (event_summary));
      pppoeclient_fill_direct_match_summary (&event_summary, PPPOECLIENT_CONTROL_MATCH_SESSION);
      break;
    default:
      return PPPOECLIENT_ERROR_BAD_CODE_IN_DISCOVERY;
    }

  switch (c->state)
    {
    case PPPOE_CLIENT_DISCOVERY:
      if (packet_code != PPPOE_PADO)
	{
	  c->next_transmit = now + PPPOECLIENT_UNEXPECTED_PKT_COOLDOWN;
	  break;
	}

      /* Zero old cookie before reuse to avoid leaking stale bytes. */
      clib_memset (c->cookie_value, 0, vec_len (c->cookie_value));
      vec_reset_length (c->cookie_value);
      vec_free (c->ac_name);
      c->discovery_error = 0;
      parse_result = pppoeclient_parse_and_record_client_control_event (c, packet_code, pppoe, b,
									&event_summary, &eth_hdr);
      if (parse_result < 0)
	return PPPOECLIENT_ERROR_MALFORMED_TAGS;
      parse_result = parse_pppoe_packet (pppoe, parse_pado_tags, c);
      if (parse_result < 0)
	return PPPOECLIENT_ERROR_MALFORMED_TAGS;

      /* Drop PADO that carried an error tag (RFC 2516 §5.4) */
      if (c->discovery_error)
	{
	  pppoeclient_update_latest_control_disposition (c, PPPOECLIENT_CONTROL_DISPOSITION_ERROR);
	  return c->discovery_error;
	}

      if (c->ac_name_filter &&
	  ((c->ac_name == 0) || (vec_len (c->ac_name_filter) != vec_len (c->ac_name)) ||
	   clib_memcmp (c->ac_name_filter, c->ac_name, vec_len (c->ac_name_filter)) != 0))
	{
	  pppoeclient_update_latest_control_disposition (c,
							 PPPOECLIENT_CONTROL_DISPOSITION_IGNORED);
	  break;
	}

      if (c->service_name && (event_summary.service_name_len != vec_len (c->service_name) ||
			      clib_memcmp (c->service_name, event_summary.service_name,
					   event_summary.service_name_len) != 0))
	{
	  pppoeclient_update_latest_control_disposition (c,
							 PPPOECLIENT_CONTROL_DISPOSITION_IGNORED);
	  break;
	}

      vlib_buffer_reset (b);
      eth_hdr = vlib_buffer_get_current (b);

      /* Record the selected AC MAC address for the PADR/session stages. */
      clib_memcpy (c->ac_mac_address, eth_hdr->src_address, 6);

      c->state = PPPOE_CLIENT_REQUEST;
      c->retry_count = 0;
      c->next_transmit = 0; /* send immediately. */
      /* Poke the client process, which will send the request */
      client_id = c - pem->clients;
      pppoeclient_wakeup (client_id);
      pppoeclient_update_latest_control_disposition (c, PPPOECLIENT_CONTROL_DISPOSITION_ACCEPTED);
      break;
    case PPPOE_CLIENT_REQUEST:
      if (packet_code == PPPOE_PADO)
	{
	  /*
	   * Once REQUEST has started we have already selected an AC and sent a
	   * PADR. Late or duplicate PADO packets should not trigger an immediate
	   * retransmit, otherwise a noisy AC can spuriously accelerate PADR
	   * retries. If PADS never arrives the existing REQUEST back-off timer
	   * will drive the next PADR send.
	   *
	   * PADOs that originate from the *selected* AC are true duplicates and
	   * we drop them silently without polluting the control-history ring.
	   * PADOs from a *different* AC (stray offers racing the PADR exchange)
	   * get parsed and logged with disposition=IGNORED so operators can see
	   * them, and bump a dedicated node error counter for visibility. They
	   * still never drive a PADR — only the cool-down timer does.
	   */
	  vlib_buffer_reset (b);
	  eth_hdr = vlib_buffer_get_current (b);
	  if (clib_memcmp (eth_hdr->src_address, c->ac_mac_address, sizeof (c->ac_mac_address)) ==
	      0)
	    break;

	  parse_result = pppoeclient_parse_and_record_client_control_event (
	    c, packet_code, pppoe, b, &event_summary, &eth_hdr);
	  if (parse_result < 0)
	    return PPPOECLIENT_ERROR_MALFORMED_TAGS;
	  pppoeclient_update_latest_control_disposition (c,
							 PPPOECLIENT_CONTROL_DISPOSITION_IGNORED);
	  return PPPOECLIENT_ERROR_REQUEST_UNSELECTED_AC_PADO;
	}

      if (packet_code != PPPOE_PADS)
	{
	  /* Any remaining control code lands here. PPPOE_PADT is the only
	   * other entry point that consume_pppoe_discovery_pkt() dispatches
	   * into switch(c->state), and PADT lookup goes through the session
	   * table: a match only exists once pppoeclient_update_session_1()
	   * has inserted the session id (see PADS handling below), which
	   * happens immediately before c->state transitions to SESSION.
	   * REQUEST + PADT is therefore unreachable today; we fall through
	   * to a short cool-down so any future caller that invents a new
	   * control code does not hot-spin the state machine. */
	  c->next_transmit = now + PPPOECLIENT_UNEXPECTED_PKT_COOLDOWN;
	  break;
	}

      parse_result = pppoeclient_parse_and_record_client_control_event (c, packet_code, pppoe, b,
									&event_summary, &eth_hdr);
      if (parse_result < 0)
	return PPPOECLIENT_ERROR_MALFORMED_TAGS;

      /*
       * REQUEST is bound to the AC selected from the accepted PADO. Ignore a
       * PADS that arrives from a different source MAC so a stray offer cannot
       * complete the session for the wrong AC.
       */
      vlib_buffer_reset (b);
      eth_hdr = vlib_buffer_get_current (b);
      if (clib_memcmp (eth_hdr->src_address, c->ac_mac_address, sizeof (c->ac_mac_address)) != 0)
	{
	  pppoeclient_update_latest_control_disposition (c,
							 PPPOECLIENT_CONTROL_DISPOSITION_IGNORED);
	  break;
	}

      if (c->service_name && (event_summary.service_name_len != vec_len (c->service_name) ||
			      clib_memcmp (c->service_name, event_summary.service_name,
					   event_summary.service_name_len) != 0))
	{
	  pppoeclient_update_latest_control_disposition (c,
							 PPPOECLIENT_CONTROL_DISPOSITION_IGNORED);
	  break;
	}

      /* Check for error tags in PADS (RFC 2516 §5.4) */
      c->discovery_error = 0;
      parse_result = parse_pppoe_packet (pppoe, parse_pado_tags, c);
      if (parse_result < 0)
	return PPPOECLIENT_ERROR_MALFORMED_TAGS;
      if (c->discovery_error)
	{
	  pppoeclient_update_latest_control_disposition (c, PPPOECLIENT_CONTROL_DISPOSITION_ERROR);
	  c->state = PPPOE_CLIENT_DISCOVERY;
	  c->retry_count = 0;
	  c->next_transmit = now + PPPOECLIENT_UNEXPECTED_PKT_COOLDOWN;
	  return c->discovery_error;
	}

      c->session_id = clib_net_to_host_u16 (pppoe->session_id);
      /* RFC 2516 says session id MUST NOT be zero or 0xFFFF. */
      if (c->session_id == 0 || c->session_id == 0xFFFF)
	{
	  /* session_id 0 means the client is not accepted by AC,
	   * turn to retransmit hoping the AC will accept us. */
	  pppoeclient_update_latest_control_disposition (c, PPPOECLIENT_CONTROL_DISPOSITION_ERROR);
	  c->session_id = 0;
	  c->next_transmit = now + PPPOECLIENT_UNEXPECTED_PKT_COOLDOWN;
	  return PPPOECLIENT_ERROR_INVALID_SESSION_ID;
	}

      pppoeclient_lookup_session_1 (&pem->session_table, c->sw_if_index, c->ac_mac_address,
				    c->session_id, &result);
      if (PREDICT_FALSE (result.fields.client_index != ~0))
	{
	  /* the session id is used by other client, turn to
	   * request state to fetch a new session id. */
	  pppoeclient_update_latest_control_disposition (c, PPPOECLIENT_CONTROL_DISPOSITION_ERROR);
	  c->session_id = 0;
	  c->state = PPPOE_CLIENT_REQUEST;
	  c->retry_count = 0;
	  c->next_transmit = 0; /* send immediately. */
	  return PPPOECLIENT_ERROR_SESSION_ID_COLLISION;
	}
      result.fields.client_index = c - pem->clients;
      pppoeclient_update_session_1 (&pem->session_table, c->sw_if_index, c->ac_mac_address,
				    c->session_id, &result);
      c->state = PPPOE_CLIENT_SESSION;
      c->session_start_time = now;
      /* A fresh PPPoE session means the BAS has (again) admitted us, so the
       * previous auth-failure streak no longer reflects current reality. */
      c->consecutive_auth_failures = 0;
      pppoeclient_save_session_to_file (c);
      /* when shift to session stage, just give control to user
       * and ppp control plane. */
      c->next_transmit = PPPOECLIENT_NEXT_TRANSMIT_PARKED;
      pppoeclient_update_latest_control_disposition (c, PPPOECLIENT_CONTROL_DISPOSITION_ACCEPTED);
      /* notify pppoe session up. */
      PPPOECLIENT_LAZY_PLUGIN_SYMBOL (pppox_lower_up_func, "pppoeclient_plugin.so",
				      "pppox_lower_up");
      if (pppox_lower_up_func == 0)
	{
	  /* The last-recorded PADS was marked ACCEPTED above because the PPPoE
	   * side did admit us; flip it to ERROR so operators inspecting the
	   * control history see that the session was not actually brought up. */
	  pppoeclient_update_latest_control_disposition (c, PPPOECLIENT_CONTROL_DISPOSITION_ERROR);
	  pppoeclient_delete_session_1 (&pem->session_table, c->sw_if_index, c->ac_mac_address,
					c->session_id);
	  c->session_id = 0;
	  pppoeclient_clear_runtime_state (c);
	  /* Roll back the SESSION-entry timestamp so pppoeclient_teardown_session
	   * doesn't later treat this aborted attempt as a real SESSION lifetime. */
	  c->session_start_time = 0;
	  c->state = PPPOE_CLIENT_DISCOVERY;
	  c->retry_count = 0;
	  c->next_transmit = now;
	  client_id = c - pem->clients;
	  pppoeclient_wakeup (client_id);
	  return PPPOECLIENT_ERROR_PPPOX_PLUGIN_MISSING;
	}
      (*pppox_lower_up_func) (c->pppox_sw_if_index);
      break;

    case PPPOE_CLIENT_SESSION:
      if (pppoe->code != PPPOE_PADT)
	{
	  break;
	}
      vlib_buffer_reset (b);
      eth_hdr = vlib_buffer_get_current (b);
      pppoeclient_record_control_event (c, packet_code, clib_net_to_host_u16 (pppoe->session_id),
					eth_hdr->src_address, &event_summary);
      pppoeclient_update_latest_control_disposition (c, PPPOECLIENT_CONTROL_DISPOSITION_ACCEPTED);
      c->last_disconnect_reason = PPPOECLIENT_DISCONNECT_PADT;
      c->total_reconnects++;
      /* notify ppp the lower is down, then it will try to reconnect. */
      PPPOECLIENT_LAZY_PLUGIN_SYMBOL (pppox_lower_down_func, "pppoeclient_plugin.so",
				      "pppox_lower_down");
      if (pppox_lower_down_func)
	(*pppox_lower_down_func) (c->pppox_sw_if_index);
      /* delete from session table and clear session_id.
       * NOTE: do NOT delete session file here — pppoeclient_exit() needs it
       * to send raw PADT on shutdown.  File is overwritten on each new PADS
       * and cleaned up by pppoeclient_exit(). */
      pppoeclient_delete_session_1 (&pem->session_table, c->sw_if_index, c->ac_mac_address,
				    c->session_id);
      c->session_id = 0;
      pppoeclient_clear_runtime_state (c);
      /*
       * BAS implementations often rate-limit redial immediately after sending
       * PADT or rejecting authentication. Cool down before re-entering
       * discovery to avoid reconnect storms.
       */
      pppoeclient_schedule_discovery (c, now + PPPOECLIENT_REDISCOVERY_COOLDOWN);
      return PPPOECLIENT_ERROR_PADT_RECEIVED;
    default:
      break;
    }

  return 0;
}

static u8 *
format_pppoe_client_state (u8 *s, va_list *va)
{
  pppoeclient_state_t state = va_arg (*va, pppoeclient_state_t);
  char *str = "BOGUS!";

  switch (state)
    {
#define _(a)                                                                                       \
  case a:                                                                                          \
    str = #a;                                                                                      \
    break;
      foreach_pppoe_client_state;
#undef _
    default:
      break;
    }

  s = format (s, "%s", str);
  return s;
}

static pppox_virtual_interface_t *
pppoeclient_get_detail_virtual_interface (pppoeclient_main_t *pem, pppoeclient_t *c,
					  u32 client_index, u32 *unit, u8 *unit_from_hw)
{
  pppox_main_t *pom = get_pppox_main ();
  pppox_virtual_interface_t *t = 0;

  *unit = ~0;
  *unit_from_hw = 0;

  if (pom == 0 || c->pppox_sw_if_index == ~0)
    return 0;

  if (c->pppox_sw_if_index < vec_len (pom->virtual_interface_index_by_sw_if_index))
    *unit = pom->virtual_interface_index_by_sw_if_index[c->pppox_sw_if_index];

  if (*unit == ~0)
    {
      vnet_sw_interface_t *sw =
	vnet_get_sw_interface_or_null (pem->vnet_main, c->pppox_sw_if_index);

      if (sw)
	{
	  vnet_hw_interface_t *hi = vnet_get_hw_interface (pem->vnet_main, sw->hw_if_index);
	  *unit = hi->dev_instance;
	  *unit_from_hw = 1;
	}
    }

  if (*unit != ~0 && *unit < vec_len (pom->virtual_interfaces) &&
      !pool_is_free_index (pom->virtual_interfaces, *unit))
    {
      pppox_virtual_interface_t *candidate = pool_elt_at_index (pom->virtual_interfaces, *unit);

      if (candidate->sw_if_index == c->pppox_sw_if_index &&
	  candidate->pppoeclient_index == client_index)
	t = candidate;
    }

  return t;
}

static u8
pppoeclient_get_detail_global_ipv6 (u32 sw_if_index, ip6_address_t *addr, u8 *prefix_len)
{
  ip_lookup_main_t *lm = &ip6_main.lookup_main;
  ip_interface_address_t *ia = 0;

  if (addr)
    ip6_address_set_zero (addr);
  if (prefix_len)
    *prefix_len = 0;

  if (sw_if_index == ~0)
    return 0;

  foreach_ip_interface_address (lm, ia, sw_if_index, 1 /* honor unnumbered */, ({
				  ip6_address_t *candidate =
				    ip_interface_address_get_address (lm, ia);

				  if (ip6_address_is_link_local_unicast (candidate))
				    continue;

				  if (addr)
				    *addr = *candidate;
				  if (prefix_len)
				    *prefix_len = ia->address_length;
				  return 1;
				}));

  return 0;
}

static u8
pppoeclient_get_detail_dhcp6_ia_na (u32 sw_if_index, dhcp6_ia_na_client_runtime_t *rt)
{
  static u8 (*dhcp6_ia_na_client_get_runtime_func) (u32, dhcp6_ia_na_client_runtime_t *) = 0;
  static u8 attempted = 0;

  if (rt == 0)
    return 0;

  clib_memset (rt, 0, sizeof (*rt));

  if (!attempted)
    {
      dhcp6_ia_na_client_get_runtime_func =
	vlib_get_plugin_symbol ("dhcp_plugin.so", "dhcp6_ia_na_client_get_runtime");
      attempted = 1;
    }

  if (dhcp6_ia_na_client_get_runtime_func == 0)
    return 0;

  return (*dhcp6_ia_na_client_get_runtime_func) (sw_if_index, rt);
}

static u8
pppoeclient_get_detail_dhcp6_pd (u32 sw_if_index, dhcp6_pd_client_runtime_t *rt,
				 dhcp6_pd_active_prefix_runtime_t *prefix_rt)
{
  static u8 (*dhcp6_pd_client_get_runtime_func) (u32, dhcp6_pd_client_runtime_t *) = 0;
  static u8 (*dhcp6_pd_client_get_active_prefix_runtime_func) (
    u32, dhcp6_pd_active_prefix_runtime_t *) = 0;
  static u8 attempted = 0;
  u8 have_runtime = 0;

  if (rt == 0 || prefix_rt == 0)
    return 0;

  clib_memset (rt, 0, sizeof (*rt));
  clib_memset (prefix_rt, 0, sizeof (*prefix_rt));

  if (!attempted)
    {
      dhcp6_pd_client_get_runtime_func =
	vlib_get_plugin_symbol ("dhcp_plugin.so", "dhcp6_pd_client_get_runtime");
      dhcp6_pd_client_get_active_prefix_runtime_func =
	vlib_get_plugin_symbol ("dhcp_plugin.so", "dhcp6_pd_client_get_active_prefix_runtime");
      attempted = 1;
    }

  if (dhcp6_pd_client_get_runtime_func)
    have_runtime = (*dhcp6_pd_client_get_runtime_func) (sw_if_index, rt);
  if (dhcp6_pd_client_get_active_prefix_runtime_func)
    (void) (*dhcp6_pd_client_get_active_prefix_runtime_func) (sw_if_index, prefix_rt);

  return have_runtime;
}

static u8
pppoeclient_get_detail_dhcp6_pd_consumer (u32 sw_if_index, dhcp6_pd_consumer_runtime_t *rt)
{
  static u8 (*dhcp6_pd_client_get_consumer_runtime_func) (u32, dhcp6_pd_consumer_runtime_t *) = 0;
  static u8 attempted = 0;

  if (rt == 0)
    return 0;

  clib_memset (rt, 0, sizeof (*rt));

  if (!attempted)
    {
      dhcp6_pd_client_get_consumer_runtime_func =
	vlib_get_plugin_symbol ("dhcp_plugin.so", "dhcp6_pd_client_get_consumer_runtime");
      attempted = 1;
    }

  if (dhcp6_pd_client_get_consumer_runtime_func == 0)
    return 0;

  return (*dhcp6_pd_client_get_consumer_runtime_func) (sw_if_index, rt);
}

static u8 *
format_ppp_phase_name (u8 *s, va_list *args)
{
  static const char *phase_names[] = {
    "DEAD",    "INITIALIZE", "SERIALCONN", "DORMANT",	 "ESTABLISH", "AUTHENTICATE", "CALLBACK",
    "NETWORK", "RUNNING",    "TERMINATE",  "DISCONNECT", "HOLDOFF",   "MASTER",
  };
  int value = va_arg (*args, int);

  if (value >= 0 && value < ARRAY_LEN (phase_names))
    return format (s, "%s", phase_names[value]);

  return format (s, "%d", value);
}

static u8 *
format_ppp_fsm_state_name (u8 *s, va_list *args)
{
  static const char *fsm_state_names[] = {
    "INITIAL",	"STARTING", "CLOSED",  "STOPPED", "CLOSING",
    "STOPPING", "REQSENT",  "ACKRCVD", "ACKSENT", "OPENED",
  };
  int value = va_arg (*args, int);

  if (value >= 0 && value < ARRAY_LEN (fsm_state_names))
    return format (s, "%s", fsm_state_names[value]);

  return format (s, "%d", value);
}

static u8 *
format_pppoe_disconnect_reason_name (u8 *s, va_list *args)
{
  static const char *reason_names[] = {
    [PPPOECLIENT_DISCONNECT_NONE] = "none",
    [PPPOECLIENT_DISCONNECT_PADT] = "padt",
    [PPPOECLIENT_DISCONNECT_ECHO_TIMEOUT] = "echo-timeout",
    [PPPOECLIENT_DISCONNECT_ADMIN] = "admin",
    [PPPOECLIENT_DISCONNECT_PPP_DEAD] = "ppp-dead",
    [PPPOECLIENT_DISCONNECT_AUTH_FAIL] = "auth-fail",
  };
  int value = va_arg (*args, int);

  if (value >= 0 && value < ARRAY_LEN (reason_names) && reason_names[value])
    return format (s, "%s", reason_names[value]);

  return format (s, "%d", value);
}

static u8 *
format_pppoe_packet_code_name (u8 *s, va_list *args)
{
  int value = va_arg (*args, int);

  switch (value)
    {
    case PPPOE_PADI:
      return format (s, "PADI");
    case PPPOE_PADO:
      return format (s, "PADO");
    case PPPOE_PADR:
      return format (s, "PADR");
    case PPPOE_PADS:
      return format (s, "PADS");
    case PPPOE_PADT:
      return format (s, "PADT");
    default:
      return format (s, "0x%x", value);
    }
}

static uword
unformat_pppoe_packet_code_name (unformat_input_t *input, va_list *args)
{
  u8 *code = va_arg (*args, u8 *);

  if (unformat (input, "pado"))
    {
      *code = PPPOE_PADO;
      return 1;
    }
  if (unformat (input, "pads"))
    {
      *code = PPPOE_PADS;
      return 1;
    }
  if (unformat (input, "padt"))
    {
      *code = PPPOE_PADT;
      return 1;
    }

  return 0;
}

static uword
unformat_pppoeclient_control_disposition_name (unformat_input_t *input, va_list *args)
{
  u8 *d = va_arg (*args, u8 *);

  if (unformat (input, "accepted"))
    {
      *d = PPPOECLIENT_CONTROL_DISPOSITION_ACCEPTED;
      return 1;
    }
  if (unformat (input, "ignored"))
    {
      *d = PPPOECLIENT_CONTROL_DISPOSITION_IGNORED;
      return 1;
    }
  if (unformat (input, "error"))
    {
      *d = PPPOECLIENT_CONTROL_DISPOSITION_ERROR;
      return 1;
    }
  if (unformat (input, "orphan"))
    {
      *d = PPPOECLIENT_CONTROL_DISPOSITION_ORPHAN;
      return 1;
    }
  if (unformat (input, "none"))
    {
      *d = PPPOECLIENT_CONTROL_DISPOSITION_NONE;
      return 1;
    }

  return 0;
}

static uword
unformat_pppoeclient_control_match_reason_name (unformat_input_t *input, va_list *args)
{
  u8 *r = va_arg (*args, u8 *);

  /* Check longer literals before shorter prefixes so partial matches are
   * not consumed by an earlier alternative. */
  if (unformat (input, "ac-mac+service"))
    {
      *r = PPPOECLIENT_CONTROL_MATCH_AC_MAC_AND_SERVICE;
      return 1;
    }
  if (unformat (input, "cookie+service"))
    {
      *r = PPPOECLIENT_CONTROL_MATCH_COOKIE_AND_SERVICE;
      return 1;
    }
  if (unformat (input, "ac+service"))
    {
      *r = PPPOECLIENT_CONTROL_MATCH_AC_AND_SERVICE;
      return 1;
    }
  if (unformat (input, "host-uniq"))
    {
      *r = PPPOECLIENT_CONTROL_MATCH_HOST_UNIQ;
      return 1;
    }
  if (unformat (input, "service-name"))
    {
      *r = PPPOECLIENT_CONTROL_MATCH_SERVICE_NAME;
      return 1;
    }
  if (unformat (input, "ac-name"))
    {
      *r = PPPOECLIENT_CONTROL_MATCH_AC_NAME;
      return 1;
    }
  if (unformat (input, "ac-mac"))
    {
      *r = PPPOECLIENT_CONTROL_MATCH_AC_MAC;
      return 1;
    }
  if (unformat (input, "cookie"))
    {
      *r = PPPOECLIENT_CONTROL_MATCH_COOKIE;
      return 1;
    }
  if (unformat (input, "unique"))
    {
      *r = PPPOECLIENT_CONTROL_MATCH_UNIQUE;
      return 1;
    }
  if (unformat (input, "session"))
    {
      *r = PPPOECLIENT_CONTROL_MATCH_SESSION;
      return 1;
    }
  if (unformat (input, "none"))
    {
      *r = PPPOECLIENT_CONTROL_MATCH_NONE;
      return 1;
    }
  if (unformat (input, "any"))
    {
      *r = PPPOECLIENT_CONTROL_MATCH_ANY;
      return 1;
    }

  return 0;
}

static void
show_pppoeclient_detail_one (vlib_main_t *vm, pppoeclient_t *c)
{
  pppoeclient_main_t *pem = &pppoeclient_main;
  u32 client_index = c - pem->clients;
  pppox_virtual_interface_t *t = 0;
  u32 unit = ~0;
  u8 unit_from_hw = 0;
  u8 *session_ac_name = 0;
  u8 *configured_ac_name = 0;
  u8 *configured_service_name = 0;
  u8 *configured_auth_user = 0;
  dhcp6_ia_na_client_runtime_t dhcp6_ia_na_rt;
  dhcp6_pd_client_runtime_t dhcp6_pd_rt;
  dhcp6_pd_active_prefix_runtime_t dhcp6_pd_prefix_rt;
  dhcp6_pd_consumer_runtime_t dhcp6_pd_consumer_rt;
  u8 dhcp6_ia_na_available = 0;
  u8 dhcp6_pd_available = 0;
  u8 dhcp6_pd_consumer_available = 0;

  t = pppoeclient_get_detail_virtual_interface (pem, c, client_index, &unit, &unit_from_hw);

  if (c->ac_name)
    session_ac_name = format (0, "%v", c->ac_name);
  else
    session_ac_name = format (0, "<none>");

  if (c->ac_name_filter && vec_len (c->ac_name_filter) > 0)
    configured_ac_name = format (0, "%v", c->ac_name_filter);
  else
    configured_ac_name = format (0, "<any>");

  if (c->service_name && vec_len (c->service_name) > 0)
    configured_service_name = format (0, "%v", c->service_name);
  else
    configured_service_name = format (0, "<any>");

  if (c->username)
    configured_auth_user = format (0, "%v", c->username);
  else
    configured_auth_user = format (0, "<unset>");

  dhcp6_ia_na_available =
    pppoeclient_get_detail_dhcp6_ia_na (c->pppox_sw_if_index, &dhcp6_ia_na_rt);
  dhcp6_pd_available =
    pppoeclient_get_detail_dhcp6_pd (c->pppox_sw_if_index, &dhcp6_pd_rt, &dhcp6_pd_prefix_rt);
  dhcp6_pd_consumer_available =
    pppoeclient_get_detail_dhcp6_pd_consumer (c->pppox_sw_if_index, &dhcp6_pd_consumer_rt);

  vlib_cli_output (vm, "[%u] access-interface %U host-uniq %u", client_index,
		   format_vnet_sw_if_index_name, pem->vnet_main, c->sw_if_index, c->host_uniq);
  vlib_cli_output (vm, "    runtime session-state %U session-id %u ac-mac %U ac-name %v",
		   format_pppoe_client_state, c->state, c->session_id, format_ethernet_address,
		   c->ac_mac_address, session_ac_name);

  if (t)
    {
      ip6_address_t observed_local_ip6;
      u8 observed_prefix_len = 0;
      u8 observed_local_present = 0;
      const ip6_address_t *ipv6cp_local_ip6 =
	ip6_address_is_zero (&c->ip6_addr) ? &t->our_ipv6 : &c->ip6_addr;
      const ip6_address_t *ipv6cp_peer_ip6 =
	ip6_address_is_zero (&c->ip6_peer_addr) ? &t->his_ipv6 : &c->ip6_peer_addr;
      const char *wan_ipv6_mode = "unset";

      observed_local_present = pppoeclient_get_detail_global_ipv6 (
	c->pppox_sw_if_index, &observed_local_ip6, &observed_prefix_len);

      if (observed_local_present)
	wan_ipv6_mode = "global-address-observed";
      else if (!ip6_address_is_zero (ipv6cp_local_ip6) || !ip6_address_is_zero (ipv6cp_peer_ip6))
	wan_ipv6_mode = "link-local-only";

      vlib_cli_output (vm,
		       "    runtime pppox-interface %U sw-if-index %u unit %u session-allocated %u",
		       format_vnet_sw_if_index_name, pem->vnet_main, c->pppox_sw_if_index,
		       c->pppox_sw_if_index, unit, t->pppoe_session_allocated);
      vlib_cli_output (vm, "    runtime ipv4 local %U peer %U", format_ip4_address, &t->our_addr,
		       format_ip4_address, &t->his_addr);
      if (c->dns1)
	vlib_cli_output (vm, "    runtime peer-dns4 primary %U", format_ip4_address, &c->dns1);
      else
	vlib_cli_output (vm, "    runtime peer-dns4 primary <none>");
      if (c->dns2)
	vlib_cli_output (vm, "    runtime peer-dns4 secondary %U", format_ip4_address, &c->dns2);
      else
	vlib_cli_output (vm, "    runtime peer-dns4 secondary <none>");
      if (dhcp6_ia_na_rt.dns_server_count > 0)
	{
	  vlib_cli_output (vm, "    runtime peer-dns6 primary %U", format_ip6_address,
			   &dhcp6_ia_na_rt.dns_servers[0]);
	  if (dhcp6_ia_na_rt.dns_server_count > 1)
	    vlib_cli_output (vm, "    runtime peer-dns6 secondary %U", format_ip6_address,
			     &dhcp6_ia_na_rt.dns_servers[1]);
	  else
	    vlib_cli_output (vm, "    runtime peer-dns6 secondary <none>");
	}
      else
	vlib_cli_output (vm, "    runtime peer-dns6 <none>");
      vlib_cli_output (vm, "    runtime ipv6cp-link-local local %U peer %U", format_ip6_address,
		       ipv6cp_local_ip6, format_ip6_address, ipv6cp_peer_ip6);
      if (observed_local_present)
	vlib_cli_output (vm, "    runtime wan-ipv6 observed %U/%u", format_ip6_address,
			 &observed_local_ip6, observed_prefix_len);
      else
	vlib_cli_output (vm, "    runtime wan-ipv6 observed <none>");
      vlib_cli_output (
	vm, "    runtime wan-ipv6-mode %s peer-host-route %u default-route4 %u default-route6 %u",
	wan_ipv6_mode, !ip6_address_is_zero (ipv6cp_peer_ip6), c->use_peer_route4,
	c->use_peer_route6);
    }
  else if (unit != ~0)
    {
      vlib_cli_output (vm, "    runtime pppox-interface sw-if-index %u unit %u detail-source %s",
		       c->pppox_sw_if_index, unit, unit_from_hw ? "hw-dev-instance" : "sw-if-map");
      vlib_cli_output (vm, "    runtime peer-dns4 primary <none>");
      vlib_cli_output (vm, "    runtime peer-dns4 secondary <none>");
      vlib_cli_output (vm, "    runtime peer-dns6 <none>");
    }
  else
    {
      vlib_cli_output (vm, "    runtime pppox-interface sw-if-index %u unit unavailable",
		       c->pppox_sw_if_index);
      vlib_cli_output (vm, "    runtime peer-dns4 primary <none>");
      vlib_cli_output (vm, "    runtime peer-dns4 secondary <none>");
      vlib_cli_output (vm, "    runtime peer-dns6 <none>");
    }

  if (dhcp6_ia_na_available)
    {
      if (dhcp6_ia_na_rt.enabled)
	{
	  if (dhcp6_ia_na_rt.T1)
	    vlib_cli_output (vm,
			     "    dhcp6 ia-na enabled addresses %u server-index %u T1 %u (%u "
			     "remaining) T2 %u (%u remaining)%s",
			     dhcp6_ia_na_rt.address_count, dhcp6_ia_na_rt.server_index,
			     dhcp6_ia_na_rt.T1, dhcp6_ia_na_rt.t1_remaining, dhcp6_ia_na_rt.T2,
			     dhcp6_ia_na_rt.t2_remaining,
			     dhcp6_ia_na_rt.rebinding ? " REBINDING" : "");
	  else
	    vlib_cli_output (vm, "    dhcp6 ia-na enabled addresses %u%s",
			     dhcp6_ia_na_rt.address_count,
			     dhcp6_ia_na_rt.rebinding ? " REBINDING" : "");
	  if (dhcp6_ia_na_rt.first_address_present)
	    vlib_cli_output (
	      vm, "    dhcp6 ia-na first-address %U/64 preferred-lifetime %u valid-lifetime %u",
	      format_ip6_address, &dhcp6_ia_na_rt.first_address,
	      dhcp6_ia_na_rt.first_address_preferred_lt, dhcp6_ia_na_rt.first_address_valid_lt);
	}
      else
	vlib_cli_output (vm, "    dhcp6 ia-na disabled");
    }
  else
    vlib_cli_output (vm, "    dhcp6 ia-na <unavailable>");

  if (dhcp6_pd_available)
    {
      if (dhcp6_pd_rt.enabled)
	{
	  if (dhcp6_pd_rt.T1)
	    vlib_cli_output (vm,
			     "    dhcp6 pd enabled prefix-group %s prefixes %u server-index %u T1 "
			     "%u (%u remaining) T2 %u (%u remaining)%s",
			     dhcp6_pd_rt.prefix_group[0] ? dhcp6_pd_rt.prefix_group : "<unset>",
			     dhcp6_pd_rt.prefix_count, dhcp6_pd_rt.server_index, dhcp6_pd_rt.T1,
			     dhcp6_pd_rt.t1_remaining, dhcp6_pd_rt.T2, dhcp6_pd_rt.t2_remaining,
			     dhcp6_pd_rt.rebinding ? " REBINDING" : "");
	  else
	    vlib_cli_output (vm, "    dhcp6 pd enabled prefix-group %s prefixes %u%s",
			     dhcp6_pd_rt.prefix_group[0] ? dhcp6_pd_rt.prefix_group : "<unset>",
			     dhcp6_pd_rt.prefix_count, dhcp6_pd_rt.rebinding ? " REBINDING" : "");

	  if (dhcp6_pd_prefix_rt.present)
	    vlib_cli_output (vm,
			     "    dhcp6 delegated-prefix %U/%u preferred-lifetime %u "
			     "valid-lifetime %u (%u remaining)",
			     format_ip6_address, &dhcp6_pd_prefix_rt.prefix,
			     dhcp6_pd_prefix_rt.prefix_length, dhcp6_pd_prefix_rt.preferred_lt,
			     dhcp6_pd_prefix_rt.valid_lt, dhcp6_pd_prefix_rt.valid_remaining);
	  else
	    vlib_cli_output (vm, "    dhcp6 delegated-prefix <none>");

	  if (dhcp6_pd_consumer_available)
	    {
	      if (dhcp6_pd_consumer_rt.present)
		vlib_cli_output (vm, "    dhcp6 pd downstream %U address %U/%u consumers %u",
				 format_vnet_sw_if_index_name, pem->vnet_main,
				 dhcp6_pd_consumer_rt.sw_if_index, format_ip6_address,
				 &dhcp6_pd_consumer_rt.address, dhcp6_pd_consumer_rt.prefix_length,
				 dhcp6_pd_consumer_rt.consumer_count);
	      else
		vlib_cli_output (vm, "    dhcp6 pd downstream <none>");
	    }
	}
      else
	vlib_cli_output (vm, "    dhcp6 pd disabled");
    }
  else
    vlib_cli_output (vm, "    dhcp6 pd <unavailable>");

  vlib_cli_output (vm,
		   "    stored-config ac-name %v service-name %v auth-user %v use-peer-dns4 %u "
		   "add-default-route4 %u add-default-route6 %u",
		   configured_ac_name, configured_service_name, configured_auth_user,
		   c->use_peer_dns, c->use_peer_route4, c->use_peer_route6);
  if (c->mtu || c->mru || c->timeout)
    vlib_cli_output (vm, "    stored-config mtu %u mru %u timeout %u", c->mtu, c->mru, c->timeout);

  vec_free (session_ac_name);
  vec_free (configured_ac_name);
  vec_free (configured_service_name);
  vec_free (configured_auth_user);
}

static void
show_pppoeclient_debug_one (vlib_main_t *vm, pppoeclient_t *c,
			    pppoeclient_history_cli_filter_t *filter)
{
  pppoeclient_main_t *pem = &pppoeclient_main;
  u32 client_index = c - pem->clients;
  f64 now = vlib_time_now (vm);
  pppox_virtual_interface_t *t = 0;
  u32 unit = ~0;
  u8 unit_from_hw = 0;
  u8 *configured_ac_name = 0;
  u8 *configured_service_name = 0;
  u8 *configured_auth_user = 0;
  u8 *next_discovery = 0;
  char linux_ifname[IFNAMSIZ];
  pppox_ppp_debug_runtime_t ppp_debug_rt;
  static u8 (*pppox_get_ppp_debug_runtime_func) (u32, pppox_ppp_debug_runtime_t *) = 0;
  static u8 attempted = 0;

  t = pppoeclient_get_detail_virtual_interface (pem, c, client_index, &unit, &unit_from_hw);

  if (c->ac_name_filter && vec_len (c->ac_name_filter) > 0)
    configured_ac_name = format (0, "%v", c->ac_name_filter);
  else
    configured_ac_name = format (0, "<any>");

  if (c->service_name && vec_len (c->service_name) > 0)
    configured_service_name = format (0, "%v", c->service_name);
  else
    configured_service_name = format (0, "<any>");

  if (c->username)
    configured_auth_user = format (0, "%v", c->username);
  else
    configured_auth_user = format (0, "<unset>");

  if (c->state != PPPOE_CLIENT_DISCOVERY)
    next_discovery = format (0, "n/a");
  else if (PPPOECLIENT_NEXT_TRANSMIT_IS_PARKED (c->next_transmit))
    next_discovery = format (0, "parked");
  else if (c->next_transmit <= now)
    next_discovery = format (0, "due");
  else
    next_discovery = format (0, "in %.2fs", c->next_transmit - now);

  clib_memset (&ppp_debug_rt, 0, sizeof (ppp_debug_rt));
  if (!attempted)
    {
      pppox_get_ppp_debug_runtime_func =
	vlib_get_plugin_symbol ("pppoeclient_plugin.so", "pppox_get_ppp_debug_runtime");
      attempted = 1;
    }
  if (pppox_get_ppp_debug_runtime_func)
    (void) (*pppox_get_ppp_debug_runtime_func) (c->pppox_sw_if_index, &ppp_debug_rt);

  vlib_cli_output (vm, "[%u] access-interface %U host-uniq %u", client_index,
		   format_vnet_sw_if_index_name, pem->vnet_main, c->sw_if_index, c->host_uniq);
  vlib_cli_output (vm, "    pppoe state %U session-id %u pppox-sw-if-index %u",
		   format_pppoe_client_state, c->state, c->session_id, c->pppox_sw_if_index);
  vlib_cli_output (vm, "    reconnects %u last-disconnect %U next-discovery %v",
		   c->total_reconnects, format_pppoe_disconnect_reason_name,
		   c->last_disconnect_reason, next_discovery);
  vlib_cli_output (vm, "    auth-failures %u", c->consecutive_auth_failures);

  vnet_hw_interface_t *hw = vnet_get_sup_hw_interface (pem->vnet_main, c->sw_if_index);

  clib_memset (linux_ifname, 0, sizeof (linux_ifname));
  pppoeclient_get_linux_ifname (pem->vnet_main, c->sw_if_index, linux_ifname, sizeof (linux_ifname),
				0);

  if (hw == 0)
    vlib_cli_output (vm, "    access-link linux-ifname %s vpp-mac <unavailable>",
		     linux_ifname[0] != '\0' ? linux_ifname : "<unresolved>");
  else if (linux_ifname[0] != '\0')
    vlib_cli_output (vm, "    access-link linux-ifname %s vpp-mac %U", linux_ifname,
		     format_ethernet_address, hw->hw_address);
  else
    vlib_cli_output (vm, "    access-link linux-ifname <unresolved> vpp-mac %U",
		     format_ethernet_address, hw->hw_address);

  if (t && unit != ~0)
    {
      vlib_cli_output (vm,
		       "    pppox unit %u detail-source %s session-allocated %u delete-pending %u",
		       unit, unit_from_hw ? "hw-dev-instance" : "sw-if-map",
		       t->pppoe_session_allocated, t->delete_pending);
      if (ppp_debug_rt.present)
	{
	  vlib_cli_output (vm, "    ppp phase %U lcp %U ipcp %U ipv6cp %U", format_ppp_phase_name,
			   ppp_debug_rt.phase, format_ppp_fsm_state_name, ppp_debug_rt.lcp_state,
			   format_ppp_fsm_state_name, ppp_debug_rt.ipcp_state,
			   format_ppp_fsm_state_name, ppp_debug_rt.ipv6cp_state);
	  vlib_cli_output (vm, "    ppp timeouts lcp %d ipcp %d ipv6cp %d",
			   ppp_debug_rt.lcp_timeout, ppp_debug_rt.ipcp_timeout,
			   ppp_debug_rt.ipv6cp_timeout);
	  vlib_cli_output (vm,
			   "    ipcp requested default-route4 %u req-dns1 %u req-dns2 %u "
			   "negotiated-dns1 %U negotiated-dns2 %U",
			   ppp_debug_rt.default_route4, ppp_debug_rt.req_dns1,
			   ppp_debug_rt.req_dns2, format_ip4_address, &ppp_debug_rt.negotiated_dns1,
			   format_ip4_address, &ppp_debug_rt.negotiated_dns2);
	  if (ppp_debug_rt.negotiated_mtu || ppp_debug_rt.negotiated_mru)
	    vlib_cli_output (
	      vm, "    lcp negotiated tx-mtu %u rx-mru %u (configured mtu %u mru %u)",
	      ppp_debug_rt.negotiated_mtu, ppp_debug_rt.negotiated_mru, c->mtu, c->mru);
	  else
	    vlib_cli_output (vm, "    lcp negotiated <pending> (configured mtu %u mru %u)", c->mtu,
			     c->mru);
	}
      else
	vlib_cli_output (vm, "    ppp debug-runtime <unavailable>");
    }
  else
    vlib_cli_output (vm, "    pppox unit unavailable");

  vlib_cli_output (vm,
		   "    stored-config ac-name %v service-name %v auth-user %v use-peer-dns4 %u "
		   "add-default-route4 %u add-default-route6 %u",
		   configured_ac_name, configured_service_name, configured_auth_user,
		   c->use_peer_dns, c->use_peer_route4, c->use_peer_route6);
  vlib_cli_output (vm, "    stored-config mtu %u mru %u timeout %u", c->mtu, c->mru, c->timeout);

  if (filter && c->control_history_count)
    {
      pppoeclient_show_filtered_control_history_summary (
	vm, "    ", "recent-control-summary", &c->control_history[0], c->control_history_count,
	c->control_history_next, filter);
      pppoeclient_show_filtered_control_history_entries (
	vm, "    ", "recent-control", &c->control_history[0], c->control_history_count,
	c->control_history_next, 0, filter);
    }
  else if (c->control_history_count)
    {
      pppoeclient_show_control_history_summary (vm, "    ", "recent-control-summary",
						&c->control_history[0], c->control_history_count,
						c->control_history_next);
      pppoeclient_show_control_history_entries (vm, "    ", "recent-control",
						&c->control_history[0], c->control_history_count,
						c->control_history_next, 0);
    }

  vec_free (configured_ac_name);
  vec_free (configured_service_name);
  vec_free (configured_auth_user);
  vec_free (next_discovery);
}

static void
show_pppoeclient_orphan_control_history (vlib_main_t *vm)
{
  pppoeclient_main_t *pem = &pppoeclient_main;

  if (pem->orphan_control_history_count == 0)
    return;

  pppoeclient_show_control_history_summary (
    vm, "", "orphan-control-summary", &pem->orphan_control_history[0],
    pem->orphan_control_history_count, pem->orphan_control_history_next);
  pppoeclient_show_control_history_entries (
    vm, "", "orphan-control", &pem->orphan_control_history[0], pem->orphan_control_history_count,
    pem->orphan_control_history_next, 1);
}

static void
show_pppoeclient_summary_filtered_one (vlib_main_t *vm, pppoeclient_t *c,
				       pppoeclient_history_cli_filter_t *filter)
{
  pppoeclient_main_t *pem = &pppoeclient_main;
  u32 client_index = c - pem->clients;
  u8 match_indices[PPPOECLIENT_CONTROL_HISTORY_LEN];
  u8 matched;

  vlib_cli_output (vm, "[%u] access-interface %U host-uniq %u", client_index,
		   format_vnet_sw_if_index_name, pem->vnet_main, c->sw_if_index, c->host_uniq);
  vlib_cli_output (vm, "    pppoe state %U session-id %u pppox-sw-if-index %u",
		   format_pppoe_client_state, c->state, c->session_id, c->pppox_sw_if_index);

  matched = pppoeclient_collect_control_history_cli_matches (
    c->control_history, c->control_history_count, c->control_history_next, filter, match_indices);
  if (!matched)
    {
      vlib_cli_output (vm, "    recent-control-summary <empty>");
      return;
    }

  pppoeclient_show_filtered_control_history_summary (
    vm, "    ", "recent-control-summary", &c->control_history[0], c->control_history_count,
    c->control_history_next, filter);
}

static void
show_pppoeclient_orphan_control_summary_filtered (vlib_main_t *vm,
						  pppoeclient_history_cli_filter_t *filter)
{
  pppoeclient_main_t *pem = &pppoeclient_main;
  u8 match_indices[PPPOECLIENT_CONTROL_HISTORY_LEN];
  u8 matched;

  matched = pppoeclient_collect_control_history_cli_matches (
    pem->orphan_control_history, pem->orphan_control_history_count,
    pem->orphan_control_history_next, filter, match_indices);
  if (!matched)
    {
      vlib_cli_output (vm, "orphan-control-summary <empty>");
      return;
    }

  pppoeclient_show_filtered_control_history_summary (
    vm, "", "orphan-control-summary", &pem->orphan_control_history[0],
    pem->orphan_control_history_count, pem->orphan_control_history_next, filter);
}

static void
show_pppoeclient_history_filtered_one (vlib_main_t *vm, pppoeclient_t *c,
				       pppoeclient_history_cli_filter_t *filter)
{
  pppoeclient_main_t *pem = &pppoeclient_main;
  u32 client_index = c - pem->clients;
  u8 matched = 0;
  u8 i;
  u8 first;

  vlib_cli_output (vm, "[%u] access-interface %U host-uniq %u", client_index,
		   format_vnet_sw_if_index_name, pem->vnet_main, c->sw_if_index, c->host_uniq);
  vlib_cli_output (vm, "    pppoe state %U session-id %u pppox-sw-if-index %u",
		   format_pppoe_client_state, c->state, c->session_id, c->pppox_sw_if_index);

  if (c->control_history_count)
    {
      first =
	(c->control_history_next + PPPOECLIENT_CONTROL_HISTORY_LEN - c->control_history_count) %
	PPPOECLIENT_CONTROL_HISTORY_LEN;
      for (i = 0; i < c->control_history_count; i++)
	{
	  pppoeclient_control_event_t *event =
	    &c->control_history[(first + i) % PPPOECLIENT_CONTROL_HISTORY_LEN];
	  if (!pppoeclient_control_event_matches_cli_filter (event, filter))
	    continue;
	  matched++;
	}
    }

  if (!matched)
    {
      vlib_cli_output (vm, "    recent-control-summary <empty>");
      return;
    }

  pppoeclient_show_filtered_control_history_summary (
    vm, "    ", "recent-control-summary", &c->control_history[0], c->control_history_count,
    c->control_history_next, filter);
  pppoeclient_show_filtered_control_history_entries (
    vm, "    ", "recent-control", &c->control_history[0], c->control_history_count,
    c->control_history_next, 0, filter);
}

static void
show_pppoeclient_orphan_control_history_filtered (vlib_main_t *vm,
						  pppoeclient_history_cli_filter_t *filter)
{
  pppoeclient_main_t *pem = &pppoeclient_main;
  u8 matched = 0;
  u8 i;
  u8 first;

  if (pem->orphan_control_history_count)
    {
      first = (pem->orphan_control_history_next + PPPOECLIENT_CONTROL_HISTORY_LEN -
	       pem->orphan_control_history_count) %
	      PPPOECLIENT_CONTROL_HISTORY_LEN;
      for (i = 0; i < pem->orphan_control_history_count; i++)
	{
	  pppoeclient_control_event_t *event =
	    &pem->orphan_control_history[(first + i) % PPPOECLIENT_CONTROL_HISTORY_LEN];
	  if (!pppoeclient_control_event_matches_cli_filter (event, filter))
	    continue;
	  matched++;
	}
    }

  if (!matched)
    {
      vlib_cli_output (vm, "orphan-control-summary <empty>");
      return;
    }

  pppoeclient_show_filtered_control_history_summary (
    vm, "", "orphan-control-summary", &pem->orphan_control_history[0],
    pem->orphan_control_history_count, pem->orphan_control_history_next, filter);
  pppoeclient_show_filtered_control_history_entries (
    vm, "", "orphan-control", &pem->orphan_control_history[0], pem->orphan_control_history_count,
    pem->orphan_control_history_next, 1, filter);
}

u8 *
format_pppoe_client (u8 *s, va_list *args)
{
  pppoeclient_t *c = va_arg (*args, pppoeclient_t *);
  pppoeclient_main_t *pem = &pppoeclient_main;

  s = format (s,
	      "[%u] sw-if-index %u host-uniq %u pppox-sw-if-index %u state %U session-id %u "
	      "ac-mac-address %U",
	      (u32) (c - pem->clients), c->sw_if_index, c->host_uniq, c->pppox_sw_if_index,
	      format_pppoe_client_state, c->state, c->session_id, format_ethernet_address,
	      c->ac_mac_address);
  return s;
}

__clib_export void
pppoeclient_open_session (u32 client_index)
{
  pppoeclient_main_t *pem = &pppoeclient_main;
  vlib_main_t *vm = pem->vlib_main;
  pppoeclient_t *c;

  if (pool_is_free_index (pem->clients, client_index))
    return;

  c = pool_elt_at_index (pem->clients, client_index);

  /* If already in SESSION or REQUEST, tear down the existing state first
   * so we don't leak the BAS session or leave stale bihash entries. */
  if (c->state == PPPOE_CLIENT_SESSION || c->state == PPPOE_CLIENT_REQUEST)
    pppoeclient_teardown_session (c, 1 /* send_padt */);

  c->state = PPPOE_CLIENT_DISCOVERY;
  c->next_transmit = 0;
  c->retry_count = 0;
  vlib_process_signal_event (vm, pppoeclient_process_node.index, EVENT_PPPOE_CLIENT_WAKEUP,
			     c - pem->clients);
}

static f64
pppoeclient_auth_backoff_delay (u32 failures)
{
  f64 delay;

  if (failures == 0)
    return PPPOECLIENT_AUTH_BACKOFF_BASE_SEC;

  /* 30s base, double each consecutive failure, hard-cap at 300s.
   * Cap failures before the shift to avoid undefined behavior when
   * failures >= 33 (shift by >= 32 on a 32-bit unsigned). */
  if (failures > 16)
    return PPPOECLIENT_AUTH_BACKOFF_CAP_SEC;
  delay = PPPOECLIENT_AUTH_BACKOFF_BASE_SEC * (f64) (1u << (failures - 1));
  if (delay > PPPOECLIENT_AUTH_BACKOFF_CAP_SEC)
    delay = PPPOECLIENT_AUTH_BACKOFF_CAP_SEC;
  return delay;
}

/* Return a multiplier in [1 - fraction, 1 + fraction] using the plugin RNG.
 * fraction <= 0 disables jitter (returns 1.0 exactly). Larger than 0.5 is
 * clamped because a factor <= 0 would cause instant retry. */
static inline f64
pppoeclient_backoff_jitter_factor (f64 fraction, u32 *seed)
{
  f64 r;

  if (fraction <= 0.0)
    return 1.0;
  if (fraction > 0.5)
    fraction = 0.5;

  r = ((f64) random_u32 (seed) / (f64) 0xffffffffu) * 2.0 - 1.0;
  return 1.0 + r * fraction;
}

__clib_export void
pppoeclient_restart_session_with_reason (u32 client_index, u8 disconnect_reason)
{
  pppoeclient_main_t *pem = &pppoeclient_main;
  vlib_main_t *vm = pem->vlib_main;
  pppoeclient_t *c;
  f64 now = vlib_time_now (vm);
  f64 cooldown;

  if (pool_is_free_index (pem->clients, client_index))
    return;

  c = pool_elt_at_index (pem->clients, client_index);
  if (c->state == PPPOE_CLIENT_DISCOVERY && c->next_transmit > now &&
      !PPPOECLIENT_NEXT_TRANSMIT_IS_PARKED (c->next_transmit))
    return;
  c->last_disconnect_reason = disconnect_reason;
  c->total_reconnects++;

  if (disconnect_reason == PPPOECLIENT_DISCONNECT_AUTH_FAIL)
    {
      c->consecutive_auth_failures++;
      cooldown = pppoeclient_auth_backoff_delay (c->consecutive_auth_failures);
    }
  else
    {
      cooldown = PPPOECLIENT_REDISCOVERY_COOLDOWN;
    }

  cooldown *= pppoeclient_backoff_jitter_factor (pem->auth_backoff_jitter_fraction, &pem->rng_seed);

  pppoeclient_teardown_session (c, 1 /* send_padt */);
  pppoeclient_schedule_discovery (c, now + cooldown);
}

__clib_export void
pppoeclient_restart_session (u32 client_index)
{
  pppoeclient_restart_session_with_reason (client_index, PPPOECLIENT_DISCONNECT_ADMIN);
}

__clib_export void
pppoeclient_stop_session (u32 client_index)
{
  pppoeclient_main_t *pem = &pppoeclient_main;
  pppoeclient_t *c;

  if (pool_is_free_index (pem->clients, client_index))
    return;

  c = pool_elt_at_index (pem->clients, client_index);
  c->last_disconnect_reason = PPPOECLIENT_DISCONNECT_ADMIN;
  pppoeclient_teardown_session (c, 1 /* send_padt */);
  c->state = PPPOE_CLIENT_DISCOVERY;
  /* Park the client so the process node does not retransmit PADI.
   * open_session or restart_session will reset next_transmit to 0. */
  c->next_transmit = PPPOECLIENT_NEXT_TRANSMIT_PARKED;
}

#define foreach_copy_field                                                                         \
  _ (sw_if_index)                                                                                  \
  _ (host_uniq)

int
vnet_pppoeclient_add_del (vnet_pppoeclient_add_del_args_t *a, u32 *pppox_sw_if_index)
{
  pppoeclient_main_t *pem = &pppoeclient_main;
  pppoeclient_t *c = 0;
  vlib_main_t *vm = pem->vlib_main;
  vnet_main_t *vnm = pem->vnet_main;
  pppoeclient_result_t result;
  u32 pppox_hw_if_index = ~0;
  vnet_sw_interface_t *sw;

  pppoeclient_lookup_1 (&pem->client_table, a->sw_if_index, a->host_uniq, &result);
  if (a->is_add)
    {
      /* adding a client: client must not already exist */
      if (result.fields.client_index != ~0)
	return VNET_API_ERROR_TUNNEL_EXIST;

      pool_get_aligned (pem->clients, c, CLIB_CACHE_LINE_BYTES);
      clib_memset (c, 0, sizeof (*c));

      /* copy from arg structure */
#define _(x) c->x = a->x;
      foreach_copy_field;
#undef _
      c->ac_name_filter = vec_dup (a->ac_name_filter);
      c->service_name = vec_dup (a->service_name);

      sw = vnet_get_sw_interface_or_null (vnm, a->sw_if_index);
      if (sw == 0)
	{
	  pppoeclient_client_free_resources (c);
	  pool_put (pem->clients, c);
	  return VNET_API_ERROR_INVALID_INTERFACE;
	}
      c->hw_if_index = sw->hw_if_index;

      /* Check if interface is an ethernet hardware interface */
      {
	vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, c->hw_if_index);
	vnet_hw_interface_class_t *hw_class = vnet_get_hw_interface_class (vnm, hw->hw_class_index);
	if (hw_class->index != ethernet_hw_interface_class.index)
	  {
	    pppoeclient_client_free_resources (c);
	    pool_put (pem->clients, c);
	    return VNET_API_ERROR_INVALID_INTERFACE;
	  }
      }

      result.fields.client_index = c - pem->clients;

      /*
       * Allocate the paired PPPoX interface via the exported plugin symbol.
       * VPP plugins do not declare hard dependencies, so this lookup remains
       * explicit here.
       */
      static u32 (*pppox_allocate_interface_func) (u32) = 0;
      PPPOECLIENT_LAZY_PLUGIN_SYMBOL (pppox_allocate_interface_func, "pppoeclient_plugin.so",
				      "pppox_allocate_interface");
      if (pppox_allocate_interface_func == 0)
	{
	  pppoeclient_client_free_resources (c);
	  pool_put (pem->clients, c);
	  return VNET_API_ERROR_UNSUPPORTED;
	}
      pppox_hw_if_index = (*pppox_allocate_interface_func) (result.fields.client_index);
      if (pppox_hw_if_index == ~0)
	{
	  pppoeclient_client_free_resources (c);
	  pool_put (pem->clients, c);
	  return VNET_API_ERROR_LIMIT_EXCEEDED;
	}
      c->pppox_hw_if_index = pppox_hw_if_index;
      vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, pppox_hw_if_index);
      c->pppox_sw_if_index = *pppox_sw_if_index = hi->sw_if_index;

      /* Apply the operator-supplied interface name (if any) before the
       * session surfaces anywhere observable. Falls back to pppoxN when
       * custom_ifname is empty. */
      if (a->custom_ifname && vec_len (a->custom_ifname))
	pppox_set_interface_name (*pppox_sw_if_index, a->custom_ifname);

      pppoeclient_update_1 (&pem->client_table, a->sw_if_index, a->host_uniq, &result);
      vec_validate_init_empty (pem->client_index_by_pppox_sw_if_index, *pppox_sw_if_index, ~0);
      pem->client_index_by_pppox_sw_if_index[*pppox_sw_if_index] = result.fields.client_index;
      pppoeclient_dispatch_ref (pem, a->sw_if_index);

      /* Add the interface output node to pppoeclient_session_output_node if not already
       * present.  Physical interfaces are few, so once added the entry is never removed. */
      {
	vnet_hw_interface_t *phy_hi = vnet_get_hw_interface (vnm, c->hw_if_index);
	u32 edge =
	  vlib_node_get_next (vm, pppoeclient_session_output_node.index, phy_hi->output_node_index);
	if (~0 == edge)
	  {
	    c->hw_output_next_index = vlib_node_add_next (vm, pppoeclient_session_output_node.index,
							  phy_hi->output_node_index);
	  }
	else
	  {
	    c->hw_output_next_index = edge;
	  }
      }
      /* dispatch is refcounted per access interface. */
    }
  else
    {
      /* deleting a client: client must exist */
      if (result.fields.client_index == ~0)
	return VNET_API_ERROR_NO_SUCH_ENTRY;

      c = pool_elt_at_index (pem->clients, result.fields.client_index);

      /* free pppox interface first to let LCP have a chance to send
       * out lcp termination and also trigger us to send a PADT.
       * Note above operations should be done synchronously in main
       * thread, otherwise the packet might be lost. */
      static void (*pppox_free_interface_func) (u32) = 0;
      PPPOECLIENT_LAZY_PLUGIN_SYMBOL (pppox_free_interface_func, "pppoeclient_plugin.so",
				      "pppox_free_interface");
      if (pppox_free_interface_func == 0)
	return VNET_API_ERROR_UNSUPPORTED;

      pppoeclient_dispatch_unref (pem, a->sw_if_index);
      pppoeclient_stop_session (result.fields.client_index);
      pppoeclient_delete_session_file (c->sw_if_index);

      /* dispatch is refcounted per access interface. */

      (*pppox_free_interface_func) (c->pppox_hw_if_index);

      pppoeclient_delete_1 (&pem->client_table, a->sw_if_index, a->host_uniq);

      pem->client_index_by_pppox_sw_if_index[c->pppox_sw_if_index] = ~0;
      pppoeclient_client_free_resources (c);
      pool_put (pem->clients, c);
    }

  return 0;
}

static clib_error_t *
pppoeclient_add_del_command_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u8 is_add = 1;
  u32 sw_if_index = ~0;
  u32 host_uniq = 0;
  u8 host_uniq_set = 0;
  u8 sw_if_index_set = 0;
  u8 *custom_ifname = 0;
  int rv;
  pppoeclient_main_t *pem = &pppoeclient_main;
  vnet_pppoeclient_add_del_args_t _a, *a = &_a;
  clib_error_t *error = 0;
  u32 pppox_sw_if_index = ~0;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "del"))
	{
	  is_add = 0;
	}
      else if (unformat (line_input, "host-uniq %u", &host_uniq))
	{
	  host_uniq_set = 1;
	}
      else if (unformat (line_input, "sw-if-index %u", &sw_if_index))
	{
	  sw_if_index_set = 1;
	}
      else if (unformat (line_input, "%U", unformat_vnet_sw_interface, pem->vnet_main,
			 &sw_if_index))
	{
	  sw_if_index_set = 1;
	}
      else if (unformat (line_input, "name %s", &custom_ifname))
	;
      else
	{
	  error = clib_error_return (0, "parse error: '%U'", format_unformat_error, line_input);
	  goto done;
	}
    }

  if (host_uniq_set == 0)
    {
      error = clib_error_return (0, "client host uniq not specified");
      goto done;
    }

  if (sw_if_index_set == 0)
    {
      error = clib_error_return (0, "sw if index not specified");
      goto done;
    }

  clib_memset (a, 0, sizeof (*a));

  a->is_add = is_add;

#define _(x) a->x = x;
  foreach_copy_field;
#undef _
  a->custom_ifname = custom_ifname;

  rv = vnet_pppoeclient_add_del (a, &pppox_sw_if_index);

  switch (rv)
    {
    case 0:
      break;

    case VNET_API_ERROR_TUNNEL_EXIST:
      error = clib_error_return (0, "client already exists...");
      goto done;

    case VNET_API_ERROR_NO_SUCH_ENTRY:
      error = clib_error_return (0, "client does not exist...");
      goto done;

    default:
      error = clib_error_return (0, "vnet_pppoeclient_add_del returned %d", rv);
      goto done;
    }

done:
  unformat_free (line_input);
  vec_free (custom_ifname);

  return error;
}

/*?
 * Add or delete a PPPoE client.
 *
 * @cliexpar
 * Example of how to create a PPPoE client:
 * @cliexcmd{create pppoe client GigabitEthernet0/0/0 host-uniq 1234}
 * Example of how to delete a PPPoE client:
 * @cliexcmd{create pppoe client sw-if-index 0 host-uniq 1234 del}
 ?*/
VLIB_CLI_COMMAND (create_pppoeclient_command, static) = {
  .path = "create pppoe client",
  .short_help = "create pppoe client <interface>|sw-if-index <nn> host-uniq <nn> "
		"[name <ifname>] [del]",
  .function = pppoeclient_add_del_command_fn,
};

/* Accept either a bare pppoeclient pool index ("0", "1", ...) or the name
 * of the PPPoX virtual interface associated with a client ("pppox0",
 * "ppp0" if a custom name was assigned, GigabitEthernet*, etc.).
 *
 * Returns 1 with *out set to the pool index on success, 0 on failure.
 * A valid interface name that doesn't resolve to any client is treated
 * as failure so the caller can surface a meaningful error. */
static uword
unformat_pppoeclient_index_or_intf (unformat_input_t *input, va_list *args)
{
  u32 *out = va_arg (*args, u32 *);
  pppoeclient_main_t *pem = &pppoeclient_main;
  vnet_main_t *vnm = pem->vnet_main;
  pppoeclient_t *c;
  u32 sw_if_index;
  u32 pool_index;

  if (unformat (input, "%U", unformat_vnet_sw_interface, vnm, &sw_if_index))
    {
      pool_foreach (c, pem->clients)
	{
	  if (c->pppox_sw_if_index == sw_if_index || c->sw_if_index == sw_if_index)
	    {
	      *out = c - pem->clients;
	      return 1;
	    }
	}
      return 0;
    }
  if (unformat (input, "%u", &pool_index))
    {
      *out = pool_index;
      return 1;
    }
  return 0;
}

static clib_error_t *
pppoeclient_restart_command_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  pppoeclient_main_t *pem = &pppoeclient_main;
  u32 client_index = ~0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%U", unformat_pppoeclient_index_or_intf, &client_index))
	;
      else
	return clib_error_return (0, "unknown input `%U'", format_unformat_error, input);
    }

  if (client_index == ~0)
    return clib_error_return (0, "please specify client index");

  if (pool_is_free_index (pem->clients, client_index))
    return clib_error_return (0, "invalid client index %u", client_index);

  pppoeclient_restart_session (client_index);
  vlib_cli_output (vm, "PPPoE client %u restarted", client_index);
  return 0;
}

/*?
 * Restart a PPPoE client session (sends PADT, then re-enters discovery).
 *
 * @cliexpar
 * @cliexcmd{pppoe client restart 0}
 ?*/
VLIB_CLI_COMMAND (pppoeclient_restart_command, static) = {
  .path = "pppoe client restart",
  .short_help = "pppoe client restart <client-index>|<interface>",
  .function = pppoeclient_restart_command_fn,
};

static clib_error_t *
pppoeclient_stop_command_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  pppoeclient_main_t *pem = &pppoeclient_main;
  u32 client_index = ~0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%U", unformat_pppoeclient_index_or_intf, &client_index))
	;
      else
	return clib_error_return (0, "unknown input `%U'", format_unformat_error, input);
    }

  if (client_index == ~0)
    return clib_error_return (0, "please specify client index");

  if (pool_is_free_index (pem->clients, client_index))
    return clib_error_return (0, "invalid client index %u", client_index);

  pppoeclient_stop_session (client_index);
  vlib_cli_output (vm, "PPPoE client %u stopped", client_index);
  return 0;
}

/*?
 * Stop a PPPoE client session (sends PADT, returns to discovery idle).
 *
 * @cliexpar
 * @cliexcmd{pppoe client stop 0}
 ?*/
VLIB_CLI_COMMAND (pppoeclient_stop_command, static) = {
  .path = "pppoe client stop",
  .short_help = "pppoe client stop <client-index>|<interface>",
  .function = pppoeclient_stop_command_fn,
};

static clib_error_t *
pppoeclient_inject_auth_fail_command_fn (vlib_main_t *vm, unformat_input_t *input,
					 vlib_cli_command_t *cmd)
{
  pppoeclient_main_t *pem = &pppoeclient_main;
  pppoeclient_t *c;
  u32 client_index = ~0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%U", unformat_pppoeclient_index_or_intf, &client_index))
	;
      else
	return clib_error_return (0, "unknown input `%U'", format_unformat_error, input);
    }

  if (client_index == ~0)
    return clib_error_return (0, "please specify client index");
  if (pool_is_free_index (pem->clients, client_index))
    return clib_error_return (0, "invalid client index %u", client_index);

  /* Testing hook — bypass the race short-circuit so successive CLI invocations
   * step through the backoff ladder without waiting for the cooldown between
   * each injection. This is not the real path a BAS-driven auth failure takes. */
  c = pool_elt_at_index (pem->clients, client_index);
  c->next_transmit = 0;
  pppoeclient_restart_session_with_reason (client_index, PPPOECLIENT_DISCONNECT_AUTH_FAIL);
  vlib_cli_output (vm, "PPPoE client %u restarted as auth-fail", client_index);
  return 0;
}

/*?
 * Inject a synthetic auth-failure teardown so operators and regressions can
 * exercise the exponential backoff without needing a BAS to reject the link.
 *
 * @cliexpar
 * @cliexcmd{test pppoe client 0 inject-auth-fail}
 ?*/
VLIB_CLI_COMMAND (pppoeclient_inject_auth_fail_command, static) = {
  .path = "test pppoe client inject-auth-fail",
  .short_help = "test pppoe client inject-auth-fail <client-index>|<interface>",
  .function = pppoeclient_inject_auth_fail_command_fn,
};

static clib_error_t *
pppoeclient_show_backoff_command_fn (vlib_main_t *vm, unformat_input_t *input,
				     vlib_cli_command_t *cmd)
{
  pppoeclient_main_t *pem = &pppoeclient_main;
  pppoeclient_t *c;
  f64 now = vlib_time_now (vm);
  u32 jitter_permille = (u32) (pem->auth_backoff_jitter_fraction * 1000.0 + 0.5);

  vlib_cli_output (vm, "auth-backoff base %us cap %us jitter-permille %u",
		   (u32) PPPOECLIENT_AUTH_BACKOFF_BASE_SEC, (u32) PPPOECLIENT_AUTH_BACKOFF_CAP_SEC,
		   jitter_permille);

  if (pool_elts (pem->clients) == 0)
    {
      vlib_cli_output (vm, "(no clients)");
      return 0;
    }

  pool_foreach (c, pem->clients)
    {
      f64 scheduled = c->next_transmit;
      /* PPPOECLIENT_NEXT_TRANSMIT_PARKED is the "park in SESSION" sentinel. */
      if (PPPOECLIENT_NEXT_TRANSMIT_IS_PARKED (scheduled))
	vlib_cli_output (vm,
			 "  client %u state %U auth-failures %u reconnects %u "
			 "last-reason %u next-retry parked",
			 (u32) (c - pem->clients), format_pppoe_client_state, c->state,
			 c->consecutive_auth_failures, c->total_reconnects,
			 c->last_disconnect_reason);
      else
	vlib_cli_output (vm,
			 "  client %u state %U auth-failures %u reconnects %u "
			 "last-reason %u next-retry in %.1fs",
			 (u32) (c - pem->clients), format_pppoe_client_state, c->state,
			 c->consecutive_auth_failures, c->total_reconnects,
			 c->last_disconnect_reason, clib_max (0.0, scheduled - now));
    }

  return 0;
}

/*?
 * Dump the exponential-backoff state for each PPPoE client: consecutive
 * auth failures, total reconnects, last disconnect reason, and the time
 * remaining until the next scheduled retransmit.
 *
 * @cliexpar
 * @cliexcmd{show pppoe client backoff}
 ?*/
VLIB_CLI_COMMAND (show_pppoeclient_backoff_command, static) = {
  .path = "show pppoe client backoff",
  .short_help = "show pppoe client backoff",
  .function = pppoeclient_show_backoff_command_fn,
};

/* Shared helper for the F7 convenience show CLIs.  Returns 1 iff the
 * pppox plugin symbol resolved and the client's LCP runtime could be read
 * into *rt; 0 means the caller should skip this client. */
static u8
pppoeclient_cli_get_ppp_runtime (pppoeclient_t *c, pppox_ppp_debug_runtime_t *rt)
{
  static u8 (*func) (u32, pppox_ppp_debug_runtime_t *) = 0;
  PPPOECLIENT_LAZY_PLUGIN_SYMBOL (func, "pppoeclient_plugin.so", "pppox_get_ppp_debug_runtime");
  clib_memset (rt, 0, sizeof (*rt));
  if (func == 0 || c->pppox_sw_if_index == ~0)
    return 0;
  return (*func) (c->pppox_sw_if_index, rt);
}

static clib_error_t *
pppoeclient_show_mtu_command_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  pppoeclient_main_t *pem = &pppoeclient_main;
  pppoeclient_t *c;

  if (pool_elts (pem->clients) == 0)
    {
      vlib_cli_output (vm, "(no clients)");
      return 0;
    }

  pool_foreach (c, pem->clients)
    {
      pppox_ppp_debug_runtime_t rt;
      u8 have_rt = pppoeclient_cli_get_ppp_runtime (c, &rt);
      if (have_rt && (rt.negotiated_mtu || rt.negotiated_mru))
	vlib_cli_output (vm, "  client %u %U configured mtu %u mru %u negotiated tx %u rx %u",
			 (u32) (c - pem->clients), format_pppoe_client_state, c->state, c->mtu,
			 c->mru, rt.negotiated_mtu, rt.negotiated_mru);
      else
	vlib_cli_output (vm, "  client %u %U configured mtu %u mru %u negotiated <pending>",
			 (u32) (c - pem->clients), format_pppoe_client_state, c->state, c->mtu,
			 c->mru);
    }
  return 0;
}

/*?
 * Print one line per client with configured and LCP-negotiated MTU/MRU.
 * Useful to spot BAS peers that clamp MTU below the operator-requested
 * value without trawling through @c show pppoe client detail.
 *
 * @cliexpar
 * @cliexcmd{show pppoe client mtu}
 ?*/
VLIB_CLI_COMMAND (show_pppoeclient_mtu_command, static) = {
  .path = "show pppoe client mtu",
  .short_help = "show pppoe client mtu",
  .function = pppoeclient_show_mtu_command_fn,
};

static clib_error_t *
pppoeclient_show_dns_command_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  pppoeclient_main_t *pem = &pppoeclient_main;
  pppoeclient_t *c;

  if (pool_elts (pem->clients) == 0)
    {
      vlib_cli_output (vm, "(no clients)");
      return 0;
    }

  pool_foreach (c, pem->clients)
    {
      pppox_ppp_debug_runtime_t rt;
      u8 have_rt = pppoeclient_cli_get_ppp_runtime (c, &rt);
      if (have_rt && (rt.negotiated_dns1 || rt.negotiated_dns2))
	vlib_cli_output (vm, "  client %u %U dns1 %U dns2 %U", (u32) (c - pem->clients),
			 format_pppoe_client_state, c->state, format_ip4_address,
			 &rt.negotiated_dns1, format_ip4_address, &rt.negotiated_dns2);
      else
	vlib_cli_output (vm, "  client %u %U dns <pending>", (u32) (c - pem->clients),
			 format_pppoe_client_state, c->state);
    }
  return 0;
}

/*?
 * Print one line per client with the IPCP-negotiated DNS servers.
 * Returns <pending> when the client has not reached an OPENED IPCP yet.
 *
 * @cliexpar
 * @cliexcmd{show pppoe client dns}
 ?*/
VLIB_CLI_COMMAND (show_pppoeclient_dns_command, static) = {
  .path = "show pppoe client dns",
  .short_help = "show pppoe client dns",
  .function = pppoeclient_show_dns_command_fn,
};

static clib_error_t *
pppoeclient_show_session_time_command_fn (vlib_main_t *vm, unformat_input_t *input,
					  vlib_cli_command_t *cmd)
{
  pppoeclient_main_t *pem = &pppoeclient_main;
  pppoeclient_t *c;
  f64 now = vlib_time_now (vm);

  if (pool_elts (pem->clients) == 0)
    {
      vlib_cli_output (vm, "(no clients)");
      return 0;
    }

  pool_foreach (c, pem->clients)
    {
      u64 total = c->total_session_seconds;
      u32 last = c->last_session_duration_seconds;
      if (c->state == PPPOE_CLIENT_SESSION && c->session_start_time > 0)
	{
	  u32 secs = (u32) (now - c->session_start_time);
	  vlib_cli_output (
	    vm, "  client %u %U current %uh %um %us last %us total %llus reconnects %u",
	    (u32) (c - pem->clients), format_pppoe_client_state, c->state, secs / 3600,
	    (secs % 3600) / 60, secs % 60, last, total, c->total_reconnects);
	}
      else
	vlib_cli_output (
	  vm, "  client %u %U current <not-in-session> last %us total %llus reconnects %u",
	  (u32) (c - pem->clients), format_pppoe_client_state, c->state, last, total,
	  c->total_reconnects);
    }
  return 0;
}

/*?
 * Print one line per client with the current session uptime.  Clients
 * not in the SESSION state report <not-in-session>.
 *
 * @cliexpar
 * @cliexcmd{show pppoe client session-time}
 ?*/
VLIB_CLI_COMMAND (show_pppoeclient_session_time_command, static) = {
  .path = "show pppoe client session-time",
  .short_help = "show pppoe client session-time",
  .function = pppoeclient_show_session_time_command_fn,
};

static clib_error_t *
pppoeclient_clear_backoff_command_fn (vlib_main_t *vm, unformat_input_t *input,
				      vlib_cli_command_t *cmd)
{
  pppoeclient_main_t *pem = &pppoeclient_main;
  pppoeclient_t *c;
  u32 client_index = ~0;
  u8 all = 0;
  u8 immediate = 0;
  f64 now;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "all"))
	all = 1;
      else if (unformat (input, "immediate"))
	immediate = 1;
      else if (unformat (input, "%U", unformat_pppoeclient_index_or_intf, &client_index))
	;
      else
	return clib_error_return (0, "unknown input `%U'", format_unformat_error, input);
    }

  if (!all && client_index == ~0)
    return clib_error_return (0, "please specify client index or 'all'");

  now = vlib_time_now (vm);

  if (all)
    {
      u32 cleared = 0, rescheduled = 0;
      pool_foreach (c, pem->clients)
	{
	  if (c->consecutive_auth_failures != 0)
	    {
	      c->consecutive_auth_failures = 0;
	      cleared++;
	    }
	  if (immediate && c->state == PPPOE_CLIENT_DISCOVERY && c->next_transmit > now &&
	      !PPPOECLIENT_NEXT_TRANSMIT_IS_PARKED (c->next_transmit))
	    {
	      pppoeclient_schedule_discovery (c, now);
	      rescheduled++;
	    }
	}
      if (immediate)
	vlib_cli_output (vm, "cleared backoff on %u client(s), rescheduled %u", cleared,
			 rescheduled);
      else
	vlib_cli_output (vm, "cleared backoff on %u client(s)", cleared);
      return 0;
    }

  if (pool_is_free_index (pem->clients, client_index))
    return clib_error_return (0, "invalid client index %u", client_index);

  c = pool_elt_at_index (pem->clients, client_index);
  c->consecutive_auth_failures = 0;

  if (immediate && c->state == PPPOE_CLIENT_DISCOVERY && c->next_transmit > now &&
      !PPPOECLIENT_NEXT_TRANSMIT_IS_PARKED (c->next_transmit))
    {
      pppoeclient_schedule_discovery (c, now);
      vlib_cli_output (vm, "client %u backoff cleared and discovery rescheduled", client_index);
    }
  else
    {
      vlib_cli_output (vm, "client %u backoff cleared", client_index);
    }
  return 0;
}

/*?
 * Reset the consecutive-auth-failure counter for one client or every
 * client. Useful after flipping a BAS-side configuration so the next
 * reconnect doesn't wait out the previously-accumulated backoff.
 *
 * With @c immediate, clients currently waiting in DISCOVERY backoff also
 * have their next transmit brought forward to now so the dialer retries
 * right away instead of serving out the remaining cooldown.  Parked
 * clients (admin-disabled, host_uniq-unbound) are not disturbed.
 *
 * @cliexpar
 * @cliexcmd{clear pppoe client backoff 0}
 * @cliexcmd{clear pppoe client backoff all}
 * @cliexcmd{clear pppoe client backoff 0 immediate}
 ?*/
VLIB_CLI_COMMAND (clear_pppoeclient_backoff_command, static) = {
  .path = "clear pppoe client backoff",
  .short_help = "clear pppoe client backoff {<client-index>|<interface>|all} [immediate]",
  .function = pppoeclient_clear_backoff_command_fn,
};

static clib_error_t *
pppoeclient_set_backoff_jitter_command_fn (vlib_main_t *vm, unformat_input_t *input,
					   vlib_cli_command_t *cmd)
{
  pppoeclient_main_t *pem = &pppoeclient_main;
  f64 fraction = -1.0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%f", &fraction))
	;
      else
	return clib_error_return (0, "unknown input `%U'", format_unformat_error, input);
    }

  if (fraction < 0.0 || fraction > 0.5)
    return clib_error_return (0, "fraction must be in [0, 0.5]");

  pem->auth_backoff_jitter_fraction = fraction;
  vlib_cli_output (vm, "auth-backoff jitter-permille set to %u", (u32) (fraction * 1000.0 + 0.5));
  return 0;
}

/*?
 * Set the +/- jitter fraction applied to each auth-fail backoff cooldown.
 * 0 (the default) keeps the schedule deterministic, 0.1 spreads each
 * cooldown by +/- 10 percent so a fleet of clients kicked by the same BAS
 * doesn't retry in lockstep.
 *
 * @cliexpar
 * @cliexcmd{set pppoeclient backoff-jitter 0.1}
 ?*/
VLIB_CLI_COMMAND (set_pppoeclient_backoff_jitter_command, static) = {
  .path = "set pppoeclient backoff-jitter",
  .short_help = "set pppoeclient backoff-jitter <fraction 0..0.5>",
  .function = pppoeclient_set_backoff_jitter_command_fn,
};

static clib_error_t *
show_pppoeclient_command_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  pppoeclient_main_t *pem = &pppoeclient_main;
  pppoeclient_t *t;

  if (pool_elts (pem->clients) == 0)
    vlib_cli_output (vm, "No pppoe clients configured...");

  pool_foreach (t, pem->clients)
    {
      vlib_cli_output (vm, "%U", format_pppoe_client, t);
    };

  return 0;
}
/*?
 * Display detailed PPPoE client entries.
 *
 * @cliexpar
 * Example of how to display detailed PPPoE client entries:
 * @cliexstart{show pppoe client}
 * [0] host_uniq sw-if-index 0 status ???
 * @cliexend
 ?*/
VLIB_CLI_COMMAND (show_pppoeclient_command, static) = {
  .path = "show pppoe client",
  .short_help = "show pppoe client",
  .function = show_pppoeclient_command_fn,
};
static clib_error_t *
show_pppoeclient_detail_command_fn (vlib_main_t *vm, unformat_input_t *input,
				    vlib_cli_command_t *cmd)
{
  pppoeclient_main_t *pem = &pppoeclient_main;
  pppoeclient_t *t;

  if (pool_elts (pem->clients) == 0)
    {
      vlib_cli_output (vm, "No pppoe clients configured...");
      return 0;
    }

  pool_foreach (t, pem->clients)
    {
      show_pppoeclient_detail_one (vm, t);
    }

  return 0;
}

/*?
 * Display detailed client-side PPPoE session state.
 *
 * @cliexpar
 * Example of how to display PPPoE client-side session details:
 * @cliexstart{show pppoe client detail}
 * [0] sw-if-index 1 (TenGigabitEthernet...) host-uniq 1234
 *     client-state PPPOE_CLIENT_SESSION session-id 4660 ac-mac aa:bb:cc:dd:ee:ff
 *     pppox-sw-if-index 2 (pppox0) pppox-unit 0 session-allocated 1
 * @cliexend
 ?*/
VLIB_CLI_COMMAND (show_pppoeclient_detail_command, static) = {
  .path = "show pppoe client detail",
  .short_help = "show pppoe client detail",
  .function = show_pppoeclient_detail_command_fn,
};
static clib_error_t *
show_pppoeclient_debug_command_fn (vlib_main_t *vm, unformat_input_t *input,
				   vlib_cli_command_t *cmd)
{
  pppoeclient_main_t *pem = &pppoeclient_main;
  pppoeclient_t *t;
  pppoeclient_history_cli_filter_t filter = { 0 };
  u32 client_index = ~0;
  u8 show_orphan_only = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "orphan"))
	show_orphan_only = 1;
      else if (unformat (input, "code %U", unformat_pppoe_packet_code_name, &filter.code))
	filter.filter_code = 1;
      else if (unformat (input, "parse-errors-only"))
	filter.parse_errors_only = 1;
      else if (unformat (input, "disposition %U", unformat_pppoeclient_control_disposition_name,
			 &filter.disposition))
	filter.filter_disposition = 1;
      else if (unformat (input, "match-reason %U", unformat_pppoeclient_control_match_reason_name,
			 &filter.match_reason))
	filter.filter_match_reason = 1;
      else if (unformat (input, "%U", unformat_pppoeclient_index_or_intf, &client_index))
	;
      else
	return clib_error_return (0, "unknown input `%U'", format_unformat_error, input);
    }

  if (show_orphan_only && client_index != ~0)
    return clib_error_return (0, "please specify either a client index or `orphan`, not both");

  if (pool_elts (pem->clients) == 0)
    {
      if (!show_orphan_only && pem->orphan_control_history_count == 0)
	{
	  vlib_cli_output (vm, "No pppoe clients configured...");
	  return 0;
	}
    }

  if (show_orphan_only)
    {
      show_pppoeclient_orphan_control_history_filtered (vm, &filter);
      return 0;
    }

  if (client_index != ~0)
    {
      if (pool_is_free_index (pem->clients, client_index))
	return clib_error_return (0, "invalid client index");
      if (pppoeclient_history_cli_filter_active (&filter))
	show_pppoeclient_debug_one (vm, pool_elt_at_index (pem->clients, client_index), &filter);
      else
	show_pppoeclient_debug_one (vm, pool_elt_at_index (pem->clients, client_index), 0);
      return 0;
    }

  pool_foreach (t, pem->clients)
    {
      if (pppoeclient_history_cli_filter_active (&filter))
	show_pppoeclient_debug_one (vm, t, &filter);
      else
	show_pppoeclient_debug_one (vm, t, 0);
    }

  if (pem->orphan_control_history_count)
    {
      if (pppoeclient_history_cli_filter_active (&filter))
	show_pppoeclient_orphan_control_history_filtered (vm, &filter);
      else
	show_pppoeclient_orphan_control_history (vm);
    }

  return 0;
}

VLIB_CLI_COMMAND (show_pppoeclient_debug_command, static) = {
  .path = "show pppoe client debug",
  .short_help = "show pppoe client debug [<client-index>|<interface>|orphan] "
		"[code pado|pads|padt] [parse-errors-only] "
		"[disposition accepted|ignored|error|orphan|none] "
		"[match-reason host-uniq|ac-name|service-name|ac-mac|"
		"ac+service|ac-mac+service|cookie|cookie+service|unique|"
		"session|any|none]",
  .function = show_pppoeclient_debug_command_fn,
};

static clib_error_t *
show_pppoeclient_summary_command_fn (vlib_main_t *vm, unformat_input_t *input,
				     vlib_cli_command_t *cmd)
{
  pppoeclient_main_t *pem = &pppoeclient_main;
  pppoeclient_t *t;
  pppoeclient_history_cli_filter_t filter = { 0 };
  u32 client_index = ~0;
  u8 show_orphan_only = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "orphan"))
	show_orphan_only = 1;
      else if (unformat (input, "max-events %u", &filter.max_events))
	;
      else if (unformat (input, "code %U", unformat_pppoe_packet_code_name, &filter.code))
	filter.filter_code = 1;
      else if (unformat (input, "parse-errors-only"))
	filter.parse_errors_only = 1;
      else if (unformat (input, "disposition %U", unformat_pppoeclient_control_disposition_name,
			 &filter.disposition))
	filter.filter_disposition = 1;
      else if (unformat (input, "match-reason %U", unformat_pppoeclient_control_match_reason_name,
			 &filter.match_reason))
	filter.filter_match_reason = 1;
      else if (unformat (input, "%U", unformat_pppoeclient_index_or_intf, &client_index))
	;
      else
	return clib_error_return (0, "unknown input `%U'", format_unformat_error, input);
    }

  if (show_orphan_only && client_index != ~0)
    return clib_error_return (0, "please specify either a client index or `orphan`, not both");

  if (show_orphan_only)
    {
      show_pppoeclient_orphan_control_summary_filtered (vm, &filter);
      return 0;
    }

  if (client_index != ~0)
    {
      if (pool_is_free_index (pem->clients, client_index))
	return clib_error_return (0, "invalid client index");
      show_pppoeclient_summary_filtered_one (vm, pool_elt_at_index (pem->clients, client_index),
					     &filter);
      return 0;
    }

  if (pool_elts (pem->clients) == 0)
    vlib_cli_output (vm, "No pppoe clients configured...");

  pool_foreach (t, pem->clients)
    {
      show_pppoeclient_summary_filtered_one (vm, t, &filter);
    }

  if (pem->orphan_control_history_count)
    show_pppoeclient_orphan_control_summary_filtered (vm, &filter);

  return 0;
}

VLIB_CLI_COMMAND (show_pppoeclient_summary_command, static) = {
  .path = "show pppoe client summary",
  .short_help = "show pppoe client summary [<client-index>|<interface>|orphan] [max-events <n>] "
		"[code pado|pads|padt] [parse-errors-only] "
		"[disposition accepted|ignored|error|orphan|none] "
		"[match-reason host-uniq|ac-name|service-name|ac-mac|"
		"ac+service|ac-mac+service|cookie|cookie+service|unique|"
		"session|any|none]",
  .function = show_pppoeclient_summary_command_fn,
};

static clib_error_t *
show_pppoeclient_history_command_fn (vlib_main_t *vm, unformat_input_t *input,
				     vlib_cli_command_t *cmd)
{
  pppoeclient_main_t *pem = &pppoeclient_main;
  pppoeclient_t *t;
  pppoeclient_history_cli_filter_t filter = { 0 };
  u32 client_index = ~0;
  u8 show_orphan_only = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "orphan"))
	show_orphan_only = 1;
      else if (unformat (input, "max-events %u", &filter.max_events))
	;
      else if (unformat (input, "code %U", unformat_pppoe_packet_code_name, &filter.code))
	filter.filter_code = 1;
      else if (unformat (input, "parse-errors-only"))
	filter.parse_errors_only = 1;
      else if (unformat (input, "disposition %U", unformat_pppoeclient_control_disposition_name,
			 &filter.disposition))
	filter.filter_disposition = 1;
      else if (unformat (input, "match-reason %U", unformat_pppoeclient_control_match_reason_name,
			 &filter.match_reason))
	filter.filter_match_reason = 1;
      else if (unformat (input, "%U", unformat_pppoeclient_index_or_intf, &client_index))
	;
      else
	return clib_error_return (0, "unknown input `%U'", format_unformat_error, input);
    }

  if (show_orphan_only && client_index != ~0)
    return clib_error_return (0, "please specify either a client index or `orphan`, not both");

  if (show_orphan_only)
    {
      show_pppoeclient_orphan_control_history_filtered (vm, &filter);
      return 0;
    }

  if (client_index != ~0)
    {
      if (pool_is_free_index (pem->clients, client_index))
	return clib_error_return (0, "invalid client index");
      show_pppoeclient_history_filtered_one (vm, pool_elt_at_index (pem->clients, client_index),
					     &filter);
      return 0;
    }

  if (pool_elts (pem->clients) == 0)
    vlib_cli_output (vm, "No pppoe clients configured...");

  pool_foreach (t, pem->clients)
    {
      show_pppoeclient_history_filtered_one (vm, t, &filter);
    }

  if (pem->orphan_control_history_count)
    show_pppoeclient_orphan_control_history_filtered (vm, &filter);

  return 0;
}

VLIB_CLI_COMMAND (show_pppoeclient_history_command, static) = {
  .path = "show pppoe client history",
  .short_help = "show pppoe client history [<client-index>|<interface>|orphan] [max-events <n>] "
		"[code pado|pads|padt] [parse-errors-only] "
		"[disposition accepted|ignored|error|orphan|none] "
		"[match-reason host-uniq|ac-name|service-name|ac-mac|"
		"ac+service|ac-mac+service|cookie|cookie+service|unique|"
		"session|any|none]",
  .function = show_pppoeclient_history_command_fn,
};

static clib_error_t *
clear_pppoeclient_history_command_fn (vlib_main_t *vm, unformat_input_t *input,
				      vlib_cli_command_t *cmd)
{
  pppoeclient_main_t *pem = &pppoeclient_main;
  u32 client_index = ~0;
  u8 clear_orphan = 0;
  u8 clear_all = 0;
  u32 cleared_clients = 0;
  pppoeclient_t *c;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "orphan"))
	clear_orphan = 1;
      else if (unformat (input, "all"))
	clear_all = 1;
      else if (unformat (input, "%U", unformat_pppoeclient_index_or_intf, &client_index))
	;
      else
	return clib_error_return (0, "unknown input `%U'", format_unformat_error, input);
    }

  if ((clear_orphan + clear_all + (client_index != ~0)) != 1)
    return clib_error_return (0, "please specify exactly one of: <client-index>, orphan, all");

  if (clear_all)
    {
      pool_foreach (c, pem->clients)
	{
	  pppoeclient_clear_control_history (c->control_history, &c->control_history_count,
					     &c->control_history_next);
	  cleared_clients++;
	}
      pppoeclient_clear_control_history (pem->orphan_control_history,
					 &pem->orphan_control_history_count,
					 &pem->orphan_control_history_next);
      vlib_cli_output (vm, "Cleared PPPoE control history for %u clients and orphan history",
		       cleared_clients);
      return 0;
    }

  if (clear_orphan)
    {
      pppoeclient_clear_control_history (pem->orphan_control_history,
					 &pem->orphan_control_history_count,
					 &pem->orphan_control_history_next);
      vlib_cli_output (vm, "Cleared PPPoE orphan control history");
      return 0;
    }

  if (pool_is_free_index (pem->clients, client_index))
    return clib_error_return (0, "invalid client index");

  c = pool_elt_at_index (pem->clients, client_index);
  pppoeclient_clear_control_history (c->control_history, &c->control_history_count,
				     &c->control_history_next);
  vlib_cli_output (vm, "Cleared PPPoE control history for client %u", client_index);
  return 0;
}

VLIB_CLI_COMMAND (clear_pppoeclient_history_command, static) = {
  .path = "clear pppoe client history",
  .short_help = "clear pppoe client history <client-index>|<interface>|orphan|all",
  .function = clear_pppoeclient_history_command_fn,
};

static clib_error_t *
set_pppoeclient_command_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  pppoeclient_main_t *pem = &pppoeclient_main;
  pppoeclient_t *c = 0;
  u32 client_index = ~0;
  u8 *ac_name = 0;
  u8 *service_name = 0;
  u8 *username = 0;
  u8 *password = 0;
  u32 mtu = 0;
  u32 mru = 0;
  u32 timeout = 0;
  u8 use_peer_dns = 0;
  u8 add_default_route4 = 0;
  u8 add_default_route6 = 0;
  u8 clear_ac_name = 0;
  u8 clear_service_name = 0;
  u8 sync_live_auth = 0;
  u8 route_or_dns_changed = 0;
  int rv;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%U", unformat_pppoeclient_index_or_intf, &client_index))
	;
      else if (unformat (input, "ac-name any"))
	clear_ac_name = 1;
      else if (unformat (input, "ac-name %s", &ac_name))
	;
      else if (unformat (input, "service-name any"))
	clear_service_name = 1;
      else if (unformat (input, "service-name %s", &service_name))
	;
      else if (unformat (input, "username %s", &username))
	;
      else if (unformat (input, "password %s", &password))
	;
      else if (unformat (input, "mtu %u", &mtu))
	;
      else if (unformat (input, "mru %u", &mru))
	;
      else if (unformat (input, "timeout %u", &timeout))
	;
      else if (unformat (input, "use-peer-dns"))
	use_peer_dns = 1;
      else if (unformat (input, "add-default-route4"))
	add_default_route4 = 1;
      else if (unformat (input, "add-default-route6"))
	add_default_route6 = 1;
      else if (unformat (input, "add-default-route"))
	add_default_route4 = add_default_route6 = 1;
      else if (unformat (input, "use-peer-route"))
	add_default_route4 = add_default_route6 = 1;
      else
	break;
    }

  if (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      vec_free (service_name);
      vec_free (ac_name);
      vec_free (username);
      vec_free (password);
      return clib_error_return (0, "unknown input `%U'", format_unformat_error, input);
    }

  pppoeclient_cli_trim_c_string (&ac_name);
  pppoeclient_cli_trim_c_string (&service_name);
  pppoeclient_cli_trim_c_string (&username);
  pppoeclient_cli_trim_c_string (&password);

  if (vec_len (username) > 64 || vec_len (password) > 64)
    {
      vec_free (service_name);
      vec_free (ac_name);
      vec_free (username);
      vec_free (password);
      return clib_error_return (0, "username and password must be <= 64 bytes");
    }

  if (client_index == ~0)
    {
      vec_free (service_name);
      vec_free (ac_name);
      vec_free (username);
      vec_free (password);
      return clib_error_return (0, "please specify client index");
    }

  if (pool_is_free_index (pem->clients, client_index))
    {
      vec_free (service_name);
      vec_free (ac_name);
      vec_free (username);
      vec_free (password);
      return clib_error_return (0, "invalid client index");
    }

  c = pool_elt_at_index (pem->clients, client_index);

  if (username)
    {
      vec_free (c->username);
      c->username = username;
      sync_live_auth = 1;
    }
  if (password)
    {
      if (c->password)
	clib_memset (c->password, 0, vec_len (c->password));
      vec_free (c->password);
      c->password = password;
      sync_live_auth = 1;
    }
  if (service_name)
    {
      vec_free (c->service_name);
      c->service_name = service_name;
    }
  else if (clear_service_name)
    {
      vec_free (c->service_name);
      c->service_name = 0;
    }
  if (ac_name)
    {
      vec_free (c->ac_name_filter);
      c->ac_name_filter = ac_name;
    }
  else if (clear_ac_name)
    {
      vec_free (c->ac_name_filter);
      c->ac_name_filter = 0;
    }
  if (mtu > 0)
    c->mtu = mtu;
  if (mru > 0)
    {
      c->mru = mru;
      /* Propagate to pppox so LCP negotiation requests this MRU. */
      if (c->pppox_sw_if_index != ~0)
	pppox_set_configured_mru (c->pppox_sw_if_index, (u16) mru);
    }
  if (timeout > 0)
    c->timeout = timeout;
  if (use_peer_dns)
    {
      c->use_peer_dns = 1;
      route_or_dns_changed = 1;
    }
  if (add_default_route4)
    {
      c->use_peer_route4 = 1;
      route_or_dns_changed = 1;
    }
  if (add_default_route6)
    {
      c->use_peer_route6 = 1;
      route_or_dns_changed = 1;
    }

  rv = sync_pppoe_client_live_default_route4 (c);
  if (rv)
    return clib_error_return (0,
			      "failed to sync live add-default-route4 on pppox sw-if-index %u: %d",
			      c->pppox_sw_if_index, rv);

  rv = sync_pppoe_client_live_default_route6 (c);
  if (rv)
    return clib_error_return (0,
			      "failed to sync live add-default-route6 on pppox sw-if-index %u: %d",
			      c->pppox_sw_if_index, rv);

  rv = sync_pppoe_client_live_use_peer_dns (c);
  if (rv)
    return clib_error_return (0, "failed to sync live use-peer-dns on pppox sw-if-index %u: %d",
			      c->pppox_sw_if_index, rv);

  if (sync_live_auth)
    {
      rv = sync_pppoe_client_live_auth (c);
      if (rv)
	return clib_error_return (0, "failed to sync live auth on pppox sw-if-index %u: %d",
				  c->pppox_sw_if_index, rv);
    }

  if (route_or_dns_changed)
    vlib_cli_output (vm,
		     "PPPoE client %u updated (route/DNS state synced; active session may need "
		     "reconnect for full effect)",
		     client_index);
  else
    vlib_cli_output (vm, "PPPoE client %u updated", client_index);
  return 0;
}
VLIB_CLI_COMMAND (set_pppoeclient_command, static) = {
  .path = "set pppoe client",
  .short_help = "set pppoe client <client-index>|<interface> "
		"[ac-name <name>|ac-name any] [service-name <name>|service-name any] "
		"[username <user>] [password <pass>] [mtu <n>] [mru <n>] [timeout <n>] "
		"[use-peer-dns] [add-default-route | add-default-route4 | add-default-route6]",
  .function = set_pppoeclient_command_fn,
};
clib_error_t *
pppoeclient_init (vlib_main_t *vm)
{
  pppoeclient_main_t *pem = &pppoeclient_main;
  u8 *packet_data;
  ethernet_header_t *eth;
  pppoe_header_t *pppoe;

  pem->vnet_main = vnet_get_main ();
  pem->vlib_main = vm;

  pppoeclient_log_class = vlib_log_register_class ("pppoeclient", "main");

  /* Create the hash table  */
  clib_bihash_init_8_8 (&pem->client_table, "pppoe client table", PPPOE_CLIENT_NUM_BUCKETS,
			PPPOE_CLIENT_MEMORY_SIZE);
  clib_bihash_init_16_8 (&pem->session_table, "pppoe client_session table",
			 PPPOE_CLIENT_NUM_BUCKETS, PPPOE_CLIENT_MEMORY_SIZE);

  /* Initialize packet template for PPPoE discovery packets */
  packet_data = 0;
  vec_validate (packet_data, sizeof (ethernet_header_t) + sizeof (pppoe_header_t) - 1);
  eth = (ethernet_header_t *) packet_data;
  eth->type = clib_host_to_net_u16 (ETHERNET_TYPE_PPPOE_DISCOVERY);
  clib_memset (eth->dst_address, 0, 6);
  clib_memset (eth->src_address, 0, 6);
  pppoe = (pppoe_header_t *) (eth + 1);
  pppoe->ver_type = PPPOE_VER_TYPE;
  pppoe->code = 0;
  pppoe->session_id = 0;
  pppoe->length = 0;

  vlib_packet_template_init (vm, &pem->packet_template, packet_data, vec_len (packet_data), 4,
			     "pppoe-discovery-packet");
  vec_free (packet_data);

  pem->auth_backoff_jitter_fraction = 0.0;
  pem->rng_seed = (u32) (vlib_time_now (vm) * 1e6);
  if (pem->rng_seed == 0)
    pem->rng_seed = 1;

  /* Keep ethertype registration disabled for now. VPP allows only one
   * plugin to register a given Ethernet type, so PPPoE ingress currently
   * goes through the device-input feature dispatch path in node.c to
   * coexist with the existing pppoe plugin.
   *
   * ethernet_register_input_type (vm, ETHERNET_TYPE_PPPOE_DISCOVERY,
   * 				pppoeclient_discovery_input_node.index);
   * ethernet_register_input_type (vm, ETHERNET_TYPE_PPPOE_SESSION,
   * 				pppoeclient_session_input_node.index);
   */

  return 0;
}

VLIB_INIT_FUNCTION (pppoeclient_init);

/*
 * pppoeclient_send_padt_raw — send a PADT frame via raw AF_PACKET socket,
 * completely bypassing VPP's frame dispatch.  This is the only reliable way
 * to get a PADT on the wire during VLIB_MAIN_LOOP_EXIT, because the main
 * loop has already stopped and will never dispatch pending frames.
 */
static void
pppoeclient_send_padt_raw (const char *linux_ifname, const u8 *src_mac, const u8 *dst_mac,
			   u16 session_id)
{
  int fd;
  struct sockaddr_ll addr;
  u8 frame[64];
  struct ifreq ifr;

  fd = socket (AF_PACKET, SOCK_RAW, htons (ETH_P_ALL));
  if (fd < 0)
    {
      vlib_log (VLIB_LOG_LEVEL_ERR, pppoeclient_log_class, "raw socket failed: %s",
		strerror (errno));
      return;
    }

  clib_memset (&ifr, 0, sizeof (ifr));
  snprintf (ifr.ifr_name, sizeof (ifr.ifr_name), "%s", linux_ifname);
  if (ioctl (fd, SIOCGIFINDEX, &ifr) < 0)
    {
      vlib_log (VLIB_LOG_LEVEL_ERR, pppoeclient_log_class, "SIOCGIFINDEX(%s) failed: %s",
		linux_ifname, strerror (errno));
      close (fd);
      return;
    }

  /* Ensure the Linux interface is UP — RDMA/mlx5 uses ibverbs directly and
   * may leave the Linux netdev in DOWN state.  Raw AF_PACKET sendto() will
   * fail with ENETDOWN if the interface is not UP.
   *
   * IMPORTANT: We must restore the interface to DOWN after sending, because
   * leaving it UP causes the kernel's network stack to compete with VPP's
   * RDMA ibverbs path for incoming packets, breaking PPPoE discovery for
   * the next VPP instance. */
  int was_down = 0;
  {
    int ctl_fd = socket (AF_INET, SOCK_DGRAM, 0);
    if (ctl_fd >= 0)
      {
	struct ifreq up_ifr;
	clib_memset (&up_ifr, 0, sizeof (up_ifr));
	snprintf (up_ifr.ifr_name, sizeof (up_ifr.ifr_name), "%s", linux_ifname);
	if (ioctl (ctl_fd, SIOCGIFFLAGS, &up_ifr) == 0)
	  {
	    if (!(up_ifr.ifr_flags & IFF_UP))
	      {
		was_down = 1;
		vlib_log (VLIB_LOG_LEVEL_DEBUG, pppoeclient_log_class,
			  "%s is DOWN, bringing UP for PADT", linux_ifname);
		up_ifr.ifr_flags |= IFF_UP;
		if (ioctl (ctl_fd, SIOCSIFFLAGS, &up_ifr) < 0)
		  vlib_log (VLIB_LOG_LEVEL_ERR, pppoeclient_log_class, "failed to bring %s UP: %s",
			    linux_ifname, strerror (errno));
		else
		  {
		    /* Give the NIC a moment to initialize link */
		    usleep (PPPOECLIENT_RAW_PADT_LINK_UP_WAIT_US);
		  }
	      }
	  }
	close (ctl_fd);
      }
  }

  /* Build minimal PADT: 14B Ethernet + 6B PPPoE header = 20 bytes */
  clib_memcpy (frame + 0, dst_mac, 6);
  clib_memcpy (frame + 6, src_mac, 6);
  frame[12] = 0x88;
  frame[13] = 0x63; /* EtherType PPPoE Discovery */
  frame[14] = 0x11; /* ver=1 type=1 */
  frame[15] = 0xa7; /* code = PADT */
  frame[16] = (session_id >> 8) & 0xff;
  frame[17] = session_id & 0xff;
  frame[18] = 0x00;
  frame[19] = 0x00; /* payload length = 0 */

  clib_memset (&addr, 0, sizeof (addr));
  addr.sll_family = AF_PACKET;
  addr.sll_ifindex = ifr.ifr_ifindex;
  addr.sll_halen = 6;
  clib_memcpy (addr.sll_addr, dst_mac, 6);

  if (sendto (fd, frame, 20, 0, (struct sockaddr *) &addr, sizeof (addr)) < 0)
    vlib_log (VLIB_LOG_LEVEL_ERR, pppoeclient_log_class, "raw PADT sendto failed: %s",
	      strerror (errno));
  else
    vlib_log (VLIB_LOG_LEVEL_INFO, pppoeclient_log_class,
	      "sent PADT via raw socket on %s session %u", linux_ifname, session_id);

  close (fd);

  /* Restore interface to DOWN if we brought it UP, so the next VPP instance's
   * RDMA driver can properly take ownership of the interface. */
  if (was_down)
    {
      int ctl_fd = socket (AF_INET, SOCK_DGRAM, 0);
      if (ctl_fd >= 0)
	{
	  struct ifreq down_ifr;
	  clib_memset (&down_ifr, 0, sizeof (down_ifr));
	  snprintf (down_ifr.ifr_name, sizeof (down_ifr.ifr_name), "%s", linux_ifname);
	  if (ioctl (ctl_fd, SIOCGIFFLAGS, &down_ifr) == 0)
	    {
	      down_ifr.ifr_flags &= ~IFF_UP;
	      if (ioctl (ctl_fd, SIOCSIFFLAGS, &down_ifr) == 0)
		vlib_log (VLIB_LOG_LEVEL_INFO, pppoeclient_log_class, "restored %s to DOWN",
			  linux_ifname);
	      else
		vlib_log (VLIB_LOG_LEVEL_ERR, pppoeclient_log_class,
			  "failed to restore %s DOWN: %s", linux_ifname, strerror (errno));
	    }
	  close (ctl_fd);
	}
    }
}

/*
 * pppoeclient_get_linux_ifname — resolve the Linux network interface name
 * for a VPP sw_if_index.  For RDMA interfaces the Linux device coexists
 * with VPP, so we can send raw frames through it during shutdown.
 *
 * Strategy: read the VPP hw interface's PCI address from /sys, then scan
 * /sys/class/net/ to find a Linux interface on the same PCI device.
 * This works even when VPP has changed the MAC address (locally administered).
 */
static int
pppoeclient_get_linux_ifname (vnet_main_t *vnm, u32 sw_if_index, char *buf, size_t buf_len,
			      u8 noisy)
{
  vnet_hw_interface_t *hw = vnet_get_sup_hw_interface (vnm, sw_if_index);
  if (!hw)
    return -1;

  /* Use VPP's device_class format function to extract the Linux interface name.
   * For RDMA, format_rdma_device() outputs "netdev <linux_ifname> pci-addr ..."
   * This avoids MAC matching (which fails when VPP uses locally-administered
   * MAC) and avoids depending on RDMA internal struct layout. */
  vnet_device_class_t *dc = vnet_get_device_class (vnm, hw->dev_class_index);
  if (noisy)
    vlib_log (VLIB_LOG_LEVEL_DEBUG, pppoeclient_log_class,
	      "get_linux_ifname: sw_if_index=%u dev_class='%s' "
	      "format_device=%p dev_instance=%u",
	      sw_if_index, dc ? dc->name : "NULL", dc ? (void *) dc->format_device : 0,
	      hw->dev_instance);
  if (dc && dc->format_device)
    {
      u8 *s = 0;
      s = format (s, "%U", dc->format_device, hw->dev_instance, /* verbose */ 0);
      if (s && vec_len (s) > 0)
	{
	  /* Null-terminate the vec for strstr */
	  vec_add1 (s, 0);
	  if (noisy)
	    vlib_log (VLIB_LOG_LEVEL_DEBUG, pppoeclient_log_class,
		      "get_linux_ifname: format_device output='%s'", (char *) s);
	  /* Output looks like: "netdev enp6s0f1 pci-addr 0000:06:00.1\n..."
	   * Parse out the interface name after "netdev " */
	  char *p = strstr ((char *) s, "netdev ");
	  if (p)
	    {
	      p += 7; /* skip "netdev " */
	      char *end = p;
	      while (*end && *end != ' ' && *end != '\n' && *end != '\t')
		end++;
	      size_t len = end - p;
	      if (len > 0 && len < buf_len)
		{
		  clib_memcpy (buf, p, len);
		  buf[len] = '\0';
		  if (noisy)
		    vlib_log (VLIB_LOG_LEVEL_DEBUG, pppoeclient_log_class,
			      "get_linux_ifname: resolved '%s'", buf);
		  vec_free (s);
		  return 0;
		}
	    }
	  else if (noisy)
	    vlib_log (VLIB_LOG_LEVEL_DEBUG, pppoeclient_log_class,
		      "get_linux_ifname: 'netdev ' not found in output");
	}
      else if (noisy)
	vlib_log (VLIB_LOG_LEVEL_DEBUG, pppoeclient_log_class,
		  "get_linux_ifname: format_device returned empty");
      vec_free (s);
    }

  /* Fallback: scan /sys/class/net/ for an interface whose hw address matches.
   * This works for non-RDMA interfaces (e.g., af_packet, tap) where VPP
   * doesn't modify the MAC. */
  {
    struct if_nameindex *ifs = if_nameindex (), *p;
    if (!ifs)
      return -1;

    int sfd = socket (AF_INET, SOCK_DGRAM, 0);
    if (sfd < 0)
      {
	if_freenameindex (ifs);
	return -1;
      }

    for (p = ifs; p->if_index != 0; p++)
      {
	struct ifreq ifr;
	clib_memset (&ifr, 0, sizeof (ifr));
	snprintf (ifr.ifr_name, sizeof (ifr.ifr_name), "%s", p->if_name);
	if (ioctl (sfd, SIOCGIFHWADDR, &ifr) == 0)
	  {
	    if (clib_memcmp (ifr.ifr_hwaddr.sa_data, hw->hw_address, 6) == 0)
	      {
		snprintf (buf, buf_len, "%s", p->if_name);
		close (sfd);
		if_freenameindex (ifs);
		return 0;
	      }
	  }
      }
    close (sfd);
    if_freenameindex (ifs);
  }

  return -1;
}

static clib_error_t *
pppoeclient_exit (vlib_main_t *vm)
{
  pppoeclient_main_t *pem = &pppoeclient_main;
  pppoeclient_t *c;
  pppox_main_t *pom = get_pppox_main ();

  if (pom)
    pom->is_shutting_down = 1;

  /* Send PADT for all active sessions via raw socket — this is the ONLY
   * reliable way to get the packet on the wire during shutdown, because
   * vlib_put_frame_to_node() frames will never be dispatched after the
   * main loop has exited.
   *
   * Read the session file (written at session establishment time, when RDMA
   * was still active) to get the cached linux_ifname and src_mac, because
   * resolving the Linux interface by MAC matching no longer works at exit
   * time — RDMA has already released the device. */
  pool_foreach (c, pem->clients)
    {
      char path[128];
      char linux_ifname[IFNAMSIZ];
      u8 file_ac_mac[6], file_src_mac[6];
      u16 file_sid = 0;
      int fd, ok = 0;

      vlib_log (VLIB_LOG_LEVEL_INFO, pppoeclient_log_class,
		"exit: client %u session_id=%u state=%u sw_if_index=%u", (u32) (c - pem->clients),
		c->session_id, c->state, c->sw_if_index);

      /* Always try to read the session file, regardless of c->session_id.
       * During normal operation CHAP failure triggers teardown which clears
       * session_id to 0, but the BAS still holds the session from PADS.
       * The session file preserves the last valid session_id. */
      pppoeclient_session_file_path (c->sw_if_index, path, sizeof (path));
      fd = open (path, O_RDONLY);
      if (fd >= 0)
	{
	  u8 buf[sizeof (u16) + 6 + 6 + IFNAMSIZ];
	  size_t got = 0;

	  clib_memset (linux_ifname, 0, sizeof (linux_ifname));

	  /* Loop on short reads.  read(2) of a small regular file almost
	   * always returns the full length on Linux, but POSIX does not
	   * guarantee it — handle it properly rather than pretending. */
	  while (got < sizeof (buf))
	    {
	      ssize_t n = read (fd, buf + got, sizeof (buf) - got);
	      if (n < 0)
		{
		  if (errno == EINTR)
		    continue;
		  break;
		}
	      if (n == 0) /* EOF — file truncated or partially written */
		break;
	      got += (size_t) n;
	    }
	  close (fd);

	  if (got == sizeof (buf))
	    {
	      size_t off = 0;
	      clib_memcpy (&file_sid, buf + off, sizeof (file_sid));
	      file_sid = clib_net_to_host_u16 (file_sid);
	      off += sizeof (file_sid);
	      clib_memcpy (file_ac_mac, buf + off, 6);
	      off += 6;
	      clib_memcpy (file_src_mac, buf + off, 6);
	      off += 6;
	      clib_memcpy (linux_ifname, buf + off, IFNAMSIZ);
	      ok = (linux_ifname[0] != '\0');
	    }
	  vlib_log (VLIB_LOG_LEVEL_DEBUG, pppoeclient_log_class,
		    "exit: session file read ok=%d got=%zu ifname='%s' "
		    "file_sid=%u",
		    ok, got, ok ? linux_ifname : "(empty)", file_sid);
	}
      else
	{
	  if (c->session_id)
	    vlib_log (VLIB_LOG_LEVEL_WARNING, pppoeclient_log_class,
		      "exit: no session file at %s for client with session_id=%u", path,
		      c->session_id);
	  continue;
	}

      if (ok)
	{
	  /* Use file_sid from session file (not c->session_id which may be 0) */
	  pppoeclient_send_padt_raw (linux_ifname, file_src_mac, file_ac_mac, file_sid);
	}
      else
	{
	  /* Last resort: try to resolve linux ifname right now */
	  u16 sid = c->session_id ? c->session_id : file_sid;
	  u8 src_mac[6];
	  if (sid)
	    {
	      vnet_main_t *vnm = pem->vnet_main;
	      clib_memset (linux_ifname, 0, sizeof (linux_ifname));
	      if (pppoeclient_get_linux_ifname (vnm, c->sw_if_index, linux_ifname,
						sizeof (linux_ifname), 1) == 0)
		{
		  vlib_log (VLIB_LOG_LEVEL_INFO, pppoeclient_log_class,
			    "exit: last-resort resolved ifname='%s'", linux_ifname);
		  vnet_hw_interface_t *hw = vnet_get_sup_hw_interface (vnm, c->sw_if_index);
		  if (hw)
		    clib_memcpy (src_mac, hw->hw_address, 6);
		  else
		    clib_memset (src_mac, 0, 6);
		  pppoeclient_send_padt_raw (linux_ifname, src_mac, c->ac_mac_address, sid);
		}
	      else
		vlib_log (VLIB_LOG_LEVEL_ERR, pppoeclient_log_class,
			  "exit: FAILED to resolve linux ifname, "
			  "PADT not sent — BAS session will linger");
	    }
	}
      /* Delete session file after sending raw PADT */
      pppoeclient_delete_session_file (c->sw_if_index);
    }

  /* Also do the normal VPP-level cleanup (session table, pppox state).
   * Loop 1 already sent raw PADTs, so pass send_padt=0 — the main loop
   * has exited and frame-based PADT send would just produce spurious
   * "failed to send PADT" warnings. */
  vlib_worker_thread_barrier_sync (vlib_get_main ());
  pool_foreach (c, pem->clients)
    {
      if (c->session_id)
	{
	  pppoeclient_teardown_session (c, 0 /* send_padt */);
	  pppoeclient_mark_session_down (c);
	}
    }
  vlib_worker_thread_barrier_release (vlib_get_main ());

  /* Release per-client vec allocations before freeing the pool */
  {
    pppoeclient_t *_c;
    pool_foreach (_c, pem->clients)
      pppoeclient_client_free_resources (_c);
  }

  /* Release global resources */
  clib_bihash_free_8_8 (&pem->client_table);
  clib_bihash_free_16_8 (&pem->session_table);
  vlib_packet_template_free (vm, &pem->packet_template);
  pool_free (pem->clients);
  vec_free (pem->dispatch_refcount_by_sw_if_index);
  vec_free (pem->client_index_by_pppox_sw_if_index);

  return 0;
}

VLIB_MAIN_LOOP_EXIT_FUNCTION (pppoeclient_exit);
VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "PPPoEClient",
};
/*
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
