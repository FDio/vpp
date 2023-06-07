/*
 * Copyright (c) 2023 Cisco and/or its affiliates.
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

#define _GNU_SOURCE

#include <linux-cp/lcp_interface.h>

#include <vnet/plugin/plugin.h>
#include <vnet/mpls/mpls.h>
#include <vppinfra/linux/netns.h>

#include <fcntl.h>

vlib_log_class_t lcp_mpls_sync_logger;

#define LCP_MPLS_SYNC_DBG(...)                                                \
  vlib_log_debug (lcp_mpls_sync_logger, __VA_ARGS__);

void
lcp_mpls_sync_pair_add_cb (lcp_itf_pair_t *lip)
{
  u8 phy_is_enabled = mpls_sw_interface_is_enabled (lip->lip_phy_sw_if_index);
  LCP_MPLS_SYNC_DBG ("pair_add_cb: mpls enabled %u, parent %U", phy_is_enabled,
		     format_lcp_itf_pair, lip);
  if (phy_is_enabled)
    mpls_sw_interface_enable_disable (&mpls_main, lip->lip_host_sw_if_index,
				      1);
}

void
lcp_mpls_sync_state_cb (struct mpls_main_t *mm, uword opaque, u32 sw_if_index,
			u32 is_enable)
{
  lcp_itf_pair_t *lip;
  index_t lipi;
  int curr_ns_fd = -1;
  int vif_ns_fd = -1;
  int ctl_fd = -1;
  u8 *ctl_path = NULL;

  LCP_MPLS_SYNC_DBG ("sync_state_cb: called for sw_if_index %u", sw_if_index);

  // If device is LCP PHY, sync state to host tap.
  lipi = lcp_itf_pair_find_by_phy (sw_if_index);
  if (INDEX_INVALID != lipi)
    {
      lip = lcp_itf_pair_get (lipi);
      LCP_MPLS_SYNC_DBG ("sync_state_cb: mpls enabled %u parent %U", is_enable,
			 format_lcp_itf_pair, lip);
      mpls_sw_interface_enable_disable (&mpls_main, lip->lip_host_sw_if_index,
					is_enable);
      return;
    }

  // If device is LCP host, toggle MPLS XC feature.
  lipi = lcp_itf_pair_find_by_host (sw_if_index);
  if (INDEX_INVALID == lipi)
    return;
  lip = lcp_itf_pair_get (lipi);

  vnet_feature_enable_disable ("mpls-input", "linux-cp-xc-mpls", sw_if_index,
			       is_enable, NULL, 0);

  LCP_MPLS_SYNC_DBG ("sync_state_cb: mpls xc state %u parent %U", is_enable,
		     format_lcp_itf_pair, lip);

  // If syncing is enabled, sync Linux state as well.
  if (!lcp_sync ())
    return;

  if (lip->lip_namespace)
    {
      curr_ns_fd = clib_netns_open (NULL /* self */);
      vif_ns_fd = clib_netns_open (lip->lip_namespace);
      if (vif_ns_fd != -1)
	clib_setns (vif_ns_fd);
    }

  ctl_path = format (NULL, "/proc/sys/net/mpls/conf/%s/input%c",
		     lip->lip_host_name, NULL);
  if (NULL == ctl_path)
    {
      LCP_MPLS_SYNC_DBG ("sync_state_cb: failed to format sysctl");
      goto SYNC_CLEANUP;
    }

  ctl_fd = open ((char *) ctl_path, O_WRONLY);
  if (ctl_fd < 0)
    {
      LCP_MPLS_SYNC_DBG ("sync_state_cb: failed to open %s for writing",
			 ctl_path);
      goto SYNC_CLEANUP;
    }

  if (fdformat (ctl_fd, "%u", is_enable) < 1)
    {
      LCP_MPLS_SYNC_DBG ("sync_state_cb: failed to write to %s", ctl_path);
      goto SYNC_CLEANUP;
    }

  LCP_MPLS_SYNC_DBG ("sync_state_cb: set mpls input for %s",
		     lip->lip_host_name);

SYNC_CLEANUP:
  if (ctl_fd > -1)
    close (ctl_fd);

  if (NULL != ctl_path)
    vec_free (ctl_path);

  if (vif_ns_fd != -1)
    close (vif_ns_fd);

  if (curr_ns_fd != -1)
    {
      clib_setns (curr_ns_fd);
      close (curr_ns_fd);
    }
}

static clib_error_t *
lcp_mpls_sync_init (vlib_main_t *vm)
{
  lcp_itf_pair_vft_t mpls_sync_itf_pair_vft = {
    .pair_add_fn = lcp_mpls_sync_pair_add_cb,
  };
  lcp_itf_pair_register_vft (&mpls_sync_itf_pair_vft);

  mpls_interface_state_change_add_callback (lcp_mpls_sync_state_cb, 0);

  lcp_mpls_sync_logger = vlib_log_register_class ("linux-cp", "mpls-sync");

  return NULL;
}

VLIB_INIT_FUNCTION (lcp_mpls_sync_init) = {
  .runs_after = VLIB_INITS ("lcp_interface_init", "mpls_init"),
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
