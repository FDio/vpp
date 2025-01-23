/*
 * Copyright (c) 2024 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/bus/pci.h>
#include <vnet/dev/counters.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
#include <dev_octeon/octeon.h>
#include <dev_octeon/common.h>
#include <base/roc_api.h>
#include <common.h>
#include <dev_octeon/tm.h>
#include <vnet/tm/tm.h>
#include <vppinfra/hash.h>

VLIB_REGISTER_LOG_CLASS (oct_log, static) = {
  .class_name = "octeon",
  .subclass_name = "tm",
};

/* hash mapping global flow_id to internal tm node id */
uword *flow_id_to_tm_node_id_hash;

static vnet_dev_rv_t
oct_roc_err (vnet_dev_t *dev, int rv, char *fmt, ...)
{
  u8 *s = 0;
  va_list va;

  va_start (va, fmt);
  s = va_format (s, fmt, &va);
  va_end (va);

  log_err (dev, "%v - ROC error %s (%d)", s, roc_error_msg_get (rv), rv);

  vec_free (s);
  return VNET_DEV_ERR_INTERNAL;
}

/* Add a mapping of flow_id to tm_node_id */
void
add_flow_id_to_tm_node_id_mapping (u32 flow_id, u32 tm_node_id)
{
  hash_set (flow_id_to_tm_node_id_hash, flow_id, tm_node_id);
}

/* Get the tm_node_id for a given flow_id */
u32
get_tm_node_id_from_flow_id (u32 flow_id)
{
  uword *p = hash_get (flow_id_to_tm_node_id_hash, flow_id);
  if (p)
    return p[0];
  return 0;
}

int
oct_tm_sys_node_add (u32 hw_if_idx, u32 node_id, i32 parent_node_id, u32 priority, u32 weight,
		     u32 lvl, tm_node_params_t *params, char *flow_name)

{
  vnet_main_t *vnm = vnet_get_main ();
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, hw_if_idx);
  vnet_dev_port_t *port = vnet_dev_get_port_from_dev_instance (hi->dev_instance);
  vnet_dev_t *dev = port->dev;
  oct_device_t *cd = vnet_dev_get_data (dev);
  struct roc_nix *nix = cd->nix;
  struct roc_nix_tm_node *parent_node = NULL;
  struct roc_nix_tm_node *tm_node = NULL;
  struct roc_nix_tm_shaper_profile *profile = NULL;
  int rc = 0;
  u32 flow_id = 0;

  /* We don't support dynamic updates */
  if (roc_nix_tm_is_user_hierarchy_enabled (nix))
    {
      rc = -ERANGE;
      return oct_roc_err (dev, rc, "roc_nix_tm_dynamic update not supported");
    }
  if (parent_node_id)
    {
      parent_node = roc_nix_tm_node_get (nix, parent_node_id);
    }

  /* Find the right level */
  if (lvl != ROC_TM_LVL_ROOT && parent_node)
    {
      lvl = parent_node->lvl + 1;
    }
  else if (parent_node_id == ROC_NIX_TM_NODE_ID_INVALID)
    {
      lvl = ROC_TM_LVL_ROOT;
    }
  else
    {
      /* Neither proper parent nor proper level id given */
      rc = -ERANGE;
      return oct_roc_err (dev, rc, "roc_nix_tm_invalid_parent-id_err");
    }

  tm_node = plt_zmalloc (sizeof (struct roc_nix_tm_node), 0);
  if (!tm_node)
    {
      rc = -ENOMEM;
      return oct_roc_err (dev, rc, "oct_nix_tm_node_alloc_failed");
    }

  tm_node->id = node_id;
  tm_node->parent_id = parent_node_id;
  tm_node->lvl = lvl;
  tm_node->priority = priority;
  tm_node->free_fn = plt_free;
  tm_node->weight = weight;
  tm_node->shaper_profile_id = params->shaper_profile_id;

  profile = roc_nix_tm_shaper_profile_get (nix, params->shaper_profile_id);

  rc = roc_nix_tm_node_add (nix, tm_node);
  if (rc < 0)
    {
      plt_free (tm_node);
      return oct_roc_err (dev, rc, "roc_nix_tm_node_add_err");
    }

  if (flow_name)
    {
      if (roc_nix_tm_lvl_is_leaf (nix, lvl))
	{
	  flow_id = tm_get_flow_id (flow_name);
	  add_flow_id_to_tm_node_id_mapping (flow_id, node_id);
	}
      else
	clib_warning ("TM node %u (lvl %u) ignores flow_name '%s' (non-leaf)", node_id, lvl,
		      flow_name);
    }

  roc_nix_tm_shaper_default_red_algo (tm_node, profile);
  return 0;
}

int
oct_tm_sys_node_delete (u32 hw_if_idx, u32 node_id)
{
  vnet_main_t *vnm = vnet_get_main ();
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, hw_if_idx);
  vnet_dev_port_t *port = vnet_dev_get_port_from_dev_instance (hi->dev_instance);
  vnet_dev_t *dev = port->dev;
  oct_device_t *cd = vnet_dev_get_data (dev);
  struct roc_nix *nix = cd->nix;
  struct roc_nix_tm_node *tm_node = NULL;
  int rc;
  bool free_node = 1;

  if ((rc = roc_nix_tm_is_user_hierarchy_enabled (nix)))
    {
      rc = -ERANGE;
      return oct_roc_err (dev, rc, "roc_nix_tm_dynamic update not supported");
    }
  if (node_id == ROC_NIX_TM_NODE_ID_INVALID)
    {
      rc = -EINVAL;
      return oct_roc_err (dev, rc, "oct_tm_node_delete_invalid_node-id");
    }

  tm_node = roc_nix_tm_node_get (nix, node_id);
  if (!tm_node)
    {
      rc = -EINVAL;
      return oct_roc_err (dev, rc, "oct_tm_node_delete  node-id not found");
    }

  rc = roc_nix_tm_node_delete (nix, tm_node->id, free_node);
  if (rc)
    {
      return oct_roc_err (dev, rc, "roc_nix_tm_delete_failed");
    }
  return 0;
}

int
oct_tm_sys_shaper_profile_create (u32 hw_if_idx, tm_shaper_params_t *params)
{
  vnet_main_t *vnm = vnet_get_main ();
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, hw_if_idx);
  vnet_dev_port_t *port = vnet_dev_get_port_from_dev_instance (hi->dev_instance);
  vnet_dev_t *dev = port->dev;
  oct_device_t *cd = vnet_dev_get_data (dev);
  struct roc_nix *nix = cd->nix;
  struct roc_nix_tm_shaper_profile *profile;
  int rc;

  if (roc_nix_tm_shaper_profile_get (nix, params->shaper_id))
    {
      rc = -EINVAL;
      return oct_roc_err (dev, rc, "oct_nix_tm_shaper_exists");
    }

  profile = plt_zmalloc (sizeof (struct roc_nix_tm_shaper_profile), 0);
  if (!profile)
    {
      rc = -ENOMEM;
      return oct_roc_err (dev, rc, "oct_nix_tm_shaper_create_alloc_failed");
    }
  profile->id = params->shaper_id;
  profile->commit_rate = params->commit.rate;
  profile->commit_sz = params->commit.burst_size;
  profile->peak_rate = params->peak.rate;
  profile->peak_sz = params->peak.burst_size;
  /* If Byte mode, then convert to bps */
  if (!params->pkt_mode)
    {
      profile->commit_rate *= 8;
      profile->peak_rate *= 8;
      profile->commit_sz *= 8;
      profile->peak_sz *= 8;
    }
  profile->pkt_len_adj = params->pkt_len_adj;
  profile->pkt_mode = params->pkt_mode;
  profile->free_fn = plt_free;

  rc = roc_nix_tm_shaper_profile_add (nix, profile);

  /* Fill error information based on return value */
  if (rc)
    {
      plt_free (profile);
      return oct_roc_err (dev, rc, "roc_nix_tm_shaper_creation_failed");
    }

  return rc;
}

int
oct_tm_sys_node_shaper_update (u32 hw_if_idx, u32 node_id, u32 profile_id)
{
  vnet_main_t *vnm = vnet_get_main ();
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, hw_if_idx);
  vnet_dev_port_t *port = vnet_dev_get_port_from_dev_instance (hi->dev_instance);
  vnet_dev_t *dev = port->dev;
  oct_device_t *cd = vnet_dev_get_data (dev);
  struct roc_nix *nix = cd->nix;
  struct roc_nix_tm_shaper_profile *profile;
  struct roc_nix_tm_node *node;
  int rc;

  rc = roc_nix_tm_node_shaper_update (nix, node_id, profile_id, false);
  if (rc)
    {
      return oct_roc_err (dev, rc, "oct_nix_tm_node_shaper_update_failed");
    }

  node = roc_nix_tm_node_get (nix, node_id);
  if (!node)
    {
      rc = -EINVAL;
      return oct_roc_err (dev, rc, "oct_nix_tm_node_shaper_update_node_failure");
    }

  profile = roc_nix_tm_shaper_profile_get (nix, profile_id);
  roc_nix_tm_shaper_default_red_algo (node, profile);

  return 0;
}
int
oct_tm_sys_shaper_profile_delete (u32 hw_if_idx, u32 shaper_id)
{
  vnet_main_t *vnm = vnet_get_main ();
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, hw_if_idx);
  vnet_dev_port_t *port = vnet_dev_get_port_from_dev_instance (hi->dev_instance);
  vnet_dev_t *dev = port->dev;
  oct_device_t *cd = vnet_dev_get_data (dev);
  struct roc_nix *nix = cd->nix;
  int rc;

  rc = roc_nix_tm_shaper_profile_delete (nix, shaper_id);
  if (rc)
    {
      return oct_roc_err (dev, rc, "roc_nix_tm_shaper_delete_failed");
    }

  return rc;
}

int
oct_tm_sys_node_sched_weight_update (u32 hw_if_idx, u32 node_id, u32 weight)
{
  vnet_main_t *vnm = vnet_get_main ();
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, hw_if_idx);
  vnet_dev_port_t *port = vnet_dev_get_port_from_dev_instance (hi->dev_instance);
  vnet_dev_t *dev = port->dev;
  oct_device_t *cd = vnet_dev_get_data (dev);
  struct roc_nix *nix = cd->nix;
  struct roc_nix_tm_node *node;
  int rc = 0;
  u32 parent_id, priority;

  node = roc_nix_tm_node_get (nix, node_id);
  if (!node)
    {
      rc = -EINVAL;
      return oct_roc_err (dev, rc, "roc_nix_tm_node_get node_id not found");
    }

  parent_id = node->parent_id;
  priority = node->priority;

  rc = roc_nix_tm_node_parent_update (nix, node_id, parent_id, priority, weight);
  if (rc)
    {
      return oct_roc_err (dev, rc, "roc_nix_tm_node_parent_update failed");
    }

  return rc;
}

int
oct_tm_sys_get_capabilities (u32 hw_if_idx, tm_capa_params_t *cap)
{

  vnet_main_t *vnm = vnet_get_main ();
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, hw_if_idx);
  vnet_dev_port_t *port = vnet_dev_get_port_from_dev_instance (hi->dev_instance);
  vnet_dev_t *dev = port->dev;
  oct_device_t *cd = vnet_dev_get_data (dev);
  vnet_dev_port_interfaces_t *ifs = port->interfaces;
  struct roc_nix *nix = cd->nix;
  int rc, max_nr_nodes = 0, i, n_lvl;
  uint16_t schq[ROC_TM_LVL_MAX];

  memset (cap, 0, sizeof (*cap));

  rc = roc_nix_tm_rsrc_count (nix, schq);
  if (rc)
    {
      return oct_roc_err (dev, rc, "oct_tm_sys_get_capabilities failed");
    }

  for (i = 0; i < NIX_TXSCH_LVL_TL1; i++)
    max_nr_nodes += schq[i];

  cap->n_nodes_max = max_nr_nodes + ifs->num_tx_queues;

  n_lvl = roc_nix_tm_lvl_cnt_get (nix);
  /* Consider leaf level */
  cap->n_levels_max = n_lvl + 1;
  cap->non_leaf_nodes_identical = 1;
  cap->leaf_nodes_identical = 1;

  /* Shaper Capabilities */
  cap->shaper_private_n_max = max_nr_nodes;
  cap->shaper_n_max = max_nr_nodes;
  cap->shaper_private_dual_rate_n_max = max_nr_nodes;
  cap->shaper_private_rate_min = NIX_TM_MIN_SHAPER_RATE / 8;
  cap->shaper_private_rate_max = NIX_TM_MAX_SHAPER_RATE / 8;
  cap->shaper_private_packet_mode_supported = 1;
  cap->shaper_private_byte_mode_supported = 1;
  cap->shaper_pkt_length_adjust_min = NIX_TM_LENGTH_ADJUST_MIN;
  cap->shaper_pkt_length_adjust_max = NIX_TM_LENGTH_ADJUST_MAX;

  /* Schedule Capabilities */
  cap->sched_n_children_max = schq[n_lvl - 1];
  cap->sched_sp_n_priorities_max = NIX_TM_TLX_SP_PRIO_MAX;
  cap->sched_wfq_n_children_per_group_max = cap->sched_n_children_max;
  cap->sched_wfq_n_groups_max = 1;
  cap->sched_wfq_weight_max = roc_nix_tm_max_sched_wt_get ();
  cap->sched_wfq_packet_mode_supported = 1;
  cap->sched_wfq_byte_mode_supported = 1;

  return 0;
}

int
oct_tm_sys_level_get_capabilities (u32 hw_if_idx, tm_level_capa_params_t *cap, u32 lvl)
{
  vnet_main_t *vnm = vnet_get_main ();
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, hw_if_idx);
  vnet_dev_port_t *port = vnet_dev_get_port_from_dev_instance (hi->dev_instance);
  vnet_dev_t *dev = port->dev;
  vnet_dev_port_interfaces_t *ifs = port->interfaces;
  oct_device_t *cd = vnet_dev_get_data (dev);
  struct roc_nix *nix = cd->nix;
  int rc, n_lvl;
  uint16_t schq[ROC_TM_LVL_MAX];

  memset (cap, 0, sizeof (*cap));

  rc = roc_nix_tm_rsrc_count (nix, schq);
  if (rc)
    {
      return oct_roc_err (dev, rc, "oct_tm_sys_get_capabilities failed");
    }

  n_lvl = roc_nix_tm_lvl_cnt_get (nix);

  if (roc_nix_tm_lvl_is_leaf (nix, lvl))
    {
      /* Leaf */
      cap->n_nodes_max = ifs->num_tx_queues;
      cap->n_nodes_leaf_max = ifs->num_tx_queues;
      cap->leaf_nodes_identical = 1;
    }
  else if (lvl == ROC_TM_LVL_ROOT)
    {
      /* Root node, a.k.a. TL2(vf)/TL1(pf) */
      cap->n_nodes_max = 1;
      cap->n_nodes_nonleaf_max = 1;
      cap->non_leaf_nodes_identical = 1;

      cap->nonleaf.shaper_private_supported = true;
      cap->nonleaf.shaper_private_dual_rate_supported =
	roc_nix_tm_lvl_have_link_access (nix, lvl) ? false : true;
      cap->nonleaf.shaper_private_rate_min = NIX_TM_MIN_SHAPER_RATE / 8;
      cap->nonleaf.shaper_private_rate_max = NIX_TM_MAX_SHAPER_RATE / 8;
      cap->nonleaf.shaper_private_packet_mode_supported = 1;
      cap->nonleaf.shaper_private_byte_mode_supported = 1;

      cap->nonleaf.sched_n_children_max = schq[lvl];
      cap->nonleaf.sched_sp_n_priorities_max = roc_nix_tm_max_prio (nix, lvl) + 1;
      cap->nonleaf.sched_wfq_n_groups_max = 1;
      cap->nonleaf.sched_wfq_weight_max = roc_nix_tm_max_sched_wt_get ();
      cap->nonleaf.sched_wfq_packet_mode_supported = 1;
      cap->nonleaf.sched_wfq_byte_mode_supported = 1;
    }
  else if (lvl < ROC_TM_LVL_MAX)
    {
      /* TL2, TL3, TL4, MDQ */
      cap->n_nodes_max = schq[lvl];
      cap->n_nodes_nonleaf_max = cap->n_nodes_max;
      cap->non_leaf_nodes_identical = 1;

      cap->nonleaf.shaper_private_supported = true;
      cap->nonleaf.shaper_private_dual_rate_supported = true;
      cap->nonleaf.shaper_private_rate_min = NIX_TM_MIN_SHAPER_RATE / 8;
      cap->nonleaf.shaper_private_rate_max = NIX_TM_MAX_SHAPER_RATE / 8;
      cap->nonleaf.shaper_private_packet_mode_supported = 1;
      cap->nonleaf.shaper_private_byte_mode_supported = 1;

      /* MDQ doesn't support Strict Priority */
      if ((int) lvl == (n_lvl - 1))
	cap->nonleaf.sched_n_children_max = ifs->num_tx_queues;
      else
	cap->nonleaf.sched_n_children_max = schq[lvl - 1];
      cap->nonleaf.sched_sp_n_priorities_max = roc_nix_tm_max_prio (nix, lvl) + 1;
      cap->nonleaf.sched_wfq_n_groups_max = 1;
      cap->nonleaf.sched_wfq_weight_max = roc_nix_tm_max_sched_wt_get ();
      cap->nonleaf.sched_wfq_packet_mode_supported = 1;
      cap->nonleaf.sched_wfq_byte_mode_supported = 1;
    }
  else
    {
      /* unsupported level */
      return oct_roc_err (dev, rc, "oct_tm_sys_get_capabilities unsupported level,failed");
    }
  return 0;
}

int
oct_tm_sys_node_read_stats (u32 hw_if_idx, u32 node_id, tm_stats_params_t *stats)
{
  vnet_main_t *vnm = vnet_get_main ();
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, hw_if_idx);
  vnet_dev_port_t *port = vnet_dev_get_port_from_dev_instance (hi->dev_instance);
  vnet_dev_t *dev = port->dev;
  oct_device_t *cd = vnet_dev_get_data (dev);
  struct roc_nix *nix = cd->nix;
  int rc = 0;
  int clear = 0;
  struct roc_nix_tm_node_stats nix_tm_stats;
  struct roc_nix_tm_node *node;

  node = roc_nix_tm_node_get (nix, node_id);
  if (!node)
    {
      goto exit;
    }

  if (roc_nix_tm_lvl_is_leaf (nix, node->lvl))
    {
      struct roc_nix_stats_queue qstats;

      rc = roc_nix_stats_queue_get (nix, node->id, 0, &qstats);
      if (!rc)
	{
	  stats->n_pkts = qstats.tx_pkts;
	  stats->n_bytes = qstats.tx_octs;
	  printf ("  - STATS for node \n");
	  printf ("  -- pkts (%" PRIu64 ") bytes (%" PRIu64 ")\n", stats->n_pkts, stats->n_bytes);
	}
      goto exit;
    }

  rc = roc_nix_tm_node_stats_get (nix, node_id, clear, &nix_tm_stats);
  if (!rc)
    {
      stats->leaf.n_pkts_dropped[TM_COLOR_RED] = nix_tm_stats.stats[ROC_NIX_TM_NODE_PKTS_DROPPED];
      stats->leaf.n_bytes_dropped[TM_COLOR_RED] = nix_tm_stats.stats[ROC_NIX_TM_NODE_BYTES_DROPPED];
    }

exit:
  if (rc)
    {
      return oct_roc_err (dev, rc, "tm_node_read_stats_err");
    }
  return rc;
}

int
oct_tm_sys_start (u32 hw_if_idx)
{
  vnet_main_t *vnm = vnet_get_main ();
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, hw_if_idx);
  vnet_dev_port_t *port = vnet_dev_get_port_from_dev_instance (hi->dev_instance);
  vnet_dev_t *dev = port->dev;
  oct_device_t *cd = vnet_dev_get_data (dev);
  vnet_dev_port_interfaces_t *ifs = port->interfaces;
  struct roc_nix *nix = cd->nix;
  int rc = 0;

  if (roc_nix_tm_is_user_hierarchy_enabled (nix))
    {
      rc = -EIO;
      return oct_roc_err (dev, rc, "oct_nix_tm_hirearchy_exists");
    }

  if (roc_nix_tm_leaf_cnt (nix) < ifs->num_tx_queues)
    {
      rc = -EINVAL;
      return oct_roc_err (dev, rc, "oct_nix_tm_incomplete hierarchy");
    }

  rc = roc_nix_tm_hierarchy_disable (nix);
  if (rc)
    {
      return oct_roc_err (dev, rc, "oct_nix_tm_hirearchy_exists");
    }

  rc = roc_nix_tm_hierarchy_enable (nix, ROC_NIX_TM_USER, true);
  if (rc)
    {
      return oct_roc_err (dev, rc, "oct_nix_tm_hierarchy_enabled_failed");
    }
  return 0;
}

int
oct_tm_sys_stop (u32 hw_if_idx)
{
  vnet_main_t *vnm = vnet_get_main ();
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, hw_if_idx);
  vnet_dev_port_t *port = vnet_dev_get_port_from_dev_instance (hi->dev_instance);
  vnet_dev_t *dev = port->dev;
  oct_device_t *cd = vnet_dev_get_data (dev);
  struct roc_nix *nix = cd->nix;
  int rc = 0;

  /* Disable hierarchy */
  rc = roc_nix_tm_hierarchy_disable (nix);
  if (rc)
    {
      rc = -EIO;
      return oct_roc_err (dev, rc, "oct_nix_tm_stop_failed");
    }

  return 0;
}

tm_system_t dev_oct_tm_ops = {
  .node_add = oct_tm_sys_node_add,
  .node_delete = oct_tm_sys_node_delete,
  .node_read_stats = oct_tm_sys_node_read_stats,
  .tm_get_capabilities = oct_tm_sys_get_capabilities,
  .tm_level_get_capabilities = oct_tm_sys_level_get_capabilities,
  .shaper_profile_create = oct_tm_sys_shaper_profile_create,
  .node_shaper_update = oct_tm_sys_node_shaper_update,
  .shaper_profile_delete = oct_tm_sys_shaper_profile_delete,
  .node_sched_weight_update = oct_tm_sys_node_sched_weight_update,
  .start_tm = oct_tm_sys_start,
  .stop_tm = oct_tm_sys_stop,
};
