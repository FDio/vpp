/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2015 Cisco and/or its affiliates.
 */

#define DPDK_NB_RX_DESC_DEFAULT   1024
#define DPDK_NB_TX_DESC_DEFAULT   1024
#define DPDK_MAX_LRO_SIZE_DEFAULT 65536

/* These args appear by themselves */
#define foreach_eal_double_hyphen_predicate_arg \
_(no-shconf)                                    \
_(no-hpet)                                      \
_(no-huge)                                      \
_(vmware-tsc-map)

#define foreach_eal_single_hyphen_arg           \
_(mem-alloc-request, m)                         \
_(force-ranks, r)

/* clang-format off */
/* These args are preceded by "--" and followed by a single string */
#define foreach_eal_double_hyphen_arg           \
_(huge-dir)                                     \
_(proc-type)                                    \
_(file-prefix)                                  \
_(vdev)                                         \
_(log-level)                                    \
_(block)                                        \
_(iova-mode)                                    \
_(base-virtaddr)
/* clang-format on */

static_always_inline void
dpdk_device_flag_set (dpdk_device_t *xd, __typeof__ (xd->flags) flag, int val)
{
  xd->flags = val ? xd->flags | flag : xd->flags & ~flag;
}

void dpdk_counters_xstats_init (dpdk_device_t *xd);

static inline void
dpdk_get_xstats (dpdk_device_t *xd, clib_thread_index_t thread_index)
{
  int ret;
  int i;
  if (!(xd->flags & DPDK_DEVICE_FLAG_ADMIN_UP))
    return;

  ret = rte_eth_xstats_get (xd->port_id, xd->xstats, vec_len (xd->xstats));
  if (ret < 0)
    {
      dpdk_log_warn ("rte_eth_xstats_get(%d) failed: %d", xd->port_id, ret);
      return;
    }
  else if (ret != vec_len (xd->xstats))
    {
      dpdk_log_warn (
	"rte_eth_xstats_get(%d) returned %d/%d stats. Resetting counters.",
	xd->port_id, ret, vec_len (xd->xstats));
      dpdk_counters_xstats_init (xd);
      return;
    }

  vec_foreach_index (i, xd->xstats)
    {
      vlib_set_simple_counter (&xd->xstats_counters, thread_index, i,
			       xd->xstats[i].value);
    }
}

#define DPDK_UPDATE_COUNTER(vnm, tidx, xd, stat, cnt)                         \
  do                                                                          \
    {                                                                         \
      u64 _v = (xd)->stats.stat;                                              \
      u64 _lv = (xd)->last_stats.stat;                                        \
      if (PREDICT_FALSE (_v != _lv))                                          \
        {                                                                     \
          if (PREDICT_FALSE (_v < _lv))                                       \
            dpdk_log_warn ("%v: %s counter decreased (before %lu after %lu)", \
                           xd->name, #stat, _lv, _v);                         \
          else                                                                \
            vlib_increment_simple_counter (                                   \
                vec_elt_at_index ((vnm)->interface_main.sw_if_counters, cnt), \
                (tidx), (xd)->sw_if_index, _v - _lv);                         \
        }                                                                     \
    }                                                                         \
  while (0)

static inline void
dpdk_update_counters (dpdk_device_t * xd, f64 now)
{
  vnet_main_t *vnm = vnet_get_main ();
  clib_thread_index_t thread_index = vlib_get_thread_index ();

  xd->time_last_stats_update = now ? now : xd->time_last_stats_update;
  clib_memcpy_fast (&xd->last_stats, &xd->stats, sizeof (xd->last_stats));
  rte_eth_stats_get (xd->port_id, &xd->stats);

  /* maybe bump interface rx no buffer counter */
  DPDK_UPDATE_COUNTER (vnm, thread_index, xd, rx_nombuf,
		       VNET_INTERFACE_COUNTER_RX_NO_BUF);
  DPDK_UPDATE_COUNTER (vnm, thread_index, xd, imissed,
		       VNET_INTERFACE_COUNTER_RX_MISS);
  DPDK_UPDATE_COUNTER (vnm, thread_index, xd, ierrors,
		       VNET_INTERFACE_COUNTER_RX_ERROR);

  dpdk_get_xstats (xd, thread_index);
}
