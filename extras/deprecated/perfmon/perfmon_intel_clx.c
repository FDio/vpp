
#include <perfmon/perfmon_intel.h>

static perfmon_intel_pmc_cpu_model_t cpu_model_table[] = {
  {0x55, 0x05, 1},
  {0x55, 0x06, 1},
  {0x55, 0x07, 1},
  {0x55, 0x08, 1},
  {0x55, 0x09, 1},
  {0x55, 0x0A, 1},
  {0x55, 0x0B, 1},
  {0x55, 0x0C, 1},
  {0x55, 0x0D, 1},
  {0x55, 0x0E, 1},
  {0x55, 0x0F, 1},

};

static perfmon_intel_pmc_event_t event_table[] = {
  {
   .event_code = {0x00},
   .umask = 0x01,
   .event_name = "inst_retired.any",
   },
  {
   .event_code = {0x00},
   .umask = 0x02,
   .event_name = "cpu_clk_unhalted.thread",
   },
  {
   .event_code = {0x00},
   .umask = 0x02,
   .event_name = "cpu_clk_unhalted.thread_any",
   },
  {
   .event_code = {0x00},
   .umask = 0x03,
   .event_name = "cpu_clk_unhalted.ref_tsc",
   },
  {
   .event_code = {0x03},
   .umask = 0x02,
   .event_name = "ld_blocks.store_forward",
   },
  {
   .event_code = {0x03},
   .umask = 0x08,
   .event_name = "ld_blocks.no_sr",
   },
  {
   .event_code = {0x07},
   .umask = 0x01,
   .event_name = "ld_blocks_partial.address_alias",
   },
  {
   .event_code = {0x08},
   .umask = 0x01,
   .event_name = "dtlb_load_misses.miss_causes_a_walk",
   },
  {
   .event_code = {0x08},
   .umask = 0x02,
   .event_name = "dtlb_load_misses.walk_completed_4k",
   },
  {
   .event_code = {0x08},
   .umask = 0x04,
   .event_name = "dtlb_load_misses.walk_completed_2m_4m",
   },
  {
   .event_code = {0x08},
   .umask = 0x08,
   .event_name = "dtlb_load_misses.walk_completed_1g",
   },
  {
   .event_code = {0x08},
   .umask = 0x0E,
   .event_name = "dtlb_load_misses.walk_completed",
   },
  {
   .event_code = {0x08},
   .umask = 0x10,
   .event_name = "dtlb_load_misses.walk_pending",
   },
  {
   .event_code = {0x08},
   .umask = 0x20,
   .event_name = "dtlb_load_misses.stlb_hit",
   },
  {
   .event_code = {0x09},
   .umask = 0x01,
   .event_name = "memory_disambiguation.history_reset",
   },
  {
   .event_code = {0x0D},
   .umask = 0x01,
   .event_name = "int_misc.recovery_cycles",
   },
  {
   .event_code = {0x0D},
   .umask = 0x01,
   .event_name = "int_misc.recovery_cycles_any",
   },
  {
   .event_code = {0x0D},
   .umask = 0x80,
   .event_name = "int_misc.clear_resteer_cycles",
   },
  {
   .event_code = {0x0E},
   .umask = 0x01,
   .event_name = "uops_issued.stall_cycles",
   },
  {
   .event_code = {0x0E},
   .umask = 0x01,
   .event_name = "uops_issued.any",
   },
  {
   .event_code = {0x0E},
   .umask = 0x20,
   .event_name = "uops_issued.slow_lea",
   },
  {
   .event_code = {0x14},
   .umask = 0x01,
   .event_name = "arith.divider_active",
   },
  {
   .event_code = {0x24},
   .umask = 0x21,
   .event_name = "l2_rqsts.demand_data_rd_miss",
   },
  {
   .event_code = {0x24},
   .umask = 0x22,
   .event_name = "l2_rqsts.rfo_miss",
   },
  {
   .event_code = {0x24},
   .umask = 0x24,
   .event_name = "l2_rqsts.code_rd_miss",
   },
  {
   .event_code = {0x24},
   .umask = 0x27,
   .event_name = "l2_rqsts.all_demand_miss",
   },
  {
   .event_code = {0x24},
   .umask = 0x38,
   .event_name = "l2_rqsts.pf_miss",
   },
  {
   .event_code = {0x24},
   .umask = 0x3F,
   .event_name = "l2_rqsts.miss",
   },
  {
   .event_code = {0x24},
   .umask = 0xc1,
   .event_name = "l2_rqsts.demand_data_rd_hit",
   },
  {
   .event_code = {0x24},
   .umask = 0xc2,
   .event_name = "l2_rqsts.rfo_hit",
   },
  {
   .event_code = {0x24},
   .umask = 0xc4,
   .event_name = "l2_rqsts.code_rd_hit",
   },
  {
   .event_code = {0x24},
   .umask = 0xd8,
   .event_name = "l2_rqsts.pf_hit",
   },
  {
   .event_code = {0x24},
   .umask = 0xE1,
   .event_name = "l2_rqsts.all_demand_data_rd",
   },
  {
   .event_code = {0x24},
   .umask = 0xE2,
   .event_name = "l2_rqsts.all_rfo",
   },
  {
   .event_code = {0x24},
   .umask = 0xE4,
   .event_name = "l2_rqsts.all_code_rd",
   },
  {
   .event_code = {0x24},
   .umask = 0xe7,
   .event_name = "l2_rqsts.all_demand_references",
   },
  {
   .event_code = {0x24},
   .umask = 0xF8,
   .event_name = "l2_rqsts.all_pf",
   },
  {
   .event_code = {0x24},
   .umask = 0xFF,
   .event_name = "l2_rqsts.references",
   },
  {
   .event_code = {0x28},
   .umask = 0x07,
   .event_name = "core_power.lvl0_turbo_license",
   },
  {
   .event_code = {0x28},
   .umask = 0x18,
   .event_name = "core_power.lvl1_turbo_license",
   },
  {
   .event_code = {0x28},
   .umask = 0x20,
   .event_name = "core_power.lvl2_turbo_license",
   },
  {
   .event_code = {0x28},
   .umask = 0x40,
   .event_name = "core_power.throttle",
   },
  {
   .event_code = {0x2E},
   .umask = 0x41,
   .event_name = "longest_lat_cache.miss",
   },
  {
   .event_code = {0x2E},
   .umask = 0x4F,
   .event_name = "longest_lat_cache.reference",
   },
  {
   .event_code = {0x32},
   .umask = 0x01,
   .event_name = "sw_prefetch_access.nta",
   },
  {
   .event_code = {0x32},
   .umask = 0x02,
   .event_name = "sw_prefetch_access.t0",
   },
  {
   .event_code = {0x32},
   .umask = 0x04,
   .event_name = "sw_prefetch_access.t1_t2",
   },
  {
   .event_code = {0x32},
   .umask = 0x08,
   .event_name = "sw_prefetch_access.prefetchw",
   },
  {
   .event_code = {0x3C},
   .umask = 0x00,
   .event_name = "cpu_clk_unhalted.thread_p",
   },
  {
   .event_code = {0x3C},
   .umask = 0x00,
   .event_name = "cpu_clk_unhalted.thread_p_any",
   },
  {
   .event_code = {0x3C},
   .umask = 0x00,
   .event_name = "cpu_clk_unhalted.ring0_trans",
   },
  {
   .event_code = {0x3C},
   .umask = 0x01,
   .event_name = "cpu_clk_thread_unhalted.ref_xclk",
   },
  {
   .event_code = {0x3C},
   .umask = 0x01,
   .event_name = "cpu_clk_thread_unhalted.ref_xclk_any",
   },
  {
   .event_code = {0x3C},
   .umask = 0x01,
   .event_name = "cpu_clk_unhalted.ref_xclk_any",
   },
  {
   .event_code = {0x3C},
   .umask = 0x01,
   .event_name = "cpu_clk_unhalted.ref_xclk",
   },
  {
   .event_code = {0x3C},
   .umask = 0x02,
   .event_name = "cpu_clk_thread_unhalted.one_thread_active",
   },
  {
   .event_code = {0x48},
   .umask = 0x01,
   .event_name = "l1d_pend_miss.pending_cycles",
   },
  {
   .event_code = {0x48},
   .umask = 0x01,
   .event_name = "l1d_pend_miss.pending",
   },
  {
   .event_code = {0x48},
   .umask = 0x02,
   .event_name = "l1d_pend_miss.fb_full",
   },
  {
   .event_code = {0x49},
   .umask = 0x01,
   .event_name = "dtlb_store_misses.miss_causes_a_walk",
   },
  {
   .event_code = {0x49},
   .umask = 0x02,
   .event_name = "dtlb_store_misses.walk_completed_4k",
   },
  {
   .event_code = {0x49},
   .umask = 0x04,
   .event_name = "dtlb_store_misses.walk_completed_2m_4m",
   },
  {
   .event_code = {0x49},
   .umask = 0x08,
   .event_name = "dtlb_store_misses.walk_completed_1g",
   },
  {
   .event_code = {0x49},
   .umask = 0x0E,
   .event_name = "dtlb_store_misses.walk_completed",
   },
  {
   .event_code = {0x49},
   .umask = 0x10,
   .event_name = "dtlb_store_misses.walk_pending",
   },
  {
   .event_code = {0x49},
   .umask = 0x20,
   .event_name = "dtlb_store_misses.stlb_hit",
   },
  {
   .event_code = {0x4C},
   .umask = 0x01,
   .event_name = "load_hit_pre.sw_pf",
   },
  {
   .event_code = {0x4F},
   .umask = 0x10,
   .event_name = "ept.walk_pending",
   },
  {
   .event_code = {0x51},
   .umask = 0x01,
   .event_name = "l1d.replacement",
   },
  {
   .event_code = {0x54},
   .umask = 0x01,
   .event_name = "tx_mem.abort_conflict",
   },
  {
   .event_code = {0x54},
   .umask = 0x02,
   .event_name = "tx_mem.abort_capacity",
   },
  {
   .event_code = {0x54},
   .umask = 0x04,
   .event_name = "tx_mem.abort_hle_store_to_elided_lock",
   },
  {
   .event_code = {0x54},
   .umask = 0x08,
   .event_name = "tx_mem.abort_hle_elision_buffer_not_empty",
   },
  {
   .event_code = {0x54},
   .umask = 0x10,
   .event_name = "tx_mem.abort_hle_elision_buffer_mismatch",
   },
  {
   .event_code = {0x54},
   .umask = 0x20,
   .event_name = "tx_mem.abort_hle_elision_buffer_unsupported_alignment",
   },
  {
   .event_code = {0x54},
   .umask = 0x40,
   .event_name = "tx_mem.hle_elision_buffer_full",
   },
  {
   .event_code = {0x59},
   .umask = 0x01,
   .event_name = "partial_rat_stalls.scoreboard",
   },
  {
   .event_code = {0x5d},
   .umask = 0x01,
   .event_name = "tx_exec.misc1",
   },
  {
   .event_code = {0x5d},
   .umask = 0x02,
   .event_name = "tx_exec.misc2",
   },
  {
   .event_code = {0x5d},
   .umask = 0x04,
   .event_name = "tx_exec.misc3",
   },
  {
   .event_code = {0x5d},
   .umask = 0x08,
   .event_name = "tx_exec.misc4",
   },
  {
   .event_code = {0x5d},
   .umask = 0x10,
   .event_name = "tx_exec.misc5",
   },
  {
   .event_code = {0x5E},
   .umask = 0x01,
   .event_name = "rs_events.empty_end",
   },
  {
   .event_code = {0x5E},
   .umask = 0x01,
   .event_name = "rs_events.empty_cycles",
   },
  {
   .event_code = {0x60},
   .umask = 0x01,
   .event_name = "offcore_requests_outstanding.cycles_with_demand_data_rd",
   },
  {
   .event_code = {0x60},
   .umask = 0x01,
   .event_name = "offcore_requests_outstanding.demand_data_rd",
   },
  {
   .event_code = {0x60},
   .umask = 0x02,
   .event_name = "offcore_requests_outstanding.demand_code_rd",
   },
  {
   .event_code = {0x60},
   .umask = 0x02,
   .event_name = "offcore_requests_outstanding.cycles_with_demand_code_rd",
   },
  {
   .event_code = {0x60},
   .umask = 0x04,
   .event_name = "offcore_requests_outstanding.demand_rfo",
   },
  {
   .event_code = {0x60},
   .umask = 0x04,
   .event_name = "offcore_requests_outstanding.cycles_with_demand_rfo",
   },
  {
   .event_code = {0x60},
   .umask = 0x08,
   .event_name = "offcore_requests_outstanding.cycles_with_data_rd",
   },
  {
   .event_code = {0x60},
   .umask = 0x08,
   .event_name = "offcore_requests_outstanding.all_data_rd",
   },
  {
   .event_code = {0x60},
   .umask = 0x10,
   .event_name = "offcore_requests_outstanding.l3_miss_demand_data_rd",
   },
  {
   .event_code = {0x79},
   .umask = 0x04,
   .event_name = "idq.mite_cycles",
   },
  {
   .event_code = {0x79},
   .umask = 0x04,
   .event_name = "idq.mite_uops",
   },
  {
   .event_code = {0x79},
   .umask = 0x08,
   .event_name = "idq.dsb_cycles",
   },
  {
   .event_code = {0x79},
   .umask = 0x08,
   .event_name = "idq.dsb_uops",
   },
  {
   .event_code = {0x79},
   .umask = 0x10,
   .event_name = "idq.ms_dsb_cycles",
   },
  {
   .event_code = {0x79},
   .umask = 0x18,
   .event_name = "idq.all_dsb_cycles_any_uops",
   },
  {
   .event_code = {0x79},
   .umask = 0x18,
   .event_name = "idq.all_dsb_cycles_4_uops",
   },
  {
   .event_code = {0x79},
   .umask = 0x20,
   .event_name = "idq.ms_mite_uops",
   },
  {
   .event_code = {0x79},
   .umask = 0x24,
   .event_name = "idq.all_mite_cycles_any_uops",
   },
  {
   .event_code = {0x79},
   .umask = 0x24,
   .event_name = "idq.all_mite_cycles_4_uops",
   },
  {
   .event_code = {0x79},
   .umask = 0x30,
   .event_name = "idq.ms_cycles",
   },
  {
   .event_code = {0x79},
   .umask = 0x30,
   .event_name = "idq.ms_uops",
   },
  {
   .event_code = {0x79},
   .umask = 0x30,
   .event_name = "idq.ms_switches",
   },
  {
   .event_code = {0x80},
   .umask = 0x04,
   .event_name = "icache_16b.ifdata_stall",
   },
  {
   .event_code = {0x83},
   .umask = 0x01,
   .event_name = "icache_64b.iftag_hit",
   },
  {
   .event_code = {0x83},
   .umask = 0x02,
   .event_name = "icache_64b.iftag_miss",
   },
  {
   .event_code = {0x83},
   .umask = 0x04,
   .event_name = "icache_64b.iftag_stall",
   },
  {
   .event_code = {0x85},
   .umask = 0x01,
   .event_name = "itlb_misses.miss_causes_a_walk",
   },
  {
   .event_code = {0x85},
   .umask = 0x02,
   .event_name = "itlb_misses.walk_completed_4k",
   },
  {
   .event_code = {0x85},
   .umask = 0x04,
   .event_name = "itlb_misses.walk_completed_2m_4m",
   },
  {
   .event_code = {0x85},
   .umask = 0x08,
   .event_name = "itlb_misses.walk_completed_1g",
   },
  {
   .event_code = {0x85},
   .umask = 0x0E,
   .event_name = "itlb_misses.walk_completed",
   },
  {
   .event_code = {0x85},
   .umask = 0x10,
   .event_name = "itlb_misses.walk_pending",
   },
  {
   .event_code = {0x85},
   .umask = 0x10,
   .event_name = "itlb_misses.walk_active",
   },
  {
   .event_code = {0x85},
   .umask = 0x20,
   .event_name = "itlb_misses.stlb_hit",
   },
  {
   .event_code = {0x87},
   .umask = 0x01,
   .event_name = "ild_stall.lcp",
   },
  {
   .event_code = {0x9C},
   .umask = 0x01,
   .event_name = "idq_uops_not_delivered.cycles_fe_was_ok",
   },
  {
   .event_code = {0x9C},
   .umask = 0x01,
   .event_name = "idq_uops_not_delivered.cycles_le_3_uop_deliv.core",
   },
  {
   .event_code = {0x9C},
   .umask = 0x01,
   .event_name = "idq_uops_not_delivered.cycles_le_2_uop_deliv.core",
   },
  {
   .event_code = {0x9C},
   .umask = 0x01,
   .event_name = "idq_uops_not_delivered.cycles_le_1_uop_deliv.core",
   },
  {
   .event_code = {0x9C},
   .umask = 0x01,
   .event_name = "idq_uops_not_delivered.cycles_0_uops_deliv.core",
   },
  {
   .event_code = {0x9C},
   .umask = 0x01,
   .event_name = "idq_uops_not_delivered.core",
   },
  {
   .event_code = {0xA1},
   .umask = 0x01,
   .event_name = "uops_dispatched_port.port_0",
   },
  {
   .event_code = {0xA1},
   .umask = 0x02,
   .event_name = "uops_dispatched_port.port_1",
   },
  {
   .event_code = {0xA1},
   .umask = 0x04,
   .event_name = "uops_dispatched_port.port_2",
   },
  {
   .event_code = {0xA1},
   .umask = 0x08,
   .event_name = "uops_dispatched_port.port_3",
   },
  {
   .event_code = {0xA1},
   .umask = 0x10,
   .event_name = "uops_dispatched_port.port_4",
   },
  {
   .event_code = {0xA1},
   .umask = 0x20,
   .event_name = "uops_dispatched_port.port_5",
   },
  {
   .event_code = {0xA1},
   .umask = 0x40,
   .event_name = "uops_dispatched_port.port_6",
   },
  {
   .event_code = {0xA1},
   .umask = 0x80,
   .event_name = "uops_dispatched_port.port_7",
   },
  {
   .event_code = {0xa2},
   .umask = 0x01,
   .event_name = "resource_stalls.any",
   },
  {
   .event_code = {0xA2},
   .umask = 0x08,
   .event_name = "resource_stalls.sb",
   },
  {
   .event_code = {0xA3},
   .umask = 0x01,
   .event_name = "cycle_activity.cycles_l2_miss",
   },
  {
   .event_code = {0xA3},
   .umask = 0x04,
   .event_name = "cycle_activity.stalls_total",
   },
  {
   .event_code = {0xA3},
   .umask = 0x05,
   .event_name = "cycle_activity.stalls_l2_miss",
   },
  {
   .event_code = {0xA3},
   .umask = 0x08,
   .event_name = "cycle_activity.cycles_l1d_miss",
   },
  {
   .event_code = {0xA3},
   .umask = 0x0C,
   .event_name = "cycle_activity.stalls_l1d_miss",
   },
  {
   .event_code = {0xA3},
   .umask = 0x10,
   .event_name = "cycle_activity.cycles_mem_any",
   },
  {
   .event_code = {0xA3},
   .umask = 0x14,
   .event_name = "cycle_activity.stalls_mem_any",
   },
  {
   .event_code = {0xA6},
   .umask = 0x01,
   .event_name = "exe_activity.exe_bound_0_ports",
   },
  {
   .event_code = {0xA6},
   .umask = 0x02,
   .event_name = "exe_activity.1_ports_util",
   },
  {
   .event_code = {0xA6},
   .umask = 0x04,
   .event_name = "exe_activity.2_ports_util",
   },
  {
   .event_code = {0xA6},
   .umask = 0x08,
   .event_name = "exe_activity.3_ports_util",
   },
  {
   .event_code = {0xA6},
   .umask = 0x10,
   .event_name = "exe_activity.4_ports_util",
   },
  {
   .event_code = {0xA6},
   .umask = 0x40,
   .event_name = "exe_activity.bound_on_stores",
   },
  {
   .event_code = {0xA8},
   .umask = 0x01,
   .event_name = "lsd.uops",
   },
  {
   .event_code = {0xA8},
   .umask = 0x01,
   .event_name = "lsd.cycles_4_uops",
   },
  {
   .event_code = {0xA8},
   .umask = 0x01,
   .event_name = "lsd.cycles_active",
   },
  {
   .event_code = {0xAB},
   .umask = 0x02,
   .event_name = "dsb2mite_switches.penalty_cycles",
   },
  {
   .event_code = {0xAE},
   .umask = 0x01,
   .event_name = "itlb.itlb_flush",
   },
  {
   .event_code = {0xB0},
   .umask = 0x01,
   .event_name = "offcore_requests.demand_data_rd",
   },
  {
   .event_code = {0xB0},
   .umask = 0x02,
   .event_name = "offcore_requests.demand_code_rd",
   },
  {
   .event_code = {0xB0},
   .umask = 0x04,
   .event_name = "offcore_requests.demand_rfo",
   },
  {
   .event_code = {0xB0},
   .umask = 0x08,
   .event_name = "offcore_requests.all_data_rd",
   },
  {
   .event_code = {0xB0},
   .umask = 0x10,
   .event_name = "offcore_requests.l3_miss_demand_data_rd",
   },
  {
   .event_code = {0xB0},
   .umask = 0x80,
   .event_name = "offcore_requests.all_requests",
   },
  {
   .event_code = {0xB1},
   .umask = 0x01,
   .event_name = "uops_executed.cycles_ge_4_uops_exec",
   },
  {
   .event_code = {0xB1},
   .umask = 0x01,
   .event_name = "uops_executed.cycles_ge_3_uops_exec",
   },
  {
   .event_code = {0xB1},
   .umask = 0x01,
   .event_name = "uops_executed.cycles_ge_2_uops_exec",
   },
  {
   .event_code = {0xB1},
   .umask = 0x01,
   .event_name = "uops_executed.cycles_ge_1_uop_exec",
   },
  {
   .event_code = {0xB1},
   .umask = 0x01,
   .event_name = "uops_executed.stall_cycles",
   },
  {
   .event_code = {0xB1},
   .umask = 0x01,
   .event_name = "uops_executed.thread",
   },
  {
   .event_code = {0xB1},
   .umask = 0x02,
   .event_name = "uops_executed.core",
   },
  {
   .event_code = {0xB1},
   .umask = 0x02,
   .event_name = "uops_executed.core_cycles_none",
   },
  {
   .event_code = {0xB1},
   .umask = 0x02,
   .event_name = "uops_executed.core_cycles_ge_4",
   },
  {
   .event_code = {0xB1},
   .umask = 0x02,
   .event_name = "uops_executed.core_cycles_ge_3",
   },
  {
   .event_code = {0xB1},
   .umask = 0x02,
   .event_name = "uops_executed.core_cycles_ge_2",
   },
  {
   .event_code = {0xB1},
   .umask = 0x02,
   .event_name = "uops_executed.core_cycles_ge_1",
   },
  {
   .event_code = {0xB1},
   .umask = 0x10,
   .event_name = "uops_executed.x87",
   },
  {
   .event_code = {0xB2},
   .umask = 0x01,
   .event_name = "offcore_requests_buffer.sq_full",
   },
  {
   .event_code = {0xB7, 0xBB},
   .umask = 0x01,
   .event_name = "offcore_response",
   },
  {
   .event_code = {0xBD},
   .umask = 0x01,
   .event_name = "tlb_flush.dtlb_thread",
   },
  {
   .event_code = {0xBD},
   .umask = 0x20,
   .event_name = "tlb_flush.stlb_any",
   },
  {
   .event_code = {0xC0},
   .umask = 0x00,
   .event_name = "inst_retired.any_p",
   },
  {
   .event_code = {0xC0},
   .umask = 0x01,
   .event_name = "inst_retired.prec_dist",
   },
  {
   .event_code = {0xC0},
   .umask = 0x01,
   .event_name = "inst_retired.total_cycles_ps",
   },
  {
   .event_code = {0xC2},
   .umask = 0x02,
   .event_name = "uops_retired.total_cycles",
   },
  {
   .event_code = {0xC2},
   .umask = 0x02,
   .event_name = "uops_retired.stall_cycles",
   },
  {
   .event_code = {0xC2},
   .umask = 0x02,
   .event_name = "uops_retired.retire_slots",
   },
  {
   .event_code = {0xC3},
   .umask = 0x01,
   .event_name = "machine_clears.count",
   },
  {
   .event_code = {0xC3},
   .umask = 0x02,
   .event_name = "machine_clears.memory_ordering",
   },
  {
   .event_code = {0xC3},
   .umask = 0x04,
   .event_name = "machine_clears.smc",
   },
  {
   .event_code = {0xC4},
   .umask = 0x00,
   .event_name = "br_inst_retired.all_branches",
   },
  {
   .event_code = {0xC4},
   .umask = 0x01,
   .event_name = "br_inst_retired.conditional",
   },
  {
   .event_code = {0xC4},
   .umask = 0x02,
   .event_name = "br_inst_retired.near_call",
   },
  {
   .event_code = {0xC4},
   .umask = 0x04,
   .event_name = "br_inst_retired.all_branches_pebs",
   },
  {
   .event_code = {0xC4},
   .umask = 0x08,
   .event_name = "br_inst_retired.near_return",
   },
  {
   .event_code = {0xC4},
   .umask = 0x10,
   .event_name = "br_inst_retired.not_taken",
   },
  {
   .event_code = {0xC4},
   .umask = 0x20,
   .event_name = "br_inst_retired.near_taken",
   },
  {
   .event_code = {0xC4},
   .umask = 0x40,
   .event_name = "br_inst_retired.far_branch",
   },
  {
   .event_code = {0xC5},
   .umask = 0x00,
   .event_name = "br_misp_retired.all_branches",
   },
  {
   .event_code = {0xC5},
   .umask = 0x01,
   .event_name = "br_misp_retired.conditional",
   },
  {
   .event_code = {0xC5},
   .umask = 0x02,
   .event_name = "br_misp_retired.near_call",
   },
  {
   .event_code = {0xC5},
   .umask = 0x04,
   .event_name = "br_misp_retired.all_branches_pebs",
   },
  {
   .event_code = {0xC5},
   .umask = 0x20,
   .event_name = "br_misp_retired.near_taken",
   },
  {
   .event_code = {0xC7},
   .umask = 0x01,
   .event_name = "fp_arith_inst_retired.scalar_double",
   },
  {
   .event_code = {0xC7},
   .umask = 0x02,
   .event_name = "fp_arith_inst_retired.scalar_single",
   },
  {
   .event_code = {0xC7},
   .umask = 0x04,
   .event_name = "fp_arith_inst_retired.128b_packed_double",
   },
  {
   .event_code = {0xC7},
   .umask = 0x08,
   .event_name = "fp_arith_inst_retired.128b_packed_single",
   },
  {
   .event_code = {0xC7},
   .umask = 0x10,
   .event_name = "fp_arith_inst_retired.256b_packed_double",
   },
  {
   .event_code = {0xC7},
   .umask = 0x20,
   .event_name = "fp_arith_inst_retired.256b_packed_single",
   },
  {
   .event_code = {0xC7},
   .umask = 0x40,
   .event_name = "fp_arith_inst_retired.512b_packed_double",
   },
  {
   .event_code = {0xC7},
   .umask = 0x80,
   .event_name = "fp_arith_inst_retired.512b_packed_single",
   },
  {
   .event_code = {0xC8},
   .umask = 0x01,
   .event_name = "hle_retired.start",
   },
  {
   .event_code = {0xC8},
   .umask = 0x02,
   .event_name = "hle_retired.commit",
   },
  {
   .event_code = {0xC8},
   .umask = 0x04,
   .event_name = "hle_retired.aborted",
   },
  {
   .event_code = {0xC8},
   .umask = 0x08,
   .event_name = "hle_retired.aborted_mem",
   },
  {
   .event_code = {0xC8},
   .umask = 0x10,
   .event_name = "hle_retired.aborted_timer",
   },
  {
   .event_code = {0xC8},
   .umask = 0x20,
   .event_name = "hle_retired.aborted_unfriendly",
   },
  {
   .event_code = {0xC8},
   .umask = 0x40,
   .event_name = "hle_retired.aborted_memtype",
   },
  {
   .event_code = {0xC8},
   .umask = 0x80,
   .event_name = "hle_retired.aborted_events",
   },
  {
   .event_code = {0xC9},
   .umask = 0x01,
   .event_name = "rtm_retired.start",
   },
  {
   .event_code = {0xC9},
   .umask = 0x02,
   .event_name = "rtm_retired.commit",
   },
  {
   .event_code = {0xC9},
   .umask = 0x04,
   .event_name = "rtm_retired.aborted",
   },
  {
   .event_code = {0xC9},
   .umask = 0x08,
   .event_name = "rtm_retired.aborted_mem",
   },
  {
   .event_code = {0xC9},
   .umask = 0x10,
   .event_name = "rtm_retired.aborted_timer",
   },
  {
   .event_code = {0xC9},
   .umask = 0x20,
   .event_name = "rtm_retired.aborted_unfriendly",
   },
  {
   .event_code = {0xC9},
   .umask = 0x40,
   .event_name = "rtm_retired.aborted_memtype",
   },
  {
   .event_code = {0xC9},
   .umask = 0x80,
   .event_name = "rtm_retired.aborted_events",
   },
  {
   .event_code = {0xCA},
   .umask = 0x1E,
   .event_name = "fp_assist.any",
   },
  {
   .event_code = {0xCB},
   .umask = 0x01,
   .event_name = "hw_interrupts.received",
   },
  {
   .event_code = {0xCC},
   .umask = 0x20,
   .event_name = "rob_misc_events.lbr_inserts",
   },
  {
   .event_code = {0xCC},
   .umask = 0x40,
   .event_name = "rob_misc_events.pause_inst",
   },
  {
   .event_code = {0xD0},
   .umask = 0x11,
   .event_name = "mem_inst_retired.stlb_miss_loads",
   },
  {
   .event_code = {0xD0},
   .umask = 0x12,
   .event_name = "mem_inst_retired.stlb_miss_stores",
   },
  {
   .event_code = {0xD0},
   .umask = 0x21,
   .event_name = "mem_inst_retired.lock_loads",
   },
  {
   .event_code = {0xD0},
   .umask = 0x41,
   .event_name = "mem_inst_retired.split_loads",
   },
  {
   .event_code = {0xD0},
   .umask = 0x42,
   .event_name = "mem_inst_retired.split_stores",
   },
  {
   .event_code = {0xD0},
   .umask = 0x81,
   .event_name = "mem_inst_retired.all_loads",
   },
  {
   .event_code = {0xD0},
   .umask = 0x82,
   .event_name = "mem_inst_retired.all_stores",
   },
  {
   .event_code = {0xD1},
   .umask = 0x01,
   .event_name = "mem_load_retired.l1_hit",
   },
  {
   .event_code = {0xD1},
   .umask = 0x02,
   .event_name = "mem_load_retired.l2_hit",
   },
  {
   .event_code = {0xD1},
   .umask = 0x04,
   .event_name = "mem_load_retired.l3_hit",
   },
  {
   .event_code = {0xD1},
   .umask = 0x08,
   .event_name = "mem_load_retired.l1_miss",
   },
  {
   .event_code = {0xD1},
   .umask = 0x10,
   .event_name = "mem_load_retired.l2_miss",
   },
  {
   .event_code = {0xD1},
   .umask = 0x20,
   .event_name = "mem_load_retired.l3_miss",
   },
  {
   .event_code = {0xD1},
   .umask = 0x40,
   .event_name = "mem_load_retired.fb_hit",
   },
  {
   .event_code = {0xD1},
   .umask = 0x80,
   .event_name = "mem_load_retired.local_pmm",
   },
  {
   .event_code = {0xD2},
   .umask = 0x01,
   .event_name = "mem_load_l3_hit_retired.xsnp_miss",
   },
  {
   .event_code = {0xD2},
   .umask = 0x02,
   .event_name = "mem_load_l3_hit_retired.xsnp_hit",
   },
  {
   .event_code = {0xD2},
   .umask = 0x04,
   .event_name = "mem_load_l3_hit_retired.xsnp_hitm",
   },
  {
   .event_code = {0xD2},
   .umask = 0x08,
   .event_name = "mem_load_l3_hit_retired.xsnp_none",
   },
  {
   .event_code = {0xD3},
   .umask = 0x01,
   .event_name = "mem_load_l3_miss_retired.local_dram",
   },
  {
   .event_code = {0xD3},
   .umask = 0x02,
   .event_name = "mem_load_l3_miss_retired.remote_dram",
   },
  {
   .event_code = {0xD3},
   .umask = 0x04,
   .event_name = "mem_load_l3_miss_retired.remote_hitm",
   },
  {
   .event_code = {0xD3},
   .umask = 0x08,
   .event_name = "mem_load_l3_miss_retired.remote_fwd",
   },
  {
   .event_code = {0xD3},
   .umask = 0x10,
   .event_name = "mem_load_l3_miss_retired.remote_pmm",
   },
  {
   .event_code = {0xD4},
   .umask = 0x04,
   .event_name = "mem_load_misc_retired.uc",
   },
  {
   .event_code = {0xE6},
   .umask = 0x01,
   .event_name = "baclears.any",
   },
  {
   .event_code = {0xEF},
   .umask = 0x01,
   .event_name = "core_snoop_response.rsp_ihiti",
   },
  {
   .event_code = {0xEF},
   .umask = 0x02,
   .event_name = "core_snoop_response.rsp_ihitfse",
   },
  {
   .event_code = {0xEF},
   .umask = 0x04,
   .event_name = "core_snoop_response.rsp_shitfse",
   },
  {
   .event_code = {0xEF},
   .umask = 0x08,
   .event_name = "core_snoop_response.rsp_sfwdm",
   },
  {
   .event_code = {0xEF},
   .umask = 0x10,
   .event_name = "core_snoop_response.rsp_ifwdm",
   },
  {
   .event_code = {0xEF},
   .umask = 0x20,
   .event_name = "core_snoop_response.rsp_ifwdfe",
   },
  {
   .event_code = {0xEF},
   .umask = 0x40,
   .event_name = "core_snoop_response.rsp_sfwdfe",
   },
  {
   .event_code = {0xF0},
   .umask = 0x40,
   .event_name = "l2_trans.l2_wb",
   },
  {
   .event_code = {0xF1},
   .umask = 0x1F,
   .event_name = "l2_lines_in.all",
   },
  {
   .event_code = {0xF2},
   .umask = 0x01,
   .event_name = "l2_lines_out.silent",
   },
  {
   .event_code = {0xF2},
   .umask = 0x02,
   .event_name = "l2_lines_out.non_silent",
   },
  {
   .event_code = {0xF2},
   .umask = 0x04,
   .event_name = "l2_lines_out.useless_pref",
   },
  {
   .event_code = {0xF2},
   .umask = 0x04,
   .event_name = "l2_lines_out.useless_hwpf",
   },
  {
   .event_code = {0xF4},
   .umask = 0x10,
   .event_name = "sq_misc.split_lock",
   },
  {
   .event_code = {0xFE},
   .umask = 0x02,
   .event_name = "idi_misc.wb_upgrade",
   },
  {
   .event_code = {0xFE},
   .umask = 0x04,
   .event_name = "idi_misc.wb_downgrade",
   },
  {
   .event_name = 0,
   },
};

PERFMON_REGISTER_INTEL_PMC (cpu_model_table, event_table);

