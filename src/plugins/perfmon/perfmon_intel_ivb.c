
#include <perfmon/perfmon_intel.h>

static perfmon_intel_pmc_cpu_model_t cpu_model_table[] = {
  {0x3A, 0x00, 0},

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
   .event_code = {0x05},
   .umask = 0x01,
   .event_name = "misalign_mem_ref.loads",
   },
  {
   .event_code = {0x05},
   .umask = 0x02,
   .event_name = "misalign_mem_ref.stores",
   },
  {
   .event_code = {0x07},
   .umask = 0x01,
   .event_name = "ld_blocks_partial.address_alias",
   },
  {
   .event_code = {0x08},
   .umask = 0x81,
   .event_name = "dtlb_load_misses.miss_causes_a_walk",
   },
  {
   .event_code = {0x08},
   .umask = 0x82,
   .event_name = "dtlb_load_misses.walk_completed",
   },
  {
   .event_code = {0x08},
   .umask = 0x84,
   .event_name = "dtlb_load_misses.walk_duration",
   },
  {
   .event_code = {0x08},
   .umask = 0x88,
   .event_name = "dtlb_load_misses.large_page_walk_completed",
   },
  {
   .event_code = {0x0D},
   .umask = 0x03,
   .event_name = "int_misc.recovery_cycles",
   },
  {
   .event_code = {0x0D},
   .umask = 0x03,
   .event_name = "int_misc.recovery_stalls_count",
   },
  {
   .event_code = {0x0D},
   .umask = 0x03,
   .event_name = "int_misc.recovery_cycles_any",
   },
  {
   .event_code = {0x0E},
   .umask = 0x01,
   .event_name = "uops_issued.any",
   },
  {
   .event_code = {0x0E},
   .umask = 0x01,
   .event_name = "uops_issued.stall_cycles",
   },
  {
   .event_code = {0x0E},
   .umask = 0x01,
   .event_name = "uops_issued.core_stall_cycles",
   },
  {
   .event_code = {0x0E},
   .umask = 0x10,
   .event_name = "uops_issued.flags_merge",
   },
  {
   .event_code = {0x0E},
   .umask = 0x20,
   .event_name = "uops_issued.slow_lea",
   },
  {
   .event_code = {0x0E},
   .umask = 0x40,
   .event_name = "uops_issued.single_mul",
   },
  {
   .event_code = {0x10},
   .umask = 0x01,
   .event_name = "fp_comp_ops_exe.x87",
   },
  {
   .event_code = {0x10},
   .umask = 0x10,
   .event_name = "fp_comp_ops_exe.sse_packed_double",
   },
  {
   .event_code = {0x10},
   .umask = 0x20,
   .event_name = "fp_comp_ops_exe.sse_scalar_single",
   },
  {
   .event_code = {0x10},
   .umask = 0x40,
   .event_name = "fp_comp_ops_exe.sse_packed_single",
   },
  {
   .event_code = {0x10},
   .umask = 0x80,
   .event_name = "fp_comp_ops_exe.sse_scalar_double",
   },
  {
   .event_code = {0x11},
   .umask = 0x01,
   .event_name = "simd_fp_256.packed_single",
   },
  {
   .event_code = {0x11},
   .umask = 0x02,
   .event_name = "simd_fp_256.packed_double",
   },
  {
   .event_code = {0x14},
   .umask = 0x01,
   .event_name = "arith.fpu_div_active",
   },
  {
   .event_code = {0x14},
   .umask = 0x04,
   .event_name = "arith.fpu_div",
   },
  {
   .event_code = {0x24},
   .umask = 0x01,
   .event_name = "l2_rqsts.demand_data_rd_hit",
   },
  {
   .event_code = {0x24},
   .umask = 0x03,
   .event_name = "l2_rqsts.all_demand_data_rd",
   },
  {
   .event_code = {0x24},
   .umask = 0x04,
   .event_name = "l2_rqsts.rfo_hit",
   },
  {
   .event_code = {0x24},
   .umask = 0x08,
   .event_name = "l2_rqsts.rfo_miss",
   },
  {
   .event_code = {0x24},
   .umask = 0x0C,
   .event_name = "l2_rqsts.all_rfo",
   },
  {
   .event_code = {0x24},
   .umask = 0x10,
   .event_name = "l2_rqsts.code_rd_hit",
   },
  {
   .event_code = {0x24},
   .umask = 0x20,
   .event_name = "l2_rqsts.code_rd_miss",
   },
  {
   .event_code = {0x24},
   .umask = 0x30,
   .event_name = "l2_rqsts.all_code_rd",
   },
  {
   .event_code = {0x24},
   .umask = 0x40,
   .event_name = "l2_rqsts.pf_hit",
   },
  {
   .event_code = {0x24},
   .umask = 0x80,
   .event_name = "l2_rqsts.pf_miss",
   },
  {
   .event_code = {0x24},
   .umask = 0xC0,
   .event_name = "l2_rqsts.all_pf",
   },
  {
   .event_code = {0x27},
   .umask = 0x01,
   .event_name = "l2_store_lock_rqsts.miss",
   },
  {
   .event_code = {0x27},
   .umask = 0x08,
   .event_name = "l2_store_lock_rqsts.hit_m",
   },
  {
   .event_code = {0x27},
   .umask = 0x0F,
   .event_name = "l2_store_lock_rqsts.all",
   },
  {
   .event_code = {0x28},
   .umask = 0x01,
   .event_name = "l2_l1d_wb_rqsts.miss",
   },
  {
   .event_code = {0x28},
   .umask = 0x04,
   .event_name = "l2_l1d_wb_rqsts.hit_e",
   },
  {
   .event_code = {0x28},
   .umask = 0x08,
   .event_name = "l2_l1d_wb_rqsts.hit_m",
   },
  {
   .event_code = {0x28},
   .umask = 0x0F,
   .event_name = "l2_l1d_wb_rqsts.all",
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
   .umask = 0x02,
   .event_name = "cpu_clk_thread_unhalted.one_thread_active",
   },
  {
   .event_code = {0x48},
   .umask = 0x01,
   .event_name = "l1d_pend_miss.pending",
   },
  {
   .event_code = {0x48},
   .umask = 0x01,
   .event_name = "l1d_pend_miss.pending_cycles",
   },
  {
   .event_code = {0x49},
   .umask = 0x01,
   .event_name = "dtlb_store_misses.miss_causes_a_walk",
   },
  {
   .event_code = {0x49},
   .umask = 0x02,
   .event_name = "dtlb_store_misses.walk_completed",
   },
  {
   .event_code = {0x49},
   .umask = 0x04,
   .event_name = "dtlb_store_misses.walk_duration",
   },
  {
   .event_code = {0x49},
   .umask = 0x10,
   .event_name = "dtlb_store_misses.stlb_hit",
   },
  {
   .event_code = {0x4C},
   .umask = 0x01,
   .event_name = "load_hit_pre.sw_pf",
   },
  {
   .event_code = {0x4C},
   .umask = 0x02,
   .event_name = "load_hit_pre.hw_pf",
   },
  {
   .event_code = {0x4F},
   .umask = 0x10,
   .event_name = "ept.walk_cycles",
   },
  {
   .event_code = {0x51},
   .umask = 0x01,
   .event_name = "l1d.replacement",
   },
  {
   .event_code = {0x58},
   .umask = 0x01,
   .event_name = "move_elimination.int_eliminated",
   },
  {
   .event_code = {0x58},
   .umask = 0x02,
   .event_name = "move_elimination.simd_eliminated",
   },
  {
   .event_code = {0x58},
   .umask = 0x04,
   .event_name = "move_elimination.int_not_eliminated",
   },
  {
   .event_code = {0x58},
   .umask = 0x08,
   .event_name = "move_elimination.simd_not_eliminated",
   },
  {
   .event_code = {0x5C},
   .umask = 0x01,
   .event_name = "cpl_cycles.ring0",
   },
  {
   .event_code = {0x5C},
   .umask = 0x01,
   .event_name = "cpl_cycles.ring0_trans",
   },
  {
   .event_code = {0x5C},
   .umask = 0x02,
   .event_name = "cpl_cycles.ring123",
   },
  {
   .event_code = {0x5E},
   .umask = 0x01,
   .event_name = "rs_events.empty_cycles",
   },
  {
   .event_code = {0x5E},
   .umask = 0x01,
   .event_name = "rs_events.empty_end",
   },
  {
   .event_code = {0x5F},
   .umask = 0x04,
   .event_name = "dtlb_load_misses.stlb_hit",
   },
  {
   .event_code = {0x60},
   .umask = 0x01,
   .event_name = "offcore_requests_outstanding.demand_data_rd",
   },
  {
   .event_code = {0x60},
   .umask = 0x01,
   .event_name = "offcore_requests_outstanding.cycles_with_demand_data_rd",
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
   .event_name = "offcore_requests_outstanding.all_data_rd",
   },
  {
   .event_code = {0x60},
   .umask = 0x08,
   .event_name = "offcore_requests_outstanding.cycles_with_data_rd",
   },
  {
   .event_code = {0x63},
   .umask = 0x01,
   .event_name = "lock_cycles.split_lock_uc_lock_duration",
   },
  {
   .event_code = {0x63},
   .umask = 0x02,
   .event_name = "lock_cycles.cache_lock_duration",
   },
  {
   .event_code = {0x79},
   .umask = 0x02,
   .event_name = "idq.empty",
   },
  {
   .event_code = {0x79},
   .umask = 0x04,
   .event_name = "idq.mite_uops",
   },
  {
   .event_code = {0x79},
   .umask = 0x04,
   .event_name = "idq.mite_cycles",
   },
  {
   .event_code = {0x79},
   .umask = 0x08,
   .event_name = "idq.dsb_uops",
   },
  {
   .event_code = {0x79},
   .umask = 0x08,
   .event_name = "idq.dsb_cycles",
   },
  {
   .event_code = {0x79},
   .umask = 0x10,
   .event_name = "idq.ms_dsb_uops",
   },
  {
   .event_code = {0x79},
   .umask = 0x10,
   .event_name = "idq.ms_dsb_cycles",
   },
  {
   .event_code = {0x79},
   .umask = 0x10,
   .event_name = "idq.ms_dsb_occur",
   },
  {
   .event_code = {0x79},
   .umask = 0x18,
   .event_name = "idq.all_dsb_cycles_4_uops",
   },
  {
   .event_code = {0x79},
   .umask = 0x18,
   .event_name = "idq.all_dsb_cycles_any_uops",
   },
  {
   .event_code = {0x79},
   .umask = 0x20,
   .event_name = "idq.ms_mite_uops",
   },
  {
   .event_code = {0x79},
   .umask = 0x24,
   .event_name = "idq.all_mite_cycles_4_uops",
   },
  {
   .event_code = {0x79},
   .umask = 0x24,
   .event_name = "idq.all_mite_cycles_any_uops",
   },
  {
   .event_code = {0x79},
   .umask = 0x30,
   .event_name = "idq.ms_uops",
   },
  {
   .event_code = {0x79},
   .umask = 0x30,
   .event_name = "idq.ms_cycles",
   },
  {
   .event_code = {0x79},
   .umask = 0x30,
   .event_name = "idq.ms_switches",
   },
  {
   .event_code = {0x79},
   .umask = 0x3C,
   .event_name = "idq.mite_all_uops",
   },
  {
   .event_code = {0x80},
   .umask = 0x01,
   .event_name = "icache.hit",
   },
  {
   .event_code = {0x80},
   .umask = 0x02,
   .event_name = "icache.misses",
   },
  {
   .event_code = {0x80},
   .umask = 0x04,
   .event_name = "icache.ifetch_stall",
   },
  {
   .event_code = {0x85},
   .umask = 0x01,
   .event_name = "itlb_misses.miss_causes_a_walk",
   },
  {
   .event_code = {0x85},
   .umask = 0x02,
   .event_name = "itlb_misses.walk_completed",
   },
  {
   .event_code = {0x85},
   .umask = 0x04,
   .event_name = "itlb_misses.walk_duration",
   },
  {
   .event_code = {0x85},
   .umask = 0x10,
   .event_name = "itlb_misses.stlb_hit",
   },
  {
   .event_code = {0x85},
   .umask = 0x80,
   .event_name = "itlb_misses.large_page_walk_completed",
   },
  {
   .event_code = {0x87},
   .umask = 0x01,
   .event_name = "ild_stall.lcp",
   },
  {
   .event_code = {0x87},
   .umask = 0x04,
   .event_name = "ild_stall.iq_full",
   },
  {
   .event_code = {0x88},
   .umask = 0x41,
   .event_name = "br_inst_exec.nontaken_conditional",
   },
  {
   .event_code = {0x88},
   .umask = 0x81,
   .event_name = "br_inst_exec.taken_conditional",
   },
  {
   .event_code = {0x88},
   .umask = 0x82,
   .event_name = "br_inst_exec.taken_direct_jump",
   },
  {
   .event_code = {0x88},
   .umask = 0x84,
   .event_name = "br_inst_exec.taken_indirect_jump_non_call_ret",
   },
  {
   .event_code = {0x88},
   .umask = 0x88,
   .event_name = "br_inst_exec.taken_indirect_near_return",
   },
  {
   .event_code = {0x88},
   .umask = 0x90,
   .event_name = "br_inst_exec.taken_direct_near_call",
   },
  {
   .event_code = {0x88},
   .umask = 0xA0,
   .event_name = "br_inst_exec.taken_indirect_near_call",
   },
  {
   .event_code = {0x88},
   .umask = 0xC1,
   .event_name = "br_inst_exec.all_conditional",
   },
  {
   .event_code = {0x88},
   .umask = 0xC2,
   .event_name = "br_inst_exec.all_direct_jmp",
   },
  {
   .event_code = {0x88},
   .umask = 0xC4,
   .event_name = "br_inst_exec.all_indirect_jump_non_call_ret",
   },
  {
   .event_code = {0x88},
   .umask = 0xC8,
   .event_name = "br_inst_exec.all_indirect_near_return",
   },
  {
   .event_code = {0x88},
   .umask = 0xD0,
   .event_name = "br_inst_exec.all_direct_near_call",
   },
  {
   .event_code = {0x88},
   .umask = 0xFF,
   .event_name = "br_inst_exec.all_branches",
   },
  {
   .event_code = {0x89},
   .umask = 0x41,
   .event_name = "br_misp_exec.nontaken_conditional",
   },
  {
   .event_code = {0x89},
   .umask = 0x81,
   .event_name = "br_misp_exec.taken_conditional",
   },
  {
   .event_code = {0x89},
   .umask = 0x84,
   .event_name = "br_misp_exec.taken_indirect_jump_non_call_ret",
   },
  {
   .event_code = {0x89},
   .umask = 0x88,
   .event_name = "br_misp_exec.taken_return_near",
   },
  {
   .event_code = {0x89},
   .umask = 0xA0,
   .event_name = "br_misp_exec.taken_indirect_near_call",
   },
  {
   .event_code = {0x89},
   .umask = 0xC1,
   .event_name = "br_misp_exec.all_conditional",
   },
  {
   .event_code = {0x89},
   .umask = 0xC4,
   .event_name = "br_misp_exec.all_indirect_jump_non_call_ret",
   },
  {
   .event_code = {0x89},
   .umask = 0xFF,
   .event_name = "br_misp_exec.all_branches",
   },
  {
   .event_code = {0x9C},
   .umask = 0x01,
   .event_name = "idq_uops_not_delivered.core",
   },
  {
   .event_code = {0x9C},
   .umask = 0x01,
   .event_name = "idq_uops_not_delivered.cycles_0_uops_deliv.core",
   },
  {
   .event_code = {0x9C},
   .umask = 0x01,
   .event_name = "idq_uops_not_delivered.cycles_le_1_uop_deliv.core",
   },
  {
   .event_code = {0x9C},
   .umask = 0x01,
   .event_name = "idq_uops_not_delivered.cycles_le_2_uop_deliv.core",
   },
  {
   .event_code = {0x9C},
   .umask = 0x01,
   .event_name = "idq_uops_not_delivered.cycles_le_3_uop_deliv.core",
   },
  {
   .event_code = {0x9C},
   .umask = 0x01,
   .event_name = "idq_uops_not_delivered.cycles_fe_was_ok",
   },
  {
   .event_code = {0xA1},
   .umask = 0x01,
   .event_name = "uops_dispatched_port.port_0",
   },
  {
   .event_code = {0xA1},
   .umask = 0x01,
   .event_name = "uops_dispatched_port.port_0_core",
   },
  {
   .event_code = {0xA1},
   .umask = 0x02,
   .event_name = "uops_dispatched_port.port_1",
   },
  {
   .event_code = {0xA1},
   .umask = 0x02,
   .event_name = "uops_dispatched_port.port_1_core",
   },
  {
   .event_code = {0xA1},
   .umask = 0x0C,
   .event_name = "uops_dispatched_port.port_2",
   },
  {
   .event_code = {0xA1},
   .umask = 0x0C,
   .event_name = "uops_dispatched_port.port_2_core",
   },
  {
   .event_code = {0xA1},
   .umask = 0x30,
   .event_name = "uops_dispatched_port.port_3",
   },
  {
   .event_code = {0xA1},
   .umask = 0x30,
   .event_name = "uops_dispatched_port.port_3_core",
   },
  {
   .event_code = {0xA1},
   .umask = 0x40,
   .event_name = "uops_dispatched_port.port_4",
   },
  {
   .event_code = {0xA1},
   .umask = 0x40,
   .event_name = "uops_dispatched_port.port_4_core",
   },
  {
   .event_code = {0xA1},
   .umask = 0x80,
   .event_name = "uops_dispatched_port.port_5",
   },
  {
   .event_code = {0xA1},
   .umask = 0x80,
   .event_name = "uops_dispatched_port.port_5_core",
   },
  {
   .event_code = {0xA2},
   .umask = 0x01,
   .event_name = "resource_stalls.any",
   },
  {
   .event_code = {0xA2},
   .umask = 0x04,
   .event_name = "resource_stalls.rs",
   },
  {
   .event_code = {0xA2},
   .umask = 0x08,
   .event_name = "resource_stalls.sb",
   },
  {
   .event_code = {0xA2},
   .umask = 0x10,
   .event_name = "resource_stalls.rob",
   },
  {
   .event_code = {0xA3},
   .umask = 0x01,
   .event_name = "cycle_activity.cycles_l2_pending",
   },
  {
   .event_code = {0xA3},
   .umask = 0x02,
   .event_name = "cycle_activity.cycles_ldm_pending",
   },
  {
   .event_code = {0xA3},
   .umask = 0x04,
   .event_name = "cycle_activity.cycles_no_execute",
   },
  {
   .event_code = {0xA3},
   .umask = 0x05,
   .event_name = "cycle_activity.stalls_l2_pending",
   },
  {
   .event_code = {0xA3},
   .umask = 0x06,
   .event_name = "cycle_activity.stalls_ldm_pending",
   },
  {
   .event_code = {0xA3},
   .umask = 0x08,
   .event_name = "cycle_activity.cycles_l1d_pending",
   },
  {
   .event_code = {0xA3},
   .umask = 0x0C,
   .event_name = "cycle_activity.stalls_l1d_pending",
   },
  {
   .event_code = {0xA8},
   .umask = 0x01,
   .event_name = "lsd.uops",
   },
  {
   .event_code = {0xA8},
   .umask = 0x01,
   .event_name = "lsd.cycles_active",
   },
  {
   .event_code = {0xA8},
   .umask = 0x01,
   .event_name = "lsd.cycles_4_uops",
   },
  {
   .event_code = {0xAB},
   .umask = 0x01,
   .event_name = "dsb2mite_switches.count",
   },
  {
   .event_code = {0xAB},
   .umask = 0x02,
   .event_name = "dsb2mite_switches.penalty_cycles",
   },
  {
   .event_code = {0xAC},
   .umask = 0x08,
   .event_name = "dsb_fill.exceed_dsb_lines",
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
   .event_code = {0xB1},
   .umask = 0x01,
   .event_name = "uops_executed.thread",
   },
  {
   .event_code = {0xB1},
   .umask = 0x01,
   .event_name = "uops_executed.stall_cycles",
   },
  {
   .event_code = {0xB1},
   .umask = 0x01,
   .event_name = "uops_executed.cycles_ge_1_uop_exec",
   },
  {
   .event_code = {0xB1},
   .umask = 0x01,
   .event_name = "uops_executed.cycles_ge_2_uops_exec",
   },
  {
   .event_code = {0xB1},
   .umask = 0x01,
   .event_name = "uops_executed.cycles_ge_3_uops_exec",
   },
  {
   .event_code = {0xB1},
   .umask = 0x01,
   .event_name = "uops_executed.cycles_ge_4_uops_exec",
   },
  {
   .event_code = {0xB1},
   .umask = 0x02,
   .event_name = "uops_executed.core",
   },
  {
   .event_code = {0xB2},
   .umask = 0x01,
   .event_name = "offcore_requests_buffer.sq_full",
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
   .event_code = {0xBE},
   .umask = 0x01,
   .event_name = "page_walks.llc_miss",
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
   .event_code = {0xC1},
   .umask = 0x08,
   .event_name = "other_assists.avx_store",
   },
  {
   .event_code = {0xC1},
   .umask = 0x10,
   .event_name = "other_assists.avx_to_sse",
   },
  {
   .event_code = {0xC1},
   .umask = 0x20,
   .event_name = "other_assists.sse_to_avx",
   },
  {
   .event_code = {0xC1},
   .umask = 0x80,
   .event_name = "other_assists.any_wb_assist",
   },
  {
   .event_code = {0xC2},
   .umask = 0x01,
   .event_name = "uops_retired.all",
   },
  {
   .event_code = {0xC2},
   .umask = 0x01,
   .event_name = "uops_retired.stall_cycles",
   },
  {
   .event_code = {0xC2},
   .umask = 0x01,
   .event_name = "uops_retired.total_cycles",
   },
  {
   .event_code = {0xC2},
   .umask = 0x01,
   .event_name = "uops_retired.core_stall_cycles",
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
   .event_code = {0xC3},
   .umask = 0x20,
   .event_name = "machine_clears.maskmov",
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
   .umask = 0x02,
   .event_name = "br_inst_retired.near_call_r3",
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
   .umask = 0x04,
   .event_name = "br_misp_retired.all_branches_pebs",
   },
  {
   .event_code = {0xC5},
   .umask = 0x20,
   .event_name = "br_misp_retired.near_taken",
   },
  {
   .event_code = {0xCA},
   .umask = 0x02,
   .event_name = "fp_assist.x87_output",
   },
  {
   .event_code = {0xCA},
   .umask = 0x04,
   .event_name = "fp_assist.x87_input",
   },
  {
   .event_code = {0xCA},
   .umask = 0x08,
   .event_name = "fp_assist.simd_output",
   },
  {
   .event_code = {0xCA},
   .umask = 0x10,
   .event_name = "fp_assist.simd_input",
   },
  {
   .event_code = {0xCA},
   .umask = 0x1E,
   .event_name = "fp_assist.any",
   },
  {
   .event_code = {0xCC},
   .umask = 0x20,
   .event_name = "rob_misc_events.lbr_inserts",
   },
  {
   .event_code = {0xCD},
   .umask = 0x02,
   .event_name = "mem_trans_retired.precise_store",
   },
  {
   .event_code = {0xD0},
   .umask = 0x11,
   .event_name = "mem_uops_retired.stlb_miss_loads",
   },
  {
   .event_code = {0xD0},
   .umask = 0x12,
   .event_name = "mem_uops_retired.stlb_miss_stores",
   },
  {
   .event_code = {0xD0},
   .umask = 0x21,
   .event_name = "mem_uops_retired.lock_loads",
   },
  {
   .event_code = {0xD0},
   .umask = 0x41,
   .event_name = "mem_uops_retired.split_loads",
   },
  {
   .event_code = {0xD0},
   .umask = 0x42,
   .event_name = "mem_uops_retired.split_stores",
   },
  {
   .event_code = {0xD0},
   .umask = 0x81,
   .event_name = "mem_uops_retired.all_loads",
   },
  {
   .event_code = {0xD0},
   .umask = 0x82,
   .event_name = "mem_uops_retired.all_stores",
   },
  {
   .event_code = {0xD1},
   .umask = 0x01,
   .event_name = "mem_load_uops_retired.l1_hit",
   },
  {
   .event_code = {0xD1},
   .umask = 0x02,
   .event_name = "mem_load_uops_retired.l2_hit",
   },
  {
   .event_code = {0xD1},
   .umask = 0x04,
   .event_name = "mem_load_uops_retired.llc_hit",
   },
  {
   .event_code = {0xD1},
   .umask = 0x08,
   .event_name = "mem_load_uops_retired.l1_miss",
   },
  {
   .event_code = {0xD1},
   .umask = 0x10,
   .event_name = "mem_load_uops_retired.l2_miss",
   },
  {
   .event_code = {0xD1},
   .umask = 0x20,
   .event_name = "mem_load_uops_retired.llc_miss",
   },
  {
   .event_code = {0xD1},
   .umask = 0x40,
   .event_name = "mem_load_uops_retired.hit_lfb",
   },
  {
   .event_code = {0xD2},
   .umask = 0x01,
   .event_name = "mem_load_uops_llc_hit_retired.xsnp_miss",
   },
  {
   .event_code = {0xD2},
   .umask = 0x02,
   .event_name = "mem_load_uops_llc_hit_retired.xsnp_hit",
   },
  {
   .event_code = {0xD2},
   .umask = 0x04,
   .event_name = "mem_load_uops_llc_hit_retired.xsnp_hitm",
   },
  {
   .event_code = {0xD2},
   .umask = 0x08,
   .event_name = "mem_load_uops_llc_hit_retired.xsnp_none",
   },
  {
   .event_code = {0xD3},
   .umask = 0x01,
   .event_name = "mem_load_uops_llc_miss_retired.local_dram",
   },
  {
   .event_code = {0xE6},
   .umask = 0x1F,
   .event_name = "baclears.any",
   },
  {
   .event_code = {0xF0},
   .umask = 0x01,
   .event_name = "l2_trans.demand_data_rd",
   },
  {
   .event_code = {0xF0},
   .umask = 0x02,
   .event_name = "l2_trans.rfo",
   },
  {
   .event_code = {0xF0},
   .umask = 0x04,
   .event_name = "l2_trans.code_rd",
   },
  {
   .event_code = {0xF0},
   .umask = 0x08,
   .event_name = "l2_trans.all_pf",
   },
  {
   .event_code = {0xF0},
   .umask = 0x10,
   .event_name = "l2_trans.l1d_wb",
   },
  {
   .event_code = {0xF0},
   .umask = 0x20,
   .event_name = "l2_trans.l2_fill",
   },
  {
   .event_code = {0xF0},
   .umask = 0x40,
   .event_name = "l2_trans.l2_wb",
   },
  {
   .event_code = {0xF0},
   .umask = 0x80,
   .event_name = "l2_trans.all_requests",
   },
  {
   .event_code = {0xF1},
   .umask = 0x01,
   .event_name = "l2_lines_in.i",
   },
  {
   .event_code = {0xF1},
   .umask = 0x02,
   .event_name = "l2_lines_in.s",
   },
  {
   .event_code = {0xF1},
   .umask = 0x04,
   .event_name = "l2_lines_in.e",
   },
  {
   .event_code = {0xF1},
   .umask = 0x07,
   .event_name = "l2_lines_in.all",
   },
  {
   .event_code = {0xF2},
   .umask = 0x01,
   .event_name = "l2_lines_out.demand_clean",
   },
  {
   .event_code = {0xF2},
   .umask = 0x02,
   .event_name = "l2_lines_out.demand_dirty",
   },
  {
   .event_code = {0xF2},
   .umask = 0x04,
   .event_name = "l2_lines_out.pf_clean",
   },
  {
   .event_code = {0xF2},
   .umask = 0x08,
   .event_name = "l2_lines_out.pf_dirty",
   },
  {
   .event_code = {0xF2},
   .umask = 0x0A,
   .event_name = "l2_lines_out.dirty_all",
   },
  {
   .event_code = {0xF4},
   .umask = 0x10,
   .event_name = "sq_misc.split_lock",
   },
  {
   .event_name = 0,
   },
};

PERFMON_REGISTER_INTEL_PMC (cpu_model_table, event_table);

