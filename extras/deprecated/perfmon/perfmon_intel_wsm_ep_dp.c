
#include <perfmon/perfmon_intel.h>

static perfmon_intel_pmc_cpu_model_t cpu_model_table[] = {
  {0x2C, 0x00, 0},

};

static perfmon_intel_pmc_event_t event_table[] = {
  {
   .event_code = {0x14},
   .umask = 0x1,
   .event_name = "arith.cycles_div_busy",
   },
  {
   .event_code = {0x14},
   .umask = 0x1,
   .event_name = "arith.div",
   },
  {
   .event_code = {0x14},
   .umask = 0x2,
   .event_name = "arith.mul",
   },
  {
   .event_code = {0xE6},
   .umask = 0x2,
   .event_name = "baclear.bad_target",
   },
  {
   .event_code = {0xE6},
   .umask = 0x1,
   .event_name = "baclear.clear",
   },
  {
   .event_code = {0xA7},
   .umask = 0x1,
   .event_name = "baclear_force_iq",
   },
  {
   .event_code = {0xE8},
   .umask = 0x1,
   .event_name = "bpu_clears.early",
   },
  {
   .event_code = {0xE8},
   .umask = 0x2,
   .event_name = "bpu_clears.late",
   },
  {
   .event_code = {0xE5},
   .umask = 0x1,
   .event_name = "bpu_missed_call_ret",
   },
  {
   .event_code = {0xE0},
   .umask = 0x1,
   .event_name = "br_inst_decoded",
   },
  {
   .event_code = {0x88},
   .umask = 0x7F,
   .event_name = "br_inst_exec.any",
   },
  {
   .event_code = {0x88},
   .umask = 0x1,
   .event_name = "br_inst_exec.cond",
   },
  {
   .event_code = {0x88},
   .umask = 0x2,
   .event_name = "br_inst_exec.direct",
   },
  {
   .event_code = {0x88},
   .umask = 0x10,
   .event_name = "br_inst_exec.direct_near_call",
   },
  {
   .event_code = {0x88},
   .umask = 0x20,
   .event_name = "br_inst_exec.indirect_near_call",
   },
  {
   .event_code = {0x88},
   .umask = 0x4,
   .event_name = "br_inst_exec.indirect_non_call",
   },
  {
   .event_code = {0x88},
   .umask = 0x30,
   .event_name = "br_inst_exec.near_calls",
   },
  {
   .event_code = {0x88},
   .umask = 0x7,
   .event_name = "br_inst_exec.non_calls",
   },
  {
   .event_code = {0x88},
   .umask = 0x8,
   .event_name = "br_inst_exec.return_near",
   },
  {
   .event_code = {0x88},
   .umask = 0x40,
   .event_name = "br_inst_exec.taken",
   },
  {
   .event_code = {0xC4},
   .umask = 0x4,
   .event_name = "br_inst_retired.all_branches",
   },
  {
   .event_code = {0xC4},
   .umask = 0x1,
   .event_name = "br_inst_retired.conditional",
   },
  {
   .event_code = {0xC4},
   .umask = 0x2,
   .event_name = "br_inst_retired.near_call",
   },
  {
   .event_code = {0x89},
   .umask = 0x7F,
   .event_name = "br_misp_exec.any",
   },
  {
   .event_code = {0x89},
   .umask = 0x1,
   .event_name = "br_misp_exec.cond",
   },
  {
   .event_code = {0x89},
   .umask = 0x2,
   .event_name = "br_misp_exec.direct",
   },
  {
   .event_code = {0x89},
   .umask = 0x10,
   .event_name = "br_misp_exec.direct_near_call",
   },
  {
   .event_code = {0x89},
   .umask = 0x20,
   .event_name = "br_misp_exec.indirect_near_call",
   },
  {
   .event_code = {0x89},
   .umask = 0x4,
   .event_name = "br_misp_exec.indirect_non_call",
   },
  {
   .event_code = {0x89},
   .umask = 0x30,
   .event_name = "br_misp_exec.near_calls",
   },
  {
   .event_code = {0x89},
   .umask = 0x7,
   .event_name = "br_misp_exec.non_calls",
   },
  {
   .event_code = {0x89},
   .umask = 0x8,
   .event_name = "br_misp_exec.return_near",
   },
  {
   .event_code = {0x89},
   .umask = 0x40,
   .event_name = "br_misp_exec.taken",
   },
  {
   .event_code = {0xC5},
   .umask = 0x4,
   .event_name = "br_misp_retired.all_branches",
   },
  {
   .event_code = {0xC5},
   .umask = 0x1,
   .event_name = "br_misp_retired.conditional",
   },
  {
   .event_code = {0xC5},
   .umask = 0x2,
   .event_name = "br_misp_retired.near_call",
   },
  {
   .event_code = {0x63},
   .umask = 0x2,
   .event_name = "cache_lock_cycles.l1d",
   },
  {
   .event_code = {0x63},
   .umask = 0x1,
   .event_name = "cache_lock_cycles.l1d_l2",
   },
  {
   .event_code = {0x0},
   .umask = 0x0,
   .event_name = "cpu_clk_unhalted.ref",
   },
  {
   .event_code = {0x3C},
   .umask = 0x1,
   .event_name = "cpu_clk_unhalted.ref_p",
   },
  {
   .event_code = {0x0},
   .umask = 0x0,
   .event_name = "cpu_clk_unhalted.thread",
   },
  {
   .event_code = {0x3C},
   .umask = 0x0,
   .event_name = "cpu_clk_unhalted.thread_p",
   },
  {
   .event_code = {0x3C},
   .umask = 0x0,
   .event_name = "cpu_clk_unhalted.total_cycles",
   },
  {
   .event_code = {0x8},
   .umask = 0x1,
   .event_name = "dtlb_load_misses.any",
   },
  {
   .event_code = {0x8},
   .umask = 0x80,
   .event_name = "dtlb_load_misses.large_walk_completed",
   },
  {
   .event_code = {0x8},
   .umask = 0x20,
   .event_name = "dtlb_load_misses.pde_miss",
   },
  {
   .event_code = {0x8},
   .umask = 0x10,
   .event_name = "dtlb_load_misses.stlb_hit",
   },
  {
   .event_code = {0x8},
   .umask = 0x2,
   .event_name = "dtlb_load_misses.walk_completed",
   },
  {
   .event_code = {0x8},
   .umask = 0x4,
   .event_name = "dtlb_load_misses.walk_cycles",
   },
  {
   .event_code = {0x49},
   .umask = 0x1,
   .event_name = "dtlb_misses.any",
   },
  {
   .event_code = {0x49},
   .umask = 0x80,
   .event_name = "dtlb_misses.large_walk_completed",
   },
  {
   .event_code = {0x49},
   .umask = 0x20,
   .event_name = "dtlb_misses.pde_miss",
   },
  {
   .event_code = {0x49},
   .umask = 0x10,
   .event_name = "dtlb_misses.stlb_hit",
   },
  {
   .event_code = {0x49},
   .umask = 0x2,
   .event_name = "dtlb_misses.walk_completed",
   },
  {
   .event_code = {0x49},
   .umask = 0x4,
   .event_name = "dtlb_misses.walk_cycles",
   },
  {
   .event_code = {0x4F},
   .umask = 0x10,
   .event_name = "ept.walk_cycles",
   },
  {
   .event_code = {0xD5},
   .umask = 0x1,
   .event_name = "es_reg_renames",
   },
  {
   .event_code = {0xF7},
   .umask = 0x1,
   .event_name = "fp_assist.all",
   },
  {
   .event_code = {0xF7},
   .umask = 0x4,
   .event_name = "fp_assist.input",
   },
  {
   .event_code = {0xF7},
   .umask = 0x2,
   .event_name = "fp_assist.output",
   },
  {
   .event_code = {0x10},
   .umask = 0x2,
   .event_name = "fp_comp_ops_exe.mmx",
   },
  {
   .event_code = {0x10},
   .umask = 0x80,
   .event_name = "fp_comp_ops_exe.sse_double_precision",
   },
  {
   .event_code = {0x10},
   .umask = 0x4,
   .event_name = "fp_comp_ops_exe.sse_fp",
   },
  {
   .event_code = {0x10},
   .umask = 0x10,
   .event_name = "fp_comp_ops_exe.sse_fp_packed",
   },
  {
   .event_code = {0x10},
   .umask = 0x20,
   .event_name = "fp_comp_ops_exe.sse_fp_scalar",
   },
  {
   .event_code = {0x10},
   .umask = 0x40,
   .event_name = "fp_comp_ops_exe.sse_single_precision",
   },
  {
   .event_code = {0x10},
   .umask = 0x8,
   .event_name = "fp_comp_ops_exe.sse2_integer",
   },
  {
   .event_code = {0x10},
   .umask = 0x1,
   .event_name = "fp_comp_ops_exe.x87",
   },
  {
   .event_code = {0xCC},
   .umask = 0x3,
   .event_name = "fp_mmx_trans.any",
   },
  {
   .event_code = {0xCC},
   .umask = 0x1,
   .event_name = "fp_mmx_trans.to_fp",
   },
  {
   .event_code = {0xCC},
   .umask = 0x2,
   .event_name = "fp_mmx_trans.to_mmx",
   },
  {
   .event_code = {0x87},
   .umask = 0xF,
   .event_name = "ild_stall.any",
   },
  {
   .event_code = {0x87},
   .umask = 0x4,
   .event_name = "ild_stall.iq_full",
   },
  {
   .event_code = {0x87},
   .umask = 0x1,
   .event_name = "ild_stall.lcp",
   },
  {
   .event_code = {0x87},
   .umask = 0x2,
   .event_name = "ild_stall.mru",
   },
  {
   .event_code = {0x87},
   .umask = 0x8,
   .event_name = "ild_stall.regen",
   },
  {
   .event_code = {0x18},
   .umask = 0x1,
   .event_name = "inst_decoded.dec0",
   },
  {
   .event_code = {0x1E},
   .umask = 0x1,
   .event_name = "inst_queue_write_cycles",
   },
  {
   .event_code = {0x17},
   .umask = 0x1,
   .event_name = "inst_queue_writes",
   },
  {
   .event_code = {0x0},
   .umask = 0x0,
   .event_name = "inst_retired.any",
   },
  {
   .event_code = {0xC0},
   .umask = 0x1,
   .event_name = "inst_retired.any_p",
   },
  {
   .event_code = {0xC0},
   .umask = 0x4,
   .event_name = "inst_retired.mmx",
   },
  {
   .event_code = {0xC0},
   .umask = 0x1,
   .event_name = "inst_retired.total_cycles",
   },
  {
   .event_code = {0xC0},
   .umask = 0x2,
   .event_name = "inst_retired.x87",
   },
  {
   .event_code = {0x6C},
   .umask = 0x1,
   .event_name = "io_transactions",
   },
  {
   .event_code = {0xAE},
   .umask = 0x1,
   .event_name = "itlb_flush",
   },
  {
   .event_code = {0xC8},
   .umask = 0x20,
   .event_name = "itlb_miss_retired",
   },
  {
   .event_code = {0x85},
   .umask = 0x1,
   .event_name = "itlb_misses.any",
   },
  {
   .event_code = {0x85},
   .umask = 0x80,
   .event_name = "itlb_misses.large_walk_completed",
   },
  {
   .event_code = {0x85},
   .umask = 0x2,
   .event_name = "itlb_misses.walk_completed",
   },
  {
   .event_code = {0x85},
   .umask = 0x4,
   .event_name = "itlb_misses.walk_cycles",
   },
  {
   .event_code = {0x51},
   .umask = 0x4,
   .event_name = "l1d.m_evict",
   },
  {
   .event_code = {0x51},
   .umask = 0x2,
   .event_name = "l1d.m_repl",
   },
  {
   .event_code = {0x51},
   .umask = 0x8,
   .event_name = "l1d.m_snoop_evict",
   },
  {
   .event_code = {0x51},
   .umask = 0x1,
   .event_name = "l1d.repl",
   },
  {
   .event_code = {0x52},
   .umask = 0x1,
   .event_name = "l1d_cache_prefetch_lock_fb_hit",
   },
  {
   .event_code = {0x4E},
   .umask = 0x2,
   .event_name = "l1d_prefetch.miss",
   },
  {
   .event_code = {0x4E},
   .umask = 0x1,
   .event_name = "l1d_prefetch.requests",
   },
  {
   .event_code = {0x4E},
   .umask = 0x4,
   .event_name = "l1d_prefetch.triggers",
   },
  {
   .event_code = {0x28},
   .umask = 0x4,
   .event_name = "l1d_wb_l2.e_state",
   },
  {
   .event_code = {0x28},
   .umask = 0x1,
   .event_name = "l1d_wb_l2.i_state",
   },
  {
   .event_code = {0x28},
   .umask = 0x8,
   .event_name = "l1d_wb_l2.m_state",
   },
  {
   .event_code = {0x28},
   .umask = 0xF,
   .event_name = "l1d_wb_l2.mesi",
   },
  {
   .event_code = {0x28},
   .umask = 0x2,
   .event_name = "l1d_wb_l2.s_state",
   },
  {
   .event_code = {0x80},
   .umask = 0x4,
   .event_name = "l1i.cycles_stalled",
   },
  {
   .event_code = {0x80},
   .umask = 0x1,
   .event_name = "l1i.hits",
   },
  {
   .event_code = {0x80},
   .umask = 0x2,
   .event_name = "l1i.misses",
   },
  {
   .event_code = {0x80},
   .umask = 0x3,
   .event_name = "l1i.reads",
   },
  {
   .event_code = {0x26},
   .umask = 0xFF,
   .event_name = "l2_data_rqsts.any",
   },
  {
   .event_code = {0x26},
   .umask = 0x4,
   .event_name = "l2_data_rqsts.demand.e_state",
   },
  {
   .event_code = {0x26},
   .umask = 0x1,
   .event_name = "l2_data_rqsts.demand.i_state",
   },
  {
   .event_code = {0x26},
   .umask = 0x8,
   .event_name = "l2_data_rqsts.demand.m_state",
   },
  {
   .event_code = {0x26},
   .umask = 0xF,
   .event_name = "l2_data_rqsts.demand.mesi",
   },
  {
   .event_code = {0x26},
   .umask = 0x2,
   .event_name = "l2_data_rqsts.demand.s_state",
   },
  {
   .event_code = {0x26},
   .umask = 0x40,
   .event_name = "l2_data_rqsts.prefetch.e_state",
   },
  {
   .event_code = {0x26},
   .umask = 0x10,
   .event_name = "l2_data_rqsts.prefetch.i_state",
   },
  {
   .event_code = {0x26},
   .umask = 0x80,
   .event_name = "l2_data_rqsts.prefetch.m_state",
   },
  {
   .event_code = {0x26},
   .umask = 0xF0,
   .event_name = "l2_data_rqsts.prefetch.mesi",
   },
  {
   .event_code = {0x26},
   .umask = 0x20,
   .event_name = "l2_data_rqsts.prefetch.s_state",
   },
  {
   .event_code = {0xF1},
   .umask = 0x7,
   .event_name = "l2_lines_in.any",
   },
  {
   .event_code = {0xF1},
   .umask = 0x4,
   .event_name = "l2_lines_in.e_state",
   },
  {
   .event_code = {0xF1},
   .umask = 0x2,
   .event_name = "l2_lines_in.s_state",
   },
  {
   .event_code = {0xF2},
   .umask = 0xF,
   .event_name = "l2_lines_out.any",
   },
  {
   .event_code = {0xF2},
   .umask = 0x1,
   .event_name = "l2_lines_out.demand_clean",
   },
  {
   .event_code = {0xF2},
   .umask = 0x2,
   .event_name = "l2_lines_out.demand_dirty",
   },
  {
   .event_code = {0xF2},
   .umask = 0x4,
   .event_name = "l2_lines_out.prefetch_clean",
   },
  {
   .event_code = {0xF2},
   .umask = 0x8,
   .event_name = "l2_lines_out.prefetch_dirty",
   },
  {
   .event_code = {0x24},
   .umask = 0x10,
   .event_name = "l2_rqsts.ifetch_hit",
   },
  {
   .event_code = {0x24},
   .umask = 0x20,
   .event_name = "l2_rqsts.ifetch_miss",
   },
  {
   .event_code = {0x24},
   .umask = 0x30,
   .event_name = "l2_rqsts.ifetches",
   },
  {
   .event_code = {0x24},
   .umask = 0x1,
   .event_name = "l2_rqsts.ld_hit",
   },
  {
   .event_code = {0x24},
   .umask = 0x2,
   .event_name = "l2_rqsts.ld_miss",
   },
  {
   .event_code = {0x24},
   .umask = 0x3,
   .event_name = "l2_rqsts.loads",
   },
  {
   .event_code = {0x24},
   .umask = 0xAA,
   .event_name = "l2_rqsts.miss",
   },
  {
   .event_code = {0x24},
   .umask = 0x40,
   .event_name = "l2_rqsts.prefetch_hit",
   },
  {
   .event_code = {0x24},
   .umask = 0x80,
   .event_name = "l2_rqsts.prefetch_miss",
   },
  {
   .event_code = {0x24},
   .umask = 0xC0,
   .event_name = "l2_rqsts.prefetches",
   },
  {
   .event_code = {0x24},
   .umask = 0xFF,
   .event_name = "l2_rqsts.references",
   },
  {
   .event_code = {0x24},
   .umask = 0x4,
   .event_name = "l2_rqsts.rfo_hit",
   },
  {
   .event_code = {0x24},
   .umask = 0x8,
   .event_name = "l2_rqsts.rfo_miss",
   },
  {
   .event_code = {0x24},
   .umask = 0xC,
   .event_name = "l2_rqsts.rfos",
   },
  {
   .event_code = {0xF0},
   .umask = 0x80,
   .event_name = "l2_transactions.any",
   },
  {
   .event_code = {0xF0},
   .umask = 0x20,
   .event_name = "l2_transactions.fill",
   },
  {
   .event_code = {0xF0},
   .umask = 0x4,
   .event_name = "l2_transactions.ifetch",
   },
  {
   .event_code = {0xF0},
   .umask = 0x10,
   .event_name = "l2_transactions.l1d_wb",
   },
  {
   .event_code = {0xF0},
   .umask = 0x1,
   .event_name = "l2_transactions.load",
   },
  {
   .event_code = {0xF0},
   .umask = 0x8,
   .event_name = "l2_transactions.prefetch",
   },
  {
   .event_code = {0xF0},
   .umask = 0x2,
   .event_name = "l2_transactions.rfo",
   },
  {
   .event_code = {0xF0},
   .umask = 0x40,
   .event_name = "l2_transactions.wb",
   },
  {
   .event_code = {0x27},
   .umask = 0x40,
   .event_name = "l2_write.lock.e_state",
   },
  {
   .event_code = {0x27},
   .umask = 0xE0,
   .event_name = "l2_write.lock.hit",
   },
  {
   .event_code = {0x27},
   .umask = 0x10,
   .event_name = "l2_write.lock.i_state",
   },
  {
   .event_code = {0x27},
   .umask = 0x80,
   .event_name = "l2_write.lock.m_state",
   },
  {
   .event_code = {0x27},
   .umask = 0xF0,
   .event_name = "l2_write.lock.mesi",
   },
  {
   .event_code = {0x27},
   .umask = 0x20,
   .event_name = "l2_write.lock.s_state",
   },
  {
   .event_code = {0x27},
   .umask = 0xE,
   .event_name = "l2_write.rfo.hit",
   },
  {
   .event_code = {0x27},
   .umask = 0x1,
   .event_name = "l2_write.rfo.i_state",
   },
  {
   .event_code = {0x27},
   .umask = 0x8,
   .event_name = "l2_write.rfo.m_state",
   },
  {
   .event_code = {0x27},
   .umask = 0xF,
   .event_name = "l2_write.rfo.mesi",
   },
  {
   .event_code = {0x27},
   .umask = 0x2,
   .event_name = "l2_write.rfo.s_state",
   },
  {
   .event_code = {0x82},
   .umask = 0x1,
   .event_name = "large_itlb.hit",
   },
  {
   .event_code = {0x3},
   .umask = 0x2,
   .event_name = "load_block.overlap_store",
   },
  {
   .event_code = {0x13},
   .umask = 0x7,
   .event_name = "load_dispatch.any",
   },
  {
   .event_code = {0x13},
   .umask = 0x4,
   .event_name = "load_dispatch.mob",
   },
  {
   .event_code = {0x13},
   .umask = 0x1,
   .event_name = "load_dispatch.rs",
   },
  {
   .event_code = {0x13},
   .umask = 0x2,
   .event_name = "load_dispatch.rs_delayed",
   },
  {
   .event_code = {0x4C},
   .umask = 0x1,
   .event_name = "load_hit_pre",
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
   .event_code = {0xA8},
   .umask = 0x1,
   .event_name = "lsd.active",
   },
  {
   .event_code = {0xA8},
   .umask = 0x1,
   .event_name = "lsd.inactive",
   },
  {
   .event_code = {0x20},
   .umask = 0x1,
   .event_name = "lsd_overflow",
   },
  {
   .event_code = {0xC3},
   .umask = 0x1,
   .event_name = "machine_clears.cycles",
   },
  {
   .event_code = {0xC3},
   .umask = 0x2,
   .event_name = "machine_clears.mem_order",
   },
  {
   .event_code = {0xC3},
   .umask = 0x4,
   .event_name = "machine_clears.smc",
   },
  {
   .event_code = {0xD0},
   .umask = 0x1,
   .event_name = "macro_insts.decoded",
   },
  {
   .event_code = {0xA6},
   .umask = 0x1,
   .event_name = "macro_insts.fusions_decoded",
   },
  {
   .event_code = {0xB},
   .umask = 0x1,
   .event_name = "mem_inst_retired.loads",
   },
  {
   .event_code = {0xB},
   .umask = 0x2,
   .event_name = "mem_inst_retired.stores",
   },
  {
   .event_code = {0xCB},
   .umask = 0x80,
   .event_name = "mem_load_retired.dtlb_miss",
   },
  {
   .event_code = {0xCB},
   .umask = 0x40,
   .event_name = "mem_load_retired.hit_lfb",
   },
  {
   .event_code = {0xCB},
   .umask = 0x1,
   .event_name = "mem_load_retired.l1d_hit",
   },
  {
   .event_code = {0xCB},
   .umask = 0x2,
   .event_name = "mem_load_retired.l2_hit",
   },
  {
   .event_code = {0xCB},
   .umask = 0x10,
   .event_name = "mem_load_retired.llc_miss",
   },
  {
   .event_code = {0xCB},
   .umask = 0x4,
   .event_name = "mem_load_retired.llc_unshared_hit",
   },
  {
   .event_code = {0xCB},
   .umask = 0x8,
   .event_name = "mem_load_retired.other_core_l2_hit_hitm",
   },
  {
   .event_code = {0xC},
   .umask = 0x1,
   .event_name = "mem_store_retired.dtlb_miss",
   },
  {
   .event_code = {0x5},
   .umask = 0x2,
   .event_name = "misalign_mem_ref.store",
   },
  {
   .event_code = {0xB0},
   .umask = 0x80,
   .event_name = "offcore_requests.any",
   },
  {
   .event_code = {0xB0},
   .umask = 0x8,
   .event_name = "offcore_requests.any.read",
   },
  {
   .event_code = {0xB0},
   .umask = 0x10,
   .event_name = "offcore_requests.any.rfo",
   },
  {
   .event_code = {0xB0},
   .umask = 0x2,
   .event_name = "offcore_requests.demand.read_code",
   },
  {
   .event_code = {0xB0},
   .umask = 0x1,
   .event_name = "offcore_requests.demand.read_data",
   },
  {
   .event_code = {0xB0},
   .umask = 0x4,
   .event_name = "offcore_requests.demand.rfo",
   },
  {
   .event_code = {0xB0},
   .umask = 0x40,
   .event_name = "offcore_requests.l1d_writeback",
   },
  {
   .event_code = {0x60},
   .umask = 0x8,
   .event_name = "offcore_requests_outstanding.any.read",
   },
  {
   .event_code = {0x60},
   .umask = 0x8,
   .event_name = "offcore_requests_outstanding.any.read_not_empty",
   },
  {
   .event_code = {0x60},
   .umask = 0x2,
   .event_name = "offcore_requests_outstanding.demand.read_code",
   },
  {
   .event_code = {0x60},
   .umask = 0x2,
   .event_name = "offcore_requests_outstanding.demand.read_code_not_empty",
   },
  {
   .event_code = {0x60},
   .umask = 0x1,
   .event_name = "offcore_requests_outstanding.demand.read_data",
   },
  {
   .event_code = {0x60},
   .umask = 0x1,
   .event_name = "offcore_requests_outstanding.demand.read_data_not_empty",
   },
  {
   .event_code = {0x60},
   .umask = 0x4,
   .event_name = "offcore_requests_outstanding.demand.rfo",
   },
  {
   .event_code = {0x60},
   .umask = 0x4,
   .event_name = "offcore_requests_outstanding.demand.rfo_not_empty",
   },
  {
   .event_code = {0xB2},
   .umask = 0x1,
   .event_name = "offcore_requests_sq_full",
   },
  {
   .event_code = {0x7},
   .umask = 0x1,
   .event_name = "partial_address_alias",
   },
  {
   .event_code = {0xD2},
   .umask = 0xF,
   .event_name = "rat_stalls.any",
   },
  {
   .event_code = {0xD2},
   .umask = 0x1,
   .event_name = "rat_stalls.flags",
   },
  {
   .event_code = {0xD2},
   .umask = 0x2,
   .event_name = "rat_stalls.registers",
   },
  {
   .event_code = {0xD2},
   .umask = 0x4,
   .event_name = "rat_stalls.rob_read_port",
   },
  {
   .event_code = {0xD2},
   .umask = 0x8,
   .event_name = "rat_stalls.scoreboard",
   },
  {
   .event_code = {0xA2},
   .umask = 0x1,
   .event_name = "resource_stalls.any",
   },
  {
   .event_code = {0xA2},
   .umask = 0x20,
   .event_name = "resource_stalls.fpcw",
   },
  {
   .event_code = {0xA2},
   .umask = 0x2,
   .event_name = "resource_stalls.load",
   },
  {
   .event_code = {0xA2},
   .umask = 0x40,
   .event_name = "resource_stalls.mxcsr",
   },
  {
   .event_code = {0xA2},
   .umask = 0x80,
   .event_name = "resource_stalls.other",
   },
  {
   .event_code = {0xA2},
   .umask = 0x10,
   .event_name = "resource_stalls.rob_full",
   },
  {
   .event_code = {0xA2},
   .umask = 0x4,
   .event_name = "resource_stalls.rs_full",
   },
  {
   .event_code = {0xA2},
   .umask = 0x8,
   .event_name = "resource_stalls.store",
   },
  {
   .event_code = {0x4},
   .umask = 0x7,
   .event_name = "sb_drain.any",
   },
  {
   .event_code = {0xD4},
   .umask = 0x1,
   .event_name = "seg_rename_stalls",
   },
  {
   .event_code = {0x12},
   .umask = 0x4,
   .event_name = "simd_int_128.pack",
   },
  {
   .event_code = {0x12},
   .umask = 0x20,
   .event_name = "simd_int_128.packed_arith",
   },
  {
   .event_code = {0x12},
   .umask = 0x10,
   .event_name = "simd_int_128.packed_logical",
   },
  {
   .event_code = {0x12},
   .umask = 0x1,
   .event_name = "simd_int_128.packed_mpy",
   },
  {
   .event_code = {0x12},
   .umask = 0x2,
   .event_name = "simd_int_128.packed_shift",
   },
  {
   .event_code = {0x12},
   .umask = 0x40,
   .event_name = "simd_int_128.shuffle_move",
   },
  {
   .event_code = {0x12},
   .umask = 0x8,
   .event_name = "simd_int_128.unpack",
   },
  {
   .event_code = {0xFD},
   .umask = 0x4,
   .event_name = "simd_int_64.pack",
   },
  {
   .event_code = {0xFD},
   .umask = 0x20,
   .event_name = "simd_int_64.packed_arith",
   },
  {
   .event_code = {0xFD},
   .umask = 0x10,
   .event_name = "simd_int_64.packed_logical",
   },
  {
   .event_code = {0xFD},
   .umask = 0x1,
   .event_name = "simd_int_64.packed_mpy",
   },
  {
   .event_code = {0xFD},
   .umask = 0x2,
   .event_name = "simd_int_64.packed_shift",
   },
  {
   .event_code = {0xFD},
   .umask = 0x40,
   .event_name = "simd_int_64.shuffle_move",
   },
  {
   .event_code = {0xFD},
   .umask = 0x8,
   .event_name = "simd_int_64.unpack",
   },
  {
   .event_code = {0xB8},
   .umask = 0x1,
   .event_name = "snoop_response.hit",
   },
  {
   .event_code = {0xB8},
   .umask = 0x2,
   .event_name = "snoop_response.hite",
   },
  {
   .event_code = {0xB8},
   .umask = 0x4,
   .event_name = "snoop_response.hitm",
   },
  {
   .event_code = {0xB4},
   .umask = 0x4,
   .event_name = "snoopq_requests.code",
   },
  {
   .event_code = {0xB4},
   .umask = 0x1,
   .event_name = "snoopq_requests.data",
   },
  {
   .event_code = {0xB4},
   .umask = 0x2,
   .event_name = "snoopq_requests.invalidate",
   },
  {
   .event_code = {0xB3},
   .umask = 0x4,
   .event_name = "snoopq_requests_outstanding.code",
   },
  {
   .event_code = {0xB3},
   .umask = 0x4,
   .event_name = "snoopq_requests_outstanding.code_not_empty",
   },
  {
   .event_code = {0xB3},
   .umask = 0x1,
   .event_name = "snoopq_requests_outstanding.data",
   },
  {
   .event_code = {0xB3},
   .umask = 0x1,
   .event_name = "snoopq_requests_outstanding.data_not_empty",
   },
  {
   .event_code = {0xB3},
   .umask = 0x2,
   .event_name = "snoopq_requests_outstanding.invalidate",
   },
  {
   .event_code = {0xB3},
   .umask = 0x2,
   .event_name = "snoopq_requests_outstanding.invalidate_not_empty",
   },
  {
   .event_code = {0xF6},
   .umask = 0x1,
   .event_name = "sq_full_stall_cycles",
   },
  {
   .event_code = {0xF4},
   .umask = 0x4,
   .event_name = "sq_misc.lru_hints",
   },
  {
   .event_code = {0xF4},
   .umask = 0x10,
   .event_name = "sq_misc.split_lock",
   },
  {
   .event_code = {0xC7},
   .umask = 0x4,
   .event_name = "ssex_uops_retired.packed_double",
   },
  {
   .event_code = {0xC7},
   .umask = 0x1,
   .event_name = "ssex_uops_retired.packed_single",
   },
  {
   .event_code = {0xC7},
   .umask = 0x8,
   .event_name = "ssex_uops_retired.scalar_double",
   },
  {
   .event_code = {0xC7},
   .umask = 0x2,
   .event_name = "ssex_uops_retired.scalar_single",
   },
  {
   .event_code = {0xC7},
   .umask = 0x10,
   .event_name = "ssex_uops_retired.vector_integer",
   },
  {
   .event_code = {0x6},
   .umask = 0x4,
   .event_name = "store_blocks.at_ret",
   },
  {
   .event_code = {0x6},
   .umask = 0x8,
   .event_name = "store_blocks.l1d_block",
   },
  {
   .event_code = {0x19},
   .umask = 0x1,
   .event_name = "two_uop_insts_decoded",
   },
  {
   .event_code = {0xDB},
   .umask = 0x1,
   .event_name = "uop_unfusion",
   },
  {
   .event_code = {0xD1},
   .umask = 0x4,
   .event_name = "uops_decoded.esp_folding",
   },
  {
   .event_code = {0xD1},
   .umask = 0x8,
   .event_name = "uops_decoded.esp_sync",
   },
  {
   .event_code = {0xD1},
   .umask = 0x2,
   .event_name = "uops_decoded.ms_cycles_active",
   },
  {
   .event_code = {0xD1},
   .umask = 0x1,
   .event_name = "uops_decoded.stall_cycles",
   },
  {
   .event_code = {0xB1},
   .umask = 0x3F,
   .event_name = "uops_executed.core_active_cycles",
   },
  {
   .event_code = {0xB1},
   .umask = 0x1F,
   .event_name = "uops_executed.core_active_cycles_no_port5",
   },
  {
   .event_code = {0xB1},
   .umask = 0x3F,
   .event_name = "uops_executed.core_stall_count",
   },
  {
   .event_code = {0xB1},
   .umask = 0x1F,
   .event_name = "uops_executed.core_stall_count_no_port5",
   },
  {
   .event_code = {0xB1},
   .umask = 0x3F,
   .event_name = "uops_executed.core_stall_cycles",
   },
  {
   .event_code = {0xB1},
   .umask = 0x1F,
   .event_name = "uops_executed.core_stall_cycles_no_port5",
   },
  {
   .event_code = {0xB1},
   .umask = 0x1,
   .event_name = "uops_executed.port0",
   },
  {
   .event_code = {0xB1},
   .umask = 0x40,
   .event_name = "uops_executed.port015",
   },
  {
   .event_code = {0xB1},
   .umask = 0x40,
   .event_name = "uops_executed.port015_stall_cycles",
   },
  {
   .event_code = {0xB1},
   .umask = 0x2,
   .event_name = "uops_executed.port1",
   },
  {
   .event_code = {0xB1},
   .umask = 0x4,
   .event_name = "uops_executed.port2_core",
   },
  {
   .event_code = {0xB1},
   .umask = 0x80,
   .event_name = "uops_executed.port234_core",
   },
  {
   .event_code = {0xB1},
   .umask = 0x8,
   .event_name = "uops_executed.port3_core",
   },
  {
   .event_code = {0xB1},
   .umask = 0x10,
   .event_name = "uops_executed.port4_core",
   },
  {
   .event_code = {0xB1},
   .umask = 0x20,
   .event_name = "uops_executed.port5",
   },
  {
   .event_code = {0xE},
   .umask = 0x1,
   .event_name = "uops_issued.any",
   },
  {
   .event_code = {0xE},
   .umask = 0x1,
   .event_name = "uops_issued.core_stall_cycles",
   },
  {
   .event_code = {0xE},
   .umask = 0x1,
   .event_name = "uops_issued.cycles_all_threads",
   },
  {
   .event_code = {0xE},
   .umask = 0x2,
   .event_name = "uops_issued.fused",
   },
  {
   .event_code = {0xE},
   .umask = 0x1,
   .event_name = "uops_issued.stall_cycles",
   },
  {
   .event_code = {0xC2},
   .umask = 0x1,
   .event_name = "uops_retired.active_cycles",
   },
  {
   .event_code = {0xC2},
   .umask = 0x1,
   .event_name = "uops_retired.any",
   },
  {
   .event_code = {0xC2},
   .umask = 0x4,
   .event_name = "uops_retired.macro_fused",
   },
  {
   .event_code = {0xC2},
   .umask = 0x2,
   .event_name = "uops_retired.retire_slots",
   },
  {
   .event_code = {0xC2},
   .umask = 0x1,
   .event_name = "uops_retired.stall_cycles",
   },
  {
   .event_code = {0xC2},
   .umask = 0x1,
   .event_name = "uops_retired.total_cycles",
   },
  {
   .event_code = {0xC0},
   .umask = 0x1,
   .event_name = "inst_retired.total_cycles_ps",
   },
  {
   .event_name = 0,
   },
};

PERFMON_REGISTER_INTEL_PMC (cpu_model_table, event_table);

