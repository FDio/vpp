
#include <perfmon/perfmon_intel.h>

static perfmon_intel_pmc_cpu_model_t cpu_model_table[] = {
  {0x37, 0x00, 0},
  {0x4C, 0x00, 0},
  {0x4D, 0x00, 0},

};

static perfmon_intel_pmc_event_t event_table[] = {
  {
   .event_code = {0xC4},
   .umask = 0x00,
   .event_name = "br_inst_retired.all_branches",
   },
  {
   .event_code = {0xC4},
   .umask = 0x7E,
   .event_name = "br_inst_retired.jcc",
   },
  {
   .event_code = {0xC4},
   .umask = 0xFE,
   .event_name = "br_inst_retired.taken_jcc",
   },
  {
   .event_code = {0xC4},
   .umask = 0xF9,
   .event_name = "br_inst_retired.call",
   },
  {
   .event_code = {0xC4},
   .umask = 0xFD,
   .event_name = "br_inst_retired.rel_call",
   },
  {
   .event_code = {0xC4},
   .umask = 0xFB,
   .event_name = "br_inst_retired.ind_call",
   },
  {
   .event_code = {0xC4},
   .umask = 0xF7,
   .event_name = "br_inst_retired.return",
   },
  {
   .event_code = {0xC4},
   .umask = 0xEB,
   .event_name = "br_inst_retired.non_return_ind",
   },
  {
   .event_code = {0xC4},
   .umask = 0xBF,
   .event_name = "br_inst_retired.far_branch",
   },
  {
   .event_code = {0xC5},
   .umask = 0x00,
   .event_name = "br_misp_retired.all_branches",
   },
  {
   .event_code = {0xC5},
   .umask = 0x7E,
   .event_name = "br_misp_retired.jcc",
   },
  {
   .event_code = {0xC5},
   .umask = 0xFE,
   .event_name = "br_misp_retired.taken_jcc",
   },
  {
   .event_code = {0xC5},
   .umask = 0xFB,
   .event_name = "br_misp_retired.ind_call",
   },
  {
   .event_code = {0xC5},
   .umask = 0xF7,
   .event_name = "br_misp_retired.return",
   },
  {
   .event_code = {0xC5},
   .umask = 0xEB,
   .event_name = "br_misp_retired.non_return_ind",
   },
  {
   .event_code = {0xC2},
   .umask = 0x01,
   .event_name = "uops_retired.ms",
   },
  {
   .event_code = {0xC2},
   .umask = 0x10,
   .event_name = "uops_retired.all",
   },
  {
   .event_code = {0xC3},
   .umask = 0x01,
   .event_name = "machine_clears.smc",
   },
  {
   .event_code = {0xC3},
   .umask = 0x02,
   .event_name = "machine_clears.memory_ordering",
   },
  {
   .event_code = {0xC3},
   .umask = 0x04,
   .event_name = "machine_clears.fp_assist",
   },
  {
   .event_code = {0xC3},
   .umask = 0x08,
   .event_name = "machine_clears.all",
   },
  {
   .event_code = {0xCA},
   .umask = 0x01,
   .event_name = "no_alloc_cycles.rob_full",
   },
  {
   .event_code = {0xCA},
   .umask = 0x04,
   .event_name = "no_alloc_cycles.mispredicts",
   },
  {
   .event_code = {0xCA},
   .umask = 0x20,
   .event_name = "no_alloc_cycles.rat_stall",
   },
  {
   .event_code = {0xCA},
   .umask = 0x50,
   .event_name = "no_alloc_cycles.not_delivered",
   },
  {
   .event_code = {0xCA},
   .umask = 0x3F,
   .event_name = "no_alloc_cycles.all",
   },
  {
   .event_code = {0xCB},
   .umask = 0x01,
   .event_name = "rs_full_stall.mec",
   },
  {
   .event_code = {0xCB},
   .umask = 0x1F,
   .event_name = "rs_full_stall.all",
   },
  {
   .event_code = {0xC0},
   .umask = 0x00,
   .event_name = "inst_retired.any_p",
   },
  {
   .event_code = {0xCD},
   .umask = 0x01,
   .event_name = "cycles_div_busy.all",
   },
  {
   .event_code = {0x00},
   .umask = 0x01,
   .event_name = "inst_retired.any",
   },
  {
   .event_code = {0x00},
   .umask = 0x02,
   .event_name = "cpu_clk_unhalted.core",
   },
  {
   .event_code = {0x00},
   .umask = 0x03,
   .event_name = "cpu_clk_unhalted.ref_tsc",
   },
  {
   .event_code = {0x3C},
   .umask = 0x00,
   .event_name = "cpu_clk_unhalted.core_p",
   },
  {
   .event_code = {0x3C},
   .umask = 0x01,
   .event_name = "cpu_clk_unhalted.ref",
   },
  {
   .event_code = {0x30},
   .umask = 0x00,
   .event_name = "l2_reject_xq.all",
   },
  {
   .event_code = {0x31},
   .umask = 0x00,
   .event_name = "core_reject_l2q.all",
   },
  {
   .event_code = {0x2E},
   .umask = 0x4F,
   .event_name = "longest_lat_cache.reference",
   },
  {
   .event_code = {0x2E},
   .umask = 0x41,
   .event_name = "longest_lat_cache.miss",
   },
  {
   .event_code = {0x80},
   .umask = 0x03,
   .event_name = "icache.accesses",
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
   .event_code = {0x86},
   .umask = 0x02,
   .event_name = "fetch_stall.itlb_fill_pending_cycles",
   },
  {
   .event_code = {0x86},
   .umask = 0x04,
   .event_name = "fetch_stall.icache_fill_pending_cycles",
   },
  {
   .event_code = {0x86},
   .umask = 0x3F,
   .event_name = "fetch_stall.all",
   },
  {
   .event_code = {0xE6},
   .umask = 0x01,
   .event_name = "baclears.all",
   },
  {
   .event_code = {0xE6},
   .umask = 0x08,
   .event_name = "baclears.return",
   },
  {
   .event_code = {0xE6},
   .umask = 0x10,
   .event_name = "baclears.cond",
   },
  {
   .event_code = {0xE7},
   .umask = 0x01,
   .event_name = "ms_decoded.ms_entry",
   },
  {
   .event_code = {0xE9},
   .umask = 0x01,
   .event_name = "decode_restriction.predecode_wrong",
   },
  {
   .event_code = {0x03},
   .umask = 0x01,
   .event_name = "rehabq.ld_block_st_forward",
   },
  {
   .event_code = {0x03},
   .umask = 0x02,
   .event_name = "rehabq.ld_block_std_notready",
   },
  {
   .event_code = {0x03},
   .umask = 0x04,
   .event_name = "rehabq.st_splits",
   },
  {
   .event_code = {0x03},
   .umask = 0x08,
   .event_name = "rehabq.ld_splits",
   },
  {
   .event_code = {0x03},
   .umask = 0x10,
   .event_name = "rehabq.lock",
   },
  {
   .event_code = {0x03},
   .umask = 0x20,
   .event_name = "rehabq.sta_full",
   },
  {
   .event_code = {0x03},
   .umask = 0x40,
   .event_name = "rehabq.any_ld",
   },
  {
   .event_code = {0x03},
   .umask = 0x80,
   .event_name = "rehabq.any_st",
   },
  {
   .event_code = {0x04},
   .umask = 0x01,
   .event_name = "mem_uops_retired.l1_miss_loads",
   },
  {
   .event_code = {0x04},
   .umask = 0x02,
   .event_name = "mem_uops_retired.l2_hit_loads",
   },
  {
   .event_code = {0x04},
   .umask = 0x04,
   .event_name = "mem_uops_retired.l2_miss_loads",
   },
  {
   .event_code = {0x04},
   .umask = 0x08,
   .event_name = "mem_uops_retired.dtlb_miss_loads",
   },
  {
   .event_code = {0x04},
   .umask = 0x10,
   .event_name = "mem_uops_retired.utlb_miss",
   },
  {
   .event_code = {0x04},
   .umask = 0x20,
   .event_name = "mem_uops_retired.hitm",
   },
  {
   .event_code = {0x04},
   .umask = 0x40,
   .event_name = "mem_uops_retired.all_loads",
   },
  {
   .event_code = {0x04},
   .umask = 0x80,
   .event_name = "mem_uops_retired.all_stores",
   },
  {
   .event_code = {0x05},
   .umask = 0x01,
   .event_name = "page_walks.d_side_walks",
   },
  {
   .event_code = {0x05},
   .umask = 0x01,
   .event_name = "page_walks.d_side_cycles",
   },
  {
   .event_code = {0x05},
   .umask = 0x02,
   .event_name = "page_walks.i_side_walks",
   },
  {
   .event_code = {0x05},
   .umask = 0x02,
   .event_name = "page_walks.i_side_cycles",
   },
  {
   .event_code = {0x05},
   .umask = 0x03,
   .event_name = "page_walks.walks",
   },
  {
   .event_code = {0x05},
   .umask = 0x03,
   .event_name = "page_walks.cycles",
   },
  {
   .event_code = {0xC4},
   .umask = 0x80,
   .event_name = "br_inst_retired.all_taken_branches",
   },
  {
   .event_name = 0,
   },
};

PERFMON_REGISTER_INTEL_PMC (cpu_model_table, event_table);

